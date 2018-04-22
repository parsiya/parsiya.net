---
title: "Proxying with Go - Part 1 - Keys and Certificates"
date: 2018-04-14T15:16:17-04:00
draft: true
toc: false
comments: true
categories:
- Go
- Crypto
tags:
- 
---

**TL;DR:** If you want to create self-signed certificates and spin up TLS client/servers dynamically to MitM, read on. If you want to create only a couple of certificates to spin up a web server, you are much better off following one of the many `OpenSSL` guides out there.

Doing mostly weird projects at work, I proxy a lot of applications. I have talked a lot about thickclient proxying with Burp as you can see:

- [https://parsiya.net/categories/thick-client-proxying/](https://parsiya.net/categories/thick-client-proxying/)

But most of these only apply if the application is using the HTTP(s) protocol. For raw TCP protocols, vanilla Burp is  useless.

<!--more-->

# Why Should I Read This?
When I first started learning Go less than two years ago (June 2016 to be exact), I was doing so by writing a TLS-terminating Man-in-the-Middle (MitM) proxy (think Burp but for non-HTTP protocols). The proxy eventually got written in some hacky way and did the job for the project I was working on (and some subsequent ones) but I never published it.

Part of such software is creating certificates on the fly for each new connection. There are quite a few tutorials out there about spinning up your own HTTPs server and some talk about creating your own certificate using `OpenSSL`. When searching for creating certificates in Go, you get page after page about "Let's Encrypt" and ACME protocol.

The standard library gives you all the tools you need to accomplish this but it's not consistent on formats. Hopefully this helps the next (most likely) infosec person to deal with the pitfalls and not Go back to Python.

# Laundry List
This article assumes you generally understand the following (general concepts, not the gory mathematical details):

* Asymmetric Cryptography:
    - How public/private key pairs work.
* x509 Certificates (specifically TLS certificates):
    - What is a certificate?
    - What is it used for?
    - What are some general fields in TLS certificates?
* DER and PEM encodings:
    - DER is ASN.1 encoded bytes.
    - PEM is DER in base64 with a text header and footer.

# Keys
Let's start with keys and build everything up.

## Key Algorithms
When creating keys, you can choose one of [the three algorithms][pub-key-algos]:

{{< codecaption title="Supported key algorithms" lang="go" >}}
var publicKeyAlgoName = [...]string{
    RSA:   "RSA",
    DSA:   "DSA",
    ECDSA: "ECDSA",
}
{{< /codecaption >}}

We're going to ignore `DSA` and work with the other two.

## Key Generation
We have to use package specific functions based on the algorithm.

### rsa.GenerateKey
To [generate an RSA key][rsa-generatekey], we have to supply the number of bits in the key.

{{< codecaption title="rsa.GenerateKey()" lang="go" >}}
// Be sure to use rand.Reader.
rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 1024)
{{< /codecaption >}}

The result will be of type [rsa.PrivateKey][rsa-privatekey]:

{{< codecaption title="rsa.PrivateKey" lang="go" >}}
type PrivateKey struct {
    PublicKey            // public part.
    D         *big.Int   // private exponent
    Primes    []*big.Int // prime factors of N, has >= 2 elements.

    // Precomputed contains precomputed values that speed up private
    // operations, if available.
    Precomputed PrecomputedValues
}
{{< /codecaption >}}

Note private key also has the [rsa.PublicKey][rsa-publickey] embedded in it:

{{< codecaption title="rsa.PublicKey" lang="go" >}}
type PublicKey struct {
    N *big.Int // modulus
    E int      // public exponent
}
{{< /codecaption >}}

### ecdsa.GenerateKey
Creating ECDSA keys are just as simple, but we need to provide a curve of type [elliptic.Curve][elliptic-curve] which is the return value of one of [these four functions][elliptic-curve-functions]:

{{< codecaption title="elliptic.Curves" lang="ps" >}}
elliptic.P224()
elliptic.P256()
elliptic.P384()
elliptic.P521()
{{< /codecaption >}}

Generating the key is done using the [ecdsa.GenerateKey()][ecdsa-generatekey] function:

{{< codecaption title="ecdsa.GenerateKey()" lang="ps" >}}
ecdsaPrivKey, err := ecdsa.GenerateKey(P224(), rand.Reader)
ecdsaPrivKey, err := ecdsa.GenerateKey(P384(), rand.Reader)
{{< /codecaption >}}

For some reason `rand io.Reader` is the second parameter for ECDSA `GenerateKey()` and first for the RSA.

If you want more granular output, there's also an [elliptic.GenerateKey()][elliptic-generatekey] function.

{{< codecaption title="elliptic.GenerateKey()" lang="go" >}}
func elliptic.GenerateKey(curve Curve, rand io.Reader)
    (priv []byte, x, y *big.Int, err error)
{{< /codecaption >}}

ECDSA [private][ecdsa-privatekey] and [public][ecdsa-publickey] keys are similar to RSA:

{{< codecaption title="ecdsa.PrivateKey" lang="go" >}}
type PrivateKey struct {
    PublicKey
    D *big.Int
}
{{< /codecaption >}}

Note that public key is again embedded into private key:

{{< codecaption title="ecdsa.PublicKey" lang="go" >}}
type PublicKey struct {
    elliptic.Curve
    X, Y *big.Int
}
{{< /codecaption >}}

### Keypair Struct
Now we know how to generate keys, before we continue we need to take a step back and do a bit of planning. Assume we want to make a general `GenerateKeys()` function that creates a pair of keys based on a provided algorithm and specifications (e.g. 2048-bit RSA), such a function needs to return an `interface{}` because the output could be either an RSA or ECDSA key.

When I wrote my TLS dump code 1.5 years ago, I had to go into so much trouble [with unmarshalling][tlsdump-unmarshal]. Oh you have this blob of bytes that you want to convert to PEM but what kind of object is it? Then after parsing, you also need to spit out another `interface{}` too.

This time I created a Keypair struct that holds pointers to everything and the key types.

{{< codecaption title="Keypair struct" lang="go" >}}
// Keypair contains a pair of public/private keys.
type Keypair struct {
    Algorithm     KeyAlgo
    Curve         elliptic.Curve
    RSAKeySize    RSAKeySize
    privateKeyRSA *rsa.PrivateKey
    privateKeyEC  *ecdsa.PrivateKey
}
{{< /codecaption >}}

`KeyAlgo` and `RSAKeySize` are just helper constants.

{{< codecaption title="KeyAlgo and RSAKeySize" lang="go" >}}
// KeyAlgo represents the supported key types.
type KeyAlgo string

const (
    KeyAlgoRSA = "RSA"
    KeyAlgoEC  = "ECDSA"
)

// RSAKeySize represents four supported RSA keysizes.
type RSAKeySize int

// Constants representing RSA keysizes.
const (
    RSAKey1024 = 1024
    RSAKey2048 = 2048
    RSAKey3072 = 3072
    RSAKey4096 = 4096
)
{{< /codecaption >}}

### Generic GenerateKeys()
Now we can create a key generator that returns a `Keypair` and we do not have to worry about the type and unmarshalling anymore.

{{< codecaption title="GenerateKeypair" lang="go" >}}
// GenerateKeypair creates a new Keypair with specified algorithm, curve or
// keysize. If algo is KeyAlgoRSA, curve is ignored and keySize is used.
// If algo is KeyAlgoEC, curve is used and keysize is ignored.
// Valid curves are elliptic.P224()/P256()/P384() and P521().
func GenerateKeypair(algo KeyAlgo, curve elliptic.Curve, keySize RSAKeySize) (key Keypair, err error) {
    switch algo {
    case KeyAlgoRSA:
        privKey, err := rsa.GenerateKey(rand.Reader, int(keySize))
        if err != nil {
            return key, err
        }
        key.Algorithm = algo
        key.RSAKeySize = keySize
        key.privateKeyRSA = privKey
    case KeyAlgoEC:
        privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
        if err != nil {
            return key, err
        }
        key.Algorithm = algo
        key.privateKeyEC = privKey
        key.Curve = curve
    default:
        return key, fmt.Errorf("error generating keypair: algorithm is not set or isn't valid, got %s", algo)
    }
    return key, nil
}
{{< /codecaption >}}

### Keypair Helper Methods
We can also make helper methods to return the private key and public keys automatically by reading `keypair.Algorithm` internally. Public and private keys are returned in an `interface{}`. Things like this:

{{< codecaption title="keypair.GetPrivateKey()" lang="go" >}}
// GetPrivateKey returns a pointer to the private key object as an interface{}.
func (k Keypair) GetPrivateKey() (interface{}, error) {
    switch k.Algorithm {
    case KeyAlgoRSA:
        if k.privateKeyRSA == nil {
            return nil, fmt.Errorf("keypair's algorithm is set to %s but the corresponding public key is not set", KeyAlgoRSA)
        }
        return k.privateKeyRSA, nil
    case KeyAlgoEC:
        if k.privateKeyEC == nil {
            return nil, fmt.Errorf("keypair's algorithm is set to %s but the corresponding public key is not set", KeyAlgoEC)
        }
        return k.privateKeyEC, nil
    default:
        return nil, fmt.Errorf("error getting private key: keypair's algorithm is not set or isn't valid, got %s", k.Algorithm)
    }
}
{{< /codecaption >}}

### Converting Keys to DER
If you decide not to create any and handle the keys manually, it's fine but be sure to create a method for returning the private key in DER format. The `x509` library has different marshalling methods for RSA and ECDSA keys. Now we can use our `GetPrivateKey()` method like this:

{{< codecaption title="GetPrivateKeyDER" lang="go" >}}
// GetPrivateKeyDER returns the private key in DER format as a []byte.
func (k Keypair) GetPrivateKeyDER() (privKeyDER []byte, err error) {
    // Check if corresponding private key is set.
    _, err = k.GetPrivateKey()
    if err != nil {
        return nil, err
    }

    switch k.Algorithm {
    case KeyAlgoRSA:
        privKeyDER := x509.MarshalPKCS1PrivateKey(k.privateKeyRSA)
        if privKeyDER == nil {
            return nil, fmt.Errorf("error getting private key: invalid RSA private key")
        }
        return privKeyDER, nil
    case KeyAlgoEC:
        return x509.MarshalECPrivateKey(k.privateKeyEC)
    default:
        return nil, fmt.Errorf("error getting private key: keypair's algorithm is not set or isn't valid, got %s", k.Algorithm)
    }
}
{{< /codecaption >}}

Here's another library inconsistency between RSA and ECDSA methods.

[x509.MarshalPKCS1PrivateKey][x509-unmarshalpkcs1privatekey] does not return an error while [x509.MarshalECPrivateKey][x509-marshalecprivatekey] does. Looking inside [the source][x509-unmarshalpkcs1privatekey-source] we can see the `asn1.Marshal` error is being ignored.

{{< codecaption title="x509.MarshalPKCS1PrivateKey" lang="go" >}}
// MarshalPKCS1PrivateKey converts a private key to ASN.1 DER encoded form.
func MarshalPKCS1PrivateKey(key *rsa.PrivateKey) []byte {
    // Removed

    b, _ := asn1.Marshal(priv)
    return b
}
{{< /codecaption >}}

Both of these methods convert a private key object into DER bytes.

### Converting DER to PEM
PEM encoding is just DER bytes with a text header and footer. Converting the private key to PEM is straightforward.

{{< codecaption title="GetPrivateKeyPEM" lang="go" >}}
// GetPrivateKeyPEM returns keypair's private key in PEM encoding.
func (k Keypair) GetPrivateKeyPEM() (keyPEM []byte, err error) {
    var pemBlock *pem.Block
    switch k.Algorithm {
    case KeyAlgoRSA:
        pemBlock.Type = "RSA PRIVATE KEY"
    case KeyAlgoEC:
        pemBlock.Type = "EC PRIVATE KEY"
    default:
        return nil, fmt.Errorf("error getting private key: keypair's algorithm is not set or isn't valid, got %s", k.Algorithm)
    }

    pemBlock.Bytes, err = k.GetPrivateKeyDER()
    if err != nil {
        return nil, err
    }

    if err := pem.Encode(bytes.NewBuffer(keyPEM), pemBlock); err != nil {
        return nil, err
    }
    return keyPEM, nil
}
{{< /codecaption >}}

The [pem][pem-package] offers two encode functions.

- [func Encode(out io.Writer, b *Block) error][pem-encode]
- [func EncodeToMemory(b *Block) []byte][pem-encodetomemory]

I would advise using `Encode` because it returns an error. It's a bit harder to use because we need to pass an `io.Writer`. With `EncodeToMemory` the the result is `nil` in case of errors.



<!-- Links -->

[pub-key-algos]: https://golang.org/src/crypto/x509/x509.go#L221
[rsa-generatekey]: https://golang.org/pkg/crypto/rsa/#GenerateKey
[rsa-privatekey]: https://golang.org/pkg/crypto/rsa/#PrivateKey
[rsa-publickey]: https://golang.org/pkg/crypto/rsa/#PublicKey
[elliptic-curve]: https://golang.org/pkg/crypto/elliptic/#Curve
[elliptic-curve-functions]: https://golang.org/pkg/crypto/elliptic/#P224
[ecdsa-generatekey]: https://golang.org/pkg/crypto/ecdsa/#GenerateKey
[elliptic-generatekey]: https://golang.org/pkg/crypto/elliptic/#GenerateKey
[ecdsa-privatekey]: https://golang.org/pkg/crypto/ecdsa/#PrivateKey
[ecdsa-publickey]: https://golang.org/pkg/crypto/ecdsa/#PublicKey
[tlsdump-unmarshal]: https://github.com/parsiya/tlsdump/blob/master/certhelper.go#L300
[x509-unmarshalpkcs1privatekey]: https://golang.org/pkg/crypto/x509/#MarshalPKCS1PrivateKey
[x509-marshalecprivatekey]: https://golang.org/pkg/crypto/x509/#MarshalECPrivateKey
[x509-unmarshalpkcs1privatekey-source]: https://golang.org/src/crypto/x509/pkcs1.go?s=2239:2294#L82
[pem-package]: https://golang.org/pkg/encoding/pem/
[pem-encode]:
[pem-encodetomemory]:




