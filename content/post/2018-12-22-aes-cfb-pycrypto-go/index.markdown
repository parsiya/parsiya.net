---
title: "AES-CFB128: PyCrypto vs. Go"
date: 2018-12-22T19:25:10-05:00
draft: false
toc: true
comments: true
twitterImage: 06-picard.jpg
categories:
- Crypto
- Go
- Python
tags:
- AES
---

We have encrypted something with AES-CFB128 in Go. How can we decrypt it with PyCrypto?

This was originally part of the next blog post (about creating Python Burp extensions) but it grew large enough to be a separate post.

Disclaimer: I am not knowledgeable enough to explain cryptography to people. Read actual papers/books/articles to figure things out. If you find mistakes here, please let me know.

Code is at: https://github.com/parsiya/Go-Security/tree/master/aes-cfb128

<!--more-->

# What is PyCrypto?
Python's standard library does not have an AES implementation. 3rd party libraries are the answer. I am using [PyCrypto][pycrypto-github]. There's also [M2Crypto][m2crypto-gitlab] and a bunch of other stuff.

If you developing on Windows like me (I am in a Windows 10 64-bit VM), save yourself a headache, skip pypi and just download the binary (I used `PyCrypto 2.6 for Python 2.7 64bit`):

* http://www.voidspace.org.uk/python/modules.shtml#pycrypto

# What is AES-CFB?
It turns AES into a stream cipher.

{{< imgcap title="AES-CFB Decryption - source: https://en.wikipedia.org/wiki/File:CFB_encryption.svg" src="01-cfb-wikiepdia.svg" >}}

Instead of encrypting the plaintext and XOR-ing with the IV (think CBC), it encrypts the IV and XOR-s it with the plaintext. The ciphertext is then encrypted and XOR-ed with the next block just like CBC.

## Segment Size
It's the number of bits of ciphertext and plaintext that are XOR-ed together. However, this changes the way the rest of the cipher works. Allow me to explain using an example.

The picture above is running in `AES-CFB128` mode. A complete block (16 bytes) is encrypted and then XOR-ed with a block of plaintext. Let's assume the last block is smaller than 16 bytes, we do not need the rest of the bytes and we will discard them.

In `CFB8` (a.k.a. `CFB1` because 8 bits == 1 byte), things get more complicated. We have a 16 byte register called `shift register`. Initially, it's populated by IV. Then we encrypt it with `AES(key)`. See initial register in big-endian.

```
IV0 IV1 IV2 ... IV14 IV15
```

*Segment size* of 8 means we will XOR the first byte of plaintext with the first byte of encrypted register to get `CI0`. This byte is pushed to the register from right, so the first byte of the register (which was `IV0`) is discarded.

```
IV1 IV2 ... IV14 IV15 CI0
```

The register is encrypted with the key again. The first byte of the result is XOR-ed with the second byte of plaintext to produce `CI1`. This is pushed to the register and so on.

```
IV2 ... IV14 IV15 CI0 CI1
```

Life was much easier in CFB128, neh?

Not only things were simpler, but it was also considerably faster. In `CFB8`, we have to call AES encryption 16 times for each block vs. 1 in `CFB128`.

## Go
Unlike Python, Go supports AES out of the box. The following Go program, encrypts a text in AES-CFB and then base64 encodes it. Run it on Go playground at https://play.golang.org/p/hNKOFqJ72Fi or locally by running `cfb.go`. **Go only support `CFB128`**.

``` go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
)

func main() {
	key := []byte("0123456789012345")
	iv := []byte("9876543210987654")
	msg := []byte("Hello AES, my old friend")

	enc, err := Encrypt(msg, key, iv)
	if err != nil {
		panic(err)
	}

    fmt.Printf("%s", enc)
}

// Encrypt encrypts the plaintext with key and iv using AES-CFB and returns it in base64.
func Encrypt(plaintext, key, iv []byte) ([]byte, error) {
	// Create ciphertext.
	ciphertext := make([]byte, len(plaintext))
	// Create AES cipher.
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// Get AES-CFB stream encrypted.
	stream := cipher.NewCFBEncrypter(aesBlock, iv)
	// Encrypt the msg and store the results in ciphertext.
	stream.XORKeyStream(ciphertext, plaintext)
	// Base64 encode it.
	encodedCiphertext := make([]byte, base64.StdEncoding.EncodedLen(len(ciphertext)))
	base64.StdEncoding.Encode(encodedCiphertext, ciphertext)
	return encodedCiphertext, nil
}
```

The output of the program is `jaJW8QJbKqHEg5zyFURe2o565/wDVca9`.

## PyCrypto
Now we can decrypt it in Python.

``` python
# pycrypto1
from Crypto.Cipher import AES
from base64 import b64decode

key = "0123456789012345"
iv = "9876543210987654"
ciphertext = "jaJW8QJbKqHEg5zyFURe2o565/wDVca9"

# decode from base64
decoded = b64decode(ciphertext)

# encrypt with AES-CFB
aes = AES.new(key, AES.MODE_CFB, iv)
decrypted = aes.decrypt(decoded)

print decrypted
```

Oh wait, it didn't work!

{{< imgcap title="What is this garbage?" src="02-pycrypto1.png" >}}

Maybe our Go program is wrong. We can check it with JavaScript using [CyberChef][cyberchef-link] (clicking on the link will open CyberChef with input and recipe).

{{< imgcap title="Decrypted in CyberChef" src="03-cyberchef.png" >}}

Let me save you the 15-minute search and give you the answer. PyCrypto's default mode is `CFB8`. We can change the mode by passing `segment_size` to `AES.new`. See here https://www.dlitz.net/software/pycrypto/api/current/Crypto.Cipher.AES-module.html.

Source (no, that's not me): https://stackoverflow.com/questions/23897809/different-results-in-go-and-pycrypto-when-using-aes-cfb

``` python
# pycrypto2
from Crypto.Cipher import AES
from base64 import b64decode

key = "0123456789012345"
iv = "9876543210987654"
ciphertext = "jaJW8QJbKqHEg5zyFURe2o565/wDVca9"

# decode from base64
decoded = b64decode(ciphertext)

# encrypt with AES-CFB
aes = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
decrypted = aes.decrypt(decoded)

print decrypted
```

{{< imgcap title="Input must be a multiple of segment size" src="04-pycrypto2.png" >}}

The input must be padded for PyCrypto's AES-CFB. How can we make it work with Go?

## Go Compatible Implementation of PyCrypto AES-CFB128
It's simpler than I thought.

Decryption:

1. Pad ciphertext with `0x00` to segment size (16 bytes). Remember padding length.
2. Decrypt with `AES-CFB128`.
3. Discard the last n bytes of cleartext where n is padding length.

Encryption:

1. Pad input with `0x00` to segment size (16 bytes). Remember padding length.
2. Encrypt with `AES-CFB128`.
3. Remove the last n bytes of ciphertext where n is padding length.

See the code in `pycrypto-aescfb128.py`. And it works!

{{< imgcap title="AES-CFB128 with PyCrypto" src="05-pycrypto3.png" >}}

# Conclusion
~~Go is faster Python with types~~ Go is awesome. Python is a dead language abandoned by its creator and it doesn't even have AES support in its standard library. Generics? What?! I cannot hear you.

{{< imgcap title="It's almost 2019, why are you still using stale memes?" src="06-picard.jpg" >}}

Python BTFO with FACTS and LOGIC. #VictoryRoyale #Owned

It's a joke. Calm down, you people.

<!-- Links -->
[pycrypto-github]: https://github.com/dlitz/pycrypto
[m2crypto-gitlab]: https://gitlab.com/m2crypto/m2crypto
[cyberchef-link]: https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true)AES_Decrypt(%7B'option':'UTF8','string':'0123456789012345'%7D,%7B'option':'UTF8','string':'9876543210987654'%7D,'CFB','Raw','Raw',%7B'option':'Hex','string':''%7D)&input=amFKVzhRSmJLcUhFZzV6eUZVUmUybzU2NS93RFZjYTk
