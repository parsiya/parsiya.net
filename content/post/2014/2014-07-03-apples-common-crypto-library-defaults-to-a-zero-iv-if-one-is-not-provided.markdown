---
categories:
- Crypto
tags:
- Encryption
- Common Crypto
comments: true
date: 2014-07-03T01:30:18Z
title: Apple's Common Crypto Library Defaults to a Zero IV if One is not Provided
---

Today I was writing some guidelines about generating keys for mobile applications at work. While providing code examples in Java and Obj-C for AES encryption I happened to look at Apple's [Common Crypto] [CCLink] library . While going through the source code for [CommonCryptor.c] [CCLink2], I noticed that IV is commented as ``/* optional initialization vector */``. This makes sense because not all ciphers use IV and not all AES modes of operation (e.g. ECB mode). However; if an IV is not provided, the library will default to a zero IV.

You can see the code here inside the function ``ccInitCryptor`` (search for defaultIV) [source][CCLink2]. ``CC_XZEROMEM`` resets all bytes of IV to zero (that is 0x00):

``` c
static inline CCCryptorStatus ccInitCryptor
(CCCryptor *ref, const void *key, unsigned long key_len, const void *tweak_key, const void *iv) {

    size_t blocksize = ccGetCipherBlockSize(ref);
    uint8_t defaultIV[blocksize];


    if(iv == NULL) {
        CC_XZEROMEM(defaultIV, blocksize);
        iv = defaultIV;
    }

    ...

    return kCCSuccess;
}

```

While I am told this is probably common behavior in crypto libraries, I think it's dangerous. I ended up putting a comment in code examples warning developers about this behavior. So, heads up ;)

[CCLink]: http://opensource.apple.com/source/CommonCrypto/CommonCrypto-60049/lib/
[CCLink2]: http://opensource.apple.com/source/CommonCrypto/CommonCrypto-60049/lib/CommonCryptor.c
