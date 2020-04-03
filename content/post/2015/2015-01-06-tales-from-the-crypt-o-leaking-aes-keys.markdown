---
categories:
- Crypto
- Reverse Engineering
tags:
- AES
- Encryption
comments: true
date: 2015-01-06T23:36:48Z
title: Tales from the Crypt(o) - Leaking AES Keys
toc: true
aliases:
- "/blog/2015-01-06-tales-from-the-crypto---leaking-aes-keys/"
---

This post is part one of a two part internal blog entry on creating a Pintool for an assessment. Unfortunately I cannot talk about it, so I decided to put the first part out. If I find an opensource program similar to the assessment I will try and recreate the tool (but I am not holding my breath). As this part is essentially a build up, it may not be coherent at times. Alteratively, if you really want to read it, you can join us. We are almost always hiring (let me do the referral though ;).

Today we are going to talk about discovering encryption keys in sneaky ways. We will start with simple examples, do a bit of Digital Forensics or DF (for low standards of DF) and finally in part two we will use our recently acquired knowledge of Pintool to do ``[redacted]``.

First let's talk a bit about the inner-workings of AES decryption. By inner-workings of AES I do not mean the following diagrams that you have seen so many times.

<!--more-->

{{< imgcap src="/images/2015/tales1/CBC-Mode-Wikipedia.jpg" title="These are not the diagrams you are looking for - Source: Wikipedia" >}}

Instead I am going to talk about what happens inside those rectangles labeled “block cipher encryption/decryption.” If you don't want to know about the AES stuff, jump directly to [2. AES Keys in Action](#2-aes-keys-in-action:2cbddf826dbc10ef777e4fb8d0b66a21).

# 1. Thinking Inside the Box
Each of these boxes consist of a few rounds. The number of rounds is based on key size in AES. Keep in mind that AES is a subset of the *Rijndael* family of ciphers (and I still do not know how to pronounce the name). NIST (National Institute of Standards and Technology) selected a fixed block size (16 bytes) and three different key sizes (128, 192 and 256 bits) and called it AES (Advanced Encryption Standard) because that's what NIST does (other than allegedly embedding backdoors in [almost never used](https://www.mail-archive.com/openssl-announce@openssl.org/msg00127.html) random number generators, see [DUAL_EC_DRBG](http://blog.cryptographyengineering.com/2013/09/the-many-flaws-of-dualecdrbg.html) ;)). You do not need to memorize the formula that calculates the number of rounds based on key and block size. You can see the result of my painstaking calculations in the following table:

    |
    | Key Size (bits)  | Number of Rounds (potatoes) |
    |------------------|-----------------------------|
    |       128        |             10              |
    |       192        |             12              |
    |       256        |             14              |
    |

That was easy. So what happens inside each of these rounds. Except the last round, there are four steps in each round (encryption/decryption). For the remainder of this section I am going to assume that we are using a 128-bit key (16 bytes) resulting in 10 rounds.

{{< imgcap src="/images/2015/tales1/AES-Rounds.jpg" title="Inside AES - Source: http://www.iis.ee.ethz.ch/~kgf/acacia/fig/aes.png" >}}

There are four different operations but I am going to go into some detail about ``AddRoundKey``. It is also the only operation which introduces an unknown element (key) into the process. The other operations are also simple and we can probably guess what they do based on their names.

## 1.1 AddRoundKey
It's a simple XOR. A 16 byte round key is XOR-ed with the current block. If we count the number of `AddRoundKey` operations for Nr==10, we get 11. But we only have one 16 byte key and need 16*11 or 176 bytes.

*“How am I going to create the extra 160 (176-16) bytes?”* one may ask. This is done through some magic known as ``key expansion`` which creates bytes out of thin air. It expands the original key into the 176 bytes also known as ``key schedule``.

### 1.1.1 AES Key Schedule (aka Rijndael Key Schedule)
The key expansion algorithm takes the original key and returns the key schedule. I could talk about the boring details of it but you are already bored and I am lazy. Search for Rijndael Key Schedule if you want to know more. Instead we are going to talk about some interesting stuff.

Don't make the convenient mistake of thinking of the key schedule as a Pseudo-Random Number Generator (PRNG) where we enter the original key as the seed and then reap bytes. In a good PRNG, we should not be able to discover the seed by observing the output. In the Rijndael/AES key schedule there is direct correlation between the original key and each round key.

In AES-128, knowing a single round key (regardless of round number) is enough to generate the original key. In AES-256 we need to know two consecutive round keys and that is a good thing for AES-256. If not, the schedule had reduced the entropy of a 256-bit key to 128 bits. In a lot of hardware (a.k.a limited on-board memory), the first (actual encryption key) and last round keys (first two and last two round keys for AES-256) are stored for encryption/decryption and the rest are generated when needed from them.

Also by looking at the key schedule, we can see that the original AES key is copied directly to the start of the key schedule. In other words, the first 128 bits (16 bytes) of the AES-128 key schedule are the same as the original key.

### 1.1.2 Round Key Usage
Great, so we have 16 bytes that are XOR-ed with something in each round. For decryption, we can create the key schedule and inverse it. This works because XOR is transitive (i.e. If ciphertext = plaintext XOR key then plaintext = ciphertext XOR key).

Notice the first AddRoundKey block in both encryption and decryption. In encryption this is first 16 bytes of the original key (or the whole key in case of AES-128). In decryption, this is the last round key. Keep this in mind, we are going to use it later.

# 2. AES Keys in Action
By now we know how AES keys are used. Let's do some stuff. We're going to use the same set up as last time. A Kali 32-bit VM running in VirtualBox.

## 2.1 Function Calls
External function calls leak information. I am going to divide them into two parts ``System Calls`` (syscalls) and ``Library Calls``. Basically these are functions that you can call and use in your program. If these functions part of the Operating System they are System Calls and if they are provided by a 3rd party library (shared library, DLL etc) they are Library Calls. For an excellent description of system calls, read the blog post by Gustavo Duartes named [System Calls Make the World Go Round]() (also read the rest of his blog).

### 2.1.1 OpenSSL Example
Our example will be a simple Encryption/Decryption program in C using OpenSSL modified from [​http://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption. It will encrypt and decrypt the string “The quick brown fox jumps over the lazy dog” with AES using the 256 bit (32 byte) key ``ee12c03ceacdfb5d4c0e67c8f5ab3362`` and IV ``d36a4bf2e6dd9c68`` (128 bits or 16 bytes). My comments start with ``///``.

{{< codecaption lang="cpp" title="AES-OpenSSL.cpp" >}}
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

/// Code from OpenSSL Wiki at http://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
/// Needs libssl-dev (e.g. sudo apt-get install libssl-dev )
/// Compile with gcc [filename].c -o [outputfile] -lcrypto -ggdb

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))  handleErrors();

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) handleErrors();
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))  handleErrors();

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))  handleErrors();
  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */

  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

int main(int arc, char *argv[])
{
  /* Set up the key and iv. Do I need to say to not hard code these in a
   * real application? :-)
   */

  /* A 256 bit key */
  /// unsigned char *key = "01234567890123456789012345678901";

  /// this is still a 256-bit (32 byte) key, each character is treated as one byte
  unsigned char *key = "ee12c03ceacdfb5d4c0e67c8f5ab3362";

  /* A 128 bit IV */
  /// unsigned char *iv = "01234567890123456";
  unsigned char *iv = "d36a4bf2e6dd9c68";

  /* Message to be encrypted */
  unsigned char *plaintext =
    "The quick brown fox jumps over the lazy dog";

  /* Buffer for ciphertext. Ensure the buffer is long enough for the
   * ciphertext which may be longer than the plaintext, dependant on the
   * algorithm and mode
   */
  unsigned char ciphertext[128];

  /* Buffer for the decrypted text */
  unsigned char decryptedtext[128];

  int decryptedtext_len, ciphertext_len;

  /* Initialise the library */
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(NULL);

  /* Encrypt the plaintext */
  ciphertext_len = encrypt(plaintext, strlen(plaintext), key, iv, ciphertext);

  /* Do something useful with the ciphertext here */
  printf("Ciphertext is:\n");
  BIO_dump_fp(stdout, ciphertext, ciphertext_len);

  /* Decrypt the ciphertext */
  decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);

  /* Add a NULL terminator. We are expecting printable text */
  decryptedtext[decryptedtext_len] = '';

  /* Show the decrypted text */
  printf("Decrypted text is:\n");
  printf("%s\n", decryptedtext);

  /* Clean up */
  EVP_cleanup();
  ERR_free_strings();

  return 0;
}
{{< /codecaption >}}

we need the ``libssl-dev`` library which can be installed by ``sudo apt-get install libssl-dev``. To compile use ``gcc [filename].c -o [outputfile] -lcrypto -ggdb``. We will use the debug information in GDB later. Here is the output:

{{< codecaption lang="bash" title="output" >}}
$ gcc AES-OpenSSL.c -ggdb -lcrypto -o sampleaes
$ ./sampleaes
Ciphertext is:
0000 - 51 34 3f 21 87 5d 4e f6-18 1d c6 6d 41 c1 12 ae   Q4?!.]N....mA...
0010 - e0 a7 de a0 fa b9 6c b0-91 5e 21 c6 d3 90 96 36   ......l..^!....6
0020 - 70 7b ec 69 89 e1 bc 0a-2c 61 f4 c6 26 61 5f 2e   p{.i....,a..&a_.
Decrypted text is:
The quick brown fox jumps over the lazy dog
{{< /codecaption >}}

## 2.2 Monitoring Library Calls
To monitor these calls, we have a few tools at hand. On *nix operating systems we can use strace (for system calls) and ltrace (for both syscalls and library calls). On Windows we can use [API Monitor](http://www.rohitab.com/apimonitor) as I have used in the [past](http://parsiya.net/blog/2014-10-07-my-adventure-with-fireeye-flare-challenge/#ch7). If you have a Mac you can try your luck with [dtruss](https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man1/dtruss.1m.html) which uses dtrace. I am not quite sure if it can be used to trace library calls and if it works on iOS.

### 2.2.1 Discovering Shared Libraries
Assuming we are approaching this application from a black-box perspective, we need to discover the shared libraries first. This can be done in different ways. We will talk about ``ldd``, ``nm``, ``strings`` or just ``ltrace``. Just using ltrace may do the job but if there are a lot of library calls, we need to spot critical/interesting libraries to filter out the noise.

## 2.2.1.1 ldd
``ldd`` “prints shared library dependencies” according to the [man](http://man7.org/linux/man-pages/man1/ldd.1.html) page. Let's run it.

{{< codecaption lang="bash" title="running ldd" >}}
$ldd sampleaes
  linux-gate.so.1 =>  (0xb77b8000)
  libcrypto.so.1.0.0 => /usr/lib/i386-linux-gnu/i686/cmov/libcrypto.so.1.0.0 (0xb75df000)
  libc.so.6 => /lib/i386-linux-gnu/i686/cmov/libc.so.6 (0xb747b000)
  libdl.so.2 => /lib/i386-linux-gnu/i686/cmov/libdl.so.2 (0xb7476000)
  libz.so.1 => /lib/i386-linux-gnu/libz.so.1 (0xb745d000)
  /lib/ld-linux.so.2 (0xb77b9000)
{{< /codecaption >}}

In line 3 we can see [libcrypto](http://wiki.openssl.org/index.php/Libcrypto_API) which means the application is using OpenSSL (the other OpenSSL library is ``libssl``).

## 2.2.1.2 nm
``nm`` “[lists symbols from object files.](http://unixhelp.ed.ac.uk/CGI/man-cgi?nm)” It's a good idea to look at its output and look for familiar symbols. We can clearly see OPENSSL and function names in the truncated output.

{{< codecaption lang="bash" title="running nm" >}}
$ nm sampleaes
         U BIO_dump_fp@@OPENSSL_1.0.0
         U ERR_free_strings@@OPENSSL_1.0.0
         U ERR_load_crypto_strings@@OPENSSL_1.0.0
         U ERR_print_errors_fp@@OPENSSL_1.0.0
         U EVP_CIPHER_CTX_free@@OPENSSL_1.0.0
         U EVP_CIPHER_CTX_new@@OPENSSL_1.0.0
         U EVP_DecryptFinal_ex@@OPENSSL_1.0.0
         U EVP_DecryptInit_ex@@OPENSSL_1.0.0
         U EVP_DecryptUpdate@@OPENSSL_1.0.0
         U EVP_EncryptFinal_ex@@OPENSSL_1.0.0
         U EVP_EncryptInit_ex@@OPENSSL_1.0.0
         U EVP_EncryptUpdate@@OPENSSL_1.0.0
         U EVP_aes_256_cbc@@OPENSSL_1.0.0
         U EVP_cleanup@@OPENSSL_1.0.0
         U OPENSSL_add_all_algorithms_noconf@@OPENSSL_1.0.0
         U OPENSSL_config@@OPENSSL_1.0.0
0804900c d _DYNAMIC
08049108 d _GLOBAL_OFFSET_TABLE_
08048d4c R _IO_stdin_used
         w _ITM_deregisterTMCloneTable
         w _ITM_registerTMCloneTable
         w _Jv_RegisterClasses
...
# removed the rest of the output
{{< /codecaption >}}

## 2.2.1.3 strings
``strings`` is useful because it may leak great information about the binary. It will give us the key and IV directly in our example. We can also see OpenSSL and libcrypto strings. It also gives us the version of the used OpenSSL library.

{{< codecaption lang="cpp" title="running strings" >}}
strings sampleaes
/lib/ld-linux.so.2
libcrypto.so.1.0.0
_ITM_deregisterTMCloneTable
__gmon_start__
_Jv_RegisterClasses
_ITM_registerTMCloneTable
EVP_aes_256_cbc
ERR_free_strings
OPENSSL_config
EVP_cleanup
ERR_load_crypto_strings
OPENSSL_add_all_algorithms_noconf
EVP_CIPHER_CTX_free
EVP_DecryptFinal_ex
ERR_print_errors_fp
EVP_DecryptInit_ex
EVP_EncryptFinal_ex
EVP_CIPHER_CTX_new
EVP_DecryptUpdate
EVP_EncryptInit_ex
BIO_dump_fp
EVP_EncryptUpdate
libc.so.6
_IO_stdin_used
puts
abort
strlen
stdout
stderr
__libc_start_main
OPENSSL_1.0.0
GLIBC_2.0
PTRh
[^_]
ee12c03ceacdfb5d4c0e67c8f5ab3362
d36a4bf2e6dd9c68
The quick brown fox jumps over the lazy dog
Ciphertext is:
Decrypted text is:
;*2$"
{{< /codecaption >}}

## 2.3  Using ltrace to Find the Key
Finally let's run ltrace on the binary. The ``i`` switch prints the value of instruction pointer at the time of library call (we will need it later). You can also trace syscalls using the ``S`` (capital S) switch.

{{< codecaption lang="nasm" title="running ltrace" >}}
$ ltrace -i ./sampleaes
[0x8048921] __libc_start_main(0x8048b8c, 1, 0xbff88534, 0x8048cd0, 0x8048cc0
[0x8048bbe] ERR_load_crypto_strings(0xb776dda6, 0xb7439a30, 0x8048629, 0xb74266d0, 0x80485d0) = 0
[0x8048bc3] OPENSSL_add_all_algorithms_noconf(0xb776dda6, 0xb7439a30, 0x8048629, 0xb74266d0, 0x80485d0) = 1
[0x8048bcf] OPENSSL_config(0, 0xb7439a30, 0x8048629, 0xb74266d0, 0x80485d0)    = 1
[0x8048bde] strlen("The quick brown fox jumps over t"...)                      = 43
[0x8048a0f] EVP_CIPHER_CTX_new(1, 0x8048434, 0x8049140, 0, 0xb742e0b4)         = 0x90bdce0
[0x8048a22] EVP_aes_256_cbc(1, 0x8048434, 0x8049140, 0, 0xb742e0b4)            = 0xb7735040
[0x8048a47] EVP_EncryptInit_ex(0x90bdce0, 0xb7735040, 0, 0x8048d50, 0x8048d71) = 1
[0x8048a78] EVP_EncryptUpdate(0x90bdce0, 0xbff883ec, 0xbff88324, 0x8048d84, 43) = 1
[0x8048aa8] EVP_EncryptFinal_ex(0x90bdce0, 0xbff8840c, 0xbff88324, 0x8048d84, 43) = 1
[0x8048ac3] EVP_CIPHER_CTX_free(0x90bdce0, 0xbff8840c, 0xbff88324, 0x8048d84, 43) = 0
[0x8048c25] puts("Ciphertext is:"Ciphertext is:
)                                             = 15
[0x8048c48] BIO_dump_fp(0xb75874e0, 0xbff883ec, 48, 0x8048d71, 0xbff883ec0000 - 51 34 3f 21 87 5d 4e f6-18 1d c6 6d 41 c1 12 ae   Q4?!.]N....mA...
0010 - e0 a7 de a0 fa b9 6c b0-91 5e 21 c6 d3 90 96 36   ......l..^!....6
0020 - 70 7b ec 69 89 e1 bc 0a-2c 61 f4 c6 26 61 5f 2e   p{.i....,a..&a_.
)     = 3
[0x8048ad3] EVP_CIPHER_CTX_new(0, 0xb77789c0, 0xbff883ec, 0xb764bda0, 0xb764b910) = 0x90bdce0
[0x8048ae6] EVP_aes_256_cbc(0, 0xb77789c0, 0xbff883ec, 0xb764bda0, 0xb764b910) = 0xb7735040
[0x8048b0b] EVP_DecryptInit_ex(0x90bdce0, 0xb7735040, 0, 0x8048d50, 0x8048d71) = 1
[0x8048b3c] EVP_DecryptUpdate(0x90bdce0, 0xbff8836c, 0xbff88324, 0xbff883ec, 48) = 1
[0x8048b6c] EVP_DecryptFinal_ex(0x90bdce0, 0xbff8838c, 0xbff88324, 0xbff883ec, 48) = 1
[0x8048b87] EVP_CIPHER_CTX_free(0x90bdce0, 0xbff8838c, 0xbff88324, 0xbff883ec, 48) = 0
[0x8048ca3] puts("Decrypted text is:"Decrypted text is:
)                                         = 19
[0x8048caf] puts("The quick brown fox jumps over t"...The quick brown fox jumps over the lazy dog
)                        = 44
[0x8048cb4] EVP_cleanup(0xbff8836c, 48, 0x8048d50, 0x8048d71, 0xbff8836c)      = 0
[0x8048cb9] ERR_free_strings(0xbff8836c, 48, 0x8048d50, 0x8048d71, 0xbff8836c) = 0
[0xffffffff] +++ exited (status 0) +++
{{< /codecaption >}}

In a non-ideal situation, we have to either recognize the good functions from past experience or search them all. Here we are looking for a function with key and IV as parameters. According to the [documentation](https://www.openssl.org/docs/crypto/EVP_EncryptInit.html) ``EVP_DecryptInit_ex`` is what we are looking for:

``int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, unsigned char *key, unsigned char *iv);``

But what are these values:  
``[0x8048b0b] EVP_DecryptInit_ex(0x90bdce0, 0xb7735040, 0, 0x8048d50, 0x8048d71) = 1``
These are pointers and are 4 bytes each (remember we are in a 32-bit OS). “*But where are these pointers pointing to? Do I have to use GDB?*” Yes, we had to use GDB before I knew that we can configure ltrace to dereference pointers. But we will use GDB too.

### 2.3.1 Configuring ltrace
If we know the type of pointers, we can dereference them by modifying [~/.ltrace.conf](http://man7.org/linux/man-pages/man5/ltrace.conf.5.html). We can also do more elaborate stuff like defining structs as explained [here](https://github.com/zenovich/ltrace/blob/master/etc/ltrace.conf). In short we can add lines to ltrace.conf for certain functions. In our case we know the 4th and 5th arguments for EVP_DecryptInit_ex are strings (char*). We do not care about the first three arguments so can ignore them by defining them as ``addr`` (for address). Let's add the following line to ltrace.conf:  
``int EVP_DecryptInit_ex(addr, addr, addr, string, string)``

run ltrace again and annnnnnnd voila (look at lines 4 for key and IV):
{{< codecaption lang="cpp" title="running ltrace after configuration" >}}
# most of the output has been removed
EVP_CIPHER_CTX_new(0, 0xb77cc9c0, 0xbfdecdec, 0xb769fda0, 0xb769f910) = 0x9ff5ce0
EVP_aes_256_cbc(0, 0xb77cc9c0, 0xbfdecdec, 0xb769fda0, 0xb769f910) = 0xb7789040
EVP_DecryptInit_ex(0x09ff5ce0, 0xb7789040, NULL, "ee12c03ceacdfb5d4c0e67c8f5ab3362", "d36a4bf2e6dd9c68") = 1
EVP_DecryptUpdate(0x9ff5ce0, 0xbfdecd6c, 0xbfdecd24, 0xbfdecdec, 48) = 1
EVP_DecryptFinal_ex(0x9ff5ce0, 0xbfdecd8c, 0xbfdecd24, 0xbfdecdec, 48) = 1
EVP_CIPHER_CTX_free(0x9ff5ce0, 0xbfdecd8c, 0xbfdecd24, 0xbfdecdec, 48) = 0
{{< /codecaption >}}

{{< imgcap src="/images/2015/tales1/Queen-Amused.jpg" title="Her Majesty is amused – If you are offended please don't send James Bond after me" >}}

## 2.4  Finding the Key (Using GDB) II: Electric Boogaloo
That was too easy but we pleased a powerful friend. Let's try and find it using GDB (gasp). Good thing that we compiled out binary using the ggdb switch. If not go ahead and do that. We know we are looking for ``EVP_DecryptInit_ex`` and we have already seen how to use GDB. We will ``set verbose on`` (in case stuff happens).

{{< codecaption lang="nasm" title="running in GDB with debug info 1" >}}
$ gdb ./sampleaes -q
Reading symbols from /root/Desktop/kek/sampleaes...done.
(gdb) set verbose on
(gdb) break EVP_DecryptInit_ex  ; setting up the breakpoint
Breakpoint 1 at 0x8048830
(gdb) run                       ; running the program
Starting program: /root/Desktop/kek/sampleaes
Reading symbols from /lib/ld-linux.so.2...(no debugging symbols found)...done.
Loaded symbols for /lib/ld-linux.so.2
Reading symbols from system-supplied DSO at 0xb7fe1000...(no debugging symbols found)...done.
Reading symbols from /usr/lib/i386-linux-gnu/i686/cmov/libcrypto.so.1.0.0...(no debugging symbols found)...done.
Loaded symbols for /usr/lib/i386-linux-gnu/i686/cmov/libcrypto.so.1.0.0
Reading symbols from /lib/i386-linux-gnu/i686/cmov/libc.so.6...(no debugging symbols found)...done.
Loaded symbols for /lib/i386-linux-gnu/i686/cmov/libc.so.6
Reading symbols from /lib/i386-linux-gnu/i686/cmov/libdl.so.2...(no debugging symbols found)...done.
Loaded symbols for /lib/i386-linux-gnu/i686/cmov/libdl.so.2
Reading symbols from /lib/i386-linux-gnu/libz.so.1...(no debugging symbols found)...done.
Loaded symbols for /lib/i386-linux-gnu/libz.so.1
Ciphertext is:
0000 - 51 34 3f 21 87 5d 4e f6-18 1d c6 6d 41 c1 12 ae   Q4?!.]N....mA...
0010 - e0 a7 de a0 fa b9 6c b0-91 5e 21 c6 d3 90 96 36   ......l..^!....6
0020 - 70 7b ec 69 89 e1 bc 0a-2c 61 f4 c6 26 61 5f 2e   p{.i....,a..&a_.

Breakpoint 1, Reading in symbols for AES-OpenSSL.c...done.
0xb7ed3a20 in EVP_DecryptInit_ex () from /usr/lib/i386-linux-gnu/i686/cmov/libcrypto.so.1.0.0
(gdb) disass    ; disassembling the function
Dump of assembler code for function EVP_DecryptInit_ex:
=> 0xb7ed3a20 <+0>: push   ebx
   0xb7ed3a21 <+1>:	sub    esp,0x28
   0xb7ed3a24 <+4>:	mov    eax,DWORD PTR [esp+0x40]
   0xb7ed3a28 <+8>:	call   0xb7e510db
   0xb7ed3a2d <+13>:    add    ebx,0xe65c7
   0xb7ed3a33 <+19>:	mov    DWORD PTR [esp+0x14],0x0
   0xb7ed3a3b <+27>:	mov    DWORD PTR [esp+0x10],eax
   0xb7ed3a3f <+31>:	mov    eax,DWORD PTR [esp+0x3c]
   0xb7ed3a43 <+35>:	mov    DWORD PTR [esp+0xc],eax
   0xb7ed3a47 <+39>:	mov    eax,DWORD PTR [esp+0x38]
   0xb7ed3a4b <+43>:	mov    DWORD PTR [esp+0x8],eax
   0xb7ed3a4f <+47>:	mov    eax,DWORD PTR [esp+0x34]
   0xb7ed3a53 <+51>:	mov    DWORD PTR [esp+0x4],eax
   0xb7ed3a57 <+55>:	mov    eax,DWORD PTR [esp+0x30]
   0xb7ed3a5b <+59>:	mov    DWORD PTR [esp],eax
   0xb7ed3a5e <+62>:	call   0xb7e50660 <EVP_CipherInit_ex@plt>
   0xb7ed3a63 <+67>:	add    esp,0x28
   0xb7ed3a66 <+70>:	pop    ebx
   0xb7ed3a67 <+71>:	ret
End of assembler dump.
{{< /codecaption >}}

We can see ``EVP_CipherInit_ex`` called at ``0xb7ed3a5e``. Let's put a breakpoint there (right before function call) and look at its arguments.

{{< codecaption lang="nasm" title="running in gdb with debug info 2" >}}
(gdb) b*0xb7ed3a5e
Breakpoint 2 at 0xb7ed3a5e
(gdb) c
Continuing.

Breakpoint 2, 0xb7ed3a5e in EVP_DecryptInit_ex () from /usr/lib/i386-linux-gnu/i686/cmov/libcrypto.so.1.0.0
(gdb) disass
Dump of assembler code for function EVP_DecryptInit_ex:
   0xb7ed3a20 <+0>:	push   ebx
   0xb7ed3a21 <+1>:	sub    esp,0x28
   0xb7ed3a24 <+4>:	mov    eax,DWORD PTR [esp+0x40]
   0xb7ed3a28 <+8>:	call   0xb7e510db
   0xb7ed3a2d <+13>:	add    ebx,0xe65c7
   0xb7ed3a33 <+19>:	mov    DWORD PTR [esp+0x14],0x0
   0xb7ed3a3b <+27>:	mov    DWORD PTR [esp+0x10],eax
   0xb7ed3a3f <+31>:	mov    eax,DWORD PTR [esp+0x3c]
   0xb7ed3a43 <+35>:	mov    DWORD PTR [esp+0xc],eax
   0xb7ed3a47 <+39>:	mov    eax,DWORD PTR [esp+0x38]
   0xb7ed3a4b <+43>:	mov    DWORD PTR [esp+0x8],eax
   0xb7ed3a4f <+47>:	mov    eax,DWORD PTR [esp+0x34]
   0xb7ed3a53 <+51>:	mov    DWORD PTR [esp+0x4],eax
   0xb7ed3a57 <+55>:	mov    eax,DWORD PTR [esp+0x30]
   0xb7ed3a5b <+59>:	mov    DWORD PTR [esp],eax
=> 0xb7ed3a5e <+62>:	call   0xb7e50660 <EVP_CipherInit_ex@plt>
   0xb7ed3a63 <+67>:	add    esp,0x28
   0xb7ed3a66 <+70>:	pop    ebx
   0xb7ed3a67 <+71>:	ret
End of assembler dump.
{{< /codecaption >}}

We can see the arguments loaded from memory to eax and then pushed to the stack (esp is the stack pointer and points to the top of the stack at all times). We are in a Linux 32-bit OS so arguments (or parameters whatever) are pushed to the stack from [right to left](http://duartes.org/gustavo/blog/post/journey-to-the-stack/) (almost the same in 32-bit Windows systems). Here is what it looks like right before the call instruction:

{{< codecaption lang="cpp" title="EVP_DecryptInit_ex arguments" >}}
int EVP_DecryptInit_ex(
EVP_CIPHER_CTX *ctx,    <== [esp]
const EVP_CIPHER *type, <== [esp+0x4]
ENGINE *impl,           <== [esp+0x8]
unsigned char *key,     <== [esp+0xc]
unsigned char *iv       <== [esp+0x10]
);
{{< /codecaption >}}

We can print the values of both key and IV. To do this in GDB we need to use this command ``x/s *((char **) ( $esp+0x10 ))``. The s switch tells GDB to print the result as a string. ``$esp+0x10`` is a pointer that points to a location on the stack. In that location we have a ``char *`` which is another pointer to a string, so we need to dereference it twice (hence the ``char **``). And finally to print it using the ``s`` switch we need to make it a string (e.g. ``char *``) so we will use the first *. And it works.

{{< codecaption lang="cpp" title="finding key and IV in gdb with debug info" >}}
(gdb) x/s *((char **) ( $esp+0x10 ))
0x8048d71:	 "d36a4bf2e6dd9c68"
(gdb) x/s *((char **) ( $esp+0xc ))
0x8048d50:	 "ee12c03ceacdfb5d4c0e67c8f5ab3362"
{{< /codecaption >}}

{{< imgcap src="/images/2015/tales1/Queen-Not-Amused.jpg" title="Her Majesty is bored because of GDB" >}}

## 2.5 Using GDB without Debug Info
Our example is in a controlled environment, so we were able to build the binary with debug info. But in a real world scenario we do not have this luxury. In this section I will discuss how to get to  ``EVP_DecryptInit_ex`` without debug info.

First we have to build our binary without  debug info, just remove the ``-ggdb`` switch to get ``gcc -o sampleaes-nodebug AES-OpenSSL.c -lcrypto``. Now how do we find the location of ``EVP_DecryptInit_ex`` call?

Remember the following line in the original ltrace output.
``[0x8048b0b] EVP_DecryptInit_ex(0x90bdce0, 0xb7735040, 0, 0x8048d50, 0x8048d71) = 1``

We used the ``i`` switch to print the value of instruction pointer after the call. This is our entry point. We will debug the binary in GDB and set up a breakpoint at ``0x8048b0b`` and see what happens.

{{< codecaption lang="nasm" title="running in gdb without debug info 1" >}}
$ gdb ./sampleaes-nodebug -q
Reading symbols from /root/Desktop/kek/sampleaes-nodebug...(no debugging symbols found)...done.
(gdb) b *0x8048b0b
Breakpoint 1 at 0x8048b0b
(gdb) run
Starting program: /root/Desktop/kek/sampleaes-nodebug
Ciphertext is:
0000 - 51 34 3f 21 87 5d 4e f6-18 1d c6 6d 41 c1 12 ae   Q4?!.]N....mA...
0010 - e0 a7 de a0 fa b9 6c b0-91 5e 21 c6 d3 90 96 36   ......l..^!....6
0020 - 70 7b ec 69 89 e1 bc 0a-2c 61 f4 c6 26 61 5f 2e   p{.i....,a..&a_.

Breakpoint 1, 0x08048b0b in decrypt ()
(gdb) disass
Dump of assembler code for function decrypt:
   0x08048ac8 <+0>:	push   ebp
   0x08048ac9 <+1>:	mov    ebp,esp
   0x08048acb <+3>:	sub    esp,0x38
   0x08048ace <+6>:	call   0x80487e0 <EVP_CIPHER_CTX_new@plt>
   0x08048ad3 <+11>:	mov    DWORD PTR [ebp-0xc],eax
   0x08048ad6 <+14>:	cmp    DWORD PTR [ebp-0xc],0x0
   0x08048ada <+18>:	jne    0x8048ae1 <decrypt+25>
   0x08048adc <+20>:	call   0x80489ec
   0x08048ae1 <+25>:	call   0x80488a0 <EVP_aes_256_cbc@plt>
   0x08048ae6 <+30>:	mov    edx,DWORD PTR [ebp+0x14]
   0x08048ae9 <+33>:	mov    DWORD PTR [esp+0x10],edx
   0x08048aed <+37>:	mov    edx,DWORD PTR [ebp+0x10]
   0x08048af0 <+40>:	mov    DWORD PTR [esp+0xc],edx
   0x08048af4 <+44>:	mov    DWORD PTR [esp+0x8],0x0
   0x08048afc <+52>:	mov    DWORD PTR [esp+0x4],eax
   0x08048b00 <+56>:	mov    eax,DWORD PTR [ebp-0xc]
   0x08048b03 <+59>:	mov    DWORD PTR [esp],eax
   0x08048b06 <+62>:	call   0x8048830 <EVP_DecryptInit_ex@plt>
=> 0x08048b0b <+67>:	cmp    eax,0x1
   0x08048b0e <+70>:	je     0x8048b15 <decrypt+77>
   0x08048b10 <+72>:	call   0x80489ec
   0x08048b15 <+77>:	mov    eax,DWORD PTR [ebp+0xc]
   0x08048b18 <+80>:	mov    DWORD PTR [esp+0x10],eax
   0x08048b1c <+84>:	mov    eax,DWORD PTR [ebp+0x8]
   0x08048b1f <+87>:	mov    DWORD PTR [esp+0xc],eax
   0x08048b23 <+91>:	lea    eax,[ebp-0x14]
   0x08048b26 <+94>:	mov    DWORD PTR [esp+0x8],eax
{{< /codecaption >}}

Again we see the arguments pushed to the stack.

{{< codecaption lang="cpp" title="EVP_DecryptInit_ex arguments" >}}
int EVP_DecryptInit_ex(
EVP_CIPHER_CTX *ctx,    <== [esp]
const EVP_CIPHER *type, <== [esp+0x4]
ENGINE *impl,           <== [esp+0x8]
unsigned char *key,     <== [esp+0xc]
unsigned char *iv       <== [esp+0x10]
);
{{< /codecaption >}}

We put a breakpoint at ``0x08048b06`` and re-run the binary. Then we can read key and IV like before:

{{< codecaption lang="cpp" title="finding key and IV in gdb without debug info" >}}
(gdb) x/s *((char **) ( $esp+0x10 ))
0x8048d71:	 "d36a4bf2e6dd9c68"
(gdb) x/s *((char **) ( $esp+0xc ))
0x8048d50:	 "ee12c03ceacdfb5d4c0e67c8f5ab3362"
{{< /codecaption >}}

However, notice the difference in the function name. It is not just called ``(0xb7ed3a21) EVP_DecryptInit_ex`` but ``(0x08048b06) EVP_DecryptInit_ex@plt``. Addresses are different. Here's a tip which is not scientific or anything but works for me. If you see an address starting with 0×08 you are in process-land and addresses starting with 0xb are in shared library land. But what is this @plt?
In short, it's the ``Procedure Linkage Table``. The compiler does not know where ``EVP_DecryptInit_ex`` points to at runtime so it just puts the function call there (relocation) because it does not know the address of our shared library at runtime. Linker will get this function call and replace it with the correct address for the function (actually this is a lot more complex but PLT and Global Offset Table or GOT need their own article). You can read about GOT/PLT in The [ELF Object File Format by Dissection on Linux Journal](http://www.linuxjournal.com/article/1060) (search for “plt” and read 3 paragraphs including the one with lazy binding).

## 2.6 iOS and Android
I am not going to go into detail about how we can monitor crypto function calls in iOS and Android as we already have two excellent tools that accomplish this. ``[redacted internal tool]`` is for iOS and ``[[redacted internal tool]]`` is for Android. You can make them hook into crypto function calls and find keys. This is left as an exercise to the reader (meaning I am too lazy). There are also two excellent tutorials by two of my co-workers on how to create custom hooks in iOS and Android [Substrate - hooking C on Android and iOS part1/2](https://hexplo.it/substrate-hooking-native-code-iosandroid/) and [Substrate - hooking C on Android and iOS part 2/2](https://hexplo.it/substrate-android/).

## 2.7 Defence?
We saw that function calls (library calls) leak information. One defense against this side-channel is to link the binaries statically. This will replicate the library code inside the binary and will hopefully make the binary independent of any shared libraries (better for installation). On the other hand, it will increase code size (and thus binary size).

# 3.0 Looking for Key in Memory
But there are ways to defeat that too. This is our small incursion into the lands of Digital Forensics. The keys are going to be on memory. So that's where we are going to look for them. But how do we find keys in memory. One step is to look for data with high entropy because keys usually look random. But there are many 128-bit (or 256) parts of memory that look random so what do we do?

Remember the ``Key Schedule``? It's the original key, followed by a number of round keys. If we see a 176 byte structure on memory that looks random, that's probably a key schedule. After finding memories with these characteristics, we can use the relation between the round keys and the original encryption key to determine if the structure is a key schedule.

There are tools that do this for us and they were mostly created for use in Cold Boot Attacks and digital forensics. Imagine if you have a computer running disk encryption software. These keys may be stored in memory in plaintext. Open it up while running until you have access to the RAM. Get a can of air spray, turn it upside down and spray the RAM with it. It will freeze. Frozen RAM degrade much slower so we will have more time to read it. Read it and then run tools on it to find keys. Because memory may have been degraded, these tools use the relationship between round keys and original key to recover degraded bits. For more information you can read this paper [Lest We Remember: Cold Boot Attacks on Encryption Keys](https://citp.princeton.edu/research/memory/).

## 3.1 Dumping Memory
First we need to dump process memory. I know of a couple of different tools. One is [memfetch](http://lcamtuf.coredump.cx/soft/memfetch.tgz) by ``lcamtuf`` (creator of [American fuzzy lop fuzzer](http://lcamtuf.coredump.cx/afl/)). In order to build it in Kali you need some [modifications](http://parsiya.net/blog/2014-11-18-building-memfetch-on-kali/). Another is [shortstop](https://code.google.com/p/shortstop/) but has not been update for a long time. By using a ``Loadable Kernel Module (LKM)`` named [LiME](https://github.com/504ensicsLabs/LiME) we can make a memory snapshot of the entire machine. And last but not least [Volatility](https://github.com/volatilityfoundation/volatility) (a memory forensics framework). If you are interested the creators of Volatility recently released a book [The Art of Memory Forensics](http://www.amazon.com/The-Art-Memory-Forensics-Detecting/dp/1118825098). I have not had time to read it but it looks very useful.

Let's use LiME in our VM.

{{< codecaption lang="bash" title="building and using LiME" >}}
/LiME/src$ make
make -C /lib/modules/3.7-trunk-686-pae/build M=/root/LiME/src modules
make[1]: Entering directory `/usr/src/linux-headers-3.7-trunk-686-pae'
  CC [M]  /root/LiME/src/tcp.o
  CC [M]  /root/LiME/src/disk.o
  CC [M]  /root/LiME/src/main.o
  LD [M]  /root/LiME/src/lime.o
  Building modules, stage 2.
  MODPOST 1 modules
  CC      /root/LiME/src/lime.mod.o
  LD [M]  /root/LiME/src/lime.ko
make[1]: Leaving directory `/usr/src/linux-headers-3.7-trunk-686-pae'
strip --strip-unneeded lime.ko
mv lime.ko lime-3.7-trunk-686-pae.ko
/LiME/src$ insmod lime-3.7-trunk-686-pae.ko path=memorydump.raw format=raw
/LiME/src$
{{< /codecaption >}}

This dumps Virtual Machine's memory to ``memorydump.raw``. Now we need to find keys.

## 3.2 Finding Keys
There are different tools that we can use here again. One is from the “Lest We Remember” paper called ``aeskeyfind``. Another is [Bulk extractor](http://www.forensicswiki.org/wiki/Bulk_extractor) which finds other memory artifacts such as URLs, emails and Credit Card numbers. We will use ``aeskeyfind``. The ``v`` switch is for verbose mode that prints the key schedule among other information. This is really not recommended in memory forensics because we are running the dump program inside the VM memory and it will alter memory but it is enough for our purposes. Another thing to note is that I was not running our example program while making the memory snapshot but I found encryption keys.

{{< codecaption lang="" title="keys inside VM memory dump" >}}
./aeskeyfind -v memorydump.raw
FOUND POSSIBLE 128-BIT KEY AT BYTE 376ecc30

KEY: 10b57f8070a27e482fd3713da5303108

EXTENDED KEY:
10b57f8070a27e482fd3713da5303108
15724f8665d031ce4a0340f3ef3371fb
d4d14059b1017197fb0231641431409f
17d89ba3a6d9ea345ddbdb5049ea9bcf
98cc11983e15fbac63ce20fc2a24bb33
be26d27d803329d1e3fd092dc9d9b21e
ab11a0a02b228971c8df805c01063242
84328cdcaf1005ad67cf85f166c9b7b3
d99be1ef768be442114461b3778dd600
9f6d821ae9e66658f8a207eb8f2fd1eb
bc536b6955b50d31ad170ada2238db31

CONSTRAINTS ON ROWS:
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
Keyfind progress: 100%
{{< /codecaption >}}

The 0 constraints mean that no keys were degraded (because we took an on a VM). **I do not know what the encryption key is, it's just in memory of VM**. If you find out please let me know. In order to find the key for our OpenSSL program this way, we need to stop execution when the key schedule is on memory. This is left as an exercise to the reader (lol).

This concludes our part one. I initially wanted to write everything in one blog post but it this was already too long. Hopefully I can find a 3rd party app to demonstrate my technique in part 2. As usual if you have any feedback/questions, you know where to find me (side bar --->).
