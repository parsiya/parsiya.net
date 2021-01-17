---
title: "ContextIS xmas CTF Writeup"
date: 2018-06-05T22:34:55-04:00
draft: false
toc: true
comments: true
twitterImage: .png
categories:
- Writeup
- Reverse Engineering
- Crypto
---

In January 2018, [Context Information Security](https://www.contextis.com/) had a CTF. Here are my write-ups for some of them and write-ups for some I did not figure out. But that's CTF for you. If you manage to walk down the path of designer, you will be fine. Otherwise, you will have a bad time.

But enough complaining, let's see what happens.

<!--more-->

# Challenge 1
A code and a picture of "Charles Wheatstone." Seems like he invented the electric telegraph along with William Cooke.

Wheatstone also invented the playfair cipher. Then the code must be in playfair cipher.

Ciphertext:

```
RSOEBLNZAYNDQOXCNVQBUGIMDRAEGIMIQMKNKIIGZTKNQYHGBKLBPGQXKGFQTNQONEOUNUN
MMZKGLAYFPYRBDRAEGIGQUHUGBRQZYQRVBILAYFPYRBAQNLGVGTNMMZKGXNGNPDQMNUIKAQ
PCNDTOFHMIYPNMBGDEPALH{QMGKRIIMSEKPCNUBTITQC}V
```

We drop into a random playfair breaker we found on the internet

http://bionsgadgets.appspot.com/ww_forms/playfair_ph_web_worker3.html

And voila!

```
congratulationsyouhavedecipheredthesecretmessagecharleswheatstoneinventedthe
playfaircipherhoweveritwaslordplayfairwhopromotedtheuseofithencewhyitisnamed
afterhimflagthehiddenkeyiswindsorx
```

"congratulations you have deciphered the secret message charles wheatstone invented the playfair cipher however it was lord playfair who promoted the use of it hence why it is named after him

**flag the hidden key is windsorx**."

# Challenge 2
Second one seems to be a pcap. It's actually a pcapng file, so before using `gopacket/pcap` we need to convert it to pcap.

Inside the pcap there are a bunch of ping requests and replies with payloads.

Wrote a golang program using gopacket and pcap to get the payloads. Some are duplicates.

Each payload starts with `$$START$$` and contains base64 encoded data. We get them all and decode them and get a lot of random text. Search for `flag{.*}` and we get the flag.

**flag{ICMP_Tunn3ling_15_c00l}**


# Challenge 3
Stego in the wav file. I have never done one before but then again I do not have a CTF team.

I started reading this:

* https://ethackal.github.io/2015/10/05/derbycon-ctf-wav-steganography/

I chose this Golang library for reading wave files:

* https://github.com/youpy/go-wav

Let's see if it supports reading the LSBs.

I wrote code that reads the LSBs and nothing came out.

There's nothing in hex.

Looking at the wav file in Audacity we can also see the waves.

If negative wave is 0 and positive is 1, we get 12*8 bits:

```
01101001
01011001
01101001
01010110
01101001
10011010
01101001
01100101
01101001
10101010
01101010
01011001
```

Using this filter in [CyberChef](https://gchq.github.io/CyberChef/):

```
Fork('\\n','\\n',false)
From_Base(2)
To_Base(16)
From_Hex('Space')
```

We get

```
69 59 69 56 69 9a 69 65 69 aa 6a 59

i Y i V i . i e i ª j Y
```

Which doesn't help.


## A Closer Look at Wave Files
Wave files are pretty easy to figure out. Here's the header for `13.wav` file.

```
00000000  52 49 46 46 74 40 01 00 57 41 56 45 66 6d 74 20  |RIFFt@..WAVEfmt |
00000010  10 00 00 00 01 00 01 00 e8 03 00 00 e8 03 00 00  |........è...è...|
00000020  01 00 08 00 64 61 74 61 50 40 01 00   |....dataP@......|
```

The specification is pretty easy to find:

- http://soundfile.sapp.org/doc/WaveFormat/
- https://www.codeproject.com/Articles/6960/Steganography-VIII-Hiding-Data-in-Wave-Audio-Files

The links do a much better job of what I can do. So I will just show follow them. Everything is big endian unless indicated with LE (Little Endian):

- `52 49 46 46` - ChunkID - Signature - RIFF
- `74 40 01 00` - ChunkSize- Size of rest of the file (e.g. filesize + 8 bytes) - LE - 82036
- `57 41 56 45` - Format (WAVE)

Wave format has two parts, `fmt` and `data`:

`fmt`:

- `66 6d 74 20`: Subchunk1ID - `fmt ` (note space in the end to align things)
- `10 00 00 00`: Subchunk1size - LE - 16 - size of the rest of the subchunk
- `01 00`: AudioFormat - LE - 01 - PCM
- `01 00`: NumChannels - LE - number of channels - 01 means mono
- `e8 03 00 00`: SampleRate - LE - 1000
- `e8 03 00 00`: ByteRate == SampleRate * NumChannels * BitsPerSample/8 - LE - 1000 (1000*1*8/8)
- `01 00`: BlockAlign == NumChannels * BitsPerSample/8 - LE - 1
- `08 00`: BitsPerSample - LE - 8

`data`:

- `64 61 74 61`: Subchunk2ID - `data`
- `50 40 01 00`: Subchunk2Size - size of data chunk - LE - 82000
- `80 80 80 80 ...`: The rest is data (82000) bytes.

**Rage quit!**


# Challenge 4 - MIPS Me Not
A MIPS ELF executable. I don't have a device or VM that runs this, will drop it in IDA.

Seems to be a simple "enter password" and then do a compare challenge.


## MIPS Assembly Primer
I don't know MIPS assembly but I know enough to be able to follow this program (and of course the program is simple).

This is good: http://logos.cs.uic.edu/366/notes/mips%20quick%20tutorial.htm


### Load and Store
Load and store are two different instructions. Only they can access memory.

**Load:**

- `lw  register, memory` == `mov dword (4 bytes) register, memory`
- `lb` same as above but one byte

**Store:**

- `sw  register, memory` == `mov dword (4 bytes) memory, register`
- `sb` same as bove but one byte


### Other instructions
All other instructions use registers.

- `addu $t1,$t6,$t7  # $t1 = $t6 + $t7; add as unsigned integers`
- `XORI -- Bitwise exclusive or immediate`
- `seb` - sign extend byte. Convert something to byte while preserving sign.


### Holy 32 registers Batman!

- `$zero` register always contains zero

### Function calls
Source:

- https://courses.cs.washington.edu/courses/cse378/09wi/lectures/lec05.pdf


Excerpt:

- "MIPS uses the jump-and-link instruction `jal` to call functions."
- Return address is saved to `$ra` instead of stack.
- To return `jr $ra`.
- First 4 function arguments go in `$a0 - $a3` == x86/x64 fastcall.
- Return values in `$v0 - $v1`.


## But what does the program do?

1. `puts "] Plain and simple MIPS Challange ["` (typo is intended?)
2. `printf "Please enter the passphrase:"`
3. `fget` 14 (0x0D) chars of user input
4. `printf` user input
5. `encrypt_pw` user input
6. `memcmp` first 9 chars of encrypted user input and `unk_400B14`
7. Profit

## encrypt_pw

``` nasm
var_10 = 0 // $zero

loc_400860:
    check if var_10 == 0x0D (14) // see step 3 above
    if so, return (jr $ra)
    if not jmp loc_40082C

loc_40082C:
    v0 = var_10
    v1 = input // 4 bytes at a time but because we are adding one byte to it,
               // it only messes with the input one byte at a time (hint: counter)
    v0 = v0 + v1 (unsigned)

    v1 = var_10
    a0 = input
    v1 = a0 + v1 (unsigned)
    v1 = v1[0] // we are effectively doing load byte at index 0 of [v1]
    v1 = v1 xor 0x42
    seb v1 // has no effect
    v1 = [v1]
    var10 ++
```

If I have to make a guess. This is what happens:

``` Go 
for i := 0 ; i < 0x0D ; i ++ {
    v1[i] := inp[i] xor 0x42
}
```

And then compared with `unk_400B14`.

## unk_400B14
Encrypted

`2D 3B 0B 2A 23 36 27 0F 0B 12 11`

We can do the XOR in CyberChef because I am lazy:

https://gchq.github.io/CyberChef/#recipe=From_Hex('Space')XOR(%7B'option':'Hex','string':'42'%7D,'Standard',false)&input=MkQgM0IgMEIgMkEgMjMgMzYgMjcgMEYgMEIgMTIgMTE

**flag: oyIhateMIPS**

**Note:** It turns out flag is actually `BoyIhateMIPS` (I mean `oy` also makes sense :D). I did not get the `B` because while looking at the hardcoded data in the file, I ignored it leading `0x00` byte. `0x00 XOR 0x42 == 0x42` or `B`.
