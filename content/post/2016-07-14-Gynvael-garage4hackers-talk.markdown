---
categories:
- Reverse Engineering
comments: true
date: 2016-07-14T23:03:51-04:00
draft: false
tags:
- Notes
- Gynvael Coldwind
title: Gynvael Coldwind - Garage4Hackers - Notes from March 2014
toc: false
---
Back in March 2014, Garage4Hackers had a live stream with Gynvael Coldwind. His talk was named ``"Data, data, data! I can't make bricks without clay"`` or `a few practical notes on reverse-engineering`. You can see the recording [on youtube](https://www.youtube.com/watch?v=Jk5Yad598vs).

Here are my notes that I discovered from 2014.

<!--more-->

# Notes Garage4Hackers RE webinar by Gynvael Coldwind (Google)

His website: http://gynvael.coldwind.pl

## If ASM is hard, translate it to C for yourself.
Read through the manual and try to write your own pseudo-C code to understand it better.

## Trace things
So if there are a lot of jumps with instructions in the middle.  
He wrote a GDB script to just go through the jumps and collect all of the instructions in between to simplify the assembly.  
Some debuggers have tracing as a separate option. E.g. OllyDBG  

http://pelock.com/products/obfuscator

## Twitch died and missed this tip name.
If you are working on an strange platform (e.g. IBM S/390), look at the manual and find the op-codes and go through them and translate them for yourself.  
Write a simple script to add instruction descriptions to the disassembled code. So you can have a description of what it does with every instruction and you do not have to go through the manual for each op-code again.  

## Be prepared to make your own tools

### Diassembly Engines
His favorite is "distorm" hosted on https://code.google.com/p/distorm/.
You can use it inside Python scripts to disassembler binaries from starting to end addresses.

### Debug APIs
Talked about useful debug APIs. E.g. CreateRemoteThread.

Twitch went down again.

### CPU Specific Stuff (x86)
* Software breakpoints (CC aka int3).
* You can run code generator for Linux run on Windows with some changes.
* Change the dependencies, addressing and I/O.
* Goes through an example of a hash function in a Linux binary and then writing C code to allocate memory address at a specific address and then copying the hash function from Linux and putting it on the memory and then calling the function from the C code in windows.

### GDB is your friend even if you like others.
* It runs on any modern OS.
* Works with various GDB stubs (e.g. QEMU).
* Is scriptable in Python and GDB script.
* Is not well suited for anti-RE tricks.

Scripting, use Python. WinDbg - Olly - IDA - Immunity and GDB support.

### Use Paimei Stalker or Similar tools (by Pedram Amini)

    SetBP(Address, function_to_call_when_the_address_is_reached)

Twitch died again :(

### Monitor the environment.

Use these tools.
* Linux: strace and ltrace.
* On Windows : Process Monitor.

Example from a CTF.  
`Mixer`: It needed a certain library. So you have to install all dependencies. Use "ldd" to check if you have everything.

`LD_LIBRARY_PATH` environmental variable.  
`readelf -l binaryname`  
will show us which loader is needed for this library.

It loaded the application in GDB but could not debug.  
Two solutions:
1. Attach after running, bad idea.
2. Manually enter CC CC at EP by ediuting the hex.
3. Then run it in GDB.

### You do not need to analyze everything - probably the most important thing when doing RE

If you have a blackbox with a small-ish input/output space, let it run and look at output to find out what it does.

### The tool might be wrong. Check the output.

### Entropy is a good recon tool.

### Know Crypto and other stuff and be able to recognize it.

I asked him for an alternative to IDA pro for x64 binaries. He didn't have any alternatives as he uses IDA Pro.
