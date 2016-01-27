---
categories:
- python
- shellcode
- interactive debugging
comments: false
date: 2014-05-25T18:39:58Z
title: Pasting Shellcode in GDB using Python
---

A few days ago I was trying to write an exploit for a buffer overflow with GDB. This was a console application and pasting shellcode would mess with it.

There are a few options:

+ Writing shellcode to a file and then using it as input for GDB.

``` python
# you can also include GDB commands like setting up breakpoints (e.g. b * 0xDEADBEEF)
# remember to include a new line after each command
$ python -c 'print "b * 0xDEADBEEF" + "\n" + "\x41"*1000 + "\n"' > input

# $ perl -e for perl

# start debugging with GDB
# -q (quiet mode): no text at startup
$ gdb executable1 -q
(gdb) run < input

```

After this you can manually debug in GDB.

+ Writing a Python script for interactive debugging
When I wrote this, I thought it was a clever idea but then someone told me I could have written a GDB script. However, I have already written this snippet so here it goes.

``` python
#!/usr/bin/python

from subprocess import Popen , PIPE
from time import sleep

# shellcode
shellcode = "\x41" * 1000 + "\n"

# opens gdb with parameter executable
# you can also manage stdout and stderr here
proc = Popen( ['gdb' , 'executable'] , bufsize=1 ,stdin=PIPE )

# sample breakpoint
# notice the new line after each command
proc.stdin.write('b *DEADBEEF\n')

# half a second of sleep after each command
sleep(0.5)

# r or run to start debugging the program with GDB
proc.stdin.write('r\n')
sleep(0.5)

# any other commands go here

# this is a loop, will get every command and pass it to GDB
# "leave" == quit GDB and terminate process
# "dump"  == paste shellcode
while True:
    mycommand = raw_input()
    if (mycommand == "leave"):
        # quit gdb
        proc.stdin.write("quit\n")
        break
	
    # paste shellcode
    if (mycommand == "dump"):
        proc.stdin.write(shellcode)
    # more custom commands go here

    # not a custom command? send it as-is
    else:
        mycommand = mycommand + '\n' 
        proc.stdin.write(mycommand)
        sleep(0.5)

# close our pipe	
proc.stdin.close()

```

I think that this code can be modified and become a very simple fuzzer. We have control over stdin and can read stdout and stderr. Change input, record output, rinse and repeat. 

``subprocess`` is a very powerful module. For example to normally run an application with an argument we can write `` subprocess.call(['gdb','executable']) .``

but let's say we want to run executable with input (containing shellcode):

``` python
import subprocess

shellcode = "\x41" * 100

subprocess.call( ['gdb' , 'executable'] , shellcode)
```
