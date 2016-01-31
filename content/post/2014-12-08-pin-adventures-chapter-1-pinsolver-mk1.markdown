---
categories:
- Reverse Engineering
tags:
- PIN
- PIN tool
- PINSolver
comments: true
date: 2014-12-08T20:46:59Z
title: Pin Adventures - Chapter 1 - PinSolver Mk1
---

While writing the writeups for the [Flare On Challenge 6](http://parsiya.net/blog/2014-10-07-my-adventure-with-fireeye-flare-challenge/#ch6) I came upon [an alternative solution](http://gaasedelen.blogspot.com/2014/09/solving-fireeyes-flare-on-six-via-side.html) by [@gaasedelen](https://twitter.com/gaasedelen) to use the number of executed instructions as a side-channel. Recently during an engagement I used [Pintool](https://software.intel.com/en-us/articles/pintool) to do ``[redacted]``. Now that I have a bit of time, I decided to use the idea to write such a tool.

As an example, we will use a C program that checks input for a hardcoded value using ``strncmp``. We want to see if it's vulnerable to this side-channel (number of executed instructions).

<!--more-->

##My Setup
I will be using a Kali 32-bit VM using VirtualBox. Installing Pin is as simple as extracting the appropriate distribution in a directory and adding it to path.

###Pintool
Pin is a dynamic binary instrumentation framework by Intel. The default installation contains a good number of examples in ``/pintool/source/tools/ManualExamples/``. If you look at various tutorials on it, most will use instruction count example in ``inscount0.cpp``. I will be simplifying it to suit our needs and do *some* comments.

Here is the modified code. Let's name it ``myins.cpp`` and save it in the ManualExamples directory. Apologies for the legal stuff at the start but I'd rather keep them than risk the wrath of open source gods.

{{< codecaption lang="cpp" title="myins.c" >}}
/*BEGIN_LEGAL 
Intel Open Source License 

Copyright (c) 2002-2014 Intel Corporation. All rights reserved.
 
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.
 
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */
#include <iostream>
#include "pin.H"

// modified version of /pintool/source/tools/ManualExamples/inscount0.cpp


// The running count of instructions is kept here
// make it static to help the compiler optimize docount
static UINT64 icount = 0;

// This function is called before every instruction is executed
// increase the count every time it is called, which is before every instruction
VOID docount() { icount++; }
    
// Pin calls this function every time a new instruction is encountered
VOID Instruction(INS ins, VOID *v)
{
    // Insert a call to docount before every instruction, no arguments are passed
    // ins: instruction about to be executed
    // IPOINT_BEFORE: call is placed before each instruction
    // (AFUNPTR)docount: name of the function to call before every instruction
    // If any arguments are to be passed to the called function, they will be placed here
    // IARG_END: indicates the end of arguments
    
    // as a result before each instruction, docount is called
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_END);
}

// This function is called when the application exits
VOID Fini(INT32 code, VOID *v)
{
    // print the number of executed instructions
    cout << "Count: " << icount << endl;

}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cout << "This tool counts the number of dynamic instructions executed" << endl;
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
/*   argc, argv are the entire command line: pin -t <toolname> -- ...    */
/* ===================================================================== */

int main(int argc, char * argv[])
{
    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();

    // Register Instruction to be called to instrument instructions
    INS_AddInstrumentFunction(Instruction, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);
    
    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}

{{< /codecaption >}}

To compile it, we can use the provided makefile. In ManualExamples run ``make obj-ia32/myins.so``. Note the filename and path. If everything works correctly, we will have ``myins.so``. Let's copy it to where we want to write our example program.

### Crackme 1 - Example C Program
The program is quite simple, it checks the first argument against the hardcoded value ``7bc3a60fbf38e98f6fef654afa26d270``. We will use this program to test our Pin tool.
{{< codecaption lang="cpp" title="crkme1.c" >}}
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{

  if ( argc!=2 )
  {
    printf("usage: ./crkme1 code\n");
    return 1;
  }
  
  char code[] = "7bc3a60fbf38e98f6fef654afa26d270";
  
  if ( !strncmp(argv[1],code,32) )
  {
    printf("Correct\n");
  }
  else
  {
    printf("Wrong\n");
  }

  return 0;
}
{{< /codecaption >}}

Remember to use the ``ggdb`` option to compile with debug information (for GDB). From what I understand this is very similar to the ``g`` option. We will be using GDB to dive into the binary to observe strncmp's behavior. Let's use ``gcc -ggdb -o crkme1 crkme1.c``.

### Using Pin with Crkme1
To run our Pin tool against any executable execute ``pin -t myins.so -- ./crkme1 012345``. Now let's experiment with some input. Our super secret code starts with ``7b`` so I will be ``fuzzing`` (for very simplistic definition of fuzzing) the first character and look at the number of executed instructions.

{{< codecaption lang="bash" title="Changing first character" >}}
$ pin -t myins.so -- ./crkme1 1zzz
Wrong
Count: 100013
$ pin -t myins.so -- ./crkme1 5zzz
Wrong
Count: 100013
$ pin -t myins.so -- ./crkme1 7zzz
Wrong
Count: 100015 # interesting
$ pin -t myins.so -- ./crkme1 bzzz
Wrong
Count: 100013
$pin -t myins.so -- ./crkme1 @zzz
Wrong
Count: 100013
{{< /codecaption >}}

Notice a pattern? Seems like we executed two extra instructions when our first character matched. Assuming our theory is correct and we have the first character ``7``, let's experiment with the second character.

{{< codecaption lang="bash" title="Changing second character" >}}
$ pin -t myins.so -- ./crkme1 71zz
Wrong
Count: 100015
$ pin -t myins.so -- ./crkme1 75zz
Wrong
Count: 100015
$ pin -t myins.so -- ./crkme1 7bzz
Wrong
Count: 100017 # 2 extra instructions executed
$ pin -t myins.so -- ./crkme1 7@zz
Wrong
Count: 100015
{{< /codecaption >}}

At this point you probably have a good idea why this is happening. But let's look at the assembly code.

### GDB and strncmp
Good thing we compiled our binary with debug information. Let's look at the assembly code for strncmp:

{{< codecaption lang="bash" title="Running crkme1 in gdb" >}}
# q starts gdb in quiet mode
$ gdb ./crkme1 -q
Reading symbols from /root/Desktop/kek/crkme1...done.
# putting a break on strncmp, this is possible because we compiled with -ggdb option
(gdb) break strncmp
Breakpoint 1 at 0x8048350
# passing 7bzz as a run-time argument. r stands for run
(gdb) r 7bzz
Starting program: /root/Desktop/kek/crkme1 7bzz

Breakpoint 1, 0xb7f82b80 in ?? () from /lib/i386-linux-gnu/i686/cmov/libc.so.6
(gdb) disass
No function contains program counter for selected frame.
# oops what happened here?
(gdb) 
{{< /codecaption >}}

To get a better a picture of the problem, we're going to go through the same process in verbose mode in GDB using the ``set verbose on`` command.

{{< codecaption lang="bash" title="Running in gdb with verbose on" >}}
$ gdb ./crkme1 -q
Reading symbols from /root/Desktop/kek/crkme1...done.
(gdb) set verbose on
(gdb) break strncmp
Breakpoint 1 at 0x8048350
(gdb) r 7bzz
Starting program: /root/Desktop/kek/crkme1 7bzz
Reading symbols from /lib/ld-linux.so.2...(no debugging symbols found)...done.
Loaded symbols for /lib/ld-linux.so.2
Reading symbols from system-supplied DSO at 0xb7fe1000...(no debugging symbols found)...done.
# aha, no debugging symbols found for libc6
Reading symbols from /lib/i386-linux-gnu/i686/cmov/libc.so.6...(no debugging symbols found)...done.
Loaded symbols for /lib/i386-linux-gnu/i686/cmov/libc.so.6

Breakpoint 1, 0xb7f82b80 in ?? () from /lib/i386-linux-gnu/i686/cmov/libc.so.6
(gdb) disass
No function contains program counter for selected frame.

{{< /codecaption >}}

According to line 12, we we need the debugging symbols for libc to look inside the code. 
On Kali use ``apt-get install libc6-dbg``. Here we go again:

{{< codecaption lang="nasm" title="After installing libc6-dbg" >}}
root@kali:~/Desktop/kek# gdb ./crkme1 -q
Reading symbols from /root/Desktop/kek/crkme1...done.
(gdb) break strncmp
Breakpoint 1 at 0x8048350
(gdb) r 7bzz
Starting program: /root/Desktop/kek/crkme1 7bzz

Breakpoint 1, __strncmp_ssse3 ()
    at ../sysdeps/i386/i686/multiarch/strcmp-ssse3.S:65
65	../sysdeps/i386/i686/multiarch/strcmp-ssse3.S: No such file or directory.
(gdb) disass
Dump of assembler code for function __strncmp_ssse3:
=> 0xb7f82b80 <+0>:	push   ebp
   0xb7f82b81 <+1>:	mov    edx,DWORD PTR [esp+0x8]
   0xb7f82b85 <+5>:	mov    eax,DWORD PTR [esp+0xc]
   0xb7f82b89 <+9>:	mov    ebp,DWORD PTR [esp+0x10]
   0xb7f82b8d <+13>:	cmp    ebp,0x10
   0xb7f82b90 <+16>:	jb     0xb7f843d0 <__strncmp_ssse3+6224>
{{< /codecaption >}}

Now we can see what happens in strncmp. The following is the cleaned up version of the assembly of strncmp.

{{< codecaption lang="nasm" title="strncmp" >}}
; assuming we called strncmp (argv[1],code,32);

0xb7f82b80 <+0>:	push   ebp
0xb7f82b81 <+1>: 	mov    edx,DWORD PTR [esp+0x8]  ; argv[1] or "7bzz"
0xb7f82b85 <+5>: 	mov    eax,DWORD PTR [esp+0xc]  ; code or "7bc3 .."
0xb7f82b89 <+9>: 	mov    ebp,DWORD PTR [esp+0x10] ; 32 or 0x20
0xb7f82b8d <+13>: 	cmp    ebp,0x10                 ; 32 compared to 0x10 (16 decimal)
0xb7f82b90 <+16>: 	jb     0xb7f843d0 <__strncmp_ssse3+6224>
...
; if number of bytes to compare is bigger than 16
; let's assume it is not and see what happens next
...
0xb7f843d0 <+6224>:	test   ebp,ebp  ; if (ebp == 0) goto 0xb7f843c3
0xb7f843d2 <+6226>:	je     0xb7f843c3 <__strncmp_ssse3+6211> 
0xb7f843d4 <+6228>:	movzx  ecx,BYTE PTR [eax] ; ecx = code
0xb7f843d7 <+6231>:	cmp    BYTE PTR [edx],cl  ; if (code[0] != argv[1][0]) goto 0xb7f843b0;
0xb7f843d9 <+6233>:	jne    0xb7f843b0 <__strncmp_ssse3+6192>
0xb7f843db <+6235>:	test   cl,cl  ; if (code[0] == 0) goto 0xb7f843c3; // have we reached the end of code?
0xb7f843dd <+6237>:	je     0xb7f843c3 <__strncmp_ssse3+6211>
0xb7f843df <+6239>:	cmp    ebp,0x1  ; if (counter == 1) goto 0xb7f843c3; // was this our last compare?
0xb7f843e2 <+6242>:	je     0xb7f843c3 <__strncmp_ssse3+6211>
0xb7f843e4 <+6244>:	movzx  ecx,BYTE PTR [eax+0x1]	; ecx = code[1];
0xb7f843e8 <+6248>:	cmp    BYTE PTR [edx+0x1],cl  ; if (code[1] != argv[1][1]) goto 0xb7f843b0;
0xb7f843eb <+6251>:	jne    0xb7f843b0 <__strncmp_ssse3+6192>
0xb7f843ed <+6253>:	test   cl,cl  ; if (code[1] == 0) goto 0xb7f843c3; // have we reached the end of code?
0xb7f843ef <+6255>:	je     0xb7f843c3 <__strncmp_ssse3+6211>
0xb7f843f1 <+6257>:	cmp    ebp,0x2
0xb7f843f4 <+6260>:	je     0xb7f843c3 <__strncmp_ssse3+6211>
...
; similar byte compares until the end
...
0xb7f8453f <+6591>:	test   cl,cl
0xb7f84541 <+6593>:	je     0xb7f843c3 <__strncmp_ssse3+621
0xb7f84547 <+6599>:	cmp    ebp,0xf
0xb7f8454a <+6602>:	je     0xb7f843c3 <__strncmp_ssse3+621
0xb7f84550 <+6608>:	movzx  ecx,BYTE PTR [eax+0xf]
0xb7f84554 <+6612>:	cmp    BYTE PTR [edx+0xf],cl
0xb7f84557 <+6615>:	jne    0xb7f843b0 <__strncmp_ssse3+619
0xb7f8455d <+6621>;	test   cl,cl
{{< /codecaption >}}

We can see that the implementation has unrolled the for and compares 16 bytes one by one. If a character is correct, two more instructions are executed (as we saw) which are ``test   cl,cl`` and ``je     0xb7f843c3`` which basically checks if we have reached the end of first string. Now we know why. Let us build our tool.

### PinSolver Mk1
I am going to use Python's subprocess module and reuse [some old code](http://parsiya.net/blog/2014-05-25-pasting-shellcode-into-gdb-using-python/). The script simply iterates through all valid characters (note: do not include space or some other special characters). For this example I am going to use alphanumeric characters. Character with the largest number of executed instructions will be chose and we move on to the next character.

{{< codecaption lang="python" title="pinsolvermk1.py" >}}
#!/usr/bin/python

from subprocess import Popen, PIPE

# create a set of alphanumeric chars
alphanumeric = "0123456789" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "abcdefghijklmnopqrstuvwxyz"

solution = []

flag = False

while (True):

  maxcount = 0
  candidate_char = 0

  for char in alphanumeric:
    # construct
    fez = "".join(solution) + char
    proc = Popen(["pin", "-t", "myins.so", "--","./crkme1", fez], stdout=PIPE, stderr=PIPE)
  
    # read output and split by lines
    output = proc.stdout.read().splitlines()
  
    if (output[0] == "Correct"):
      print "Code found: ", "".join(solution)
      break
    else:
      count = int (output[1].split(' ')[1])
    
      if (count > maxcount):
        maxcount = count
        candidate_char = char
    
    # print ("Trying %s - Count is: %d - Maxcount is: %d - Candidate_char is: %s") % (fez, count, maxcount, candidate_char)
  
  # after a loop has finished, add the chosen char to the solution
  solution.append(candidate_char)
{{< /codecaption >}}

Note: If your VM has multiple CPUs this will not work. At this moment I do not know why.

TODO in next chapter:

1. Try to find some simple crackmes2 from CTFs to run this tool on
2. Find a way to increase pin's performance
3. Why is the instruction count not calculated correctly occasionally when VM has multiple CPUs?

As usual, if there is a any feedback please feel free to comment or contact me on Twitter. My handle is in the side bar ---->.
