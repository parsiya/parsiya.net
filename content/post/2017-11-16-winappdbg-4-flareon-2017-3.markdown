---
title: "WinAppDbg - Part 4 - Bruteforcing FlareOn 2017 - Challenge 3"
date: 2017-11-15T18:45:04-05:00
draft: false
toc: true
comments: true
categories:
- winappdbg
- reverse engineering
- CTF
tags:
- python
- FlareOn
---

Previous parts:

- [Part 1 - Basics]({{< ref "2017-11-09-winappdbg-1-basics.markdown" >}} "WinAppDbg - Part 1 - Basics")
- [Part 2 - Function Hooking and Others]({{< ref "2017-11-11-winappdbg-2-function-hooking.markdown" >}} "WinAppDbg - Part 2 - Function Hooking and Others")
- [Part 3 - Manipulating Function Calls]({{< ref "2017-11-11-winappdbg-2-function-hooking.markdown" >}} "WinAppDbg - Part 3 - Manipulating Function Calls")

We have learned some good stuff. In this part I am going to talk about the original problem that led me to learning WinAppDbg. This is my writeup for challenge 3 "Greek to me" of [FlareOn 2017][flare-solutions]. This is a bruteforce challenge and is rather easy but instead of bruteforcing it the conventional (and straightforward way), I will show how I traversed arbitrary Assembly blobs using WinAppDbg.

I will (hopefully) mostly talk about solving the challenge and not a lot of recon or other places I was stuck at.

Code is in my clone:

- [https://github.com/parsiya/Parsia-Code/tree/master/winappdbg][winappdbg-clone]

[winappdbg-clone]: https://github.com/parsiya/Parsia-Code/tree/master/winappdbg "WinAppDbg code in Parsia-Code"
[flare-solutions]: https://www.fireeye.com/blog/threat-research/2017/10/2017-flare-on-challenge-solutions.html
<!--more-->

# Setup
- Same Windows 7 32-bit VM from other parts.
- Get the binaries from this URL:
    + [http://flare-on.com/files/Flare-On4_Challenges.zip][flare4-binaries]
    + Password is `flare`.
- Solutions:
    + [https://www.fireeye.com/blog/threat-research/2017/10/2017-flare-on-challenge-solutions.html][flare-solutions]

# Recon
Run `strings` on the binary. On Windows I have two favorites:

- strings from [Cygwin][cygwin-url]'s binutils package.
- [strings][strings-sysinternals] from Sysinternals.

Running strings (from Sysinternals) we get:

- `-nobanner`: do not display banner.
- `-o`: print the offset of the string (useful in case we want to use find the string in the file).

```
PS > .\SysinternalsSuite\strings.exe -o -nobanner .\3-GreektoMe\greek_to_me.exe
0077:!This program cannot be run in DOS mode.
0176:Rich
0432:.text
0472:.rdata
...
1584:Nope, that's not it.
1608:Congratulations! But wait, where's my flag?
1652:127.0.0.1
1752:WS2_32.dll
```
`WS2_32.dll` is the Windows socket library. So network connectivity.

Here's some interesting  but unrelated info that I found when searching for the DLL:

- [https://nakedsecurity.sophos.com/2009/10/12/windows-ws232dll-file-safe/][sophos-ws2_32]

`127.0.0.1` means the application has network connectivity. It's either trying to connect to a port on localhost or listening on some port.

To discover, run procmon or Wireshark:

- Procmon filters:
    + `process name is greek_to_me.exe`.
    + `Operation is TCP/UDP Connect`.
- Wireshark:
    + Capture Windows loopback traffic with `npcap`.
    + [https://wiki.wireshark.org/CaptureSetup/Loopback][wireshark-loopback]

Nothing. So it's listening on localhost.

Run the app and use `netstat -anb` in an Admin command prompt (needed for the `b` switch).

```
 TCP    127.0.0.1:2222         0.0.0.0:0              LISTENING       5816
[greek_to_me.exe]
```

Application is listening on port `2222`.

# Short Analysis
The application is listening on port `2222`. When it receives data, it uses the first byte (and only the first byte) of our input as we see here:

``` asm
.text:00401029 loc_401029:      ; CODE XREF: sub_401008+1A
.text:00401029          mov     ecx, offset loc_40107C
.text:0040102E          add     ecx, 79h
.text:00401031          mov     eax, offset loc_40107C
.text:00401036          mov     dl, [ebp+buf]   ; first byte of input moved to dl
```

Now dl points to the first byte that we sent to the socket.

``` asm
.text:00401039 loc_401039:      ; CODE XREF: sub_401008+3D
.text:00401039          mov     bl, [eax]   ; bl = grab a byte from blob
.text:0040103B          xor     bl, dl      ; bl = blob_byte xor our_first_byte
.text:0040103D          add     bl, 22h     ; bl += 0x22
.text:00401040          mov     [eax], bl   ; *eax = bl
.text:00401042          inc     eax         ; eax++ (next char)
.text:00401043          cmp     eax, ecx    ; ecx is the address of the second section
.text:00401045          jl      short loc_401039 ; check if we have reached the next section
```

It grabs some data (`0x79` or 121 bytes to be exact) from `0x40107C`, XOR-es them with our first byte and then add `0x22`.

The data is some blob at `offset loc_40107C`.

    33 E1 C4 99 11 06 81 16 F0 32 9F C4 91 17 06 81
    14 F0 06 81 15 F1 C4 91 1A 06 81 1B E2 06 81 18
    F2 06 81 19 F1 06 81 1E F0 C4 99 1F C4 91 1C 06
    81 1D E6 06 81 62 EF 06 81 63 F2 06 81 60 E3 C4
    99 61 06 81 66 BC 06 81 67 E6 06 81 64 E8 06 81
    65 9D 06 81 6A F2 C4 99 6B 06 81 68 A9 06 81 69
    EF 06 81 6E EE 06 81 6F AE 06 81 6C E3 06 81 6D
    EF 06 81 72 E9 06 81 73 7C

{{< imgcap title="XOR and ADD instructions" src="/images/2017/winappdbg-4/01-crypto.png" >}}

Then this modified blob (after XOR and add) is passed to `sub_4011E6` and processed:

``` nasm
.text:00401047          mov     eax, offset loc_40107C  ; eax = *modified_blob
.text:0040104C          mov     [ebp+var_C], eax        ; varC = eax
.text:0040104F          push    79h                     ; length of modified_blob
.text:00401051          push    [ebp+var_C]
.text:00401054          call    sub_4011E6              ; sub_4011E6(*modified_blob, 0x79)
.text:00401059          pop     ecx
.text:0040105A          pop     ecx
.text:0040105B          movzx   eax, ax
.text:0040105E          cmp     eax, 0FB5Eh ; compare return value with 0xFB5E

.text:00401063          jz      short loc_40107C
.text:00401065          push    0               ; flags
.text:00401067          push    14h             ; len
.text:00401069          push    offset buf      ; "Nope, that's not it."
.text:0040106E          push    [ebp+s]         ; s
.text:00401071          call    ds:send
.text:00401077          jmp     loc_401107
```

Return value of the `sub_4011E6` is compared with `0xFB5E`. If they do not match, `jz` will not be taken and execution will continue. Application will send back `Nope, that's not it.`.

{{< imgcap title="Result comparison" src="/images/2017/winappdbg-4/02-result-comparison.png" >}}

Now here it gets interesting. If the results match, it will jump to the section which houses the blob we just modified and attempts to execute it as code. If the application does not crash and reaches the end, it will send back `Congratulations!`

In other words, our first byte is supposed to transform that blob into valid assembly opcodes.

Now we could solve this is in different ways. I think everyone solved it by opening a socket, sending 256 possible bytes and looking at the response. I think it's the way the challenge was meant to be solved.

# Bruteforcing with WinAppDbg
I solved it a different way. Originally I went down the rabbit hole and tried to RE `sub_4011E6`. That was a shit-show. Then I realized I can use WinAppDbg to bruteforce the "crypto" in-memory. We need to learn a bit more about WinAppDbg to reproduce it.

## Breakpoints in WinAppDbg
WinAppDbg allows us to set breakpoints at arbitrary addresses:

{{< codecaption title="Setting a breakpoint" lang="python" >}}
debug.break_at(pid, address, action_callback)

def action_callback(event):
    # do something
{{< /codecaption >}}

When the breakpoint is hit, the `action_callback` function is called. We have not seen this before but all of our hooking has been performed internally with these instructions.

More info:

- [Documentation - Example #11: setting a breakpoint][docs-example11]
- [breakpoint.py source code][breakpoint-py]

## Getting and Setting Memory
WinAppDbg allows us to save/restore memory and context.

- Get memory: `memory = process.take_memory_snapshot()`
    + [take_memory_snapshot source][take-memory-snapshot-source]
- Set memory: `process.restore_memory_snapshot(memory, bSkipMappedFiles=True)`
    + [restore_memory_snapshot source][restore-memory-snapshot-source]
    + In general, keep the `bSkipMappedFiles` to `True`. Otherwise you will get memory address violations.
        + [Explanation of bSkipMappedFiles in source][bSkipMappedFiles-source]

## Getting and Setting Context
Context contains register and flag values. It's per thread (instead of per process like memory).

- Get context: `context = thread.get_context()`
    + [get_context source][get-context-source]
    + Manipulate registers in context:
        * `context["Edx"] = 0x1234`
- Set context: `thread.set_context(context)`
    + [set_context source][set-context-source]

Note: After setting the context, we need to manually change the program counter to start execution at a specific location. For example if we grab the context, change `Eip` to an address and set it, the program counter will not change. After setting the context, manually change the program counter to your desired address with `thread.set_pc(address)`.

For both memory and context operations, make sure to suspend the process/thread first and resume it after the operation is done.

## Battle Plan
Now that we have the building blocks, we need to device a battle plan. It's very straightforward.

1. Run the application.
2. Set breakpoints at `0x401036` and `0x40105B`.
3. Open a socket and send any random byte.
4. At breakpoint `0x401036`:
    - If it's first_time:
        - Save memory, context and blob at `0x40107C`.
    - `context["Edx"] = key` - swap the key.
    - key++.
    - Bypass the key assignment instruction and manually jump to `0x401039` with:
        - `thread.set_pc(0x401039)`
5. At breakpoint `0x40105B`:
    - If function return value is `0xFB5E`, print key.
    - Else:
        - Restore memory, context and blob at `0x40107C` (blob has been modified so it needs to be restored to the original bytes).
        - Go back to `0x401036` with `thread.set_pc(0x401036)`


{{< imgcap title="Bruteforcing plan" src="/images/2017/winappdbg-4/03-bruteforcer-1.png" >}}

It would have been easier to change the first byte of `buf` instead of `edx` and avoiding the jump labeled 2 in the picture.

## Bruteforcing in Action
Code is in the repo and named `19-GreekToMe.py`. You need to place `greek_to_me.exe` in the same directory. It's not in the repo so you need to download it from the website.

That was pretty fast because our address space was only one byte (0x00 to 0xFF).

```
$ python 19-GreekToMe.py
[21:23:48.0743] Starting simple_debugger
[21:23:48.0753] Started simple_debugger. Sleeping for 2 seconds.
[21:23:50.0756] Starting send_me.
[21:23:50.0875] Socket connected
[21:23:50.0875] Sent 0
[21:23:53.0490]
-------------------------------------------------------------------------------
Key: 0xa2
Eax: 0000FB5E
[21:23:54.0901] Reached 0x100
```

## Flag
Run the application in a debugger, set a breakpoint at the "Congratulations!" instruction and send `0xA2`. The blob results in the correct instructions and we get the flag.

**flag: et_tu_brute_force@flare-on.com**

# Some More Analysis - Optional Read
This part is optional but I had already written them during the challenge.

Start of the app:

``` nasm
public start
start proc near
call    sub_401008
xor     eax, eax
retn
start endp
```

`sub_401008` is called, then app returns 0 and exits.

Inside `sub_401008` we see another subroutine `sub_401121`. Before that a `*buf` is pushed (as an argument) and is empty.

## sub_401121
We can see the socket being constructed with [WSAStartup][WSAStartup-MSDN]:

``` nasm
lea     eax, [ebp+WSAData]
push    eax             ; lpWSAData
push    202h            ; wVersionRequested
call    ds:WSAStartup
test    eax, eax
jz      short loc_401147
```

Then if `WSAStartup` was successful we can see the port and other parameters being passed to `socket`. IDA highlights a lot of them for us.

``` nasm
loc_401147:
push    esi
push    edi
push    6               ; protocol
push    1               ; type
push    2
pop     edi
push    edi             ; af
call    ds:socket
mov     esi, eax
cmp     esi, 0FFFFFFFFh
jz      short loc_4011D8
```

We can see [socket][socket-MSDN] here. And of course the arguments are pushed to the stack from right to left.

- af = 2 = AF_INET = IPv4
- type = 1 = SOCK_STREAM = TCP socket
- protocol = 6 = IPPROTO_TCP = TCP

The string `127.0.0.1` is being converted to an inet address with [inet_addr][inet_addr-MSDN].

``` nasm
push    offset cp       ; "127.0.0.1"
mov     [ebp+name.sa_family], di
call    ds:inet_addr
```
Then port with [htons][htons-MSDN].

``` nasm
push    8AEh            ; hostshort
mov     dword ptr [ebp+name.sa_data+2], eax
call    ds:htons
```

"The htons function converts a u_short from host to TCP/IP network byte order (which is big-endian)."

Port number `0x8AE` is `2222` decimal.

Then [bind][bind-MSDN]:

``` nasm
mov     word ptr [ebp+name.sa_data], ax
lea     eax, [ebp+name]
push    10h             ; namelen
push    eax             ; name
push    esi             ; s
call    ds:bind
```

"The bind function associates a local address with a socket."

After there is `listen`, `accept` and `recv` but we already know what they do.

Finally we are listening on `127.0.0.1:2222`.

Let's take a closer look at [recv][recv-MSDN].

"The recv function receives data from a connected socket or a bound connectionless socket."

``` nasm
push    0               ; flags
push    4               ; len
push    [ebp+buf]       ; buf
push    edi             ; s
call    ds:recv
test    eax, eax
jle     short loc_4011CA
```

`Buf` from the parameter is going to be the pointer to the data received. `recv` returns the number of bytes received (which going to be in eax).

If nothing was received, the `jle` is successful and socket is closed.

Otherwise the function returns the number of received bytes.

The rest is explained above.

# Conclusion
I think I am going to stop writing back-to-back blogs for a few days. I have had 0 off-time. But I am glad I learned WinAppDbg, it will help me a lot in my day job.

As usual if you have any suggestions or catch any errors, feel free to contact me.

<!-- Links -->

[flare4-binaries]: http://flare-on.com/files/Flare-On4_Challenges.zip
[flare-solutions]: https://www.fireeye.com/blog/threat-research/2017/10/2017-flare-on-challenge-solutions.html
[cygwin-url]: https://www.cygwin.com/
[strings-sysinternals]: https://docs.microsoft.com/en-us/sysinternals/downloads/strings
[sophos-ws2_32]: https://nakedsecurity.sophos.com/2009/10/12/windows-ws232dll-file-safe/
[wireshark-loopback]: https://wiki.wireshark.org/CaptureSetup/Loopback
[docs-example11]: https://winappdbg.readthedocs.io/en/latest/Debugging.html?highlight=break_at#example-11-setting-a-breakpoint
[breakpoint-py]: https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/breakpoint.py#L3905
[take-memory-snapshot-source]: https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/process.py#L3261
[restore-memory-snapshot-source]: https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/process.py#L3301
[bSkipMappedFiles-source]: https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/process.py#L3317
[get-context-source]: https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/thread.py#L469
[set-context-source]: https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/thread.py#L570
[WSAStartup-MSDN]: https://msdn.microsoft.com/en-us/library/windows/desktop/ms742213(v=vs.85).aspx
[socket-MSDN]: https://msdn.microsoft.com/en-us/library/windows/desktop/ms740506(v=vs.85).aspx
[inet_addr-MSDN]: https://msdn.microsoft.com/en-us/library/windows/desktop/ms738563(v=vs.85).aspx
[htons-MSDN]: https://msdn.microsoft.com/en-us/library/windows/desktop/ms738557(v=vs.85).aspx
[bind-MSDN]: https://msdn.microsoft.com/en-us/library/windows/desktop/ms737550(v=vs.85).aspx
[recv-MSDN]: https://msdn.microsoft.com/en-us/library/windows/desktop/ms740121(v=vs.85).aspx
