---
title: "WinAppDbg - Part 2 - Function Hooking and Others"
date: 2017-11-11T12:04:48-05:00
draft: false
toc: true
comments: true
categories:
- winappdbg
- reverse engineering
tags:
- python
- function hooking
---

In [part one]({{< ref "2017-11-09-winappdbg-1-basics.markdown" >}} "WinAppDbg - Part 1 - Basics") we talked about the basics of WinAppDbg. In this part we are going to learn a few new things:

- I wrote a [simple python module][winapputil-github] to simplify my use of WinAppDbg. It will most likely be modified later, but I have included a version that works with the tutorials at:
    + [https://github.com/parsiya/Parsia-Code/tree/master/winappdbg][winappdbg-clone]
    + We do not need to type the full filename anymore if the executable is in PATH. Note Run Line (`win+r`) pulls stuff from more locations than PATH, so we cannot call `chrome.exe`. I have written about it [here]({{< ref "2017-10-23-windows-run-line-vs-cmd.markdown" >}} "Run Line vs. cmd vs. PowerShell").
- **DLL enumeration**: We're going to implement one of procmon's features.
- **Process/Thread tracing**: Another procmon feature.
- **Function Hooking**: It's very easy in WinAppDbg and we will learn how to do it a couple of different ways.
    + We will hook pre-TLS encryption data for Internet Explorer and Firefox to hack the Gibson.

Copy this directory [https://github.com/parsiya/Parsia-Code/tree/master/winappdbg][winappdbg-clone] to your VM and let's go.

[winappdbg-clone]: https://github.com/parsiya/Parsia-Code/tree/master/winappdbg "WinAppDbg code in Parsia-Code"
[winapputil-github]: https://github.com/parsiya/WinAppUtil "WinAppDbg repository on Github"

<!--more-->

Moving forward, the `main` function is not going to change. It is now re-written using `WinAppUtil` but the functionality has not changed.

# EventHandler Class
WinAppDbg uses callback methods for handling debugging events. In short, we can pass a class of type `winappdbg.EventHandler` to the `Debug` constructor at creation. When a certain event occurs during the execution, a method in the EventHandler class is called. Inside that method, we can write code that does something and "handle" that event.

Here's how we create and use such a class:

{{< codecaption title="Simple EventHandler Usage" lang="python" >}}
import winappdbg

class DebugEvents(winappdbg.EventHandler):
    """
    This is the event handler class.
    """

    def load_dll(self, event):
        """
        This function is called when a new DLL is loaded.
        """

        # do something with the event object

# Inside main
debug = winappdbg.Debug(DebugEvents(), bKillOnExit=True)
debug.loop()

{{< /codecaption >}}

We can define quite a few events. Things like `create_process`, `create_thread` and `exception` (useful for catching crashes and other errors). Mario enumerates and explains them in [the docs][eventhandler-docs] much better than I can do.

We can also define custom breakpoints and handlers in this class (and outside). We will see how to use them later. 

Like always, we can learn much by reading the source. The source for EventHandler is at [event.py][eventhandler-source].

# 08 - Not Procmon - Enumerating Loaded Modules
You might have seen the procmon filter `load image` that lists DLLs loaded by the process. We can even grab a handle to the [Process Environment Block][PEB-msdn] and read them from the linked-list in [PEB_LDR_DATA][PEB-LDR-msdn]. We can do it with WinAppDbg using the `load_dll` callback.

{{< codecaption title="08-NotProcmon-LoadedModules.py" lang="python" >}}
import winappdbg
import argparse
import winapputil


class DebugEvents(winappdbg.EventHandler):
    """
    Event handler class.
    event: https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/event.py
    """

    def load_dll(self, event):
        """
        Called when a new module is loaded.
        """
        module = event.get_module()

        logstring = "\nLoaded DLL:\nName: %s\nFilename: %s\nBase Addr: %s" % \
            (module.get_name(), module.get_filename(), hex(module.get_base()))

        mylogger.log_text(logstring)


# ---------------

def main():
    ...
{{< /codecaption >}}

## dll_load 
The `event` object is passed to the method when a DLL is loaded. First we get the `module` object. It contains information about the DLL that is being loaded. For all module methods see [module.py][module-py]. 

Let's look at the output for `calc.exe`

``` python
$ python 08-NotProcmon-LoadedModules.py -r calc.exe
[21:25:51.0894] Starting calc
[21:25:51.0904]
Loaded DLL:
Name: ntdll
Filename: ntdll.dll
Base Addr: 0x77ca0000
<FileHandle: 276>
[21:25:51.0914]
Loaded DLL:
Name: kernel32
Filename: C:\Windows\system32\kernel32.dll
Base Addr: 0x75ee0000
<FileHandle: 280>
[21:25:51.0914]
Loaded DLL:
Name: kernelbase
Filename: C:\Windows\system32\KERNELBASE.dll
Base Addr: 0x75bd0000
<FileHandle: 284>
[21:25:51.0914]
Loaded DLL:
Name: shell32
Filename: C:\Windows\system32\SHELL32.dll
Base Addr: 0x76970000
<FileHandle: 288>
[21:25:51.0914]
Loaded DLL:
Name: msvcrt
Filename: C:\Windows\system32\msvcrt.dll
Base Addr: 0x76130000
<FileHandle: 292>
[21:25:51.0914]
Loaded DLL:
Name: shlwapi
Filename: C:\Windows\system32\SHLWAPI.dll
Base Addr: 0x76910000
<FileHandle: 296>
[21:25:51.0914]
Loaded DLL:
Name: gdi32
Filename: C:\Windows\system32\GDI32.dll
Base Addr: 0x764e0000
<FileHandle: 300>
[21:25:51.0914]
Loaded DLL:
Name: user32
Filename: C:\Windows\system32\USER32.dll
Base Addr: 0x778f0000
<FileHandle: 304>
...
```

Who knew calculator loads all these modules.

Procmon with the following filters shows we got the right info:

- `Process Name is calc.exe`
- `Operation is Load Image`

{{< imgcap title="Procmon Load Image filter" src="/images/2017/winappdbg-2/01-procmon-loadimage.png" >}}

If the image looks small, right click and open in a new tab.

## get_size() and get_entry_point() Invalid Handle Errors

Not all `module` methods work, for example `get_size` and `get_entry_point` do not. Uncomment the line for calling `get_size()` in our code to get this error:

``` python
$ python 08-NotProcmon-LoadedModules.py -r calc.exe
[17:39:20.0900] Starting calc.exe
[17:39:20.0900]
Loaded DLL:
Name: ntdll
Filename: ntdll.dll
Base Addr: 0x77ca0000
C:\Python27\lib\site-packages\winappdbg\module.py:294: RuntimeWarning: Cannot get 
size and entry point of module ntdll, reason: The handle is invalid.
  % (self.get_name(), e.strerror), RuntimeWarning)
```

At this point I am not exactly sure why we get this error. I dug around and found some really interesting things about how module are loaded on Windows. In short, WinAppDbg uses [GetModuleInformation][GetModuleInformation-msdn] and according to the MSDN article it cannot get info on files "that were loaded with the `LOAD_LIBRARY_AS_DATAFILE` flag." We can see it in [get_size()][get-size-source] source (scroll down to line 280 to see `GetModuleInformation` called) and [winappdbg.win32.GetModuleInformation][GetModuleInformation-winappdbg].

However I found [this MSDN blog entry][GetModuleInformation-blog] by Raymond Chen[^raymond-1] where he explains why we get an invalid handle error when calling [GetModuleFileNameEx][GetModuleFileNameEx-msdn]. Because the module has not been executed(??) yet, there's almost nothing at the location that the handle is pointing to (that's my understanding but I could be wrong). I think we are facing the same issue here, because `load_dll` is called right before DLL is loaded. This is something I need to look at later.


# 09 - Not Procmon - Tracing Processes and Threads
We can also trace processes and threads. This code implements this procmon functionality:

{{< codecaption title="09-NotProcmon-CreateProcess.py" lang="python" >}}
class DebugEvents(winappdbg.EventHandler):
    """
    Event handler class.
    event: https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/event.py
    """

    def create_process(self, event):
        process  = event.get_process()
        pid      = event.get_pid()
        # pid    = process.get_pid()
        filename = process.get_filename()

        mylogger.log_text("CreateProcess %d - %s" % (pid, filename))

    def exit_process(self, event):
        process  = event.get_process()
        pid      = event.get_pid()
        # pid    = process.get_pid()
        filename = process.get_filename()

        mylogger.log_text("ExitProcess %d - %s" % (pid, filename))

    def create_thread(self, event):
        process  = event.get_process()
        thread   = event.get_thread()

        tid  = thread.get_tid()
        name = thread.get_name()

        mylogger.log_text("CreateThread %d - %s" % (tid, name))

    def exit_thread(self, event):
        process  = event.get_process()
        thread   = event.get_thread()

        tid  = thread.get_tid()
        name = thread.get_name()

        mylogger.log_text("ExitThread %d - %s" % (tid, name))


# ---------------

def main():
    ...
{{< /codecaption >}}

We have created four callback methods in the EventHandler class. They trace creation and termination of processes/threads.

``` python
$ python 09-NotProcmon-CreateProcess.py -r calc.exe
[21:35:09.0727] Starting calc.exe
[21:35:09.0727] CreateProcess 3720 - C:\Windows\System32\calc.exe
[21:35:09.0788] CreateThread 1688 - None
[21:35:09.0798] CreateThread 2344 - None
[21:35:12.0289] ExitThread 1688 - None
[21:35:12.0289] ExitThread 2344 - None
[21:35:12.0299] ExitProcess 3720 - C:\Windows\System32\calc.exe
```

Procmon can display the same info using these five filters:

- `Process Name is calc.exe`
- `Operation is Process Start`
- `Operation is Process Exit`
- `Operation is Thread Create`
- `Operation is Thread Exit`

{{< imgcap title="Tracing in procmon" src="/images/2017/winappdbg-2/02-procmon-trace.png" >}}

# 10 - Basic Hooking with debug.hook_function()
Enough with things we can already do with other tools. Let's hook functions. Hooking functions is pretty useful. For example they can [leak AES keys]({{< ref "2015-01-06-tales-from-the-crypt-o-leaking-aes-keys.markdown#2-3-using-ltrace-to-find-the-key" >}} "Tales from the Crypto - Leaking encryption Keys - Using ltrace to Find the Key") and tons of other useful information.

Unfortunately we do not have `ltrace` on Windows but we can hook functions pretty easily with WinAppDbg in a few ways.

In this example we are going to hook the [CreateFile][CreateFile-msdn] Windows API calls from `kernel32` for `calc` and `notepad`.

{{< codecaption title="10-BasicHook.py" lang="python" >}}
from winappdbg.win32 import PVOID, DWORD, HANDLE


class DebugEvents(winappdbg.EventHandler):
    """
    Event handler class.
    event: https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/event.py
    """

    def load_dll(self, event):
        module = event.get_module()

        if module.match_name("kernel32.dll"):

            # Resolve function addresses
            address_CreateFileA = module.resolve("CreateFileA")
            address_CreateFileW = module.resolve("CreateFileW")

            # Types are here
            # https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/win32/defines.py#L380
            sig_CreateFileA = (PVOID, DWORD, DWORD, PVOID, DWORD, DWORD, HANDLE)
            sig_CreateFileW = (PVOID, DWORD, DWORD, PVOID, DWORD, DWORD, HANDLE)

            pid = event.get_pid()

            # Hook function(pid, address, preCB, postCB, paramCount, signature)
            # https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/breakpoint.py#L3969
            event.debug.hook_function(pid, address_CreateFileA,
                                      preCB=pre_CreateFileA,
                                      signature=sig_CreateFileA)

            event.debug.hook_function(pid, address_CreateFileW,
                                      preCB=pre_CreateFileW,
                                      signature=sig_CreateFileW)

            # Another way of setting up hooks without signature

            """
            event.debug.hook_function(pid, address_CreateFileA,
                                      preCB=pre_CreateFileA,
                                      paramCount=7)

            event.debug.hook_function(pid, address_CreateFileW,
                                      preCB=pre_CreateFileW,
                                      paramCount=7)
            """

# ---------------

def main():
    ...
{{< /codecaption >}}

That's quite a lot of code but it's mostly boilerplate. Let's break it down.

First we are importing some symbols from `winappdbg.win32`. We will use them in a bit. We can see all of these symbols in [defines.py][defines-py].

Inside `dll_load`, we check if we are loading `kernel32.dll`. If so, we call [module.resolve()][module-resolve] for `CreateFileA` and `CreateFileW`. These return the address for exported functions in the target process[^dll-land-addr]. A is the ANSI and W (Wide) is the UTF-16 version of the `CreateFile` function[^ansi-wide-msdn].

## Function Signatures
Then we create a signature for each hooked function. The signature is like a function prototype from C/C++. It tells WinAppDbg the type and number of arguments for each function.

This is `CreateFile`[^asm-highlight]:

``` asm
HANDLE WINAPI CreateFile(
  _In_     LPCTSTR               lpFileName,
  _In_     DWORD                 dwDesiredAccess,
  _In_     DWORD                 dwShareMode,
  _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  _In_     DWORD                 dwCreationDisposition,
  _In_     DWORD                 dwFlagsAndAttributes,
  _In_opt_ HANDLE                hTemplateFile
);
```

So our signature for both `CreateFile` functions is `(PVOID, DWORD, DWORD, PVOID, DWORD, DWORD, HANDLE)`. Hungarian notation rocks!

When creating signatures, **use PVOID for all pointers**. Otherwise according to the docs, ctypes become too helpful and ruin everything by trying "to access the memory pointed to by them... and crash[ing], since those pointers only work in the debugged process..)".

## event.debug.hook_function()
Next we hook each function using [event.debug.hook_function][hook-function] like this[^hook-breakpoint]:

``` asm
event.debug.hook_function(pid, address_CreateFileW, 
                          preCB=pre_CreateFileW,
                          postCB=post_CreateFileW,
                          signature=sig_CreateFileW)
```

- `pid` is the current process ID. We are passing `event.get_pid()`.
- `address_CreateFileW` is the `CreateFileW` function address in process memory.
- `preCB` is name of the pre-execution callback function for this breakpoint. This function could be anywhere.
- `postCB` is called when the hooked function returns.
- `signature` is the signature we just created.
- Instead of `signature` we can pass `paramCount` which is just an int containing the number of parameters (starting from 1) which is `7` here.
    - According to [source code][paramcount-source], using signature is better for cross-platform functionality. `paramCount` is used to retrieve items from stack and read dwords in 32-bit processes. This might pose some issues for 64-bit processes because first four parameters are stored in registers and pointers are qwords (64-bits) on Windows 64-bit[^64-bit].

## Pre Callback Functions
Next is `pre_CreateFileW`. The first two arguments for each callback function are always `event` and `ra` (return address) and `self` if needed.

{{< codecaption title="Pre Callback Functions" lang="python" >}}
# Callback functions
# -------------------

# Callback function parameters are always
# (event, ra (return address), then function parameters)
# self is first if part of the eventhandler class


def pre_CreateFileW(event, ra, lpFileName, dwDesiredAccess, dwShareMode,
                    lpSecurityAttributes, dwCreationDisposition,
                    dwFlagsAndAttributes, hTemplateFile):

    """
    This will be called as soon as we enter the function and before the
    function stack frame is created.
    """

    process = event.get_process()

    # Suspend the process because why not
    process.suspend()

    mylogger.log_text("Hit kernel32!CreateFileW")

    # 32-bit so all parameters are on stack

    # In case you want a pointer to the top of the stack
    # thread = event.get_thread()

    # All memory read stuff are at
    # https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/process.py#L125

    # fUnicode=True because we are in the Wide or Unicode version of the API
    myFileName = process.peek_string(lpFileName, fUnicode=True)

    mylogger.log_text("lpFilename: %s" % (myFileName))

    # Resume the process
    process.resume()


def pre_CreateFileA(event, ra, lpFileName, dwDesiredAccess, dwShareMode,
                    lpSecurityAttributes, dwCreationDisposition,
                    dwFlagsAndAttributes, hTemplateFile):

    process = event.get_process()

    # Suspend the process because why not
    process.suspend()

    mylogger.log_text("Hit kernel32!CreateFileA")

    # fUnicode=False because we are in the ANSI version
    myFileName = process.peek_string(lpFileName, fUnicode=False)

    mylogger.log_text("lpFilename: %s" % (myFileName))

    process.resume()
{{< /codecaption >}}

First we suspend the process and log some text to indicate we are inside the function.

Now we can read each argument. We are interested in `lpFileName` which is a long pointer to a UTF-16 string (lpsz == long pointer to null-terminated [zeroed] string). WinAppDbg comes with a [lot of methods][process-py-memory-methods] for reading and writing process memory. In this case we want to read a UTF-16 string so we call `process.peek_string(lpFileName, fUnicode=True)`. In the ANSI version we do the same but with `fUnicode=False`.

After printing `lpFileName`, we resume the process and the callback function returns.

## Post Callback Functions
Post callback functions are similar to pre ones. They only have two arguments `([self], event, retval)`. They are called just after the function returns and allow us to manipulate return values.

{{< codecaption title="Post Callback Functions" lang="python" >}}
def post_CreateFileW(event, retval):

    mylogger.log_text("Leaving kernel32!CreateFileW")
    mylogger.log_text("Return value: %x" % (retval))


def post_CreateFileA(event, retval):

    mylogger.log_text("Leaving kernel32!CreateFileA")
    mylogger.log_text("Return value: %x" % (retval))
{{< /codecaption >}}

## Hooking in Action
Now we can run it on `calc` and see the results:

``` python
$ python 10-BasicHook.py -r calc
[00:12:15.0736] Starting calc
[00:12:15.0796] Hit kernel32!CreateFileW
[00:12:15.0796] lpFilename: C:\Windows\Fonts\staticcache.dat
[00:12:15.0796] Leaving kernel32!CreateFileW
[00:12:15.0796] Return value: c4
```

And in procmon with these filters:

- `Process Name is calc.exe`
- `Operation is ReadFile`
    + If you have enabled `Filter (menu) > Enable Advanced Output`, use `IRP_MJ_READ` instead of `ReadFile`.

{{< imgcap title="Procmon ReadFile filter" src="/images/2017/winappdbg-2/03-procmon-readfile.png" >}}

I am not going to post the `notepad` output here. Run the script with `-r notepad` and you will see a wall of text when you open a common file dialog to open a file or save.

For a similar example in the docs, see [example 12 - hooking a function][docs-example12].

# 11 - Easier Hooking via apiHooks
That was fun but we wrote a lot of boilerplate code. WinAppDbg offers a better way to hook functions through `apiHooks`.

{{< codecaption title="11-BetterHook.py" lang="python" >}}
from winappdbg.win32 import PVOID, DWORD, HANDLE


class DebugEvents(winappdbg.EventHandler):
    """
    Event handler class.
    event: https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/event.py
    """

    # Better hooking
    # https://winappdbg.readthedocs.io/en/latest/Debugging.html#example-9-intercepting-api-calls

    apiHooks = {

        # Hooks for the kernel32 library.
        "kernel32.dll": [

            # We have seen these before
            # Function       Signature
            ("CreateFileA", (PVOID, DWORD, DWORD, PVOID, DWORD, DWORD, HANDLE)),
            ("CreateFileW", (PVOID, DWORD, DWORD, PVOID, DWORD, DWORD, HANDLE)),

            # Can also pass parameter count
            # ("CreateFileA", 6),
            # ("CreateFileW", 6),
        ],
    }

    # Now we can simply define a method for each hooked API.
    # "pre_"  methods are called when entering the hooked function.
    # "post_" methods are called when returning from the hooked function.

    def pre_CreateFileW(self, event, ra, lpFileName, dwDesiredAccess,
                        dwShareMode, lpSecurityAttributes, dwCreationDisposition,
                        dwFlagsAndAttributes, hTemplateFile):

        process = event.get_process()
        myFileName = process.peek_string(lpFileName, fUnicode=True)
        mylogger.log_text("pre_CreateFileW opening file %s" % (myFileName))

    def post_CreateFileW(self, event, retval):
        mylogger.log_text("Return value: %x" % retval)

    def pre_CreateFileA(self, event, ra, lpFileName, dwDesiredAccess,
                        dwShareMode, lpSecurityAttributes, dwCreationDisposition,
                        dwFlagsAndAttributes, hTemplateFile):

        process = event.get_process()
        myFileName = process.peek_string(lpFileName, fUnicode=False)
        mylogger.log_text("pre_CreateFileA opening file %s" % (myFileName))

    def post_CreateFileA(self, event, retval):
        mylogger.log_text("Return value: %x" % retval)
{{< /codecaption >}}

This looks much easier and more straightforward (of course I am biased).

## apiHooks
Inside our EventHandler class we create a dictionary named `apiHooks`. DLL name is key and hooked functions (and their signatures) are values. I am hooking functions from one DLL it's possible to add multiple DLLs/functions quickly.

``` asm
apiHooks = {

    # Hooks for the kernel32 library.
    'kernel32.dll': [

        # We have seen these before
        # Function       Signature
        ('CreateFileA', (PVOID, DWORD, DWORD, PVOID, DWORD, DWORD, HANDLE)),
        ('CreateFileW', (PVOID, DWORD, DWORD, PVOID, DWORD, DWORD, HANDLE)),

        # Can also pass parameter count
        # ('CreateFileA', 6),
        # ('CreateFileW', 6),
    ],
}
```

We can also pass parameter count instead of signature. I personally prefer signature because it's easier to keep track of argument types.

Then for each hooked functions we create two methods name `pre` and `post` like before (note method names are non-negotiable so don't go creative here).

## apiHooks in Action
And it works.

``` python
$ python 11-BetterHook.py -r calc
[00:54:01.0164] Starting calc
[00:54:01.0213] pre_CreateFileW opening file C:\Windows\Fonts\staticcache.dat
[00:54:01.0213] Return value: c4
```

For a similar example in docs see [example 9: intercepting-api-calls][docs-example9].

{{< imgcap title="Eating your bandwith two megabytes at a time" src="https://i.giphy.com/media/zcCGBRQshGdt6/giphy.gif" >}}

Moving forward we will be using this method for hooking.

# 12 - Not Echo Mirage - Hooking IE - Part 1
Echo Mirage was an application that used function hooking to view and modify pre-encryption/pre-TLS traffic. Good luck finding a clean version of it :D. We are going to hook IE using WinAppDbg to just view payloads.

## What to Hook?
We learn from malware. They are the best. In this article titled [Analyzing a form-grabber malware][thisissecurity], there's a table that contains what this malware hooks[^no-anchor]. This is the part we are interested in.

| Browser      | DLL         | Function           |
|--------------|-------------|--------------------|
| iexplore.exe | Wininet.dll | HttpSendRequestW/A |
| firefox.exe  | nspr4.dll   | PR_Write           |


## HttpSendRequest
For IE we need to hook `HttpSendRequestW` (not going to bother with the Ansi version on Win 7). According to [MSDN][HttpSendRequest-msdn] it looks like this:

``` asm
BOOL HttpSendRequest(
  _In_ HINTERNET hRequest,
  _In_ LPCTSTR   lpszHeaders,
  _In_ DWORD     dwHeadersLength,
  _In_ LPVOID    lpOptional,
  _In_ DWORD     dwOptionalLength
);
```

We want to log the `lpOptional` parameter because it contains the `POST` and `PUT` payloads and most likely passwords (which this malware is interested in) are submitted via `POST`.

{{< codecaption title="12-NotEchoMirage-IE-1.py" lang="python" >}}
from winappdbg.win32 import PVOID, DWORD, HANDLE


class DebugEvents(winappdbg.EventHandler):
    """
    Event handler class.
    event: https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/event.py
    """

    apiHooks = {

        # Hooks for the wininet.dll library - note this is case-sensitive
        'wininet.dll': [

            # Function            Signature
            ('HttpSendRequestW', (HANDLE, PVOID, DWORD, PVOID, DWORD)),
        ],
    }

    def pre_HttpSendRequestW(self, event, ra, hRequest, lpszHeaders,
                             dwHeadersLength, lpOptional, dwOptionalLength):

        process = event.get_process()

        if dwHeadersLength != 0:
            mylogger.log_text(winapputil.utils.get_line())
            mylogger.log_text("HttpSendRequestW")

            headers = process.peek_string(lpszHeaders, fUnicode=True)
            mylogger.log_text("Headers %s" % (headers))

        if dwOptionalLength != 0:
            # This is not unicode - see the pointer name (lp vs. lpsz)
            # fUnicode is set to False (default) then
            optional = process.peek_string(lpOptional, fUnicode=False)

            mylogger.log_text("Optional %s" % (optional))
            mylogger.log_text(winapputil.utils.get_line())
{{< /codecaption >}}

Our code looks simple thanks to the `apiHooks` functionality.

In `pre_HttpSendRequestW` we are reading `lpszHeaders` and `lpOptional` (both are not Unicode) and print them.

## Hooking IE
Run IE (note it's not in PATH so you have to enter the full path) and go around the web, see headers (no cookies) and the occasional `POST` request (mostly ads). To see a `POST` request in action, head over to pastebin and submit a new paste:

``` asm
$ python 12-NotEchoMirage-IE-1.py -r "c:\Program Files\Internet Explorer\iexplore.exe"
...
[01:50:02.0115] ---------------------------------------------------------------------------
[01:50:02.0115] HttpSendRequestW
[01:50:02.0115] Headers Referer: https://pastebin.com/
Accept-Language: en-US
User-Agent: Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko
Content-Type: multipart/form-data; boundary=---------------------------7e16a21104fe
Accept-Encoding: gzip, deflate
[01:50:02.0115] Optional -----------------------------7e16a21104fe
Content-Disposition: form-data; name="csrf_token_post"

MTUxMDM4Mjk1N0g5d1d2TkJXZnNXUEk3UWdmTnlycXp2WHp3M0lJc1VG
-----------------------------7e16a21104fe
Content-Disposition: form-data; name="submit_hidden"

submit_hidden
-----------------------------7e16a21104fe
Content-Disposition: form-data; name="paste_code"

Random text in pastebin
-----------------------------7e16a21104fe
Content-Disposition: form-data; name="paste_format"

1
-----------------------------7e16a21104fe
Content-Disposition: form-data; name="paste_expire_date"

N
-----------------------------7e16a21104fe
Content-Disposition: form-data; name="paste_private"

0
-----------------------------7e16a21104fe
Content-Disposition: form-data; name="paste_name"


-----------------------------7e16a21104fe--
...
```

This is nice but we do not see where the data is sent or any GET requests.

# 13 - Not Echo Mirage - Hooking IE - Part 2
To gather more information we need to hook more functions.

## HttpOpenRequest
The first parameter for `HttpSendRequest` is a handle to a request. This request is returned by a call to [HttpOpenRequest][HttpOpenRequest-msdn]:

``` asm
HINTERNET HttpOpenRequest(
  _In_ HINTERNET hConnect,
  _In_ LPCTSTR   lpszVerb,
  _In_ LPCTSTR   lpszObjectName,
  _In_ LPCTSTR   lpszVersion,
  _In_ LPCTSTR   lpszReferer,
  _In_ LPCTSTR   *lplpszAcceptTypes,
  _In_ DWORD     dwFlags,
  _In_ DWORD_PTR dwContext
);
```

Interesting parameters are:

- `lpszVerb`: *str to HTTP verb. If NULL, verb is `GET`.
- `lpszObjectName`: *str to name of target obj. "This is generally a file name, an executable module, or a search specifier."
- `lpszReferer`: *str to referer (we already seen it in `HttpSendRequest.lpszHeaders`).

{{< codecaption title="12-NotEchoMirage-IE-2.py" lang="python" >}}
from winappdbg.win32 import PVOID, DWORD, HANDLE


class DebugEvents(winappdbg.EventHandler):
    """
    Event handler class.
    event: https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/event.py
    """

    apiHooks = {

        # Hooks for the wininet.dll library - note this is case-sensitive
        "wininet.dll": [

            # Function            Signature
            ("HttpSendRequestW", (HANDLE, PVOID, DWORD, PVOID, DWORD)),
            ("HttpOpenRequestW", (HANDLE, PVOID, PVOID, PVOID, PVOID, PVOID,
                                  DWORD, PVOID)),
        ],
    }

    def pre_HttpSendRequestW(self, event, ra, hRequest, lpszHeaders,
                             dwHeadersLength, lpOptional, dwOptionalLength):

        ...

    def pre_HttpOpenRequestW(self, event, ra, hConnect, lpszVerb,
                             lpszObjectName, lpszVersion, lpszReferer,
                             lplpszAcceptTypes, dwFlags, dwContext):

        process = event.get_process()

        verb = process.peek_string(lpszVerb, fUnicode=True)
        if verb is None:
            verb = "GET"

        obj = process.peek_string(lpszObjectName, fUnicode=True)

        mylogger.log_text(winapputil.utils.get_line())
        mylogger.log_text("HttpOpenRequestW")
        mylogger.log_text("verb: %s" % verb)
        mylogger.log_text("obj : %s" % obj)
        mylogger.log_text(winapputil.utils.get_line())
{{< /codecaption >}}

## Hooking more IE
Let's see what we can get this time (and if we need to dig further). Note I have removed a lot of junk from the output.

Here's what we `GET` for `example.com`

``` asm
$ python 13-NotEchoMirage-IE-2.py -r "C:\Program Files\Internet Explorer\iexplore.exe"
...
[08:49:34.0502] ---------------------------------------------------------------------------
[08:49:36.0494] ---------------------------------------------------------------------------
[08:49:36.0494] HttpOpenRequestW
[08:49:36.0494] verb: GET
[08:49:36.0494] obj : /
[08:49:36.0494] ---------------------------------------------------------------------------
[08:49:36.0505] ---------------------------------------------------------------------------
[08:49:36.0505] HttpSendRequestW
[08:49:36.0505] Headers Accept-Language: en-US
User-Agent: Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko
Accept-Encoding: gzip, deflate
...
```

Similar for `google.com` (today is veterans' day hence the requests to get the logo):

``` asm
...
[08:50:57.0878] ---------------------------------------------------------------------------
[08:50:58.0217] ---------------------------------------------------------------------------
[08:50:58.0217] HttpOpenRequestW
[08:50:58.0217] verb: GET
[08:50:58.0217] obj : /
[08:50:58.0217] ---------------------------------------------------------------------------
[08:50:58.0217] ---------------------------------------------------------------------------
[08:50:58.0217] HttpSendRequestW
[08:50:58.0217] Headers Accept-Language: en-US
User-Agent: Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko
Accept-Encoding: gzip, deflate
[08:50:58.0479] ---------------------------------------------------------------------------
[08:50:58.0479] HttpOpenRequestW
[08:50:58.0479] verb: GET
[08:50:58.0479] obj : /logos/doodles/2017/veterans-day-2017-5171750613549056-s.png
[08:50:58.0479] ---------------------------------------------------------------------------
[08:50:58.0489] ---------------------------------------------------------------------------
[08:50:58.0489] HttpSendRequestW
[08:50:58.0489] Headers Referer: https://www.google.com/
Accept-Language: en-US
User-Agent: Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko
Accept-Encoding: gzip, deflate
[08:50:58.0489] ---------------------------------------------------------------------------
[08:50:58.0489] HttpOpenRequestW
[08:50:58.0489] verb: GET
[08:50:58.0489] obj : /logos/doodles/2017/veterans-day-2017-5171750613549056-l.png
[08:50:58.0489] ---------------------------------------------------------------------------
[08:50:58.0489] ---------------------------------------------------------------------------
[08:50:58.0489] HttpSendRequestW
[08:50:58.0489] Headers Referer: https://www.google.com/
Accept-Language: en-US
User-Agent: Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko
Accept-Encoding: gzip, deflate
[08:50:58.0499] ---------------------------------------------------------------------------
[08:50:58.0499] HttpOpenRequestW
[08:50:58.0499] verb: GET
[08:50:58.0499] obj : /images/icons/hpcg/usflag-transbg_42.png
[08:50:58.0499] ---------------------------------------------------------------------------
[08:50:58.0499] ---------------------------------------------------------------------------
[08:50:58.0499] HttpSendRequestW
[08:50:58.0499] Headers Referer: https://www.google.com/
Accept-Language: en-US
User-Agent: Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko
Accept-Encoding: gzip, deflate
...
```

We are not getting everything. That means we need to hook more functions.

At this point I am moving on to a different program because the three people that will read this blog are already bored. *ahem* I will leave the rest of IE stuff *as an exercise for the readers*. Academia, amirite fellow intellectuals?

> Here in my university ivory tower, just published this new paper here. It's fun to look myself up on Google Scholar. But you know what I like more than being cited? KNOWLEDGE.

# 14 - Not Echo Mirage - Firefox
The other item in that malware hooking table (well part of the table that I copied) is Firefox.

## PR_Write (in Rust)
Hooking pre-TLS Firefox encryption is trickier because it does not use Windows APIs. In Firefox it's [PR_Write][pr-write-mdn]:

``` c
PRInt32 PR_Write(
    PRFileDesc *fd,
    const void *buf,
    PRInt32 amount);

fd:     A pointer to the PRFileDesc object for a file or socket
buf:    A pointer to the buffer holding the data to be written
amount: The amount of data, in bytes, to be written from the buffer
```

Could not talk about Firefox, `PR_Write` and not make a "Re-write in Rust"[^rewrite-rust] joke. Maybe we should hook Chrome and talk about generics.

## Where is PR_Write?
Tl;dr it's exported in `nss3.dll`.

The Mozilla docs are less helpful than MSDN. MSDN lists the DLL that exports the function but Mozilla does not. Searching in MDN (Mozilla Developer Network) got me nowhere.

That malware table listed it under `nspr4.dll` and search engine results also mostly say the same thing. Grey Hat Python also lists it in the same DLL. In my Firefox (32-bit 56.0.2) there's no such DLL in `C:\Program Files\Mozilla Firefox`[^32-bit-program-files].

We finally get to [Hooking Firefox with Frida][wiremark-frida] from Wiremask.eu which is doing exactly what we do but with Frida[^frida-vs-winappdbg]. Ew, JavaScript code embedded in Python (j/k). Our answer is there `nss3.dll`.

## Null-Terminated Strings vs. Random Buffer
Pointers in `PR_Write` point to different kind of data than what we saw in IE. In IE we were mostly dealing with pointers to null-terminated strings. Meaning we could call `peek_string` and it would go and read until the null-terminator (which is `00 00` for UTF-16[^utf-16-terminator]). Now we have a random buffer but we have the length so we have to go and read that many bytes from memory directly. It's good to see both types of string/data storage in action[^c-vs-pascal-strings].

{{< codecaption title="14-NotEchoMirage-FF.py" lang="python" >}}
from winappdbg.win32 import PVOID, DWORD, HANDLE


class DebugEvents(winappdbg.EventHandler):
    """
    Event handler class.
    event: https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/event.py
    """
    apiHooks = {

        # Hooks for the nss3.dll library
        'nss3.dll': [

            ('PR_Write', (PVOID, PVOID, PVOID)),
        ],
    }

    def pre_PR_Write(self, event, ra, fd, buf, amount):

        process = event.get_process()

        if (amount > 100) and (amount < 1000):
            mylogger.log_text("PR_Write")

            # https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/process.py#L1581
            contents = process.read(buf, amount)

            mylogger.log_text("%s" % str(contents))

            mylogger.log_text(winapputil.utils.get_line())
{{< /codecaption >}}

Things are similar but as we saw above, the buffer might contain null-bytes (e.g. binary data vs. null-terminated strings). So we use `process.read` to read `amount` bytes from the place `buf` points to. Then we convert it to string and print it.

## Firefox in Action
Before you run this, beware that `PR_Write` is used in a lot more than just TLS in Firefox. This will be slow and Firefox might be unresponsive for a minute after you go to a website. The logs will also gather a lot of garbage. As a result I am only printing buffers that are between 100 and 1000 bytes.

I suggest piping the output to a file instead of command prompt with the `-o` switch like this:

- `$ python 14-NotEchoMirage-FF.py -r "C:\Program Files\Mozilla Firefox\firefox.exe" -o firefox-1.txt`

After starting Firefox and entering `example.com`, Firefox will die for a minute or so. But loot is inside the log file. If you do webapps, you have seen the annoying captive portal detection requests `detectportal.firefox.com` in Burp. I hate those and Brian King agrees and has [some tips][quieter-firefox] on how to make them go away.

```
[09:23:41.0933] Starting C:\Program Files\Mozilla Firefox\firefox.exe
[09:23:42.0835] PR_Write
[09:23:42.0835] GET /success.txt HTTP/1.1

Host: detectportal.firefox.com
User-Agent: Mozilla/5.0 (Windows NT 6.1; rv:56.0) Gecko/20100101 Firefox/56.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Cache-Control: no-cache
Pragma: no-cache
Connection: keep-alive
```

Oh shit, OCSP[^OSCP]. Alert the authorities, certificates are expiring.

```
[09:23:43.0467] PR_Write
[09:23:43.0467] POST /ocsp HTTP/1.1

Host: clients1.google.com
User-Agent: Mozilla/5.0 (Windows NT 6.1; rv:56.0) Gecko/20100101 Firefox/56.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Length: 75
Content-Type: application/ocsp-request
Connection: keep-alive

[payload removed]
```

Mooooom, Firefox is tracking me.

```
[09:23:44.0049] PR_Write
[09:23:44.0049] GET /v1/country?key=fff72d56-b040-4205-9a11-82feda9d83a3 HTTP/1.1

Host: location.services.mozilla.com
User-Agent: Mozilla/5.0 (Windows NT 6.1; rv:56.0) Gecko/20100101 Firefox/56.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Origin: null
Connection: keep-alive
```

And finally our request to `example.com`

```
[09:24:25.0388] PR_Write
[09:24:25.0388] GET / HTTP/1.1

Host: example.com
User-Agent: Mozilla/5.0 (Windows NT 6.1; rv:56.0) Gecko/20100101 Firefox/56.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
If-Modified-Since: Fri, 09 Aug 2013 23:54:35 GMT
If-None-Match: "359670651"
```

# Conclusion
I wanted to continue but this blog is already long enough. The markdown file is at 45KBs and counting (mainly because I pasted a lot of code, crap and went full-academia with links and footnotes). But I am bored and you are most likely too.

Go out there and hook stuff. Practice on eavesdropping and tune in for part 3 where we learn how to manipulate function arguments and return values.

If you have feedback, you know where to find me. And check out the rest of the [clone][parsia-clone], there's some good stuff there.

<!-- Footnotes -->
[^raymond-1]: Raymond's blog, [The Old New Thing][old-new-thing] has interesting articles.
[^dll-land-addr]: On a 32-bit machine we will most likely get an address starting with `0x7F` which is in DLL-land.
[^ansi-wide-msdn]: See [MSDN][ansi-vs-wide-msdn] for their differences.
[^hook-breakpoint]: We are essentially putting a breakpoint for each function at the addresses we just resolved.
[^64-bit]: In [64-bit][windows-64-function-calls] processes, first four arguments are stored in `rcx`, `rdx`, `r8`, `r9` and the rest are pushed to the stack (in reverse order) like 32-bit functions.
[^asm-highlight]: Looks much better with `asm` highlighting.
[^no-anchor]: The heading does not have an anchor so I had to link to the first table row. Generate IDs for all your headings people.
[^utf-16-terminator]: That is another *fun* exercise. Read UTF-16 null-terminated strings from memory and see how they are stored.
[^32-bit-program-files]: Remember we are in a 32-bit VM so we have only one `Program Files` not two like x64 Windows that also have `Program Files (x86)` for 32-bit emulation.
[^frida-vs-winappdbg]: Yet another TODO. Try Frida vs. WinAppDbg in terms of performance.
[^c-vs-pascal-strings]: For more information, search for C-style vs. Pascal-style strings.
[^rewrite-rust]: **F E A R L E S S - C O N C U R R E N C Y**
[^OSCP]: Not to be confused with the current infosec meme-cert.

<!-- Links -->

[eventhandler-docs]: https://winappdbg.readthedocs.io/en/latest/Debugging.html#the-eventhandler-class "The EventHandler class - WinAppDbg documentation"
[eventhandler-source]: https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/event.py
[PEB-msdn]: https://msdn.microsoft.com/en-us/library/windows/desktop/aa813706(v=vs.85).aspx "Process Environment Block structure - MSDN"
[PEB-LDR-msdn]: https://msdn.microsoft.com/en-us/library/windows/desktop/aa813708(v=vs.85).aspx "PEB_LDR_DATA structure - MSDN"
[GetModuleInformation-blog]: https://blogs.msdn.microsoft.com/oldnewthing/20150716-00/?p=45131 "Why do I get ERROR_INVALID_HANDLE from GetModuleFileNameEx when I know the process handle is valid? - The Old New Thing"
[module-py]: https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/module.py#L75
[GetModuleInformation-msdn]: https://msdn.microsoft.com/en-us/library/ms683201(v=VS.85).aspx "GetModuleInformation - MSDN"
[old-new-thing]: https://blogs.msdn.microsoft.com/oldnewthing/ "The Old New Thing - Raymond Chen's MSDN blog"
[get-size-source]: https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/module.py#L260
[GetModuleInformation-winappdbg]: https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/win32/psapi.py#L330
[GetModuleFileNameEx-msdn]: https://msdn.microsoft.com/en-us/library/windows/desktop/ms683198(v=vs.85).aspx "GetModuleFileNameEx - MSDN"
[CreateFile-msdn]: https://msdn.microsoft.com/en-us/library/windows/desktop/aa363858(v=vs.85).aspx "CreateFile - MSDN"
[defines-py]: https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/win32/defines.py#L380
[module-resolve]: https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/module.py#L696
[hook-function]: https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/breakpoint.py#L3969
[windows-64-function-calls]: https://msdn.microsoft.com/en-us/library/ms235286.aspx "Overview of x64 Calling Conventions - MSDN"
[paramcount-source]: https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/breakpoint.py#L1107-L1112
[process-py-memory-methods]: https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/process.py#L125
[ansi-vs-wide-msdn]: https://msdn.microsoft.com/en-us/library/windows/desktop/dd374089(v=vs.85).aspx "Unicode in the Windows API - MSDN"
[docs-example12]: https://winappdbg.readthedocs.io/en/latest/Debugging.html#example-12-hooking-a-function "Example #12: hooking a function - WinAppDbg documentation"
[docs-example9]: https://winappdbg.readthedocs.io/en/latest/Debugging.html#example-9-intercepting-api-calls "Example #9: intercepting API calls - WinAppDbg documentation"
[thisissecurity]: https://thisissecurity.stormshield.com/2017/09/28/analyzing-form-grabber-malware-targeting-browsers/#t01 "Analyzing a form-grabber malware - ThisIsSecurity"
[HttpSendRequest-msdn]: https://msdn.microsoft.com/en-us/library/windows/desktop/aa384247(v=vs.85).aspx "HttpSendRequest - MSDN"
[HttpOpenRequest-msdn]: https://msdn.microsoft.com/en-us/library/windows/desktop/aa384233(v=vs.85).aspx "HttpOpenRequest - MSDN"
[pr-write-mdn]: https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSPR/Reference/PR_Write "PR_Write - Mozilla Developer Network"
[wiremark-frida]: https://wiremask.eu/articles/hooking-firefox-with-frida/ "Hooking Firefox with Frida - Wiremask.eu"
[quieter-firefox]: https://www.blackhillsinfosec.com/towards-quieter-firefox/ "Towards a Quieter Firefox - Black Hills Information Security"
[parsia-clone]: https://github.com/parsiya/Parsia-Clone/ "Parsia Clone on Github"
