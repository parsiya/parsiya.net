---
title: "WinAppDbg - Part 1 - Basics"
date: 2017-11-09T19:22:24-05:00
draft: false
toc: true
comments: true
categories:
- winappdbg
- reverse engineering
tags:
- python
---

[WinAppDbg][winappdbg-github] by [Mario Vilas][mario-twitter] is perhaps one of the most underrated instrumentation frameworks for Windows. In this day and age where everyone write JavaScript code to hook functions (I am looking at you Frida), writing Python code feels great. Just kidding, Frida is pretty cool too.

Going around the web searching for tutorials did not give me many results. [The docs][winappdbg-docs] are great, they are some of the most practical docs I have seen. But apart from that, I could not find much. There are some random code here and there where people have documented using it but there were no guides to get me started apart from the docs.

Here's the result of my learning. I am sharing it to fill the gap that I encountered while getting started with the tool. We're going to learn as we go using real-world applications and will write code. We will start from the basics, expanding our code-base as we learn more.

Code is in my clone at:

- [https://github.com/parsiya/Parsia-Code/tree/master/winappdbg][winappdbg-clone]

[winappdbg-docs]: https://winappdbg.readthedocs.io/en/latest/ "WinAppDbg documentation on readthedocs"
[winappdbg-github]: https://github.com/MarioVilas/winappdbg "WinAppDbg repository on Github"
[mario-twitter]: https://twitter.com/Mario_Vilas "Mario Vilas Twitter account"
[winappdbg-clone]: https://github.com/parsiya/Parsia-Code/tree/master/winappdbg "WinAppDbg code in Parsia-Code"
<!--more-->

Let's get started.

# Prerequisites

- Windows Virtual Machine. I used a 32-bit Windows 7 VM from [modern.ie][modern-ie]: FREE
- Python 2.7 32-bit: FREE
- WinAppDbg 1.6: FREE
    - See below for installation steps/tips
- Basic knowledge of the following (hopefully FREE too):
    - Python: Hopefully
    - x86/x86_64 Assembly
    - Windows APIs

# When I was Stuck

1. Read the docs:
    - https://winappdbg.readthedocs.io/en/latest/
2. Read the source code on Github. For example methods for a `process` objects are at [process.py][process-py].
    - https://github.com/MarioVilas/winappdbg
3. Looked around the internet.
    - There are bits and pieces about WinAppDbg in blog posts/presentations/git repos.

# Installation

- **Install Python 2.7, not 3.**
- Install Python 32-bit to instrument 32-bit applications and vice versa.
    - Instrumenting 32-bit applications on 64-bit Windows works but Python arch must match.
- **Don't use pip to install WinAppDbg**, it installs an older version that will not work. Pip for other packages is fine.
- Clone the [WinAppDbg github][winappdbg-github] repository, and run `install.bat` (optionally in an admin command prompt).
- Install some additional software:
    - Capstone: `python -m pip install capstone-windows`.
    - distorm3: Download binaries from [Github release page][distorm-release].
    - [More installers][installers-mario] from Mario's blog at https://breakingcode.wordpress.com.

# Examples
Now that our environment is ready, we can start learning.

## 01 - Running Applications
As we can see, We are starting with a working Python script.

{{< codecaption title="01-Run.py" lang="python" >}}
import winappdbg
import argparse
from winappdbg import win32

# Debug an app passed by -r
# e.g. python 01-debug1.py -r c:\windows\system32\notepad.exe


def main():
    parser = argparse.ArgumentParser(description="WinAppDbg stuff.")
    parser.add_argument("-r", "--run", help="path to application")

    args = parser.parse_args()

    # Use Win32 API functions provided by WinAppDbg
    if win32.PathFileExists(args.run) is True:
        # File exists

        # Create a Debug object
        debug = winappdbg.Debug()

        try:
            # Debug the app
            # First item is program and the rest are arguments
            # execv: https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/debug.py#L274
            my_process = debug.execv([args.run])

            print "Attached to %d - %s" % (my_process.get_pid(),
                                           my_process.get_filename())

            # Keep debugging until the debugger stops
            debug.loop()

        finally:
            # Stop the debugger
            debug.stop()
            print "Debugger stopped."

    else:
        print "%s not found." % (args.run)


if __name__ == "__main__":
    main()
{{< /codecaption >}}

We can run it as follows, the debugger will stop when we close notepad.

```
$ python 01-Run.py -r c:\windows\system32\notepad.exe
Attached to 1936 - C:\Windows\System32\notepad.exe
Debugger stopped.
```
    
### Argparse
[Argparse module][python-argparse] is easy to use. We can see basic usage in the first three lines.

- Create an ArgumentParser.
- add_arguments to it.
- Parse the arguments.

The output of `argparse.run` is a list of strings. In this case, it contains the path to the executable.

### Windows API Wrappers
WinAppDbg also comes with support for calling a lot of Windows APIs from Python. In this case we are calling [PathFileExists][PathFileExists-msdn] instead of `os.path`. Our program checks if the input passed by `r/run` is valid (e.g. file exists) before running it. Note that this means we need to supply the full path to the executable.

More info:

- [Win32 API wrappers documentation][win32-api-docs]
- [Win32 API wrappers source code][win32-api-source]

### Starting a New Application
To start an application and debug, first we must create a `winappdbg.Debug` object and then call `execv` or `execl`.

There are two ways to run applications:

- `execv`: Accepts a list of strings. First item in the list is the program (including path). Every subsequent item is a command line parameter. We can pass the output of argparse.run directly.
    - For example `['c:\windows\system32\notepad.exe', 'c:\textfile.txt']`.
    - Internally it uses `execl`.
    - [execv source][execv-source]
- `execl`: Accepts a string containing the command line. This string is the exact input that we type to run the program (including arguments).
    - [execl source][execl-source]

### Process
The result of both methods is a `winappdbg.process`. Later we will see what we can do with the process.

For now we are calling two obvious methods to get the process ID and the executable name. All `process` methods are [here][process-py].

### Debugging
To debug newly created application, call `debug.loop()` otherwise it will stay suspended. This will instrument the application until it's terminated (or exits).

`debug.stop()` will terminate the process.

## 02 - Running Applications with Arguments
Just running an application is not usually useful. Most times we want to pass arguments.

{{< codecaption title="02-RunWithArgs.py" lang="python" >}}
import winappdbg
import argparse
from winappdbg import win32

# Debug an app with parameters passed by -r
# e.g. python 02-RunWithArgs.py -r c:\windows\system32\notepad.exe c:\textfile.txt


def main():
    parser = argparse.ArgumentParser(description="WinAppDbg stuff.")
    parser.add_argument("-r", "--run", nargs="+",
                        help="path to application followed by parameters")

    args = parser.parse_args()

    if (args.run):
        # Concat all arguments into a string
        myargs = " ".join(args.run)

        # Use Win32 API functions provided by WinAppDbg
        if win32.PathFileExists(args.run[0]) is True:
            # File exists

            # Create a Debug object
            debug = winappdbg.Debug()

            try:
                # Debug the app
                # Debug.execv([args.app])
                # execl: https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/debug.py#L358
                my_process = debug.execl(myargs)

                print "Started %d - %s" % (my_process.get_pid(),
                                           my_process.get_filename())

                # Keep debugging until the debugger stops
                debug.loop()

            finally:
                # Stop the debugger
                debug.stop()
                print "Debugger stopped."

        else:
            print "%s not found." % (args.run[0])

if __name__ == "__main__":
    main()
{{< /codecaption >}}

There are only two changes but the functionality is the same:

- Line 17: We are re-creating the command line string by joining the output from `argparse.run`.
- Line 31: Command line is passed to `execl` instead of `execv`.

After running the script, it will attempt to create `c:\textfile.txt` if it does not exist. Manually close notepad to stop the debugger.

```
$ python 02-RunWithArgs.py -r c:\windows\system32\notepad.exe c:\textfile.txt
Started 1416 - C:\Windows\System32\notepad.exe
Debugger stopped.
```

## 03 - Some System Information
WinAppDbg comes with some helpful utilities. One of them is the [`System`][system-py] object. System has a lot more to offer than what we will be using in this part.

Moving forward I will just show the modified parts of the scripts. The complete scrips are in the Github clone.

We will add another switch to our script to print some system information.

{{< codecaption title="03-SystemInfo.py" lang="python" >}}
if(args.sysinfo):
    # Create a System object
    # https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/system.py#L66
    system = winappdbg.System()

    # Use the built-in WinAppDbg table
    # https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/textio.py#L1094
    table = winappdbg.Table("\t")

    # New line
    table.addRow("", "")

    # Header
    title = ("System Information", "")
    table.addRow(*title)

    # Add system information
    table.addRow("------------------")
    table.addRow("Bits", system.bits)
    table.addRow("OS", system.os)
    table.addRow("Architecture", system.arch)
    table.addRow("32-bit Emulation", system.wow64)
    table.addRow("Admin", system.is_admin())
    table.addRow("WinAppDbg", winappdbg.version)
    table.addRow("Process Count", system.get_process_count())

    print table.getOutput()

    exit()
{{< /codecaption >}}

The most important ones are:

- `system.bits`: This will return `32` or `64` based on the architecture of the current OS. This will come in handy later when we want to modify function parameters and need to adhere to the respective Application Binary Interface (ABI) (e.g. are functions pushed to stack or are stored in registers). Do not worry about it for now.
    - **This is different from the application being instrumented.** For example the output of `bits` while debugging a 32-bit app on 64-bit Windows will be `64`. In that case we need to check `system.wow64` output.
- `system.wow64`: Returns `True` if we are running a 32-bit application in emulation mode on a 64-bit Windows and `False` otherwise. Returns `False` on 32-bit operating systems.
- `system.is_admin()`: Returns `True` if we are running as admin.

Result in my VM:

```
$ python 03-SystemInfo.py -i

System Information
------------------
Bits                    32
OS                      Windows 7
Architecture            i386
32-bit Emulation        False
Admin                   False
WinAppDbg               Version 1.6
Process Count           49
```

### Built-in Table
WinAppDbg comes with a built-in table. It's pretty easy to use.

1. Create a table object with `table = winappdbg.Table()`. Constructor supports an optional delimiter between rows. For example `\t` will insert a tab between rows.
2. Add rows with `table.addRow("col1", "col2", "col3")`.
3. Justify columns with `table.Justify(0, 1, 1)` where `0` is justify right and `1` is justify left.
4. `table.Show()` will print the table.
5. `table.getOutput()` returns a string that can be printed.
6. One good way of separating headers from the rest of rows with a separator is in [code from more examples-4][table-example]:

    ``` python
    header = ("column1", "column2", "column3")
    separator = [ "-" * len(x) for x in header ]
    table.addRow(*header)
    table.addRow(*separator)
    ```

More info:

- [Table documentation][table-docs]
- [Table source code][table-source]

## 04 - List Running Processes
We are adding a new functionality to our script. If no argument is passed, print a list of running processes with their pid and filename sorted by pid. This will come in handy later.

We can accomplish this by creating a `System` object and then iterating through the processes.

{{< codecaption title="04-Processes.py" lang="python" >}}
# If no arguments, print running processes
system = winappdbg.System()

# We can reuse example 02 from the docs
# https://winappdbg.readthedocs.io/en/latest/Instrumentation.html#example-2-enumerating-running-processes
table = winappdbg.Table("\t")
table.addRow("", "")

header = ("pid", "process")
table.addRow(*header)

table.addRow("----", "----------")

processes = {}

# Add all processes to a dictionary then sort them by pid
for process in system:
    processes[process.get_pid()] = process.get_filename()

# Iterate through processes sorted by pid
for key in sorted(processes.iterkeys()):
    table.addRow(key, processes[key])

print table.getOutput()
{{< /codecaption >}}

We are using the built-in `Table` again.

Partial output in my VM:

```
$ python 04-Processes.py

pid     process
----    ----------
0       None
4       System
220     smss.exe
248     C:\Windows\system32\Dwm.exe
296     csrss.exe
344     wininit.exe
352     csrss.exe
380     winlogon.exe
436     services.exe
452     lsass.exe
460     lsm.exe
568     svchost.exe
628     VBoxService.exe
1060    C:\Windows\system32\taskhost.exe
1748    C:\Program Files\Google\Chrome\Application\chrome.exe
1888    C:\Windows\system32\cmd.exe
1944    C:\Program Files\Google\Chrome\Application\chrome.exe
```

## 05 - Attach to Process by pid
Starting applications is fun but usually we want to attach to a running process. Let's add a `pid` switch to our script.

The `Debug.attach(pid)` method does what we want. The rest of the code checks if the pid exists before attempting to attach to it.

{{< codecaption title="05-Attach.py" lang="python" >}}
if (args.pid):
    system = winappdbg.System()

    # Get all pids
    pids = system.get_process_ids()

    if args.pid in pids:
        # pid exists

        # Create a Debug object
        debug = winappdbg.Debug()

        try:
            # Attach to pid
            # attach: https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/debug.py#L219
            my_process = debug.attach(args.pid)

            print "Attached to %d - %s" % (my_process.get_pid(),
                                           my_process.get_filename())

            # Keep debugging until the debugger stops
            debug.loop()

        finally:
            # Stop the debugger
            debug.stop()
            print "Debugger stopped."

    else:
        print "pid %d not found." % (args.pid)

    exit()
{{< /codecaption >}}


### Mutually Exclusive Argparse Groups
Adding the new `pid` switch will conflict with our old `run` switch. We do not want to do both of them at the same time. This is done in `argparse` by creating a mutually exclusive group and adding arguments to it. These arguments cannot be passed together.

Other argument can be added normally via `add_argument` to the original parser object.

{{< codecaption title="Mutually exclusive Argparse groups" lang="python" >}}
parser = argparse.ArgumentParser(description="WinAppDbg stuff.")
# Make -r and -pid mutually exclusive
group = parser.add_mutually_exclusive_group()
group.add_argument("-r", "--run", nargs="+",
                   help="path to application followed by parameters")
group.add_argument("-pid", "--attach-pid", type=int, dest="pid",
                   help="pid of process to attach and instrument")

parser.add_argument("-i", "--sysinfo", action="store_true",
                    help="print system information")

args = parser.parse_args()
{{< /codecaption >}}

Now we can run notepad (or any other application), run the script without any arguments to get a list running processes and then attach to notepad using the pid.

```
$ notepad.exe

$ python 05-Attach.py | findstr notepad
2924    C:\Windows\system32\notepad.exe

$ python 05-Attach.py -pid 2924
Attached to 2924 - C:\Windows\system32\notepad.exe
Debugger stopped.
```

## 06 - Attach to Process by Name
We can attach to a process by name with `debug.system.find_processes_by_filename`.

We also need to add the new `-pname` argument to the mutually exclusive group.

{{< codecaption title="06.AttachByName.py" lang="python" >}}
# Find a process by name and attach to it
if (args.pname):
    debug = winappdbg.Debug()

    # example 3:
    # https://winappdbg.readthedocs.io/en/latest/_downloads/03_find_and_attach.py

    try:
        debug.system.scan()
        for (process, name) in debug.system.find_processes_by_filename(args.pname):
            print "Found %d, %s" % (process.get_pid(),
                                    process.get_filename())

            debug.attach(process.get_pid())

            print "Attached to %d-%s" % (process.get_pid(),
                                         process.get_filename())

        debug.loop()

    finally:
        debug.stop()

    exit()
{{< /codecaption >}}

Usage is similar:

```
$ notepad.exe

$ python 06-AttachByName.py | findstr notepad
3596    C:\Windows\system32\notepad.exe

$ python 06-AttachByName.py -pname notepad
Found 3596, C:\Windows\system32\notepad.exe
Attached to 3596-C:\Windows\system32\notepad.exe
```

## 07 - Logging
Up until now we have used `print` statements to display information which is barbaric at best (lol). WinAppDbg has a built-in logger. We can also use our own logger but the built-in logger has some extra utilities. However, I wish the built-in logger could disable timestamps.

We will add logging functionality to our script with `-o` and use the built-in logger. With `-o` we can pass a file to store the logs.

winappdbg.Logger can be created using two arguments. First one is a filename and second one is `verbose`. If `verbose` is set to `True`, output will be logged to stdout.

{{< codecaption title="07-Logging.py" lang="python" >}}
# Setup logging
# https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/textio.py#L1766
# Log to file

global logger
if args.output:
    # verbose=False disables printing to stdout
    logger = winappdbg.Logger(args.output, verbose=False)
else:
    logger = winappdbg.Logger()
{{< /codecaption >}}

Now we can use `logger.log_text(str)` to log any string. Just note that we need to pass a string to it (otherwise it will raise an exception), so wrap everything in `str`.

More info:

- [Logger documentation][logger-docs]
- [Logger source code][logger-source]


# Conclusion
We learned a bunch of basic building blocks. In next part I will introduce my helper code and we will tackle more advanced subjects like function hooking and manipulation. For now, go out and start experimenting with WinAppDbg. As usual, if you have any feedback, please let me know.

<!-- links -->

[process-py]: https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/process.py#L89-L153
[distorm-release]: https://github.com/gdabah/distorm/releases
[installers-mario]: https://breakingcode.wordpress.com/2012/04/08/quickpost-installer-for-beaenginepython/ "Installers for BeaEnginePython, Pymsasid, PyDasm and Libdisassemble - BreakingCode.blogspot.com"
[modern-ie]: https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/ "Modern.ie Windows Virtual Machines"
[python-argparse]: https://docs.python.org/2.7/library/argparse.html "Argparse Python 2.7 docs"
[PathFileExists-msdn]: https://msdn.microsoft.com/en-us/library/windows/desktop/bb773584(v=vs.85).aspx "PathFileExists - MSDN"
[execv-source]: https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/debug.py#L274
[execl-source]: https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/debug.py#L358
[win32-api-docs]: https://winappdbg.readthedocs.io/en/latest/Win32APIWrappers.html "The Win32 API wrappers - WinAppDbg documentation"
[win32-api-source]: https://github.com/MarioVilas/winappdbg/tree/master/winappdbg/win32
[system-py]: https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/system.py#L124
[table-source]: https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/textio.py#L1094
[table-example]: http://winappdbg.readthedocs.io/en/latest/MoreExamples.html#show-processes-dep-settings
[table-docs]: https://winappdbg.readthedocs.io/en/latest/Helpers.html#text-output-in-tables "Text output in tables - WinAppDbg documentation"
[logger-docs]: https://winappdbg.readthedocs.io/en/latest/Helpers.html#logging "Logging - WinAppDbg documentation"
[logger-source]: https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/textio.py#L1766
