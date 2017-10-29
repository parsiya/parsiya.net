---
title: "Run Line vs. cmd vs. PowerShell"
date: 2017-10-23T22:01:50-04:00
draft: false
toc: false
comments: true
categories:
- Windows
tags:
- cmd
- Run Line
- PowerShell
---

Note about the differences between search paths when running stuff via the Windows Run Line (`win+r`), command line and PowerShell.

We can type `iexplore` in Run Line to open up Internet Explorer but doing the same in a cmd or PowerShell is not successful.

**tl;dr**\\
Run Line looks in the following registry location then PATH. Credit Vic Laurie at [commandwindows.com](https://commandwindows.com/runline.htm).

- `HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths`

**Search order**

- cmd searches first in local directory and then in PATH.
- PowerShell searches first in PATH and then in local directory.
- Run Line searches in `App Paths` first.

Usual blabbering and needless digging follows.

<!--more-->

<!-- MarkdownTOC -->

- [Question](#question)
  - [What is PATH?](#what-is-path)
- [Executing in cmd/ps vs. Run Line](#executing-in-cmdps-vs-run-line)
  - [Setup and Tools](#setup-and-tools)
  - [cmd](#cmd)
    - [Note about javapath](#note-about-javapath)
  - [PowerShell](#powershell)
  - [Run Line](#run-line)
    - [What is in App Paths?](#what-is-in-app-paths)
    - [Run Line Search Order](#run-line-search-order)

<!-- /MarkdownTOC -->


<a name="question"></a>
# Question
When running something via the command line (a.k.a. cmd) or PowerShell (ps), Windows will search for the executable in PATH. Type `notepad` or `calc` and they will be executed because both are in `%WINDIR%\System32` which is usually in PATH. Same thing can be done in Run Line.

Now try `iexplore` or `chrome` in Run Line. It works. Do the same in cmd/ps and they cannot find the executable. Something is different. We know both of these search in PATH but Run Line is looking in other places.

<a name="what-is-path"></a>
## What is PATH?
In short it's "a bunch of places Windows will search for things."

View it in cmd:

``` powershell
C:\>echo %PATH%

C:\ProgramData\Oracle\Java\javapath;C:\Python27\;C:\Python27\Scripts;C:\Windows\
system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShe
ll\v1.0\
```

Or in ps:

``` powershell
PS C:\> ls Env:path | Format-List

Name  : Path
Value : %SystemRoot%\system32\WindowsPowerShell\v1.0\;C:\ProgramData\Oracle\Java\javapath;
        C:\Python27\;C:\Python27\Scripts;C:\Windows\system32;
        C:\Windows;C:\Windows\System32\Wbem;
        C:\Windows\System32\WindowsPowerShell\v1.0\

# Make sure to pipe the output to Format-List otherwise it will be truncated
PS C:\> ls Env:path

Name                           Value
----                           -----
Path                           %SystemRoot%\system32\WindowsPowerShell\v1.0\;
                               C:\ProgramData\Oracle\Java\javapath;C:\...
```

Although these are for disposable VMs, I am quite sure I am giving away free intel. But let's move on.

<a name="executing-in-cmdps-vs-run-line"></a>
# Executing in cmd/ps vs. Run Line
A search does not bring any relevant info. I could only find one relevant result from `commandwindows.com` which had the answer.

As an exercise we are going to analyze how these work and where they search.

<a name="setup-and-tools"></a>
## Setup and Tools
Usual setup is a Windows 7 32-bit VM.

Tools are:

- Procmon
- API Monitor

<a name="cmd"></a>
## cmd
1. Start API Monitor and procmon and open a command prompt.
2. In procmon set this filter
    - `Process Name is cmd.exe`
3. In API Monitor clear the filter and only monitor
    - `Data Access and Storage > Local File System > File Management > Kernel32.dll`
4. Type `iexplore` and see the results.

cmd is looking in the current directory `(C:\)` first and then in PATH.

{{< imgcap title="cmd calls in API Monitor" src="/images/2017/runline/01-cmd-api-monitor.png" >}}

{{< imgcap title="cmd calls in procmon" src="/images/2017/runline/02-cmd-procmon.png" >}}

We can see that it searches in current directory first and then in PATH.

<a name="note-about-javapath"></a>
### Note about javapath
`C:\ProgramData\Oracle\Java\javapath` is actually a *junction* or *soft link*  to `C:\ProgramData\Oracle\Java\javapath_target_36229975`. It's like an NTFS *symlink* but not exactly (NTFS junction can only point to local volume while NTFS symlink can point to remote shares). See more at MSDN [Hard Links and Junctions][msdn-junction]. As far as I was able to understand, hard links are for files (local and remote) while junctions are for local directories.

This is different from a shortcut (or lnk). It's an alias. We can cd to `javapath` and Windows will think such a directory exists while we are actually in `javapath_target_36229975`.

``` powershell
C:\ProgramData\Oracle\Java>dir
 Directory of C:\ProgramData\Oracle\Java

10/06/2017  11:16 PM    <DIR>          .
10/06/2017  11:16 PM    <DIR>          ..
10/06/2017  11:16 PM    <DIR>          .oracle_jre_usage
10/06/2017  11:16 PM    <DIR>          installcache
10/06/2017  11:16 PM    <JUNCTION>     javapath [C:\ProgramData\Oracle\Java\java
path_target_36229975]
10/06/2017  11:16 PM    <DIR>          javapath_target_36229975

C:\ProgramData\Oracle\Java>dir javapath
 Directory of C:\ProgramData\Oracle\Java\javapath

10/06/2017  11:16 PM    <DIR>          .
10/06/2017  11:16 PM    <DIR>          ..
10/06/2017  11:16 PM           191,040 java.exe
10/06/2017  11:16 PM           191,552 javaw.exe
10/06/2017  11:16 PM           270,912 javaws.exe

C:\ProgramData\Oracle\Java>dir javapath_target_36229975
 Directory of C:\ProgramData\Oracle\Java\javapath_target_36229975

10/06/2017  11:16 PM    <DIR>          .
10/06/2017  11:16 PM    <DIR>          ..
10/06/2017  11:16 PM           191,040 java.exe
10/06/2017  11:16 PM           191,552 javaw.exe
10/06/2017  11:16 PM           270,912 javaws.exe
```

<a name="powershell"></a>
## PowerShell
Do the same for PowerShell but run API Monitor as admin.

{{< imgcap title="PowerShell calls in API Monitor" src="/images/2017/runline/03-ps-api-monitor.png" >}}

{{< imgcap title="PowerShell calls in procmon" src="/images/2017/runline/04-ps-procmon.png" >}}

PowerShell is using different API calls and also looking for files with specific extensions (ps files and `PATHEXT` env variable).

It's also searching first in PATH and then in current directory.

<a name="run-line"></a>
## Run Line
For Run Line, we will use a different approach to find stuff in procmon.

After we run iexplore in Run Line, open process tree at `Tools > Process Tree (ctrl+t)` in procmon (don't forget to reset the filter). Double clicking on `iexplore.exe` which will take us to the `Process Start` event.

{{< imgcap title="Process Start for iexplore" src="/images/2017/runline/05-run-procmon1.png" >}}

A bit further up we will see the registry key in the tl;dr section.

{{< imgcap title="App Paths in procmon" src="/images/2017/runline/06-run-procmon2.png" >}}

Going up in procmon and watching the results in API Monitor does not show anything about searching path. It seems like Run Line first searches in `App Paths` and then in PATH.

<a name="what-is-in-app-paths"></a>
### What is in App Paths?
Let's look at this so-called registry keys.

{{< imgcap title="App Paths in registry" src="/images/2017/runline/08-app-paths.png" >}}

Each application has a separate key. Inside we can see the default key and a path key for Chrome.

{{< imgcap title="Chrome app paths" src="/images/2017/runline/09-chrome-app-paths.png" >}}

<a name="run-line-search-order"></a>
### Run Line Search Order
Let's test our search order theory by running `java.exe` via Run Line and observing it in procmon.

This time will add a new filter and reduce the noise.

- `Path contains java`

{{< imgcap title="Run Line searching for java.exe" src="/images/2017/runline/10-procmon-java.png" >}}

Note that while we have a `javaws.exe` key in App Paths, there's none for `java.exe`.

See the `REPARSE` results? That's the java *junction* we talked about.

Looks like we were right. Interesting but potentially useless stuff.

<!-- links -->
[SearchPath-link]: https://msdn.microsoft.com/en-us/library/windows/desktop/aa365527(v=vs.85).aspx
[msdn-junction]: https://msdn.microsoft.com/en-us/library/windows/desktop/aa365006(v=vs.85).aspx
