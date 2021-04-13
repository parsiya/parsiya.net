---
title: "Attack Surface Analysis - Part 1 - Application Update:\n'A Novel Way to Bypass Executable Signature Checks with Electron'"
date: 2021-01-08T22:33:32-08:00
draft: false
toc: true
comments: true
twitterImage: 13-cmd.png
categories:
- Electron
- Attack Surface Analysis
- Bug Bounty
aliases:
- "/blog/2021-01-08-a-novel-way-to-bypass-executable-signature-checks-with-electron/"
---

A few months ago I found a way to subvert the update process of an Electron
application to get local privilege escalation. The application stores the
updater under a path where standard users have write access. But, it also
checked if the executable was signed by the vendor. I managed to bypass the
signing using a backdoored Electron application.

<!--more-->

# Light Attack Surface Analysis
After reading this section you should have a pretty good idea of how to attack
the update process of a Windows application. I have not been to find such a
section anywhere else ;).

## What is Privilege Escalation?
In short, you want to go from one of these levels to the next:

1. Remote attacker
2. Local attacker running as a standard user
3. Local admin/SYSTEM

Note: This is intentionally ignoring domain-connected machines and their attack
surfaces.

Moving from one level to the next is a privilege escalation.

{{< blockquote author="Raymond Chen" link="https://devblogs.microsoft.com/oldnewthing/20060508-22/?p=31283" >}}
Code injection doesn't become a security hole until you have elevation of privilege.
{{< /blockquote >}}

## From Update to Privilege Escalation
The update process is usually a good way to gain local privilege. Application
updates on Windows usually need local admin (run as elevated) or SYSTEM (run via
a Windows service or scheduled task) access. They usually need to modify files
under the two `C:\Program Files` directories and these paths are not writable by
standard users.

### Spoofing The Server
If a remote attacker can spoof a server and taint the update binary then they
can go from a remote attacker to local or even SYSTEM.

Most often, this is not in scope for the few bounty programs with desktop
applications in scope. Also, TLS certificates do a good job of preventing such
attacks. But, if you can mess with the certificate checks then you might have a
case.

#### Nintendo
Let's skim through this report in Nintendo's bug bounty program.

* https://hackerone.com/reports/894922

The signature verification in 3DS is bypassed. This allows an attacker to
successfully sit between the console and the internet. For consoles this is
usually a feasible attack surface because the objective is to get root on them.

The next two reports take advantage of this attack vector and inject data into
the console's transmissions to achieve Remote Code Execution.
      
* https://hackerone.com/reports/897606
* https://hackerone.com/reports/895769

If we have such a bug in a desktop application we can spoof the server and taint
the update binary.

#### Backblaze #1 - CVE-2020-8289
Another example is by [Jason Geffner][jason-twitter]. Jason is my former boss at
Electronic Arts and an all-around awesome guy.

* https://github.com/geffner/CVE-2020-8289

The application disabled certificate checks if the URL had some specific strings
in it like `api/clientversion.xml`. The attacker could MitM the connection and
bypass the certificate check because the update URL had the string above. Then,
they could send their own tainted update binary to be executed as SYSTEM.

[jason-twitter]: https://twitter.com/JasonGeffner

#### My Undisclosed Bug #1 - Updates Downloaded Over HTTP
This is a bug I reported on HackerOne on April 24th, 2020 (around 9 months ago)
and is still open (no bounty awarded, either).

A Java application used [getdown][getdown] to download its update over HTTP.
With HTTP, I could MitM the connection without any issues.

{{< imgcap title="Updates downloaded over HTTP" src="01-update-http.png" >}}

Before downloading the actual files, `getdown` downloads a file named
`digest.txt`. This file has the hashes of the incoming update files. The hash in
this case was `MD5` (newer versions use `SHA-256`) but it did not really matter.
The digest file was also downloaded over HTTP and could be replaced, too.

I created a fake Python HTTP server to act as my spoofed server. I created my
own digest and a backdoored jar. The jar was a Swing application that only
displayed a JFrame. You can see the code at:

* https://github.com/parsiya/EvilSwing

[getdown]: https://github.com/threerings/getdown

### Swapping The Update File
Sometimes, the update file is written to a path where a standard user has write
access and then executed (usually by a Windows service).

The usual suspects for such path are:

* Paths under `%ProgramData%` (usually `C:\ProgramData`).
* Paths under `%APPDATA%`
* Predictable paths under `%TEMP%`

In these cases, we might be able to get LPE by overwriting the file with our
binary and then wait for the updater service to run it.

To avoid this, the applications check the signature of the binary (sometimes the
hash of the binary) or change the DACL of the path where it's stored to prevent
users from modifying it. The binary is executed only if the check passes.

As an attacker, you might be able to take advantage of a
`Time Of Check to Time of Use (TOCTOU)` vulnerability and exploit a race
condition to replace the binary after the check but before execution.

#### Backblaze #2 - CVE-2020-8290
Here's another bug by Jason in Backblaze.

* https://github.com/geffner/CVE-2020-8290

The updater which was a Windows service, created a directory to store the update
binary at `%ProgramData%\Backblaze\bzdata\bzupdates` if the path did not exist.
The DACL of the directory did not give standard users write access. But, the
updater did not check if the directory was already created and would store the
updater there without changing its permissions. Hence, a local attacker could
create this directory and then replace the updater after download before
execution.

In a typical bug like this we are racing against the service that executes the
downloaded file. The way to win these races is often through OpLocks. This is
usually pretty easy with the [SetOpLock][setoplock] utility in the great
[symboliclink-testing-tools][symboliclink-testing-tools] suite by
[James Forshaw][james-twitter].

[symboliclink-testing-tools]: https://github.com/googleprojectzero/symboliclink-testing-tools
[setoplock]: https://github.com/googleprojectzero/symboliclink-testing-tools/blob/master/SetOpLock/SetOpLock_ReadMe.txt
[james-twitter]: https://twitter.com/tiraniddo

#### My Undisclosed Bug #2 - Installer Modified The Program Directory ACL
This second bug was reported on April 23rd, 2020 (around 9 months ago) and is
still open with no bounty, again (see a pattern?).

**Update April 13th, 2021**: This bug has finally been closed. The application
was retired and I got some money.

![](15-bounty-bad-dacl.png)

It's a bug in the same application as undisclosed bug #1. The installer changed
the DACL of the entire application directory under `C:\Program Files\app\`. The
new DACL gave write access to standard users.

{{< imgcap title="Standard users have fullcontrol on the app directory" src="02-acl.png" >}}

I think the reason was seamless updates from userland without the need for a
Window service or UAC prompts. Usually, applications that want these kind of
updates are stored under `%APPDATA%` (e.g., VS Code).

I modified the uninstaller (which always ran elevated). A local attacker could
swap the binary with a backdoored executable and then wait for or convince an
admin to run the uninstaller elevated.

# The Main Dish
Now, we have a pretty good idea of how to get LPE through automatic updates.
Let's talk about my last bug. I sat on the bug for six months because I was lazy
(see a pattern here? lol) and then reported it recently. It's still in review
and I doubt it will get disclosed.

## Named Pipe
The application uses a Windows service to do updates. The service talks to the
userland application using a [named pipe][namedpipe].

Named pipe is another great attack surface. I want to write a similar blog post
about them later but for now you can read these great series of posts by
[Robert Hawes][robert-twitter] on the Versprite blog:

1. [Part I: The Fundamentals of Windows Named Pipes][pipe-1]
2. [Part II: Analysis of a Vulnerable Microsoft Windows Named Pipe Application][pipe-2]
3. [Part 3: Reversing & Exploiting Custom Windows Named Pipe Servers][pipe-3]
4. [Part 4: Windows Named Pipes Part 4: Taking a Trip Down Static Analysis Lane][pipe-4]

[namedpipe]: https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipes
[robert-twitter]: https://twitter.com/HawesRT
[pipe-1]: https://versprite.com/blog/security-research/microsoft-windows-pipes-intro/
[pipe-2]: https://versprite.com/blog/security-research/vulnerable-named-pipe-application/
[pipe-3]: https://versprite.com/blog/security-research/reverse-exploit-custom-windows-named-pipe-servers/
[pipe-4]: https://versprite.com/blog/security-research/windows-named-pipes-static-analysis-exploitation/

This named pipe has a (fortunately) json-based protocol. The pipe is named
`george` (lol).

{{< imgcap title="George" src="03-george.png" >}}

Everyone can open a pipe and talk to the updater service. This is not a
vulnerability by itself. So don't go reporting pipe permissions nilly willy.

{{< imgcap title="George likes everyone" src="04-george-acl.png" >}}

I used `github.com/microsoft/go-winio` to create a Go client. By sending
specific messages to the service I could check for an update, download it and
then run it. Unfortunately, I could only tell the service perform an action but
not how to do it. E.g., I could not specify the download URL, where to download
the file, or which file to execute.

## Storage Path
To observe the update process on Windows, your best tool is Process Monitor or
procmon. It's probably my favorite tool. You can run the updater process and see
where the file is downloaded and executed.

I did not need to use OpLocks because I could initiate the download and
execution events individually. In other words, I could tell the installer to
just download the update and nothing else. This gave me ample time to swap the
binary.

{{< imgcap title="Downloaded file" src="05-downloaded-file.png" >}}

We can see the update is downloaded to
`C:\ProgramData\[redacted]\Updates\GUID.exe`. As we have seen before, by default,
standard users have write access here and this was not an exception.

```
$ accesschk c:\ProgramData\[redacted]

c:\ProgramData\[redacted]\Updates
  RW BUILTIN\Users   <---- WE HAVE RW ACCESS
  RW NT AUTHORITY\SYSTEM
  RW BUILTIN\Administrators
```

By now, you are thinking of pulling a "Jason's second bug" to overwrite the
downloaded file. This is what I did but the installer did not execute the file.

## Signature Check
Looking at procmon, I located the events where the file is accessed.

{{< imgcap title="File access event in procmon" src="06-procmon-events.png" >}}

Procmon has a very useful feature where we can see the call stack of each event
(usually). All highlighted events above had a similar stack.

{{< imgcap title="Call stack in Procmon" src="07-procmon-stack.png" >}}

Note the `WinVerifyTrust` calls. They are usually called to check the signature
of a file. At first, I  thought I need to pass any signed file. There are some
[signed Windows binaries that can be used to run arbitrary commands][lolbas].
This is often used by red teams to evade detection.

[lolbas]: https://github.com/LOLBAS-Project/LOLBAS#criteria

My first try was swapping the file with a signed binary like `taskmgr.exe`. It
not work. Seemed like the updater was looking for a specific signature and not
just any valid one.

I hooked `WinVerifyTrust` in API Monitor and ran the original updater to see
the APIs arguments.

{{< imgcap title="WinVerifyTrust in API Monitor" src="08-api-monitor.png" >}}

Looking at the [WinVerifyTrust MSDN page][winverifytrust-msdn] we can see that
the GUID (`00aac56b-cd44-11d0-8cc2-00c04fc295ee`) is for
`WINTRUST_ACTION_GENERIC_VERIFY_V2` which is the typical authenticode check. In
other words, it's checking the certificate. For the original updater, the return
value of our calls is `S_OK` or `0` which means it has a valid signature.

[winverifytrust-msdn]: https://docs.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust

I dropped the executable in IDA and searched for `WinVerifyTrust`. After some
analysis, I landed at the following location. There are two calls to
`WinVerifyTrust` around a call to `sub_100550`. After more dynamic analysis, I
discovered the subroutine checks the Common Name (CN) of the certificate against
`vendor`. This means the updater is looking for a binary file signed by the
vendor. You had already guessed it by now.

{{< imgcap title="Signatute checks in IDA" src="09-check-in-ida.png" >}}

It does three checks on each file:

1. Signature check.
2. Check if CN is `vendor`.
3. Signature check (again).

Why are there two authenticode checks? Most likely, to prevent TOCTOU race
conditions.

# Using Electron to Bypass Signature Checks
At this point, I was back to square one. I needed a binary that was signed by
the vendor and allowed me to run arbitrary code. Binary modification does not
work because it invalidates the signature.

That's when I realized I already have such a binary and it can run arbitrary
code. The original app was an Electron app and the executable was signed by the
`vendor`.

## Enter Electron
A typical Electron app on Windows comes with a bunch of executables. I cannot
use the actual app so let's look at another Electron app named Discord. Almost
everything in the app directory is part of the Electron framework and not
application code.

{{< imgcap title="Discord's application directory" src="10-discord-files.png" >}}

The executable is `Discord.exe` which is signed by `Discord Inc.`. In my target
application, it was signed by `vendor`.

{{< imgcap title="Discord executable's signature" src="11-discord-sig.png" >}}

The actual code of the Electron application is usually in `resources\app.asar`.
The asar container is unsigned. It's just a bunch of data and the format does
not support signing. TWe can modify it and the signed binary `Discord.exe` will
run our modified code.

For my proof of concept, I created a backdoored Electron application:

* https://github.com/parsiya/evil-electron/

All it does is spawn a command prompt using `preload.js`.

```js
// Spawn a command prompt.
require('child_process').exec('start cmd.exe');
```

The built `app.asar` file is at 
https://github.com/parsiya/evil-electron/tree/master/release.

{{< imgcap title="It took me a while to figure out the payload" src="12-backdoored-app.png" >}}

The idea of backdooring an Electron app is not really new. After writing this
blog, I discovered a blog post by [Pavel Tsakalidis][pavel-twitter] from January
2019 (almost two years ago):

* [Basic Electron Framework Exploitation][pavel-blog]

The title of the web page says `How To Backdoor Any Electron Application` which
appears to have been the original title of the blog.

Most of the blog talks about backdooring the `resources\electron.asar` file
which is not present in many modern Electron applications anymore. But, the
concept is sound. We can modify asar files and backdoor them. This blog, while
nice, is more of a red team persistence trick and not signature evasion like
what we want to do.

[pavel-twitter]: https://twitter.com/sadreck
[pavel-blog]: https://www.contextis.com/en/blog/basic-electron-framework-exploitation

## Recap

1. The application's updater service downloads the update and stores it in
   `C:\ProgramData\[redacted]\GUID.exe`.
2. Standard users have write access to this path.
3. The updater service checks the signature of the file before executing it.
4. The file should have a valid signature and it must be signed by `vendor`.
5. The bundled Electron app is signed by `vendor` and we can backdoor it.

## Steps to Reproduce

1. Tell the service to download the update (via the named pipe).
2. Copy everything inside `C:\Program Files (x86)\vendor\electron-app\` to
   `C:\ProgramData\[redacted]\Updates` (where the update is downloaded).
3. Delete the downloaded installer but copy its filename (`GUID.exe`).
4. Rename `electron-app.exe` to the name of the downloaded installer (`GUID.exe`).
5. Replace the `resources\app.asar` file in the destination with my own
   backdoored file.
6. Tell the Windows service to run the installer.
7. Command prompt spawned as SYSTEM.

{{< imgcap title="cmd as SYSTEM" src="13-cmd.png" >}}

I got 200 USD for the bug. Financially, not worth the time spent but, I learned
a new trick. Although, it would have been completely different if I were living
in a cheap country with low taxes.

{{< imgcap title="Bounty" src="14-bounty.png" >}}

# What Did We Learn Here Today?

1. Attack surface analysis of application update mechanisms on Windows.
2. How to take advantage of the above.
3. Reviewed a bunch of bugs to learn a variety of exploitation techniques.
4. Learned a 'novel' way of bypassing signature checks using Electron
   applications.
