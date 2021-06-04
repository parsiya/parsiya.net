---
title: "No, You Are Not Getting a CVE for That"
date: 2020-07-25T16:21:15-07:00
draft: false
toc: false
comments: true
twitterImage: 01-goodnews.png # ZZZ change this
categories:
- soapbox
---

An intentionally insecure system is insecure. As [Raymond Chen says]
(https://devblogs.microsoft.com/oldnewthing/?p=18593), "You can't make up for
the absence of any actual vulnerability by piling on style points and cranking
up the degree of difficulty."

<!--more-->

Every once in a while I see a vulnerability write-up or disclosure report that
makes me scream internally and not in a good way. Usually, I try to be polite
and act professional. Professional means I will send you this blog post by
Raymond Chen:

* [It rather involved being on the other side of this airtight hatchway][hatchway-original].

[hatchway-original]: https://devblogs.microsoft.com/oldnewthing/20060508-22/?p=31283

The title is from the book [The Hitchhiker's Guide to the Galaxy][hh-wikipedia]
by one of my favorite authors Douglas Adams.

[hh-wikipedia]: https://en.wikipedia.org/wiki/The_Hitchhiker%27s_Guide_to_the_Galaxy

{{< blockquote author="Douglas Adams" source="Hitchhiker's Guide to the Galaxy - Fit The Second" >}}
Arthur: But can't you think of something?!  
Ford: I did.  
Arthur: You did!  
Ford: Unfortunately, it rather involved being on the other side of this airtight hatchway—  
Arthur: oh.  
Ford: —that's just sealed behind us.  
{{< /blockquote >}}

You can find a plethora of these on [Raymond's blog][oldnewthing-search-airtight-hatchway].

[oldnewthing-search-airtight-hatchway]: https://devblogs.microsoft.com/oldnewthing/?s=airtight+hatchway&submit=%EE%9C%A1

These vulnerabilities have one thing in common. In order to exploit them you
need to already be part of the user group that can do that thing. Commonly, you
need to be admin to do admin things. You just need to be on the other side of
the airtight hatchway, first.

{{< imgcap title="Good news, everyone!" src="01-goodnews.png" >}}

Before we continue, let's talk about privilege levels.

# Privilege Levels in a Typical Windows Machine
From low to high we have:

`Remote attacker < Local standard user < Local admin/SYSTEM`[^1].

[^1]: Local admin to/from `NT Authority/SYSTEM` is intended and not a security issue.

{{< blockquote author="Raymond Chen" link="https://devblogs.microsoft.com/oldnewthing/20060508-22/?p=31283" >}}
Code injection doesn't become a security hole until you have elevation of privilege.
{{< /blockquote >}}

The following are not issues:

1. A user can inject code into their own process.
2. A user can inject code into a less-privileged process.

But, this is an issue:

1. A less-privileged user can inject code into a more-privileged process.

This could be a remote attacker running code on the machine or Remote Code
Execution (RCE).

{{< blockquote author="Raymond Chen" link="https://devblogs.microsoft.com/oldnewthing/20060508-22/?p=31283" >}}
If some hacker on the Internet can inject code onto your computer, then they 
have successfully elevated their privileges, because that hacker didn't have
the ability to execute arbitrary code on your machine prior to the exploit.
{{< /blockquote >}}

Or a standard user running code as admin/SYSTEM. This is called "Local Privilege
Escalation."

# Non-issues
Here's some common non-issues that are hyped with style points.

Style points are fancy ways of doing something common. In the context of this
blog style points are all the extra steps to get code execution on a machine
when you already have code execution on a machine at that privilege level.

{{< blockquote author="Raymond Chen" link="https://devblogs.microsoft.com/oldnewthing/?p=18593" >}}
You just found a complicated way of doing something perfectly mundane. You can't
make up for the absence of any actual vulnerability by piling on style points
and cranking up the degree of difficulty.
{{< /blockquote >}}

## Unquoted Service Paths
Reading assignment:

* https://docs.microsoft.com/en-us/archive/blogs/aaron_margosis/it-rather-involved-being-on-the-other-side-of-this-airtight-hatchway-unquoted-service-paths

**Unquoted Service Paths are almost never exploitable.** Standard users do not
have access to create files in the root of the `C` drive. This means you cannot
make `C:\program.exe`. Standard users have no write access inside `C:\Program
Files` or the 32-bit counterpart, either.

But what if you installed it on a flash drive and with no access restrictions?
Well, don't. The user could install the app in a location and then change the
ACLs. It's a minor issue and you are not getting a CVE for that.

{{< blockquote author="Parsia" link="https://twitter.com/CryptoGangsta/status/1279242524100407297" >}}
'unquoted service path' is the clickjacking of thickclient vulnerabilities.
{{< /blockquote >}}

Yes, I just quoted myself, lol.

**Update 2021-06-03:** I was proven wrong. Someone actually [got a CVE for
that][CVE-2020-15261]. Not dissing the finder, but this is not a vulnerability.

[CVE-2020-15261]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-15261

> On Windows the Veyon Service contains an unquoted service path vulnerability,
> allowing locally authenticated users with administrative privileges to run
> malicious executables with LocalSystem privileges.

Local admin to SYSTEM is intended. 

## DLL Hijacking
Reading assignment:

* https://itm4n.github.io/windows-dll-hijacking-clarified/

In simple words means the OS will search for a missing DLL in certain paths. You
might be able to plant your own malicious DLL in one of those and get code
execution.

A [good chunk of DLL Hijacking CVEs][dll-python] happen when there's a DLL
missing and people use `C:\python27` to plant their DLL. Well, no shit. I bet
the overwhelming majority of Windows users do not have that directory, I don't
and I am a power user. I don't have Python on my host OS.

[dll-python]: https://www.bing.com/search?q=%22C%3A%5Cpython27%22+DLL+hijacking

**Always test in a clean install.** If you have to intentionally weaken the OS
then it's not a security issue.

{{< blockquote author="Raymond Chen" link="https://devblogs.microsoft.com/oldnewthing/20180227-00/?p=98115" >}}
An insecure system is insecure.
{{< /blockquote >}}

### The .Local File
The `.local` file can be used to [mitigate DLL hell][dot-local]. If you have
`whatever.exe.local` then `whatever.exe` will look in the current directory for
DLLs first and then somewhere else.

[dot-local]: https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-redirection

A common explanation is putting the `.local` file by the executable. If you have
write access to that directory? **Why can't you just edit the executable?**

`.local` files also come up in the context of installers:

1. Make users download the `.local` file and a malicious DLL.
    1. These get stored in the downloads directory.
2. Users download the installer for an application.
3. When the user starts the installer it will load your DLL and run your code.

Why do all of this when you can:

1. Make users download a malicious installer.
2. When they run it, your code is executed.

## Overwriting Admin Only Writable Item
This was covered briefly in the DLL hijacking section. If you can modify a
binary that is executed or loaded as SYSTEM then you can be SYSTEM. But if only
admins can modify it then you have accomplished nothing.

Here's a blog by Raymond where he talks about a reported issue. Planting DLLs
in `System32` to get DLL hijacking can only be done by admins. So, no CVE.

* https://devblogs.microsoft.com/oldnewthing/20131023-00/?p=2853

Note: This is completely different if you manage to exploit a (usually logical)
bug where you can trick a higher privileged process into overwriting a file
there. This usually happens with symlink and Windows services.

## Content Injection on 404 Pages
This is a web application thing. 404 pages are usually very bland. Sometimes
they include the missing page. Something along the lines of:

> Page X could not be found. Please contact the site administrator.

There are a few web servers with 404 templates that do this. I have seen a ton
of reports where the proof of concept has been:

1. Navigate to `whatever.com/[bunch of spaces here]website not found, go to evil.com`.
2. Observe the injected content.

Usually the spaces are ignored and it looks like.

> Page website not found, go to evil.com could not be found. Please contact the site administrator.

This is not a security issue. The `evil.com` is almost never a link. This means
the user has to manually enter `evil.com` in their browser. In other words, it's
much easier to create a link to `evil.com` with the caption `example.net` and
spray internet forums with it.

Google specifically excludes this:

* https://sites.google.com/site/bughunteruniversity/nonvuln/limited-content-reflection-or-content-spoofing

## Adding "Account Takeover" to the End of Vulnerability Title
I have read reports with `Clickjacking to Account Takeover` where the only thing
in the report was the OWASP test page. It only shows that you can load the page
in an iframe. Clickjacking without a proof of concept is not an issue. What can
you do with it?

I blame bugbounty influencers for this. There are entire guides on how to hype
up your bug to get better payouts. I am all for people making money. Hell, **I
encourage you to milk the companies as much as you can while the fad
continues.** But, please do not try to trick me or other security engineers.

# What Did We Learn Here Today?

0. Only report actual security issues.
1. Adding extra style points does not work.
2. CVE is a shitty way of measuring your success.
3. We both know what we are doing, please don't try to trick me. I am on your
   side.
