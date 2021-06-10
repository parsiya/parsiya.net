---
title: "The JavaScript Bridge in Modern Desktop Applications"
date: 2021-06-08T00:53:25-07:00
draft: false
toc: true
comments: true
twitterImage: 05-XSS-5.png
categories:
- Attack Surface Analysis
---

We have an XSS in a desktop application, what happens next? How can you
escalate it to remote code execution? Let's see.

<!--more-->

Modern desktop applications are mostly[^1] based on [Chromium][chromium-link].
There are three major frameworks:

* [Electron][electronjs.org]: The most popular one.
* [Chromium Embedded Framework][cef-link].
* [QtWebEngine][qtwebengine-link]: A part of the Qt framework (pronounced like `cute`).

[chromium-link]: https://www.chromium.org/Home
[^1]: I say almost because I might be missing some but I have never seen desktop apps based on another browser.

There also some miscellaneous frameworks like [NW.js][nwjs.io]. I have only seen
a single commercial app using this framework and it was six years ago when I was
still doing consulting at good ole' Cigital.

[electronjs.org]: https://www.electronjs.org/
[cef-link]: https://bitbucket.org/chromiumembedded/cef/src
[qtwebengine-link]: https://wiki.qt.io/QtWebEngine
[nwjs.io]: https://nwjs.io/wh

# What's The JavaScript Bridge?
There are two kinds of browser-based desktop applications:

1. Just displays a website in Electron, e.g., Trello.
2. Also interacts with the machine, e.g., Steam.

The JavaScript bridge is a set of APIs that allow the web content in the
application to interact with the host machine. In Steam (based on CEF), you
click on the install button on a web page displayed in the app and a game gets
installed on your machine. The web page button calls some JavaScript and
eventually it uses the JavaScript bridge to do stuff on the machine.

# Why is The JavaScript Bridge Important?
Rogue JavaScript (e.g., via XSS) can use it to jump the browser sandbox and do
bad things to the underlying machine.

{{< blockquote author="Parsia" source="2 am thought while playing Anthem" >}}
XSS Happens (lol)
{{< /blockquote >}}

"But, I am not gonna have XSS, Parsia." You will, my friend. Even if you do
everything right, you might get hit by a
[framework bypass][angularjs-sandbox-escape].

[angularjs-sandbox-escape]: https://portswigger.net/research/dom-based-angularjs-sandbox-escapes

# Examples
As is tradition, we're gonna review public bugs. That's how I learn.

## Razer Comms - CEF
Years ago (probably around 2015), I looked at [Razer Comms][razer-comms-link].
Think of it as the precursor to Discord. Razer Comms was a CEF app and I managed
to get a few trivial XSS instances there.

[razer-comms-link]: https://mysupport.razer.com/app/answers/detail/a_id/3756/

Not knowing what to do next, the best I could do was show a prompt to phish
user's passwords. Now, I wish I had explored the JavaScript bridge to see what
else I could have done.

{{< imgcap title="Is this the best I could do?" src="05-XSS-5.png" >}}

I never disclosed them and published a post after it was retired:

* {{< xref path="/post/2017/2017-09-21-razercomms.markdown" >}}

## Origin XSS to RCE - QtWebEngine
Disclosure: I work for EA and Origin is one of our products.

I have used [this bug][origin-xss-1] numerous times. There are a few reasons:

1. It's a cool bug.
2. It's one of the few public Origin bugs I can talk about.
3. I know Origin like the back of my hand (at least I think so).

XSS happened because of an AngularJS sandbox bypass. This is one of those
situations when you can do everything correctly but get hit. We see a typical
`alert`.

[origin-xss-1]: https://zero.lol/posts/2019-05-13-xss-to-rce/

But, the last section named [The Third Bug (RCE)][origin-xss-js-bridge] explores
the JavaScript bridge. Origin is using the QtWebEngine to display web pages and
the `Origin.client.desktopServices` API is available. The weapon of choice is
`asyncOpenUrl` which allows us to pass a scheme (including `file:///` to execute
files) but, no parameters.

[origin-xss-js-bridge]: https://zero.lol/posts/2019-05-13-xss-to-rce/#the-third-bug--rce

## Overwolf XSS to RCE - CEF
This is a new one by [Joel Noguera][joel-twitter] of
[SwordBytes Security][swbytes-twitter]. You should read it:

* [https://swordbytes.com/blog/security-advisory-overwolf-1-click-remote-code-execution-cve-2021-33501/][overwolf-xss-rce]

[joel-twitter]: https://twitter.com/niemand_sec
[swbytes-twitter]: https://twitter.com/SwordBytesSec
[overwolf-xss-rce]: https://swordbytes.com/blog/security-advisory-overwolf-1-click-remote-code-execution-cve-2021-33501/

I am not gonna go through the blog post but, here's a summary (quoting myself
again lol):

{{< blockquote author="Parsia" link="https://twitter.com/CryptoGangsta/status/1399421900565090307" >}}
CEF App -> Protocol Handler -> Send request -> Response has XSS ->
XSS calls JavaScript bridge API -> Write file with API -> Execute file with API
{{< /blockquote >}}

Let's focus on the `Escaping the CEF sandbox` section. The Overwolf JavaScript
bridge provides a [openUrlInDefaultBrowser(url)][openurl-overwolf] which is
similar to what we have seen before. We can open URL/file or execute files
without parameters.

[openurl-overwolf]: https://overwolf.github.io/docs/api/overwolf-utils#openurlindefaultbrowserurl

But, there's also [writeFileContents][writefile-overwolf] which allows writing a
file to disk. The rest of the path is clear, write a bat file (or an HTA file if
you feel fancy) and then execute it with the previous API.

[writefile-overwolf]: https://overwolf.github.io/docs/api/overwolf-io#writefilecontentsfilepath-content-encoding-triggeruacifrequired-callback

## Electron - Not Again!
I have purposefully not talked about Electron in this post. Electron has the
ultimate JavaScript bridge with `nodeIntegration`. I have talked about it a lot.
Even, when it's disabled, [RCE happens][discord-rce] (this is a great writeup,
btw). With the Electron defaults becoming more secure, we need to start using
the techniques in this blog.

[discord-rce]: https://mksben.l0.cm/2020/10/discord-desktop-rce.html

Here's a ton of examples (including two of mine):

* [https://github.com/doyensec/awesome-electronjs-hacking][awesome-electronjs]

[awesome-electronjs]: https://github.com/doyensec/awesome-electronjs-hacking

# What Did We Learn Here Today?
XSS happens. After you get XSS in a modern desktop app, start poking the
JavaScript bridge to jump out of the Chromium sandbox.
