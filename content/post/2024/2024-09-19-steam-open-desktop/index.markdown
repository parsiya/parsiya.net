---
title: "Steam's 'Open in Desktop' Button"
date: 2024-09-19T19:45:53-07:00
draft: false
toc: true
comments: true
url: /blog/steam-open-desktop/
twitterImage: 01.png
categories:
- Attack Surface Analysis
---

This is not a bug, but some notes about the new Steam "Open in Desktop" button.
I am going to show how to look for bugs in these kinds of browser-to-desktop
interactions.

<!--more-->

When you go to a game's Steam page in the browser, you get this button.

![Game page](01.png)

Clicking on it, will open the game page in the Steam desktop app.

Every time you see a web to app transition without any user notification, a
security control has been circumvented. Whether this is good or bad is not the
objective here.

# Summary: How does it Work?

1. WebSocket connection from the web page to the Steam desktop app at `localhost:27060`.
2. Web page passes a message like this to the desktop app.
   ```json
    {
      "message": "OpenSteamURL",
      "url": "steam://openurl/https://store.steampowered.com/app/1517290/Battlefield_2042/?utm_bid=3546095213808494257",
      // removed
    }
   ```
3. Steam desktop opens the page URL.

# How Can I Also See It?
There are only a few ways to bypass those browser security controls and it's
almost always a WebSocket.

1. Go to the BF 2042 page at https://store.steampowered.com/app/1517290/Battlefield_2042/.
2. `F12` to open Developer Tools (I assume you're using a Chromium based browser).
    1. Edge annoyingly asks if you actually want to open DevTools. Check the box so it doesn't ask again.
3. Switch to the `Network` tab.
4. `ctrl + F5` to refresh the page.
5. Click on `Open in Desktop`. Switch back to Dev Tools.
6. There will be a bunch of junk here that we have to sift through.
    1. Optionally, you could use Burp and filter these in `HTTP Proxy`.
7. Click on the `Status` column to sort by the response status code.
8. See this `101` on top? That's what we want.

![WebSocket handshake](02.png)

It's even conveniently named `openindesktopclient.js`. Click on it to see the
header, request, response, and messages.

![WebSocket handshake](03.png)

[101][101-mdn] is the response code for switching protocols. While the
[Protocol upgrade mechanism][upgrade-mdn] is technically protocol agnostic, I
have only seen it in WebSocket connections. Upon further searching, it looks
like it can also be used to upgrade an [HTTP/1.1 connection to HTTP/2][http-upgrade].

[101-mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/101
[upgrade-mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Protocol_upgrade_mechanism
[http-upgrade]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Upgrade

## I Wanna See the WebSocket Messages
You can click on the `Message` tab in the previous image or go the `Network` tab
of DevTools Click `WS`. You can even filter messages by connection (which is
supposedly useful if you have multiple ones in the same page which I've never
seen).

![WebSocket Messages](04.png)

The 3rd message is the one that opens the page.

```json
{
  "message": "OpenSteamURL",
  "url": "steam://openurl/https://store.steampowered.com/app/1517290/Battlefield_2042/?utm_bid=3546095213808494257",
  "universe": 1,
  "accountid": 0,
  "sequenceid": 2
}
```

If you want to see which process is doing this, run `netstat -anb` in an admin
prompt and look for who is listening on `127.0.0.1:27060`. It's `steam.exe`.

## Protocol Handlers
This is actually the Steam protocol handler. And that can also lead to
{{< xref path="/post/2021/2021-03-17-attack-surface-analysis-2-custom-uri/"
    text="a bunch of RCEs." >}}

1. Close Steam. As in right-click on the taskbar icon and select `Exit Steam`.
2. Run [Process Monitor][procmon].
3. Press `F12` to open DevTools for this page and select the `Console` tab.
4. Click on this link. Hover you mouse over it to see the actual link matches the caption.
    1. [steam://openurl/https://store.steampowered.com/app/1517290/Battlefield_2042/][bf2042-protocol].
5. See the browser pop-up that asks if you want to open Steam.
6. If you click on `Open Steam`, Steam desktop will open and navigate the BF 2042 page.

[procmon]: https://learn.microsoft.com/en-us/sysinternals/downloads/procmon
[bf2042-protocol]: steam://openurl/https://store.steampowered.com/app/1517290/Battlefield_2042/

You can see the protocol handler in the `Console` tab of DevTools.

![Protocol handler in the Console tab](05.png)

Steam is actually executed with this protocol handler as the parameter. Switch
to Procmon and press `ctrl + t` or `Tools (menu) > Process Tree`. Procmon is
cutting off the complete parameter in the screenshot.

![Steam launched in Procmon](06.png)

This blog is just trying to show where to look for these things. If you want to
learn more please start with the following links:

1. [Eric Lawrence's][eric-twitter] (he also wrote Fiddler) excellent blog: [Web-to-App Communication: App Protocols][eric-protocol].
2. {{< xref path="/post/2021/2021-03-17-attack-surface-analysis-2-custom-uri/"
    text="a Attack Surface Analysis - Part 2 - Custom Protocol Handlers" >}}.

[eric-protocol]: https://textslashplain.com/2019/08/29/web-to-app-communication-app-protocols/
[eric-twitter]: https://twitter.com/ericlaw

## Why Use a WebSocket?
A WebSocket is the most common way to bypass the annoying protocol handler dialog
because **{{< xref path="/post/2020/2020-11-01-same-origin-gone-wild/"
    anchor="websockets-are-not-bound-by-the-sop"
    text="it's not bound by the Same Origin Policy" >}}**.

[websocket-sop]: https://blog.securityevaluators.com/websockets-not-bound-by-cors-does-this-mean-2e7819374acc

It's not always a WebSocket server. Here's a bug by [Jonathan Leitschuh][jl-twitter]
where it turns out [Zoom was using a local web server][zoom] (that even remained
on the machine after removing Zoom) to do "seamless transition."

[zoom]: https://infosecwriteups.com/zoom-zero-day-4-million-webcams-maybe-an-rce-just-get-them-to-visit-your-website-ac75c83f4ef5
[jl-twitter]: https://twitter.com/JLLeitschuh

# So How do I Find Bugs Here?
The moment you see a local web server or WebSocket server, you need to open Burp
and **change the `Origin` header**.

1. Go to the website in Burp.
2. Select the WebSocket handshake request (the one with the `101` response header).
3. Send to Repeater. Hint: `ctrl + r` thanks to [Agarri's Burp course][agarri-course].
4. Switch to Repeater. Hint: `ctrl + shift + r`.
5. Change the `Origin` header to something else like `https://example.net`.
6. ???
7. Click send.

[agarri-course]: https://hackademy.agarri.fr/syllabus

If this goes through then you have a bug. You can connect to the local WebSocket
server from any website and send requests.

But in this case, we cannot. Fiddle with the `Origin` header and see what is
accepted. It's only `https://store.steampowered.com` and not even other subdomains.

![Fiddling with the Origin header](07.png)

This means it's not vulnerable (at least from this attack surface). This issue is so common that is even has its own specific CWE: [CWE-1385: Missing Origin Validation in WebSockets][cwe-1385].

[cwe-1385]: https://cwe.mitre.org/data/definitions/1385.html

Note the browser sets the `Origin` header and it cannot be modified by
JavaScript because it's a [Forbidden Header][forbidden].

[forbidden]: https://developer.mozilla.org/en-US/docs/Glossary/Forbidden_header_name

**But what if I have a malicious local app?** If you're running a local app that
wants to spoof the `Origin` header then you have bigger problems.

**But muh persistence tradecraft!** lol, shut up!

There are other way to do web-to-app communication apart from protocol handlers
and WebSockets. See [Browser Architecture: Web-to-App Communication Overview][web-to-app]

[web-to-app]: https://textslashplain.com/2019/08/28/browser-architecture-web-to-app-communication-overview/

## How about You Show Us Some Actual Bugs!
Here are a bunch of references:

1. [Websites Can Run Arbitrary Code on Machines Running the ‘PlayStation Now’ Application][psnow].
    1. The images were not disclosed the report, but the H1 report starts from scratch and shows how to find an RCE in a local WebSocket server.
2. {{< xref path="/post/2021/2021-12-20-vscode-wsl-rce/"
    text="CVE-2021-43907 - Remote Code Execution in Visual Studio Code's Remote WSL Extension" >}}
    1. This is basically the same bug as before.
    2. See me and a bunch of people from [HackerNews][websocket-sop] complain about MSRC.
3. {{< xref path="/post/2020/2020-08-13-localghost-dc28-appsec-village/"
    text="localghost: Escaping the Browser Sandbox Without 0-Days" >}}
4. Tavis Ormandy found a similar issue in [Logitech Options][logi]
5. [Full Steam Ahead: Remotely Executing Code in Modern Desktop Application Architectures][full] by [Thomas Shadwell][thomas-twitter] in Infiltrate 2019.

Obviously, there's more, but I am le tired. Thanks for reading and you
know where to find me.

[psnow]: https://hackerone.com/reports/873614
[wsl-rce-hackernews]: https://news.ycombinator.com/item?id=29635300
[logi]: https://project-zero.issues.chromium.org/issues/42450729
[full]: https://vimeo.com/335206831
[thomas-twitter]: https://twitter.com/zemnmez