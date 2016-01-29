---
categories:
- Hipchat
- Proxying
- Burp
comments: true
date: 2015-10-09T22:34:37Z
title: 'Proxying Hipchat Part 2: So You Think You Can Use Burp?'
---

In [**part1**]({% post_url 2015-10-08-hipchat-part-1-where-did-the-traffic-go >}} "Proxying Hipchat Part 1: Where did the Traffic Go?") I talked about identifying Hipchat endpoints and promised to discuss proxying the application. In this post I will show how to proxy *some* of Hipchat’s traffic using Burp.

This is specific to Hipchat client for Windows. The current version at the time of writing was is **2.2.1361**. Atlassian is skipping version 3 and version 4 still in beta.

<!--more-->

### 1. EZ-Mode Proxy Settings
To see the proxy settings, log off and select Configure Connection. Note that in the most recent version (2.2.1395) this added to the settings menu inside the application and there is no need to logoff.

{{< imgcap src="" caption="" /images/2015/hipchat2/01-Hipchat-login-screen.png Hipchat login screen >}}

Yay for proxy settings. So you think you can use Burp? It’s not going to be that easy, otherwise why would I been writing this?

My Burp proxy is listening on `127.0.0.1:8080` so I will add it as proxy.

{{< imgcap src="" caption="" /images/2015/hipchat2/02-Hipchat-proxy-settings.png Hipchat proxy settings >}}

You can also enable proxy settings by modifying the `%appdata%\Atlassian\Hipchat.ini` file (on Windows). We need to modify these settings:

    httpHostname=localhost
    httpPort=8080
    proxyType=Http

Now login. We will see some requests in Burp. We have seen them before, first one is the `Latest News` and the second one is the emoticon associated with it. The emoticon is loaded over HTTPs while latest news is loaded over HTTP. We will play with it later.

    1. http://downloads.hipchat.com/blog_info.html
    # section 2.2 in part 1
    
    2. https://s3.amazonaws.com/uploads.hipchat.com/10804/368466/FM3tGM05hUCySVj/freddie.png 
    # emoticon in this case it is Freddie Mercury
    # note that this changes because last time I saw success kid
    # section 2.3 in part 1.
    
    3.<?xml version='1.0'?><stream:stream to='chat.hipchat.com'
    # looks like the start of an XMPP handshake.

Note: `hipchatserver.com`, our imaginary Hipchat server's IP is `10.11.1.25` in this post.

{{< imgcap src="" caption="" /images/2015/hipchat2/03-Initial-requests-in-Burp.png Initial requests in Burp >}}

The third request looks like the start of an XMPP handshake which has been cut off by Burp. It should be something like this:

    <?xml version='1.0'?><stream:stream to='chat.hipchat.com' xmlns='jabber:client' 
    xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>

### 2. Why did Burp, Burp?

To diagnose the problem, we must look at the traffic capture. Run Netmon and login to Hipchat again. Remember that you cannot capture Hipchat’s traffic to Burp with Netmon or Wireshark as it is local (from `127.0.0.1:49xxx` to `127.0.0.1:8080`) so you need to sniff local traffic with something like [RawCap][rawcap-download]. But we can look at Burp’s outbound traffic in Netmon. Look for traffic belonging to the `javaw.exe` process (for Burp).

{{< imgcap src="" caption="" /images/2015/hipchat2/04-Traffic-to-hipchat.png Burp <–> hipchatserver.com traffic in Netmon >}}

Or using sequence diagram created on [https://www.websequencediagrams.com](https://www.websequencediagrams.com). We have a bunch of internal licenses for this at Cigital so I have started adding sequence diagrams to all of my blog posts and reports :D.

{{< imgcap src="" caption="" /images/2015/hipchat2/05-Failed-XMPP-Handshake.png What happen? >}}

As we see the XMPP handshake is incomplete. In short, Burp somehow messes up the first part of the XMPP handshake and drops the packet just after it sees `to='chat.hipchat.com'` and sends an incomplete payload which causes the server to reject it and reset the connection.

### 3. Burp’s SSL Pass Through
It’s time to talk about another one of Burp’s capabilities. This one is named `SSL Pass Through` and is very useful for exactly the situation we are in. We can specify endpoints (domain/IP and port) and tell Burp not to mess with the to/from those points and just pass it through as it is. This means that Burp will not Man-in-the-Middle (MitM) the connection and just ignore the traffic. It is located at `Proxy > Option > SSL Pass Through` (scroll all the way to the bottom). Let’s tell Burp not to proxy anything to/from the `hipchatserver.com` at `10.11.1.25:5222`.

{{< imgcap src="" caption="" /images/2015/hipchat2/06-SSL-Pass-Through.png SSL Pass Through settings >}}

And yay!

{{< imgcap src="" caption="" /images/2015/hipchat2/07-Hipchat-logged-in-with-Burp-as-proxy.png Logged in with Burp  >}}

Now let’s take a look at these requests. We have already seen the first two before.

    1. GET: http://downloads.hipchat.com/blog_info.html
    2. GET: https://s3.amazonaws.com/uploads.hipchat.com/10804/368466/FM3tGM05hUCySVj/freddie.png
    3. GET: https://www.hipchat.com/img/silhouette_125.png
    4. GET: https://hipchat.com/release_notes/appcast/qtwindows?auth-uid=351&auth-token=JHAgpsxHVva3SMC
    5. GET: https://www.hipchat.com/release_notes/appcast/qtwindows?auth-uid=351&auth-token=JHAgpsxHVva3SMC

**Request number 3** is retrieving an image. It is the placeholder image for profile pictures in Hipchat.

    GET /img/silhouette_125.png HTTP/1.1
    Connection: Keep-Alive
    Accept-Encoding: gzip, deflate
    Accept-Language: en-US,*
    User-Agent: Mozilla/5.0
    Host: www.hipchat.com

{{< imgcap src="" caption="" /images/2015/hipchat2/08-Profile-pic-placeholder.png Do not track me bro  >}}

Why are we retrieving this image from hipchat.com every time when it can be stored in the application and conserve bandwidth? I don’t know but Paranoid Parsia tells me that it is an Atlassian tracking request. This way they will know where and when an instance has been executed. There is no identifying data sent with the request.

{{< imgcap src="" caption="" /images/2015/hipchat2/09-I-am-not-saying-it-was-Atlassian-but-it-was-Atlassian.jpg I am not saying it was Atlassian, but it was Atlassian  >}}

**Request 4** is another GET request.

    GET /release_notes/appcast/qtwindows?auth-uid=351&auth-token=JHAgpsxHVva3SMC HTTP/1.1
    Cache-Control: no-cache
    Pragma: no-cache
    Connection: Keep-Alive
    Accept-Encoding: gzip, deflate
    Accept-Language: en-US,*
    User-Agent: Mozilla/5.0
    Host: hipchat.com

But it gets redirected to [https://www.hipchat.com/release_notes/appcast/qtwindows?auth-uid=351&auth-token=JHAgpsxHVva3SMC](https://www.hipchat.com/release_notes/appcast/qtwindows?auth-uid=351&auth-token=JHAgpsxHVva3SMC). Remember when we saw the application communicating with both `hipchat.com` and `www.hipchat.com` (sections 2.4 and 2.5 of [part 1](hipchat-part1))? This is it.

    HTTP/1.1 301 Moved Permanently
    Cache-control: no-cache="set-cookie"
    Content-Type: text/html
    Date: Mon, 07 Sep 2015 22:41:37 GMT
    Location: https://www.hipchat.com/release_notes/appcast/qtwindows?auth-uid=351&auth-token=JHAgpsxHVva3SMC
    Server: nginx
    Set-Cookie: AWSELB=05C1D11310299FE142D714774ABD93C5B09ED1734381C4F7DC691A8BCC5031E618740E2045508C8D72C034DD48A74BD4A2E439469DEA3BD63B536161358959E4151A965466;PATH=/
    Strict-Transport-Security: max-age=31536000
    X-Content-Type-Options: nosniff
    X-XSS-Protection: 1; mode=block
    Content-Length: 178
    Connection: keep-alive

    Response:
    <html>
    <head><title>301 Moved Permanently</title></head>
    <body bgcolor="white">
    <center><h1>301 Moved Permanently</h1></center>
    <hr><center>nginx</center>
    </body>
    </html>

Which results in **request 5**.

    GET /release_notes/appcast/qtwindows?auth-uid=351&auth-token=JHAgpsxHVva3SMC HTTP/1.1
    Cache-Control: no-cache
    Pragma: no-cache
    Connection: Keep-Alive
    Accept-Encoding: gzip, deflate
    Accept-Language: en-US,*
    User-Agent: Mozilla/5.0
    Host: www.hipchat.com

Response to request 5 is an RSS feed containing release versions of the Hipchat client for Windows. Click this link if you want to see it in action [https://www.hipchat.com/release_notes/appcast/qtwindows](https://www.hipchat.com/release_notes/appcast/qtwindows).
	
    HTTP/1.1 200 OK
    Cache-control: no-cache="set-cookie"
    Content-Type: application/xml
    Date: Mon, 07 Sep 2015 22:41:38 GMT
    Server: nginx
    Set-Cookie: AWSELB=05C1D11310299FE142D714774ABD93C5B09ED1734381C4F7DC691A8BCC5031E618740E204546FF579CEC855051CA268C2FEED4240DD3110178C6BD0BB2D00F1E409F9F4DA6;PATH=/
    Strict-Transport-Security: max-age=31536000
    X-Content-Type-Options: nosniff
    X-XSS-Protection: 1; mode=block
    Content-Length: 21562
    Connection: keep-alive

    <?xml version="1.0" encoding="utf-8"?><rss version="2.0"
    xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle"
    xmlns:dc="http://purl.org/dc/elements/1.1/"
    xmlns:hipchat="http://hipchat.com">
    <channel>
    <title>HipChat Windows App Changelog</title>
    <link>https://www.hipchat.com/release_notes/appcast/qtwindows</link>
    <description>Appcast of updates.</description>
    <language>en</language>

    <item>
    <title>Version 2.2.1388 (1388)</title>
    <pubDate>Tue, 23 Jun 2015 00:00:00 +0000</pubDate>
    <sparkle:releaseNotesLink>https://www.hipchat.com/release_notes/client_embed/qtwindows?version_num=1373&amp;auth-token=JHAgpsxHVva3SMC&amp;auth-uid=351</sparkle:releaseNotesLink>
    <sparkle:minimumSystemVersion>10.8</sparkle:minimumSystemVersion>
    <enclosure url="https://s3.amazonaws.com/downloads.hipchat.com/windows/HipChat-2.2.1388-win32.msi"
    sparkle:version="1388"
    sparkle:shortVersionString="2.2.1388"
    length="43982848"
    type="application/octet-stream" />
    <hipchat:required>0</hipchat:required>
    </item>
    ...

    </channel>
    </rss>

I think this RSS feed is used to check for updates.

### 5. GET request over HTTP
Now let’s take a look at request one. It is loading an HTML page and displays it in the app. directly We can intercept the response in Burp and modify it. The request is to [http://downloads.hipchat.com/blog_info.html](http://downloads.hipchat.com/blog_info.html) and that page is not available over TLS.

{{< imgcap src="" caption="" /images/2015/hipchat2/10-Changing-latest-news.png It has crashed again! >}}

That was easy. Now let’s see if we can modify it to display something else.

Seems like it does not have JavaScript enabled so we cannot do a fancy looking alert box. We can inject buttons and forms but the submit action does not work. We can also inject images.

{{< imgcap src="" caption="" /images/2015/hipchat2/11-image-tag.png Pepe is watching you load links over HTTP >}}

This is not a serious vulnerability. The attacker needs to be on the same network or in the path and MitM the HTTP connection. But because it is HTTP, there are no certificate warnings. A number of Internet Service Providers also inject ads and other stuff in HTTP traffic. If injected they will appear here. I still do not know why even the emoticon is loaded over https but this latest news is not (`downloads.hipchat.com` is not even available over HTTPs).

In my opinion the best strategy for an attacker is to inject links to phishing sites. Something along the lines of `Click to download the new version` and serve infected files or `Click to verify your account` and point to a phishing login screen. Doubly so because this is *the Hipchat link box* and users are expected to click these links. We should also remember that Hipchat is also used in non-corporate environments so the next person at Starbucks may be messing with your traffic.

#### 5.1 The Container
The container looks like to be QtWebKit (remember the User-Agent?). It does not have JavaScript enabled so injected JS will not be executed. We can inject forms, but the actions will not work (e.g. I injected a simple form with one input field to pass its contents to do a Google search but nothing happens when the button is clicked). This part needs more investigation and I will probably get back to it. If you know about this container (whatever that is) please let me know.

In part three, we will talk about proxying Hipchat client’s traffic with the Hipchat server that we skipped using Burp's SSL Pass Through and do more exciting stuff.

As usual if you have any questions/feedback/complaints or just want life advice from ancient Persian spirits, you know where to find me.

<!--links-->
[rawcap-download]: http://www.netresec.com/?page=RawCap

