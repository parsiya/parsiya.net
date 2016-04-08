---
title: "Burp Tips and Tricks for Non-Webapp Testing - Part 3: Options and Extender"
date: 2016-04-02T20:22:37-04:00
# change the date later
draft: false
toc: true
tags:
- Burp
- Tutorial
categories:
- Burp
---

Previous parts:

* [Burp Tips and Tricks for Non-Webapp Testing - Part 1: Interception and Proxy Listeners]({{< ref "2016-03-27-burp-tips-and-tricks-for-non-webapp-testing-part-1.markdown" >}} "Burp Tips and Tricks for Non-Webapp Testing - Part 1: Interception and Proxy Listeners")
* [Burp Tips and Tricks for Non-Webapp Testing - Part 2: History, Intruder, Scanner and More]({{< ref "2016-03-29-burp-tips-and-tricks-for-non-webapp-testing-part-2.markdown" >}} "Burp Tips and Tricks for Non-Webapp Testing - Part 2: History, Intruder, Scanner and More")

Almost there, I will get through `Options` and `Extender` in this part and we will actually start doing stuff moving forward.

<!--more-->

# 1. Options
The place to configure Burp and make tricky apps work with it.

## 1.1 Connections

### 1.1.1 Platform Authentication
If the application needs to do special forms of authentication such as `NTLM` or `Basic` you can configure it here. If you are doing authentication in the browser then you probably do not need to do it here and will see the headers in Burp but adding them here means you do not have to enter them every time you login to the application. For thick clients this is usually helpful if you need to access the environment using some sort of platform authentication first.

Sometimes one of your tools does not support thse settings or has problems with it. I have had this problem when using Appscan with some weird websites (although Appscan supports platform authentication). You can pipe your other tool (Appscan supports such a setting) to Burp and then let Burp do the work. I would not suggest it for any tool like Appscan which generates a lot of traffic but "needs must when ~~the devil drives~~ you have to use Appscan." If the authentication fails, the error messages will appear in the `Alerts` tab.

{{< imgcap title="Platform authentication options" src="/images/2016/burp-tips-3/01.PNG" >}}

Enable the `Prompt for credentials on platform authentication failure` to pass the prompt to browser on authentication failure.

### 1.1.2 Upstream Proxy Servers - SOCKS Proxy
I have talked a lot about using Burp as part of a proxy chain. This is where we can configure where the requests are forwarded from Burp. It's also useful for using Burp in environments with corporate proxy servers. Usually these proxy servers are automatically configured. These settings can usually be accessed in Internet Explorer's proxy settings at `Tools (menu) > Internet Options (menu item)> Connections (tab) > LAN settings (button)`. Often there is a `proxy auto-config` or `pac` file configured via the `Use automatic configuration script` setting. Retrieve the pac file and view it in a text editor. The proxy address:port should be there.

{{< imgcap title="Upstream Proxy Servers" src="/images/2016/burp-tips-3/02.PNG" >}}

Using a SOCKS proxy is similar. According to the fine print, this will override the previous proxy settings. Personally I have never had to configure a SOCKS proxy for Burp.

### 1.1.3 Timeouts
Use it for slow servers. We usually test on UAT, QA or whatever-environment-the-client-can-spare which are slow. If you are dealing with a slow server, increase the timeouts here. If Burp is part of a proxy chain, definitely increase the timeouts to compensate for delays.

{{< imgcap title="Timeout settings" src="/images/2016/burp-tips-3/03.PNG" >}}

### 1.1.4 Hostname Resolution
I have talked about it briefly in [Part 2: Request Handling]({{< ref "2016-03-27-burp-tips-and-tricks-for-non-webapp-testing-part-1.markdown#2-2-request-handling" >}} "Request Handling"). The application talks to multiple endpoints but doesn't support proxy settings. We redirect application's traffic to Burp using other means (e.g. Windows hosts file or other OS level mechanisms). Now Burp needs to know where to forward the traffic otherwise it will go into a infinite loop and send the traffic back to itself again.

We cannot use the `Request Handling` functionality because it only supports one endpoint. Instead we will leave it empty and add the endpoints and their associated IP address here in `Hostname Resolution`. For example `server.com` and `10.11.12.13`. If the endpoint is behind load balancers, CDNs or is on shared hosting like an Amazon S3 bucket then things get a bit more complicated. In this case, run `Wireshark` or `Netmon` and capture application's traffic without a proxy. Discover the IP address that the HTTP requests are sent to. Use the discovered IP with the hostname in this section and the `host` header will do its magic (OK, there are more technical ways to do this but this is the easiest in my opinion).

<!-- *Note to self*: Do a small example with `parsiya.net` in later posts. -->

### 1.1.5 Out-of-Scope Requests
We can instruct Burp to drop all requests if they are not in scope. This can work in our favor if we have set-up the scope properly and reduces traffic/noise. There is one big catch, if the application is connecting to some other endpoints apart from the ones we are testing (and thus have added to scope), it may stop working. If you are setting up Burp for an inexperienced person and don't want them to hit production, you can designate it here. Apart from that I cannot think of a lot of uses and I have never used this functionality.

## 1.2 HTTP
`Redirections` and `Status 100 Responses` are straightforward so I will skip them.

### 1.2.1 Streaming Responses
This is an underrated functionality especially for non-webapp testing. To understand when we must use this functionality, let's step back and look at how proxies work. I have written about it in some detail (with examples) in [Hipchat Part 3 - 2. How does a Proxy Work?]({{< ref "2015-10-19-proxying-hipchat-part-3-ssl-added-and-removed-here.markdown#2-how-does-a-proxy-work" >}} "Proxying Hipchat Part 3: SSL Added and Removed Here - 2. How does a Proxy Work?").

In short, the following happens (these are copied from the link above):

{{< imgcap title="GET http://downloads.hipchat.com/blog_info.html" src="/images/2016/burp-tips-3/04.PNG" >}}

1. Hipchat creates a TCP connection to Burp.
2. Hipchat sends the GET request to Burp.
3. Burp creates a TCP connection to Server.
4. Burp sends the GET request to Server.
5. Server send the web page to Burp.
6. Burp closes the TCP connection to Server.
7. Burp sends the web page to Hipchat.
8. Burp closes the TCP connection to Hipchat.

Note that this figure is different for HTTPS requests.

Now assume `http://downloads.hipchat.com/blog_info.html` is a large file (like a 100MB update), and the application requests this file. The application treats this file as a stream and displays a progress bar depending on how much data is downloaded.

If we proxy this request, Burp will request this file in step four. Burp will not send this data to the application until the download has finished (meaning step five has not been completed). This means the application is waiting for this file for a while and may just discard it and re-send the request or just timeout and freeze. If we add `http://downloads.hipchat.com/blog_info.html` to the `Streaming Responses` section, Burp will immediately pass the response to the application as soon as it starts receiving data and saves the day.

<!-- Note to self: do a streaming response example. Symantec update seems a good choice but find a smaller application -->

## 1.3 SSL
`Server SSL Certificates` just shows a list a certificates retrieved from server. You could easily get the certificates using a command line tool like `OpenSSL` but I guess you can view the certificate info here too.

### 1.3.1 SSL Negotiation
It's a good idea to install the [Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files][jce-1] anyways but you can use unlimited cipher strength in Burp too. Also make sure you are running a recent version of Java Runtime Environment (JRE). The other day I was trying to proxy an application and the TLS handshake failed even with the unlimited strength policy until I realized the machine had JRE 6.

**Enable all options** except the `Disable Java SNI extension`, chances are that you need SNI. The `Allow unsafe renegotiation` looks a bit scary but helps a lot when using client side certificates.

During proxying if you are not confident that the current TLS settings work, keep a close eye on the `Alerts` tab. If the TLS handshake fails or if Burp and server cannot complete the TLS handshake, there will be errors there. Again, for troubleshooting use [SSL Pass Through]({{< ref "2016-03-27-burp-tips-and-tricks-for-non-webapp-testing-part-1.markdown#1-4-ssl-pass-through" >}} "SSL Pass Through").

### 1.3.2 Client SSL Certificates
If the application needs a client-side certificate, we can add it here. Easy peasy. We can select a destination host and Burp will use the certificate for that host.

## 1.4 Session
This tab gives us a decent amount of automation. You can create macros. You do a bunch of stuff and the request are logged, then you choose some of them and save as a macro. Later in `Session Handling Rules` you can choose to run the macro for a certain scope or after a specific request. For example you can create a macro for login and let Burp login before you send any request. Another thing to do is to create a parameter (with a specific value) and add it to every request (or requests in a certain scope) or modify the value of a parameter automatically.

I would write more about this tab but I do not usually use it. I have only used it a few times to do stuff as I have described above. Hopefully in our examples we will be able to use it in action.

## 1.5 Display
You can change the font, encoding and other items here. Note that the font/size of Burp theme is different from the text boxes that display request/responses.

## 1.6 Misc
Most items here do not need any explanation. If you have the Pro version, I suggest turning on `Automatic Backup`. I usually set it to one hour and enable `Backup on exit`. Because I like to keep daily backups of Burp savedstates, I also enable `Include in-scope items only` which decreases the size of the savedstate dramatically.

Having backup of savedstates have saved my backside quite a number of times. During report writing, I remember that I have not taken screenshots of some items so I can just open up the savedstate and create the evidence. Also, if you need to check something when the testing period has ended or your account is locked, sometimes you can use savedstates.

`Scheduled Tasks` allow you to do some scheduling. For example you can set the scanner to start at a certain hour. If you do not want to or can't scan during the day, set it to start a scan at a certain hour. Unfortunately it does not allow to run a macro as a scheduled tasks and the options are very limited.

{{< imgcap title="Schedule task options" src="/images/2016/burp-tips-3/05.PNG" >}}

### 1.6.1 Burp Collaborator Server
Burp Collaborator is the new thing. Default setting is to `Use the default collaborator server` which is annoying. So after every new installation of Burp, this is one of the options that I modify. I am not quite sure what kind of information is passed to the server, but I'd rather not have our clients' info sent to the default server. You can run your own too. Read more about it in the [documentation][burp-collab1].

# 2. Alerts
Alerts tab is important. Especially on TLS connection problem or timeouts. Pay close attention to this tab and read the information if it lights up.

# 3. Extender
Burp has support for extensions. Extensions can be created in Java, Python or Ruby. Unfortunately there is not a lot of documentation for non-Java extension deployment. Personally I prefer Python and most of what I have learned has been from reading other people's extensions.

## 3.1 Extensions
This tab shows the current extensions and if they are loaded. It also displays their output and errors. You can also add extensions here. After loading an extension pay attention to the errors tab in case there are errors. Adding an extension is simple, click `Add` and then select the type and path to the extension file. I usually put them in a sub-directory inside the Burp directory.

## 3.2 BApp Store
Installing plugins from the Burp app store is a breeze. Just switch to this tab, select the extension and click `Install`. If the extension is written in Python you have to install `Jython` and if it is not set in the application, Burp conveniently shows you a `Download Jython` button.

{{< imgcap title="Need Jython" src="/images/2016/burp-tips-3/06.PNG" >}}

Clicking on the download button open up [this page][jython-dl]. Download the latest `Standalone Jar`. I usually just put it in the same directory as Burp. Then switch to the `Extender > Options` tab and select it under the `Python Environment > Location of the Jython standalone JAR file` and you are good to go.

 {{< imgcap title="Path to Jython" src="/images/2016/burp-tips-3/07.PNG" >}}

Now the `Install` button lights up and you can install the extension(s).

## 3.3 APIs
APIs tab contains the API documentation. Burp extensions can use this APIs to interact with Burp. As you can see the documentation is for Java extensions.

## 3.4 Options
As we have seen before, we can set the paths to `Jython` and `JRuby` here. We can also designate directories for extension written in Java and Python. When Burp starts, extensions in these directories are automatically loaded.

-----------

# 4. Where do We Go from Here?
I have talked a lot about the options in Burp, but I have done nothing. From next part, I am going to proxy some sample thick clients using Burp. My biggest problem is finding applications that need the Burp functionalities that we have talked about (e.g. `Streaming Responses` or `Hostname Resolution`). If I cannot find such applications in the real world, I am going to develop a few small applications and then we can practice on them.

Practice is important. We don't want to turn into what the famous Persian poet and scholar [Saadi Shirazi (سعدی شیرازی)][saadi-wiki] called "عالم بی عمل" or "learned man without practice." As Saadi says in his Gulistan (گلستان or rose garden), chapter 8: "On Rules for Conduct in Life" [Maxim 50][chapter8-maxim50-adelaide]:

> A disciple without intention is a lover without money; a traveller without knowledge is a bird without wings; a scholar without practice is a tree without fruit, and a devotee without science is a house without a door. The Quran was revealed for the acquisition of a good character, not for chanting written chapters. A pious unlettered man is like one who travels on foot, whilst a negligent scholar is like a sleeping rider. A sinner who lifts his hands in supplication is better than a devotee who keeps them proudly on his head.

> A good humoured and pleasant military officer  
Is superior to a theologian who injures men.

> One being asked what a learned man without practice resembled, replied: ‘A bee without honey.’

> Say to the rude and unkind bee,  
‘At least forbear to sting, if thou givest no honey.’

It's a good book, there are English translations of it in the public domain. [Translation from the University of Adelaide website][Golestan-adelaide] or [Archive.org][Golestan-archive].

<!-- Links -->
[jce-1]: https://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html
[burp-collab1]: https://portswigger.net/burp/help/collaborator.html
[jython-dl]: http://www.jython.org/downloads.html
[saadi-wiki]: https://en.wikipedia.org/wiki/Saadi_Shirazi
[chapter8-maxim50-adelaide]: https://ebooks.adelaide.edu.au/s/saadi/s12g/chapter8.html#section256
[Golestan-adelaide]: https://ebooks.adelaide.edu.au/s/saadi/s12g/complete.html
[Golestan-archive]: https://archive.org/details/GulistanSaadiShirziPersianTextEnglishTranslation
