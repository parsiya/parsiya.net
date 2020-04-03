---
categories:
- Thick Client Proxying
- Proxy
comments: true
date: 2016-07-28T02:04:23-04:00
draft: false
tags:
- Proxying
- Burp
- Tutorial
title: "Thick Client Proxying - Part 6: How HTTP(s) Proxies Work"
toc: true
aliases:
- "/blog/2016-07-28-thick-client-proxying---part-6-how-https-proxies-work/"
---

In order to create our own custom proxies, first we need to know how proxies work. When I wanted to write a custom proxy tool (it's a simple Python script) in [Hipchat part3]({{< ref "2015-10-19-proxying-hipchat-part-3-ssl-added-and-removed-here.markdown" >}} "Proxying Hipchat Part 3: SSL Added and Removed Here"), I had to go back and learn how they work. I did not find such a resource online that looked at proxies from an infosec perspective. Most talked about how to configure caching or forwarding proxies and not much about MitM ones. I have briefly talked about it in the section 2 of the same post named `How does a Proxy Work?`. In this post I am going to take a deep(er) dive. I actually read some RFCs and they were surprisingly well written.

If you want to skip the intro, go to [section 3]({{< relref "#section-3" >}} "How HTTP Proxies Work").

<!--more-->

# 0. Why do I Need to Know How Proxies Work?
That is a fair question. Most of the time, we pipe the browser to Burp and it works out of the box. However, if something small changes we will go into panic mode. What if the webapp uses a Java or Silverlight component and it has some quirky things? Another reason is for proxying thick clients because Burp as you have seen here is not just for webapps. My opinion is "**if the application uses HTTP, you can Burp it**." Thick clients may not work out of the box when proxied (often just redirecting their traffic to the proxy is a pain). If we do not know how proxies work internally, we cannot troubleshoot the issues.

You are now convinced that you need to read this right? **riiiiiiiiiiiiight?**

# 1. Become One with the Proxy
It really helps to put ourselves in place of the proxy when reading this. At least that is what worked for me. Proxy does not know whatever happens in the system like an observer. As an observer we can just make decisions about what the proxy _should_ do. Things like "the user typed google.com in their browser so the proxy must send the request to google.com." Well, how does the proxy know that? The proxy cannot magically see the browser's address bar.

## 1.1. What does it Mean?
We are the proxy. The only things we see are the requests/packets that the client (e.g. browser) and the endpoint send to us. We do not know anything else. And as a proxy we must decide what to do with the requests that we receive with only our knowledge.

Now that we are hopefully in the zone, let's start.

# 2. Brief Intro to Two Types of Proxies
I am going to talk about two types of proxies here.

* Forwarding proxies
* TLS terminating proxies

The descriptions are not entirely accurate or detailed but are enough for our purpose. Of course this is not an exhaustive list. There are other proxies out there but these are the ones that we are interested in. To be honest we are only interested in TLS terminating proxies.

## 2.1. Forwarding Proxies
We have all seen them before. These are corporate proxies that we see and use everyday. If you are in a corporate environment, check the proxy auto-config (pac) scripts. Essentially it's a text file that tells the application where to send the traffic and re-routes the traffic based on the endpoint. Usually if the endpoint is internal, things get routed normally through the internal network otherwise (requests sent over the internet) requests are sent to a forwarding proxy. You can see some examples at [Microsoft Technet][pac-examples]. From the point of view of the application,  the forwarding proxy is sitting between the internal network and the internet.

Based on the name, these proxies just forward packets and cannot look inside encrypted payloads (e.g. TLS). From the point of view of a typical forwarding proxy, an established TLS connection is just a bunch of packets with random looking TCP payloads.

## 2.2. TLS Terminating Proxies
Burp is the prime example of this type. If you know what Burp does (and you probably do because you are reading this), you know what a TLS terminating proxy does. These are proxies that usually MitM the connections and unwrap TLS to look inside the payloads.

They could be applications like Burp or Fiddler which are usually used for (security) testing. Or could be appliances like Bluecoat or the [SSL decryption module][ssl-decyprtion-paloalto] of Palo Alto Networks' "thing" (whatever it is named). Usually these appliances are used for deep packet inspection.

You could make Burp work like a forwarding proxy by adding all endpoints to Burp's [SSL Pass Through]({{< ref "2016-03-27-thickclient-proxying-1.markdown#1-4-ssl-pass-through" >}} "SSL Pass Through"). This is useful for troubleshooting connections.

### 2.2.1. It's not Always TLS
True. Sometimes our proxy decrypts (or decodes) layers of non-TLS encryption (or encoding). I am classifying all of these proxies under this category because TLS has become the most common way of protecting data in transit.

# 3. How HTTP(s) Proxies work {#section-3}
Now we get to the main part. In all examples we have a browser that uses a proxy (via some proxy settings) and the browser knows that it is connected to a proxy (I will talk about this later).

## 3.1. HTTP Proxy
In this case the browser is using plain HTTP (meaning there's no TLS). Both forwarding and TLS terminating proxies work similarly in this case.

Let's assume we have typed http://www.yahoo.com in the browser. Let's forget that we get a 302 redirect in the real world and assume yahoo.com is available over HTTP. I probably should have used example.com instead but I am lazy and don't want to create the diagrams again.

The browser establishes a TCP connection to the proxy (the famous `SYN-SYNACK-ACK`) and then sends the GET request.

{{< imgcap title="What does the proxy see?" src="/images/2016/thickclient-6/01.png" >}}

Here's how the GET request looks like in Wireshark (we can see it in plaintext because there's no TLS).

{{< imgcap title="GET request sent to the proxy" src="/images/2016/thickclient-6/02.png" >}}

Now, we (proxy) must decide where to send this GET request. Note that both the proxy (Burp) and the browser are on the same machine so the source and destination IP addresses in the previous picture are both `127.0.0.1`. So we cannot forward the request based on the destination IP address.

How is this GET request different from a non-proxied GET request? I disabled my browser's proxy settings and recaptured the same GET request.

{{< imgcap title="GET request without using a proxy" src="/images/2016/thickclient-6/03.png" >}}

Check the highlighted parts. The request sent to proxy has the `absoluteURI`. In simple words it has the complete URI (or URL) in the GET request. The proxy uses this to discover the endpoint. This was initially discussed in RFC2616 which discusses HTTP/1.1. In [section 5.1.2. Request-URI][rfc-2616-requesturi], we see:

> The absoluteURI form is REQUIRED when the request is being made to a proxy.  
> ...  
> An example Request-Line would be:  
> GET http://www.w3.org/pub/WWW/TheProject.html HTTP/1.1

In newer RFCs you can look it up using `absolute-URI`. This format is called `absolute-form`. In [RFC7230 - HTTP/1.1: Message Syntax and Routing][rfc7230-link] we can check [section 5.3.2. absolute-form][rfc7230-absoluteform] to see:

> When making a request to a proxy, other than a CONNECT or server-wide OPTIONS request (as detailed below), a client MUST send the target URI in absolute-form as the request-target.  
>
> absolute-form  = absolute-URI  

Note that the RFC instructs clients to send the `absolute-URI` no matter what (even if they are using a `CONNEC` request) as we will see shortly.

The proxy uses this `absolute-URI` to forward the request to the endpoint (in this case Yahoo!). Both forwarding and TLS terminating proxies work similarly in this case because they both can look inside HTTP payloads.

{{< imgcap title="HTTP proxy in action" src="/images/2016/thickclient-6/04.png" >}}

1. Browser establishes a TCP connection to proxy.
2. Browser sends the HTTP request (with an absolute-URI) to proxy.
3. Proxy establishes a TCP connection to yahoo.com (using the absolute-URI).
4. Proxy forwards the HTTP request.
5. Proxy receives the response.
6. Proxy closes the connection to yahoo.com.
7. Proxy forwards the response to browser.
8. Proxy signals to close the connection (using FIN).
9. Connection between browser and Proxy is closed.

### 3.1.1. Why not Use the Host Header?
If you have done at least a bit of HTTP security testing (or have seen some HTTP requests), you are probably asking "why not just use the Host header?" That is a very good question and it was mine too. We are the proxy and we see the `Host` header, why do we need to use the absolute-URI instead?

The answer is backward compatibility with HTTP/1.0 proxies. This is hinted in [section 5.4. Host][rfc7230-host] of RFC7230:

> A client MUST send a Host header field in an HTTP/1.1 request even if the request-target is in the absolute-form, since this allows the Host information to be forwarded through ancient HTTP/1.0 proxies that might not have implemented Host.

Later it instructs proxies to rely on the absolute-URI and ignore the `Host` header. If the `Host` header is different from the URI, then the proxy must generate the correct header and send it with the request.

## 3.2. Forwarding Proxy and HTTPs
But what about HTTP(s) forwarding proxies? How do they work?

Again let's put ourselves in place of the forwarding proxy. We do not do TLS handshakes and just forward things around. After the user types https://www.google.com in their browser, it creates a TCP connection to us and then starts the TLS handshake. The first step of a TLS handshake is `ClientHello` discussed in [RFC5246 section 7.4.1.2.][rfc5246-clienthello] ([RFC5246][rfc5246-link] is essentially TLS 1.2).

{{< imgcap title="ClientHello sent from browser to proxy" src="/images/2016/thickclient-6/05.png" >}}

Now I did not read the TLS 1.2 RFC completely and I doubt you need to either. As the proxy, we will see a `ClientHello` like this:

{{< imgcap title="ClientHello as seen by proxy" src="/images/2016/thickclient-6/06.png" >}}

But we are a proxy and we should know what it means. Tools should be able to do this for us. In this case I used Netmon and it decodes the `ClientHello` like this:

{{< imgcap title="ClientHello deciphered" src="/images/2016/thickclient-6/07.png" >}}

Now, we need to decide where to send this `ClientHello`. How can we discover the endpoint with this information?

Well, the answer is **we can't**.

### 3.2.1. The CONNECT Request
In simple words, the browser needs to tell the proxy where to forward the requests and this should happen before the TLS handshake (and obviously after the TCP connection is established). That's where the `CONNECT` method comes into play.

The browser sends a request with the `CONNECT` method with the name of the domain to the proxy before the TLS handshake. This request contains the endpoint and the port in this format (`HOST:PORT`). Which called the `authority-form` format for request-target. We can see it in [RFC7230 section 5.3.3 - authority-form][rfc7230-authorityform].

> The authority-form of request-target is only used for CONNECT requests  
> ...  
> a client MUST send only the target URI's authority component (excluding any userinfo and its "@" delimiter) as the request-target. For example,
>
> CONNECT www.example.com:80 HTTP/1.1

The `CONNECT` method is discussed in [RFC7231 - HTTP/1.1: Semantics and Content][rfc7231-link] in [section 4.3.6 - CONNECT][rfc7231-connect].

> The CONNECT method requests that the recipient establish a tunnel to the destination origin server identified by the request-target and, if successful, thereafter restrict its behavior to blind forwarding of packets, in both directions, until the tunnel is closed.

The client instructions are as follows:

> A client sending a CONNECT request MUST send the authority form of request-target.  
> ...  
> For example,
>
> CONNECT server.example.com:80 HTTP/1.1  
> Host: server.example.com:80

The proxy should establish a connection to the destination and if successful should respond with a `2xx (Successful) response`. Before reading the RFC, I thought that the proxy sends the 2xx response immediately and then creates a connection to the destination. But I was wrong. The proxy only replies if it could connect to the endpoint, otherwise how could we tell the application that we could not establish a tunnel. The application starts the TLS handshake when it receives the 2xx response.

{{< imgcap title="Forwarding proxy and HTTPs in action" src="/images/2016/thickclient-6/08.png" >}}

1. Browser creates a TCP connection to the forwarding proxy.
2. Browser sends the `CONNECT google.com:443` request to the proxy.
3. Proxy attempts to connect to `google.com:443`.
4. If successful, proxy responds with a `200 connection established`.
5. Now the browser knows that the proxy can contact the endpoint and starts the TLS handshake.
6. The forwarding proxy just passes requests until one side closes the connection, then it closes the other connection.

## 3.3. Burp and HTTPs
Things are similar with Burp (or any TLS terminating proxy). The only difference is that Burp MitMs the connection by doing a TLS handshake with the browser and thus will have the data in plaintext. By default Burp uses the endpoint name in the `CONNECT` request to auto-generate a certificate (signed by its root CA) and presents it to the client.

### 3.3.1. Correction - July 30th 2016
The following picture is wrong. As our friends in the comments have noticed, there are two TCP connections from Burp to the server. My train of thought was that Burp first checks connectivity with the server before returning the 200 response and acts according to the RFC. And then opens a new connection to the server and does the sides of the connection.

{{< imgcap title="This is wrong - see below" src="/images/2016/thickclient-6/09.png" >}}

What actually happens is that Burp does not do the initial TCP connection to the endpoint after the `CONNECT` request and just responds with the 200 response. I went ahead and captured the traffic using Microsoft Message Analyzer (MMA). It enabled me to capture both local traffic from browser to Burp and from Burp to Google.com. Here's a picture of MMA that shows both TLS handshakes.

{{< imgcap title="Both browser and Burp handshakes" src="/images/2016/thickclient-6/12.png" >}}

The top part is the local traffic between browser and Burp and the bottom one is between Burp and Google.com. Packets are sorted chronologically. As you can see, Burp does not do a connectivity check when it gets the `CONNECT`. It proceeds with the TLS handshake and then only contacts Google.com after it  receives the first request (in this case the GET request). So the actual diagram should be this:

{{< imgcap title="Burp and HTTPs in action - the correct one" src="/images/2016/thickclient-6/13.png" >}}

### 3.3.1. Burp's Invisible Mode
I have talked about this probably [a hundred times]({{< ref "#2-2-1-burp-s-invisible-proxying" >}} "Burp's Invisible Proxying"). We read that the RFC prevents proxies from using the `Host` header to re-route the traffic. Now if we have a client which uses HTTP but is not proxy-aware (or we have redirected its traffic to Burp without using proxy settings), we can enable Burp's invisible mode which uses the `Host` header to redirect traffic. This is one of the beauties of HTTP which makes is much easier to proxy than a custom protocol (e.g. a binary blob wrapped in TLS).

# 4. Cloudfront and Server Name Indication
If you have captured `ClientHello` requests while playing around to see proxies in action (or just in general), you have noticed that your requests are not like the one I showed above. You can see the server's name in those `ClienHello`s. In fact, it is harder to catch a one without the server name. For my picture I had to navigate to a website by IP address.

What is that server name? It's a TLS extension called `Server Name Indication` or SNI. We can read about it in [RFC6066 section 3. Server Name Indication][rfc6066-sni]:

> It may be desirable for clients to provide this information to facilitate secure connections to servers that host multiple 'virtual' servers at a single underlying network address.

I am going to use my website as an example. `Parsiya.net` is a statically generated website using [Hugo](https://gohugo.io). It's hosted from an Amazon S3 bucket. S3 does not support TLS (or HTTPs if you want to call it) for statically hosted websites (it supports serving single files over TLS). In order to get TLS, I use Cloudfront in front of it. Cloudfront is Amazon's Content Distribution Network (CDN) and supports custom TLS certificates. If you use Cloudfront you can get a free TLS cert for your website. Cloudfront in this case is acting as the endpoint for many resources.

There should be a way for the browser to tell Cloudfront which endpoint it wants to connect so that Cloudfront can grab the correct TLS certificate and present it to the browser. This is enabled by SNI. A typical `ClientHello` for `parsiya.net` looks like the following (with decoded SNI):

{{< imgcap title="ClientHello with SNI" src="/images/2016/thickclient-6/10.png" >}}

Now we can see how Cloudfront works (simplified):

{{< imgcap title="SNI and Cloudfront" src="/images/2016/thickclient-6/11.png" >}}

In this case Cloudfront is acting like a TLS terminating proxy. On one side it has HTTPs (browser <-> Cloudfront) and on the other side it has HTTP (Cloudfront <-> S3). But instead of using the `CONNECT` request we use SNI. This makes sense because Cloudfront is not set as a proxy for the browser.

# 5. Proxy-Aware Clients
Now I can talk about proxy-aware clients. We have already seen them and know what they do.

Proxy-aware clients know when they are connected to a proxy and if so, do the following:

* Use the `absolute-URI` in the requests sent to the proxy.
* Send the `CONNECT` request to talk to the proxy about the endpoint before the TLS handshake.

Usually proxy-aware clients have proxy settings or honor some OS specific ones (e.g. IE proxy settings). This signals that the browser is connected to a proxy and should act accordingly. Almost all browsers are proxy-aware.

# 6. Conclusion and Future Plans
Well that was all folks. Hopefully this is useful. Now we know how proxies work internally. Next time Burp messes up, capture the local traffic between the client and Burp and diagnose the problem. Pay attention to Burp's alert tab, usually TLS problems show up there too.

My plans for next part is to talk about traffic redirection techniques.

As usual if you have any questions/comments/feedback, you know where to find me.

<!-- links -->
[pac-examples]: https://technet.microsoft.com/en-us/library/cc985335.aspx
[ssl-decyprtion-paloalto]: https://live.paloaltonetworks.com/t5/Configuration-Articles/How-to-Implement-and-Test-SSL-Decryption/ta-p/59719
[rfc-2616-requesturi]: https://tools.ietf.org/html/rfc2616#section-5.1.2
[rfc7230-link]: https://tools.ietf.org/html/rfc7230
[rfc7230-absoluteform]: https://tools.ietf.org/html/rfc7230#section-5.3.2
[rfc7230-host]: https://tools.ietf.org/html/rfc7230#section-5.4
[rfc5246-clienthello]: https://tools.ietf.org/html/rfc5246#section-7.4.1.2
[rfc5246-link]: https://tools.ietf.org/html/rfc5246
[rfc7230-authorityform]: https://tools.ietf.org/html/rfc7230#section-5.3.3
[rfc7231-link]: https://tools.ietf.org/html/rfc7231
[rfc7231-connect]: https://tools.ietf.org/html/rfc7231#section-4.3.6
[rfc6066-sni]: https://tools.ietf.org/html/rfc6066#page-6
