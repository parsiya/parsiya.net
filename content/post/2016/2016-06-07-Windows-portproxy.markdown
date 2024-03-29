---
categories:
- Thick Client Proxying
- Portproxy
comments: true
date: 2016-06-07T22:29:49-04:00
draft: false
tags:
- Proxying
- Portproxy
- Windows
title: Windows Netsh Interface Portproxy
toc: false
---

I thought I had found the Windows `iptables` with [Portproxy][portproxy-link]
but I was wrong. But I learned something neat in the process and I am
documenting it.

Portproxy allows you to listen on a certain port on one of your network
interfaces (or all interfaces) and redirect all traffic
**destined to that interface** to another port/IP.

The `to that interface` is the limitation that unfortunately kills it. This will
be a short post.

[portproxy-link]: https://technet.microsoft.com/de-de/library/cc731068(v=ws.10).aspx
<!--more-->

A typical Portproxy command is like this:

``` bash
netsh interface portproxy add v4tov4 listenport=9090 listenaddress=192.168.0.100
    connectaddress=192.168.1.200 connectport=9095
```

I thought I could change `listenaddress:listenport` and redirect all outgoing
traffic to that `IP:port` to wherever I wanted (e.g. localhost). But I was
wrong, the command creates a listener on the interface with the
`listeneraddress` IP and redirects all TCP traffic. In other words, the
`listeneraddress` needs to be the IP of an interface of your machine and **the
traffic needs to be destined for your machine to be able to be redirected with
this command**. Boo!

## Install IPv6 Support
**Update 2021-06-08:** This is not needed anymore.

~~Before we start, install IPv6 support in your OS. According to
[KB555744][kb555744-link] Portproxy may not work if IPv6 support is not
installed.~~

Why? I don't know. I think because Portproxy supports both IPv4 and IPv6
addresses which is a good thing. If you look at the [MSDN][portproxy-link] link
you can see the four variations that mix v4 and v6 addresses.

## Portproxy in Action
Let's start with something simple. We want to redirect anything that goes to
`127.0.0.1:9090` to `google.com:443`.

Open an **admin** command prompt and run this command (`protocol=tcp` is
optional because Portproxy only supports TCP):

``` bash
netsh interface portproxy add v4tov4 listenport=9090 listenaddress=127.0.0.1
    connectaddress=216.58.217.78 connectport=443 protocol=tcp
```

Remember to remove the new line (I have split the command into two lines for
better readability).

This command creates a listener on `localhost:9090` and forwards all traffic to
`216.58.217.78:443` (which is Google for me - you might get a different IP
address if you ping it).

We can display all current Portproxy listeners:

* `netsh interface portproxy show all`.

In the same admin command prompt run this command to see the listener:

* `netstat -anb | findstr 9090`.

{{< imgcap title="Portproxy to Google" src="/images/2016/portproxy/01.PNG" >}}

Open a browser and go to `https://localhost:9090`.

{{< imgcap title="Obviously bad certificate" src="/images/2016/portproxy/02.PNG" >}}

Accept the security exception and we will see:

{{< imgcap title="Somewhere in Google land" src="/images/2016/portproxy/03.PNG" >}}

Not exactly `google.com` but you know what we accomplished.

## Other Uses
Apart from doing failed tricks we can do other things with this. We can redirect
local resources to remote ones.

We can also switch ports. Using the `hosts` file, we can redirect traffic to
domains, but not the port. E.g., we can redirect `google.com` to `localhost`,
but we cannot change the port. With Portproxy, we can add a new listener on
`localhost:443` and redirect all traffic to a different IP:port (e.g. a VM
running our proxy). This might replace the [Traffic
Redirector][traffic-redirector-link] Burp extension.

<!-- links -->

[kb555744-link]: https://mskb.pkisolutions.com/kb/555744
[traffic-redirector-link]: http://blog.portswigger.net/2012/12/sample-burp-suite-extension-traffic.html
