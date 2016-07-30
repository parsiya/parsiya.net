---
categories:
- Thick Client Proxying
comments: true
date: 2016-07-15T00:27:14-04:00
draft: true
tags:
- Burp
- Windows
title: "Thick Client Proxying - Part 6: Traffic Redirection Techniques"
toc: false
---
In this post I am going to talk about the different ways that we can redirect application's traffic to the proxy. It's mainly focused on Windows (and I have already explained the reasons behind it) but the main concepts are transferrable to other operating systems.

<!--more-->

# 1. Application's Proxy Settings
I will start with easy mode. If the application has its own proxy settings, it means it is proxy-aware and we can redirect its traffic to a proxy. For a good example we can look at [FileHippo in part 5]({{< ref "2016-05-15-thick-client-testing-5.markdown#2-1-proxy-settings" >}} "Filehippo proxy settings"). It can't get easier than this.

# 2. Win



WInHTTP vs. WinINet

https://msdn.microsoft.com/en-us/library/windows/desktop/hh227297(v=vs.85).aspx


About WinINet

https://msdn.microsoft.com/en-us/library/windows/desktop/aa383630(v=vs.85).aspx


Understanding Web Proxy Configuration

https://blogs.msdn.microsoft.com/ieinternals/2013/10/11/understanding-web-proxy-configuration/
