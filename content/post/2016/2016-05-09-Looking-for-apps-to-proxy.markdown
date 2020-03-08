---
categories:
- Update
- Not-Security
comments: true
date: 2016-05-09T01:37:41-04:00
draft: false
tags:
- Update
title: Looking for Apps to Proxy
toc: false
---
It's been a while since Burp part four and I want to continue writing these. It's time to actually proxy applications. However I have three problems:

1. I was too busy at work.
2. I could not find a lot of interesting applications that are interesting to proxy and can showcase different Burp functionalities that we talked about.
3. I found some interesting applications but there were security vulns so I am going through disclosure (unfortunately I may never be able to release them publicly).

The last point was a surprise, these are decently popular apps and I could not believe that no one has looked at them before.

Nevertheless, I will continue soon.

In the meanwhile, Burp version `1.7` has been [released](http://releases.portswigger.net/). Now we have Burp projects. Instead of saving the state everyday, we can use one project file that contains all the items. Pretty cool. Some of the items have changed, especially options. Now it has `User Options` and `Project Options` but the options by themselves are still there.

<!--more-->
