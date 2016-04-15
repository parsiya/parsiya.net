---
categories:
- Not Security
- Migration to Hugo
comments: true
date: 2016-04-14T20:45:15-04:00
draft: false
tags:
- Cloudfront
- Amazon
- S3
- TLS
- Blog
title: "Cloudfront and TLS"
toc: false
---
I finally decided to cave in and take advantage of the Amazon Cloudfront free TLS certificate. I know I will end up paying more than what I already do but I pay few bucks each month. Each month I pay one dollar for two hosted zones and another dollar or so for the bandwidth. Even if I was still in my home country, I would have been able to pay this as it is less than a large pizza even where I lived.

If you are interested in free hosting alternatives, you can use [Github-pages](https://gohugo.io/tutorials/github-pages-blog/), [Bitbucket](https://gohugo.io/tutorials/hosting-on-bitbucket/) or just go with the excellent [Gitlab-Pages](https://gitlab.com/pages/hugo) (which supports Hugo and whole lot of other static website generators natively).

It took me a lot of tries and probably burning a good amount of money on Cloudfront invalidation requests (otherwise I had to wait for a day or so to see the changes) but it finally worked. The trick was to setup the origin policy during creation of the distribution as it cannot be modified through the web portal after that.

Burp part five is still on hold for now because I am doing something else.

<!--more-->
