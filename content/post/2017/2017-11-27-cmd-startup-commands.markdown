---
title: "cmd Startup Commands"
date: 2017-11-27T23:13:55-05:00
draft: false
toc: false
comments: true
categories:
- Windows
tags:
- cmd
---

This blog talks about how to run a command automatically every time you open a new command prompt on Windows.

1. Open registry.
2. Navigate to the following location:
    - `HKCU\Software\Microsoft\Command Processor`
3. Double click `Autorun` and type in your command. For example:
    - `cd /d C:\Users\IEUser\Desktop\Whatever\`
4. If the `Autorun` property is missing, create one with type `REG_SZ`.
5. Now every cmd will automatically cd to the `Whatever` directory.

I am going to keep blogging consistently (hopefully). This means breaking my habit of having to write extensive blog posts.

<!--more-->
