---
title: "Windows XP 32-bit SP3 Virtual Machines"
date: 2017-12-19T19:45:22-05:00
draft: false
toc: false
comments: true
categories:
- Windows
tags:
- XP
- virtual machine
---

There used to be Windows XP virtual machines on [modern.ie](https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/). I still have a couple of copies around for testing. Unfortunately after XP going out of support, they were removed. But the copies used to be on [Azure CDN](https://www.reddit.com/r/AskNetsec/comments/6qea8a/need_a_windows_xp_iso/dkwq0qw/) (credit [/u/JoshBrodieNZ](https://www.reddit.com/user/JoshBrodieNZ). Seems like they recently removed them too.

There's still a way to get Windows XP 32-bit VMs from Microsoft (no 64-bit) through Windows XP mode. It contains a VHD (virtual hard disk) with a 32-bit Windows XP SP3.

1. Download Microsoft XP Mode from https://www.microsoft.com/en-us/download/details.aspx?id=8002.
2. Using 7-zip or any other utility decompress the exe.
3. Inside sources, there's another file called `xpm`. Decompress it too. With 7-zip, right click on it and select "Extract to ... ."
4. One of the extracted files is `VirtualXPVHD` and around 1.2 GB. Rename it to `VirtualXP.vhd`.
5. In VirtualBox (or any other virtualization software that supports importing VHDs), create a new Windows XP 32-bit VM and use this file as the hard disk. When you start the VM, it will start a Windows XP setup. My mouse did not work, but you can use shortcut keys to navigate the installer (e.g. Alt+N for Next).
6. ???
7. Profit.

For a step by step guide with pictures, check [this post](https://www.howtogeek.com/howto/12183/how-to-run-xp-mode-in-virtualbox-on-windows-7/) from howtogeek.com.

<!--more-->