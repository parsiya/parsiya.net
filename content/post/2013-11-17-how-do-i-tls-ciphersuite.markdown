---
categories:
- TLS
- Ciphersuites
- AES
- RC4
comments: true
date: 2013-11-17T00:00:00Z
title: How do I TLS Ciphersuite?
---

“Should we use RC4 or AES-CBC ?”
This is a legitimate question. Many have heard of the highly publicized attacks against AES-CBC (CRIME, BEAST etc) and lean towards RC4. 
If asked (granted no one asks me), my answer would be: If you can control web servers (not feasible in all situations) and users’ browsers 
(almost impossible), upgrade to TLS 1.2 and go with AES-GCM. However, not many browsers supported these and to be honest, more users trumps loss 
of security in many cases.

<!--more-->

RC4 was a masterpiece for its time (it still is) but it has extreme biases in its PRNG and attacks are prevalent [[1]][link1] and because it only takes a 
seed (with no nonce), if a key is re-used, one can find the XOR of plaintexts by XOR-ing two ciphertexts. 
A recent demonstration of this weakness was in the popular “Whatsapp” application where the same key was used in both directions [[2]][link2]. Granted 
This was an application design flaw but Whatsapp has quite the security history (google Whatsapp and IMEI).

A few days ago Microsoft released security advisory 2868725 “Recommendation to disable RC4.” 
They found out that less than 4% of their 5 million sample websites only worked with RC4 (although from my personal experience RC4 share is 
probably higher) [[3]][link3].

Major browsers are also starting to support TL2 1.2 and AES-GCM.
Chrome has had TLS 1.2 support for a while (Since Chrome 29) [[4]][link4] and Chrome 31 (released a few days ago) has support for AES-GCM [[5]][link5].

Firefox has implemented TLS 1.2. [[6]][link6] and AES-GCM [[7]][link7].

IE 11 turns TLS 1.2 on by default [[8]][link8].

A day after I wrote the draft of this blog post, Adam Langley (author of patches in links [4][link4] and [5][link5]) wrote a blogpost named 
"A roster of TLS cipher suites weaknesses" [[9]][link9]. He discusses the strengths and weaknesses of the aforementioned three different ciphersuites 
(RC4, AES-CBC and AES-GCM) on top of Chacha20,Poly1305 (if you do not know why the numbers are not powers of 2, google it :D).

tl;dr: seems like AES-GCM is the flavor of the month. More and more browsers are supporting it, it may be a good time to start moving towards it.

PS: I know, I will get the contact page fixed soon (tm).

[link1]: http://www.isg.rhul.ac.uk/tls/
[link2]: https://blog.thijsalkema.de/blog/2013/10/08/piercing-through-whatsapp-s-encryption/ "Octopress FTW"
[link3]: http://blogs.technet.com/b/srd/archive/2013/11/12/security-advisory-2868725-recommendation-to-disable-rc4.aspx
[link4]: https://src.chromium.org/viewvc/chrome?revision=203090&view=revision
[link5]: https://src.chromium.org/viewvc/chrome?revision=217716&view=revision
[link6]: https://bugzilla.mozilla.org/show_bug.cgi?id=861266
[link7]: https://bugzilla.mozilla.org/show_bug.cgi?id=880543
[link8]: http://blogs.msdn.com/b/ie/archive/2013/11/12/ie11-automatically-makes-over-40-of-the-web-more-secure-while-making-sure-sites-continue-to-work.aspx (has some good information in between IE propaganda)
[link9]: http://googleonlinesecurity.blogspot.com/2013/11/a-roster-of-tls-cipher-suites-weaknesses.html
