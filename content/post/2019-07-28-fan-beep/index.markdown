---
title: "Disabling Cascade Fan's Beep"
date: 2019-07-28T13:23:50-07:00
draft: false
toc: false
comments: true
twitterImage: 12.jpg
categories:
- Not security
- Hardware
---

**TL;DR**:

1. Open 11 screws.
2. Remove the cap on the buzzer.
3. Done.

<!--more-->

The [Cascade Personal Fan][cascade-link] has a very loud beep. I disabled the
beep by removing the cap from the buzzer. I am documenting my steps because in
my quest, I saw a lot of people with the same issue.

We got a 2-pack from Costco and while the fan is very quiet, the beep is quite
loud. Seems like everyone else has the same issue with this fan. All we need is
a number 3 Philips screwdriver.

{{< imgcap title="The box" src="01.jpg" >}}

There are two of them in the pack (because of course, it's Costco):

{{< imgcap title="One fan" src="02.jpg" >}}

First, we start with these four screws in the back.

{{< imgcap title="Four screws in the back" src="03.jpg" >}}

We can see the control board:

{{< imgcap title="Back opened" src="04.jpg" >}}

We need to remove another three screws:

{{< imgcap title="Closer look at the top" src="05.jpg" >}}

Can't really remove the connection with the board screwed to the top. We need to
remove four more screws:

{{< imgcap title="Top detached" src="06.jpg" >}}

A closer look at the board (open the image in a new tab for a larger view):

{{< imgcap title="Control board" src="07.jpg" >}}

On the back of the board, we see:

* `Home Star international Ltd`
* `25400640000 V002`

{{< imgcap title="Back of the board" src="08.jpg" >}}

We see a [Piezo][piezo-wiki] buzzer (I had to Google the type) marked with
`ZLFY`. Looking around the internet, it seems like many household items use
these buzzers and a lot of people are annoyed with the sounds. I saw guides on
how to remove these buzzers for many items.

{{< imgcap title="Buzzer" src="09.jpg" >}}

The second result for searching `ZLFY` is the datasheet. It appears to be a
`ZLFY ZL-YDW12055-4005PA-7.5`:

* https://lcsc.com/product-detail/Buzzers_ZLFY-ZL-YDW12055-4005PA-7-5_C219730.html

I used a flathead screwdriver to pop the buzzer cap:

{{< imgcap title="Buzzer's cap" src="10.jpg" >}}

Having given away my soldering kit before the move, I was thinking I needed to
unsolder the buzzer but the cap was actually easy to remove:

{{< imgcap title="Buzzer's cap is a moved a bit" src="11.jpg" >}}

And done:

{{< imgcap title="Cap removed" src="12.jpg" >}}

Enjoy no beeps and add `Hardware Hacking` to your resume /s.

<!-- Links -->
[cascade-link]: https://www.walmart.ca/en/ip/Cascade-33-cm-13-in-Personal-Fan-2-pack/PRD2FQDH6BDOW60
[piezo-wiki]: https://en.wikipedia.org/wiki/Buzzer#Piezoelectric_2