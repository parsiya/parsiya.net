---
title: "\"Hacking\" Car Mechanic Simulator 2015"
date: 2017-11-29T20:29:30-05:00
draft: false
toc: false
comments: true
categories:
- Game Hacking
tags:
- Car mechanic simulator 2015
---

Not real hacking!

**Tl;dr:**

1. Open this file with a hex editor:
    - `\AppData\LocalLow\Red Dot Games\Car Mechanic Simulator 2015\profile#\global`
2. Search for `money` and `xp`.
3. Locate the int32 value of each property in little-endian.
4. Convert your current XP and money to hex to make the search easier.
5. Overwrite them with`6F FF FF FF`.
6. ???
7. You have "hacked" the game.

It does not get easier than this.

<!--more-->

<!-- MarkdownTOC -->

- [Background](#background)
- [The Game](#the-game)
- [Savegame Location](#savegame-location)
- [How Stats are Stored](#how-stats-are-stored)
- [What did We do Wrong?](#what-did-we-do-wrong)
- [Signed Int32 Representation](#signed-int32-representation)
- [Very Money, Much Experience](#very-money-much-experience)
- [Integer Overflow](#integer-overflow)

<!-- /MarkdownTOC -->


<a name="background"></a>
## Background
Savegame editing is perhaps the oldest (and most basic) variant of game hacking. One of the reasons I went into security (or got decent at reverse engineering file formats) was computer games.

I used to play the original version of [Heroes of Might and Magic][heroes-gog]. I usually rushed to get a few units. Split them into arbitrary stacks (e.g. 2 archers in slot 1, 3 in slot 2 and so on), then looked in the savegame for those numbers and modified the count to `FF`. Voila, I had 255 of every unit.

This is exactly what we are going to do here too.

<a name="the-game"></a>
## The Game
Over the thanksgiving weekend I got [Car Mechanic Simulator 2015][car-mechanic-2015-steam] for 2 dollars in the Steam sale. I played it for around 10 hours (that's 20 cents per hour which is quite the bargain :D). It's a good game but it has a lot of grinding[^1].

<a name="savegame-location"></a>
## Savegame Location
First item is to locate the savegame which brings us to this [Steam community thread][savegame-thread]. They are at:

- `\AppData\LocalLow\Red Dot Games\Car Mechanic Simulator 2015\`

Each `profile#` directory will contain a different profile.

Note the developer is claiming the file is encrypted `try to hack'em :) good luck with decrypting`. It's not encrypted. I am not trying to shit on the dev, it's a good game.

<a name="how-stats-are-stored"></a>
## How Stats are Stored
When editing savegames, chances are numbers are saved in hex (or decimal). Convert them into hex and grep.

{{< imgcap title="Starting money and XP" src="/images/2017/car-mechanic-2015/01-starting.jpg" >}}

Currently we have $2000 (`0x07D0`) and `1` experience. Now we can grep for the money like this `grep -arb $'\x07\xd0'` but won't find anything. You need to remember endian-ness or you could just search for the word `money`:

{{< codecaption title="Grep for little-endian money" lang="nasm" >}}
$ grep -arb $'\xd0\x07'
global:631:▒▒▒▒{~gameVer▒▒▒▒▒1.1.6.0{~date▒▒▒▒▒2017-11-28 22:56:20{

$ grep -arb money
global:610:▒▒▒{~money
{{< /codecaption >}}

Offset `631` is `0x277`. Open the file with a hex editor such as [HxD][hxd-website].

{{< imgcap title="Global file in hex editor" src="/images/2017/car-mechanic-2015/02-inside-global.png" >}}

This seems to be a serialized Unity file according to [DisUnity][disunity-github]. But we do not care about the format, we want to edit XP and money to unlock auctions.

We can see our XP and money as an int32 (aka 4 bytes) in little-endian (first byte is the LSB). Replace them with whatever you want (remember they are in hex). For example I am going to max out everything with `FF FF FF FF`.

{{< imgcap title="Editing money and XP with FF FF FF FF" src="/images/2017/car-mechanic-2015/03-global-edited.png" >}}

Well that did not work out as expected:

{{< imgcap title="Oops" src="/images/2017/car-mechanic-2015/04-after-edit1.jpg" >}}

<a name="what-did-we-do-wrong"></a>
## What did We do Wrong?
We assumed that a variable representing XP or money is going to be an unsigned int (well money is debatable as games usually use negative balance to indicate debt). But these are signed int32s.

<a name="signed-int32-representation"></a>
## Signed Int32 Representation
We already know how signed ints are stored. Most significant bit or `msb` (note the lowercase `b` and do not confuse it with most significant byte or `MSB`) is sign:

- `0`: Number is positive. Rest of bits represent the number.
- `1`: Number is negative. Rest of bits represent two's complement of absolute value of number.

Two's complement is created simply by flipping all the bits and then adding by one. So `FF FF FF FF` is `-1`. 

<a name="very-money-much-experience"></a>
## Very Money, Much Experience
To get the max signed int32 positive number we need to keep the first bit as `0` and set the rest to `1`. Take the last byte (first byte to the left) and convert it to bits `1111 1111`. Flip the first bit to the left (or msb) to get `0111 1111` or `7F`. So max int32 is `7F FF FF FF`.

{{< imgcap title="Editing money and XP again" src="/images/2017/car-mechanic-2015/05-global-edit-2.png" >}}

You do not need to exit the game every time, go to the main menu between edits.

{{< imgcap title="Much experience!" src="/images/2017/car-mechanic-2015/06-much-experience.jpg" >}}

<a name="integer-overflow"></a>
## Integer Overflow
However, this is not a good number. If you earn one dollar or XP, int32 will overflow and you are left with min int32 number `80 00 00 00` (MSB: `1000 0000`).

{{< imgcap title="Much experience!" src="/images/2017/car-mechanic-2015/07-int32-underflow.jpg" >}}

Just do `7F 00 00 00` to unlock everything.

{{< imgcap title="Master guru ji mechanic" src="/images/2017/car-mechanic-2015/08-monies.jpg" >}}

<!-- Footnotes -->

[^1]: I have other issues with the game. For example ordering parts is a pain because you have to do them one by one. But this is not a game review.

<!-- Links -->

[heroes-gog]: https://www.gog.com/game/heroes_of_might_and_magic
[car-mechanic-2015-steam]: http://store.steampowered.com/app/320300/Car_Mechanic_Simulator_2015/
[savegame-thread]: https://steamcommunity.com/app/270850/discussions/0/558746089536162358/
[hxd-website]: https://mh-nexus.de/en/hxd/
[disunity-github]: https://github.com/ata4/disunity/wiki/Serialized-file-format
