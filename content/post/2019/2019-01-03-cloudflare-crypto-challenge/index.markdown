---
title: "Cloudflare Concise Christmas Cryptography Challenges 2019 Solutions"
date: 2019-01-03T20:24:15-05:00
draft: false
toc: true
comments: true
twitterImage: 04-rpki.png
categories:
- Crypto
- CTF
---

Cloudflare had a [Christmas crypto(graphy) challenge](https://blog.cloudflare.com/christmas-cryptography-challenges-2019/). Here are my solutions. The first two questions were pretty easy but the 3rd sent me down on a rabbit hole. Apparently, only 15 people solved it which places me in the world top 15 cryptographers (that's how it works right?).

<!--more-->

# Client says Hello
The packet is a raw `ClientHello` (not completely but let's not debate that). `ClientHello` is the first part in the 3-way TLS handshake (don't mix it up with the 3-way TCP handshake).

Dropping it into CyberChef and applying `From Hex` filter shows us an interesting payload. Supposedly SNI but I did not check the format of the packet.

SNI stands for Server Name Indication. It's a way for the client to tell a virtual host what certificate to use for communication. Read about it:

* [How HTTP Proxies Work - CloudFront and Server Name Indication]({{< relref "post/2016/2016-07-24-thickclient-proxying-6-how-proxies-work.markdown#4-cloudfront-and-server-name-indication" >}} "How HTTP Proxies Work - CloudFront and Server Name Indication")

On the Cloudflare blog we can read about encrypting the SNI to prevent privacy leaks:

* https://blog.cloudflare.com/encrypted-sni/

The result from Cyberchef looks like this:

```
....¬.xOC}¿Ç..E..òV.@.@.ÛX¬. ÈCÇø.Ñ÷.»È²¯4Iµ.u...*r§.....
g[Î.xz½.....¹...µ..\.¥iÕöMóØc
è½ÝÑ..uõ(®W}$6..èÞ·....D.ÿÀ,À+À$À#À
À	À.À0À/À(À'À.À.À......k.g.9.3.......=.<.5./.
.¯.®.........H.....	...cfl.re.
.................
.....................................R0VUIC8yQWRLemdCClRFWFQgT04gTElORVMgNCBBTkQgNQ==
```

{{< imgcap title="From Hex applied to the payload" src="01-fromhex.png" >}}

Base64 decode the payload:

```
GET /2AdKzgB
TEXT ON LINES 4 AND 5
```

Combine it with `clf.re` (included in the raw data) to get https://cfl.re/2AdKzgB which redirects to https://www.cloudflare.com/robots.txt.

```
#    .__________________________.
#    | .___________________. |==|
#    | | ................. | |  |
#    | | ::[ Dear robot ]: | |  |
#    | | ::::[ be nice ]:: | |  |
#    | | ::::::::::::::::: | |  |
#    | | ::::::::::::::::: | |  |
#    | | ::::::::::::::::: | |  |
#    | | ::::::::::::::::: | | ,|
#    | !___________________! |(c|
#    !_______________________!__!
#   /                            \
#  /  [][][][][][][][][][][][][]  \
# /  [][][][][][][][][][][][][][]  \
#(  [][][][][____________][][][][]  )
# \ ------------------------------ /
#  \______________________________/
```

**Answer: Lines 4 and 5 say `Dear Robot be nice`.**

# TOTP
Convert each of those times into a Unix timestamp. We can use Cyberchef again:

{{< imgcap title="Dates converted to time" src="02-timestamps.png" >}}

The hints say it's using TOTP w/o a secret. TOTP is a modified version HOTP that uses timestamps. Long story short, you use a shared secret to calculate an HMAC (SHA-1 by default) of counter and secret. Then convert the result to six digits for usage. The counter is the number of durations (usually `30` seconds) since the start (usually it's `0` epoch). This means each code will be valid for 30 seconds.

Cyberchef has a TOTP and HOTP module but it creates it does not support generation without a secret. If a secret is not provided, it will generate a random secret and use that.

We can use a Go package [github.com/pquerna/otp/totp](https://github.com/pquerna/otp/totp) to test our theory. January 1st 2019 is `1546300800` and plugging it into the code gives us the result.

``` go
package main

import (
	"fmt"
	"time"

	"github.com/pquerna/otp/totp"
)

func main() {

	time1 := time.Unix(1545409768, 0)
	fmt.Println(time1.UTC())

	str1, _ := totp.GenerateCode("", time1)
	fmt.Println(str1)

	time2 := time.Unix(1546300800, 0)
	str2, _ := totp.GenerateCode("", time2)
	fmt.Println(str2)
}
```

**Answer: `301554`.**

{{< imgcap title="Output of Go code" src="03-totp.png" >}}

# RPKI
I wasted five hours on this one.

Using the hints:

* Hint #0: Four or six? Probably six.
  * Cloudflare supports both IPv4 and IPv6 addresses. We should be looking for IPv6 addresses.
* Hint #1: If only there was a way of listing only our IPs!
  * IP addresses are here: https://www.cloudflare.com/ips/
  * Only IPv6 addresses: https://www.cloudflare.com/ips-v6
* Hint #2: What is the only part of the ROA where we can hide information into?
  * ROA has four fields: ASN, Prefix, Maximum Length, Trust Anchor (TA),
  * They are using ASN.
* Hint #3: Subtract the reserve, the char will show itself.
  * See below. We did not really need to do any subtracting.

Plugin IPv6 addresses into this website http://ripeval.labs.lacnic.net:8080/roas. You can also run a local version of it using https://github.com/RIPE-NCC/rpki-validator-3.

Searching for `2803:f800::/32` we get some interesting results:

{{< imgcap title="Funky looking ASNs" src="04-rpki.png" >}}

If you have looked at ASCII codex in Hex or Decimal long enough, you can see the last digits are printable Decimal ASCII characters.

```
97      a
98      b
111     o
114     r
118     v
```

This doesn't make any sense. So I thought maybe we need to subtract `42` from them (`subtract the reserve` in the hints). Which gives us:

```
97	    a	    55      U
98	    b	    56	    V
111	    o	    69	    E
114	    r	    72	    H
118	    v	    76	    L
```

This does not make any sense either. Now, look at the prefixes. They end with a single digit from 1 to 5. Sorting by prefix we get `bravo` or `VHULE` if you do the subtracting. **I went with `bravo`.**

# Lessons Learned from The RPKI Challenge
I wasted five hours going around the internet for the third challenge. The first three hints were easy. The whole challenge up to that moment had taken only five minutes (that's not a brag, it's very easy). But then I got stuck. Note the solution prefixes do not show up in any of the following places.

So `Route Origin Authorisation` or ROA is an object that is signed by a CA. It's using the x509 ecosystem and five root CAs to sign these announcements (one for each region). This supposedly reduces BGP hijacking. I do not know enough to give you a good explanation so please read their blog post and other resources:

* https://blog.cloudflare.com/rpki/

### Cloudflare Cirrus
My train of thought was "Ok, they are signing certificate like objects" (ROAs are not certificates but they are signed). Cloudflare has a certificate transparency log for ROAs called Cirrus at https://ct.cloudflare.com/logs/cirrus.

Supposedly, you can get the logs but how? The page does not have anything. 15 minutes of searching and I realized the `get-entries` and other items in the left side bar are REST style endpoints. There's an RFC at https://tools.ietf.org/html/rfc6962.

Jump down to [page 20](https://tools.ietf.org/html/rfc6962#page-20) to see `get-entries`:

`GET https://<log server>/ct/v1/get-entries?start=1234&end=5678`

Looking at their status page I saw two certificates were recently enrolled (20th and 21st December 2018). These must be the new certificates, right?

{{< imgcap title="New certificates added to the Cirrus certificate transparency log" src="05-cirrus.png" >}}

There were `7906` certificates in the log. We can access each of the individual entries or search for ranges, so to get the last six entries we can use this GET request:

* https://ct.cloudflare.com/logs/cirrus/ct/v1/get-entries?start=7900&end=7906

Which gives us this big JSON file, the keys are discussed in the RFC on the same page. Unfortunately, neither of them are the certificate:

* `leaf_input` is the Merkle Tree.
* `extra_data` is the chain.

We can decode them from base64 to get the underlying item but it's not what we want.

### gortr
Cloudflare is a Go shop and they have this utility: https://github.com/cloudflare/gortr.

I do not know enough to tell you what it does but it has a link to this file:

* https://rpki.cloudflare.com/rpki.json

It has records like this:

``` json
{"prefix":"157.119.101.0/24","maxLength":24,"asn":"AS3177","ta":""}
```

I looked up Cloudflare's IPv6 addresses to find the ASNs. Nothing looked out of the ordinary.

### BGPMON Whois
I also stumbled upon this blog:

* https://bgpmon.net/securing-bgp-routing-with-rpki-and-roas/

We can get ROA information from this whois server. Plugging the prefixes from the `rpki.json` file or any other place we can see the results:

```
$ whois -h whois.bgpmon.net 2400:cb00:151::/48
% This is the BGPmon.net whois Service
% You can use this whois gateway to retrieve information
% about an IP adress or prefix
% We support both IPv4 and IPv6 address.
%
% For more information visit:
% http://bgpmon.net/bgpmonapi.php

Prefix:              2400:cb00:151::/48
Prefix description:  101 Townsend Street, San Francisco, California 94107, US
Country code:        US
Origin AS:           13335
Origin AS Name:      Cloudflare Inc
RPKI status:         ROA validation successful
First seen:          2018-12-21
Last seen:           2018-12-26
Seen by #peers:      57
```

There's a typo in line 4 (`adress`) that is bugging me but we get some info. Next, we can plug the ASN and prefix into this other command:

```
$ whois -h whois.bgpmon.net " --roa 13335 2400:cb00:151::/48"
0 - Valid
------------------------
ROA Details
------------------------
Origin ASN:       AS13335
Not valid Before: 2018-11-29 20:32:10
Not valid After:  2019-07-30 00:00:00  Expires in 214d16h22m30s
Trust Anchor:     rpki.apnic.net
Prefixes:         2400:cb00:11::/48 (max length /48)
                  2400:cb00:2048::/48 (max length /48)
                  2400:cb00:27::/48 (max length /48)
                  2400:cb00:120::/48 (max length /48)
                  2400:cb00:42::/48 (max length /48)
                  2400:cb00:174::/48 (max length /48)
```

You don't even need the first command. Simply send the second command with any ROA and the output will correct you:

```
$ whois -h whois.bgpmon.net " --roa 123456 2400:cb00:151::/48"
2 - Not Valid: Invalid Origin ASN, expected 13335
```

I plugged in Cloudflare's IPv6 IP and could not find anything fishy there. The solution prefixes are not found here either.

```
$ whois -h whois.bgpmon.net 2803:f800:cfcf:cfcf:cfcf:cfcf:cfcf:3/128
Prefix not found
```

Seems like we can also use this whois server:

* https://www.ripe.net/analyse/archived-projects/ris-tools-web-interfaces/riswhois

```
$ whois -h riswhois.ripe.net 2400:cb00:151::/48
% This is RIPE NCC's Routing Information Service
% whois gateway to collected BGP Routing Tables, version2.0
% IPv4 or IPv6 address to origin prefix match
%
% For more information visit http://www.ripe.net/ris/riswhois.html
%
% Connected to backend ris-whois12.ripe.net

route6:       2400:cb00:151::/48
origin:       AS13335
descr:        CLOUDFLARENET - Cloudflare, Inc., US
lastupd-frst: 2018-10-03 06:11Z  2001:478:124::241@rrc16
lastupd-last: 2018-12-26 23:34Z  2001:7f8:4::9471:1@rrc01
seen-at:      rrc00,rrc01,rrc03,rrc04,rrc05,rrc06,rrc07,rrc10,rrc11,rrc12,rrc13,rrc14,rrc15,rrc19,rrc20,rrc21,rrc23
num-rispeers: 211
source:       RISWHOIS
```

And again, nothing there for the fishy prefixes:

```
$ whois -h riswhois.ripe.net 2803:f800:cfcf:cfcf:cfcf:cfcf:cfcf:3/128
% This is RIPE NCC's Routing Information Service
% whois gateway to collected BGP Routing Tables, version2.0
% IPv4 or IPv6 address to origin prefix match
%
% For more information visit http://www.ripe.net/ris/riswhois.html
%
% Connected to backend ris-whois04.ripe.net

% No entries found
```

### rsync://rpki.ripe.net/repository/
Validators use `rsync` to get all the certificates and ROAs. We can get them manually too.

```
$ rsync -av rsync://rpki.ripe.net/repository/ .
```

The `v` switch prints everything, and there are a ton of files being downloaded so I removed it. The result is this huge lot of certificates, ROAs, CRLs, and other stuff. Seriously, there were 40000+ files in 14000 folders. There was no way that I could parse all of these and figure out the solution so I gave up there.

```
│   2a7dd1d787d793e4c8af56e197d4eed92af6ba13.cer
│   ripe-ncc-ta.crl
│   ripe-ncc-ta.mft
│
├───aca
│       HGp1AESLbyiopScGy7yW4b6s_T4.cer
│       Kn3R14fXk-TIr1bhl9Tu2Sr2uhM.crl
│       Kn3R14fXk-TIr1bhl9Tu2Sr2uhM.mft
│
└───DEFAULT
    │   0-sjfvx8LHPCPmrwyaX3vz51CQw.cer
    │   0-SVCv6AXz7c9M8RLlcYO_0ALFY.cer
    │   01qjZwczxpcrS5FhVwvd6aIPlTU.cer
    │   01Z_Y4Iw6KiE7J_X-uTLSRwv_eU.cer
    │   03l7bVyOqC4v44GDY6-4JscZKOc.cer
    │   03z5DDj2eKrXwsVXQmiNpZ9pzis.cer
    │   04kZ4OLyGlSKdZHdOvDg_k7YO_g.cer
    │   05BnEzOQAuBsZwwCI4CEJmVs0L4.cer
```

If you wanna know what these files are, navigate to this page https://www.ripe.net/publications/docs/ripe-549#Repositories and scroll up.

{{< imgcap title="Description of files downloaded via rsync" src="06-rsync-files.png" >}}

I wanted to parse the ROA files and see if I can grab any information from inside them but I gave up. There might be some support here:

* https://github.com/google/certificate-transparency-go/blob/master/x509/rpki.go

Seems like that is a fork of the x509 package aimed for working with certificate transparency logs.
