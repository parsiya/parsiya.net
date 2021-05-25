---
title: "Some SANS Holiday Hack 2020 Solutions"
date: 2021-01-17T11:33:47-08:00
draft: false
toc: false
comments: true
twitterImage: .png
categories:
- Writeup
---

This year like last year and unlike 2018, I only did a few of the SANS Holiday
Hack challenges. I got invited into this private bug bounty program with a
desktop application in scope (those are quite rare) so I had to poke at it. To
be fair, I hit the motherlode and submitted $10K of bounties.

Previous writeups:

* {{< xref path="/post/2019/2019-01-15-sans-holiday-hack-2018/" text="SANS Holiday Hack 2018 Solutions" >}}
* {{< xref path="/post/2020/2020-01-15-sans-holiday-hack-2019/" text="Some SANS Holiday Hack 2019 Solutions" >}}

<!--more-->

**Table of Contents:**

{{< toc >}}

# Objective 1 - Uncover Santa's Gift List
Talk to Jingle Ringford at the bottom of the mountain for advice.

On the billboard there is a picture of the desk. Santa's list is "obfuscated."
What is the name? Swirl? We need to undo it.

We cut and paste the part of the billboard with the text into a new image and do
it.

https://cybercop-training.ch/?p=457 has some info.

I unswirled it with paint.net (`Effects > Distort > Twist`) and the result was `Proxmark`.

{{< imgcap title="List from the billboard" src="01-billboard-crop.png" >}}

# Castle Entrance
Go to the castle entrance. Picked up broken candy cane at the door.

# Objective 2 - Investigate S3 Bucket

```
When you unwrap the over-wrapped file, what text string is inside the package?
Talk to Shinny Upatree in front of the castle for hints on this challenge.
```

Shinny Upatree

```
Hiya hiya - I'm Shinny Upatree!

Check out this cool KringleCon kiosk!

You can get a map of the castle, learn about where the elves are, and get your
own badge printed right on-screen!

Be careful with that last one though. I heard someone say it's "ingestible." Or
something...
```

The challenge: `Escape the menu by launching /bin/bash`

Option 4 is vulnerable to command injection. Solution: `1;/bin/bash`.

We can also get a text map of the castle.

```
Enter choice [1 - 5] 1
 __       _    --------------                                                
|__)_  _ (_   | NetWars Room |                                               
| \(_)(_)|    |              |                                               
              |            * |                                               
               --------------                                                
                                                                             
__  __                              __  __                                   
 _)|_                                _)|_          -------                   
/__|        Tracks                  __)|          |Balcony|                  
            1 2 3 4 5 6 7                          -------                   
 -------    -------------                             |                      
|Speaker|--| Talks Lobby |                        --------                   
|Unprep |  |             |                       |Santa's |                  
 -------    ------       |                       |Office  |                  
                  |      |                        --    --                   
                  |     *|                          |  |                     
                   ------                           |   ---                  
                                                    |    * |                 
    __                                               ------                  
 /||_                                                                        
  ||                                          __ __           --------       
  --------------------------              /| |_ |_           |Wrapping|      
 |        Courtyard         |              |.__)|            |  Room  |      
  --------------------------                                  --------       
    |                    |                                       |           
 ------    --------    ------                          ---    --------       
|Dining|--|Kitchen |--|Great |                            |--|Workshop|      
|      |   --------   |      |                            |  |        |      
| Room |--|      * |--| Room |                            |  |        |      
|      |  |Entryway|  |      |                            |  |        |      
 ------    --------    ------                             |  |        |      
               |                                             | *      |      
           ----------                                         --------       
          |Front Lawn|       NOTE: * denotes Santavator 
```

Directory

```
Name:               Floor:      Room:
Bushy Evergreen     2           Talks Lobby
Sugarplum Mary      1           Courtyard
Sparkle Redberry    1           Castle Entry
Tangle Coalbox      1           Speaker UNPreparedness
Minty Candycane     1.5         Workshop
Alabaster Snowball  R           NetWars Room
Pepper Minstix                  Front Lawn
Holly Evergreen     1           Kitchen
Wunorse Openslae    R           NetWars Room
Shinny Upatree                  Front Lawn
```

A secret?

```
$ cat /opt/plant.txt
  Hi, my name is Jason the Plant!

  ( U
   \| )
  __|/
  \    /
   \__/ ejm96

$ cat .bashrc
export PAGER=less
export PATH=/usr/games:$PATH
/home/elf/runtoanswer WelcomeToSantasCastle
cat /opt/success.txt
sleep 2
```

Hint after success:

```
Do you think you could check and see if there is an issue?
Golly - wow! You sure found the flaw for us!
Say, we've been having an issue with an Amazon S3 bucket.
Do you think you could help find Santa's package file?
Jeepers, it seems there's always a leaky bucket in the news. You'd think we
could find our own files!
Digininja has a great guide, if you're new to S3 searching.
He even released a tool for the task - what a guy!
The package wrapper Santa used is reversible, but it may take you some trying.
Good luck, and thanks for pitching in!
```

Maybe we need to watch his talk and use his tool to discover it? What is this
package and wrapper? Encryption?

```
Can you help me? Santa has been experimenting with new wrapping technology, and
we've run into a ribbon-curling nightmare!
We store our essential data assets in the cloud, and what a joy it's been!
Except I don't remember where, and the Wrapper3000 is on the fritz!

Can you find the missing package, and unwrap it all the way?
```

The wordlist provided with the tool has three names in it.


```
$ ./bucket_finder.rb wordlist
http://s3.amazonaws.com/kringlecastle
Bucket found but access denied: kringlecastle
http://s3.amazonaws.com/wrapper
Bucket found but access denied: wrapper
http://s3.amazonaws.com/santa
Bucket santa redirects to: santa.s3.amazonaws.com
http://santa.s3.amazonaws.com/
        Bucket found but access denied: santa
```

Wrapper is reversible as in we need to reverse the word? `repparw`. `repparw`
does not exist.

Bucket is `wrapper3000` based on the puzzle text. Add the text to the wordlist
with nano and run the tool.

```
http://s3.amazonaws.com/wrapper3000
Bucket Found: wrapper3000 ( http://s3.amazonaws.com/wrapper3000 )
        <Public> http://s3.amazonaws.com/wrapper3000/package
```

Go to the URL and get a file. It's base64 encoded, drop it into cyberchef and
see the magic `PK` header. It's a zip file.

After a few layers of compression we get to a file named `package.txt.Z.xz.xxd`.
Which is a hex dump of the file.

```
00000000: fd37 7a58 5a00 0004 e6d6 b446 0200 2101  .7zXZ......F..!.
00000010: 1600 0000 742f e5a3 0100 2c1f 9d90 4ede  ....t/....,...N.
00000020: c8a1 8306 0494 376c cae8 0041 054d 1910  ......7l...A.M..
00000030: 46e4 bc99 4327 4d19 8a06 d984 19f3 f08d  F...C'M.........
00000040: 1b10 45c2 0c44 a300 0000 0000 c929 dad6  ..E..D.......)..
00000050: 64ef da24 0001 452d 1e52 57e8 1fb6 f37d  d..$..E-.RW....}
00000060: 0100 0000 0004 595a                      ......YZ
```

Put the following in a file and open it?

```
fd37 7a58 5a00 0004 e6d6 b446 0200 2101
1600 0000 742f e5a3 0100 2c1f 9d90 4ede
c8a1 8306 0494 376c cae8 0041 054d 1910
46e4 bc99 4327 4d19 8a06 d984 19f3 f08d
1b10 45c2 0c44 a300 0000 0000 c929 dad6
64ef da24 0001 452d 1e52 57e8 1fb6 f37d
0100 0000 0004 595a
```

`package.txt.Z` contains `North Pole: The Frostiest Place on Earth`.

Solution: `North Pole: The Frostiest Place on Earth`.

# Objective 3 - Point-of-Sale Password Recovery
Help Sugarplum Mary in the Courtyard find the supervisor password for the
point-of-sale terminal. What's the password?

```
Sugarplum Mary? That's me!

I was just playing with this here terminal and learning some Linux!

It's a great intro to the Bash terminal.

If you get stuck at any point, type hintme to get a nudge!

Can you make it to the end?
```

## Linux Primer

```
$ ls
# ls /home/ is not an answer
$ cat munchkin_19315479765589239
munchkin_24187022596776786
$ rm munchkin_19315479765589239 
$ pwd
/home/elf
$ ls -alt
total 56
drwxr-xr-x 1 elf  elf   4096 Dec 11 03:43 .
-rw-r--r-- 1 elf  elf      0 Dec 11 03:43 .munchkin_5074624024543078
drwxr-xr-x 1 elf  elf  20480 Dec 10 18:19 workshop
-rw-r--r-- 1 elf  elf     31 Dec 10 18:18 .bash_history
drwxr-xr-x 1 root root  4096 Dec 10 18:14 ..
-rw-r--r-- 1 elf  elf   3105 Dec  5 00:00 .bashrc
-rw-r--r-- 1 elf  elf    168 Dec  5 00:00 HELP
-rw-r--r-- 1 elf  elf    220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 elf  elf    807 Apr  4  2018 .profile
$ cat .munchkin_5074624024543078
$ cat .bash_history 
echo munchkin_9394554126440791
$ env
...
z_MUNCHKIN=munchkin_20249649541603754
$ cd workshop/
$ grep -ir "munchkin"
toolbox_191.txt:mUnChKin.4056180441832623
$ chmod +x lollipop_engine 
$ ./lollipop_engine 
munchkin.898906189498077
$ mv blown_fuse0 fuse0
$ ln -s fuse0 fuse1
$ cp fuse1 fuse2
$ echo MUNCHKIN_REPELLENT > fuse2
$ find /opt/munchkin_den -iname "*munchkin*"
/opt/munchkin_den/apps/showcase/src/main/resources/mUnChKin.6253159819943018
$ find /opt/munchkin_den/ -user munchkin
/opt/munchkin_den/apps/showcase/src/main/resources/template/ajaxErrorContainers/niKhCnUm_9528909612014411
$ find /opt/munchkin_den/ -size +108k -size -110k
/opt/munchkin_den/plugins/portlet-mocks/src/test/java/org/apache/m_u_n_c_h_k_i_n_2579728047101724
$ ps -all
F S   UID   PID  PPID  C PRI  NI ADDR SZ WCHAN  TTY          TIME CMD
4 S  1051 12054 12051  1  80   0 - 21079 x64_sy pts/2    00:00:00 14516_munchkin
0 R  1051 12533   187  0  80   0 -  6931 -      pts/3    00:00:00 ps
$ netstat -tulpn
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:54321           0.0.0.0:*               LISTEN      12054/python3
# ping and wget were not available. The answer was curling
$ curl localhost:54321
munchkin.73180338045875
$ pkill 14516_munchkin 
```

After success. [lol Electron][psnow].

[psnow]: https://hackerone.com/reports/873614

```
You did it - great! Maybe you can help me configure my postfix mail server on Gentoo!
Just kidding!
Hey, wouldja' mind helping me get into my point-of-sale terminal?
It's down, and we kinda' need it running.
Problem is: it is asking for a password. I never set one!
Can you help me figure out what it is so I can get set up?
Shinny says this might be an Electron application.
I hear there's a way to extract an ASAR file from the binary, but I haven't looked into it yet.
```

Inside `santa-shop.exe` there is a file named `app-64.7z`. Extract it and we got
an Electron app. The only interesting parts of an Electron app on Windows are
inside the `resources` directory.

`asar e app.asar app.asar.extracted` to extract the asar file and look inside.

We are looking for a password so we just search for it and find
`const SANTA_PASSWORD = 'santapass';`

Solution: `santapass`.

----------

# Objective 4 - Operate the Santavator
Talk to Pepper Minstix in the entryway to get some hints about the Santavator.

```
Howdy - Pepper Minstix here!
I've been playing with tmux lately, and golly it's useful.
Problem is: I somehow became detached from my session.
Do you think you could get me back to where I was, admiring a beautiful bird?
If you find it handy, there's a tmux cheat sheet you can use as a reference.
I hope you can help!
```

```
$tmux ls
$tmux attach-session
```

After solving:

```
You found her! Thanks so much for getting her back!
Hey, maybe I can help YOU out!
There's a Santavator that moves visitors from floor to floor, but it's a bit wonky.
You'll need a key and other odd objects. Try talking to Sparkle Redberry about the key.
For the odd objects, maybe just wander around the castle and see what you find on the floor.
Once you have a few, try using them to split, redirect, and color the Super Santavator Sparkle Stream (S4).
You need to power the red, yellow, and green receivers with the right color light!
```

1. Talk to Sparkle Redberry about the key
2. Pickup odd objects.
3. Use them to split, redirect, and color the Super Santavator Sparkle Stream (S4).
4. Power the red, yellow, and green receivers with the right color light.

Make the green light pop and go to 2nd floor. Pick up the green light bulb.

With red and green we can go to the roof which is Netwars. Pick up the yellow
light bulb.

Then we put the candy cane at the bottom and the nut at the top. The light bulbs
near the receptor. Now we can access Santa's office and objective 4 is complete.

# Objective 5 - Open HID Lock
Open the HID lock in the Workshop. Talk to Bushy Evergreen near the talk tracks
for hints on this challenge. You may also visit Fitzy Shortstack in the kitchen
for tips.

```
Ohai! Bushy Evergreen, just trying to get this door open.
It's running some Rust code written by Alabaster Snowball.
I'm pretty sure the password I need for ./door is right in the executable itself.
Isn't there a way to view the human-readable strings in a binary file?
```

Speaker UNPrep challenge:

```
Help us get into the Speaker Unpreparedness Room!
The door is controlled by ./door, but it needs a password! If you can figure
out the password, it'll open the door right up!
Oh, and if you have extra time, maybe you can turn on the lights with ./lights
activate the vending machines with ./vending-machines? Those are a little
trickier, they have configuration files, but it'd help us a lot!
(You can do one now and come back to do the others later if you want)
We copied edit-able versions of everything into the ./lab/ folder, in case you
want to try EDITING or REMOVING the configuration files to see how the binaries
react.
Note: These don't require low-level reverse engineering, so you can put away IDA
and Ghidra (unless you WANT to use them!)
```

## door

Run `strings`

```
$ strings -n 10 ./door | grep -i "pass"
/home/elf/doorYou look at the screen. It wants a password. You roll your eyes - the 
password is probably stored right in the binary. There's gotta be a
Be sure to finish the challenge in prod: And don't forget, the password is "Op3nTheD00r"
Beep boop invalid password
```

Solution: `Op3nTheD00r`.

After solving the door, Bushy says:

```
hat's it! What a great password...
Oh, this might be a good time to mention another lock in the castle.
Santa asked me to ask you to evaluate the security of our new HID lock.
If ever you find yourself in posession of a Proxmark3, click it in your badge to interact with it.
It's a slick device that can read others' badges!
Hey, you want to help me figure out the light switch too? Those come in handy sometimes.
The password we need is in the lights.conf file, but it seems to be encrypted.
There's another instance of the program and configuration in ~/lab/ you can play around with.
What if we set the user name to an encrypted value?
```

So we need to find a proxmark3 to clone someone's badge.

## lights
Run `strings -n 10 lights`. Some interesting strings.

```
passwordlightson # this is not the password
 >>> CONFIGURATION FILE LOADED, SELECT FIELDS DECRYPTED: ---t to help figure out the password... I guess you'll just have to make do!

00000000-0000-4000-0000-000000000000WARNING: The RESOURCE_ID is 00000000-0000-4000-0000-000000000000 - be sure to use a real one in production!
resource_id is not a valid uuidv4!
It's vresource_id is not a valid uuid (Couldn't get resource_id from the environmental variable

"action": "00010203040506070809101112131415161
718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616
263646566676869707172737475767778798081828384858687888990919293949596979899
```

Inside `lights.conf`

```
$ cat lights.conf 
password: E$ed633d885dcb9b2f3f0118361de4d57752712c27c5316a95d9e5e5b124
name: elf-technician
```

Based on the hints we change the value of the `name` to the encrypted value. The
prompt has changed:

`The terminal just blinks: Welcome back, Computer-TurnLightsOn`.

Solution: `Computer-TurnLightsOn`

## vending-machines
Talk to Bushy again.

```
Wow - that worked? I mean, it worked! Hooray for opportunistic decryption, I guess!
Oh, did I mention that the Proxmark can simulate badges? Cool, huh?
There are lots of references online to help.
In fact, there's a talk going on right now!
So hey, if you want, there's one more challenge.
You see, there's a vending machine in there that the speakers like to use sometimes.
Play around with ./vending_machines in the lab folder.
You know what might be worth trying? Delete or rename the config file and run it.
Then you could set the password yourself to AAAAAAAA or BBBBBBBB.
If the encryption is simple code book or rotation ciphers, you'll be able to roll back the original password.
```

Inside the config file:

``` json
$ cat vending-machines.json 
{
  "name": "elf-maintenance",
  "password": "LVEdQPpBwr"
}
```

```
AAAAAAAAAA
XiGRehmwXi


BBBBBBBBBB
DqTpKv7fDq

CCCCCCCCCC
Lbn3UP9WLb
```

Saw `C` is the first letter. I thought it would be something starting with
`Crypto` but then realized the passwords are probably holiday themed.

Solution: `CandyCane1`.

After solving:

```
Your lookup table worked - great job! That's one way to defeat a polyalphabetic cipher!
Good luck navigating the rest of the castle.
And that Proxmark thing? Some people scan other people's badges and try those codes at locked doors.
Other people scan one or two and just try to vary room numbers.
Do whatever works best for you!
```

Pick up elevator 1.5 button from the speaker room.

Open the HID lock in the Workshop. Talk to Bushy Evergreen near the talk tracks
for hints on this challenge. You may also visit Fitzy Shortstack in the kitchen
for tips.

Bushy already gave us some info. Let's talk to Fitzy.

## 33.6 Kbps

```
Fitzy Shortstack
"Put it in the cloud," they said...
"It'll be great," they said...
All the lights on the Christmas trees throughout the castle are controlled through a remote server.
We can shuffle the colors of the lights by connecting via dial-up, but our only modem is broken!
Fortunately, I speak dial-up. However, I can't quite remember the handshake sequence.
Maybe you can help me out? The phone number is 756-8347; you can use this blue phone.
```

Basically mimic the sounds.

```
baa DEE brrr
aaah
WeWEW
beDURR
SCHHRRR
```

After the challenge

```
We did it! Thank you!!
Anytime you feel like changing the color scheme up, just pick up the phone!
You know, Santa really seems to trust Shinny Upatree...
```

Go to Santa's workshop and pick up the marble. Go inside the room and pick up
the rubber ball and the proxmark.

Clicking on the tag generator gives us

`The Tag Generator is for Santa and select wrapping engineer elves only.`

The hint from Bushy is

```
You can also use a Proxmark to impersonate a badge to unlock a door, if the
badge you impersonate has access. lf hid sim -r 2006......
```

In the proxmark cli we see a hid after the `auto` command

```
#db# TAG ID: 2006e22ee1 (6000) - Format Len: 26 bit - FC: 113 - Card: 6000
```

## Sort-O-Matic Regex Challenege
Let's do the JavaScript regex sorting machine

1. Matches at least one digit
\d
  
2. Matches 3 alpha a-z characters ignoring case
[a-zA-Z]{3}
 
3. Matches 2 chars of lowercase a-z or numbers
[a-z\d]{2}
  
4. Matches any 2 chars not uppercase A-L or 1-5
[^A-L1-5]{2}
 
5. Matches three or more digits only
^\d{3,}$
  
6. Matches multiple hour:minute:second time formats only
^([0-5]\d):([0-5]\d):([0-5]\d)$
 
7. Matches MAC address format only while ignoring case
^([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})$
  
8. Matches multiple day, month, and year date formats only
^[0-3][0-9][\.\/-][0-1][0-9][\.\/-]\d{4}$
 
after the challenge

```
Great job! You make this look easy!
Hey, have you tried the Splunk challenge?
Are you newer to SOC operations? Maybe check out his intro talk from last year. https://www.youtube.com/watch?v=qbIhHhRKQCw
Dave Herrald is doing a great talk on tracking adversary emulation through Splunk! https://www.youtube.com/watch?v=RxVgEFt08kU
Don't forget about useful tools including Cyber Chef for decoding and decrypting data!
It's down in the Great Room, but oh, they probably won't let an attendee operate it.
```

## The Elf Code

```
Ribb Bonbowford9:26PM
Hello - my name is Ribb Bonbowford. Nice to meet you!
Are you new to programming? It's a handy skill for anyone in cyber security.
This challenge centers around JavaScript. Take a look at this intro and see how far it gets you!
Ready to move beyond elf commands? Don't be afraid to mix in native JavaScript.
Trying to extract only numbers from an array? Have you tried to filter?
Maybe you need to enumerate an object's keys and then filter?
Getting hung up on number of lines? Maybe try to minify your code.
Is there a way to push array items to the beginning of an array? Hmm...
```

```js
// Level 1
elf.moveTo(lollipop[0])
elf.moveUp(10)

// Level 2
elf.moveTo(lever[0])
var answer1 = elf.get_lever(0) + 2
elf.pull_lever(answer1)
elf.moveLeft(4) // elf.moveTo(lollipop[0]) does not work because the thingie is in the way?
elf.moveUp(10)

// Level 3
elf.moveTo(lollipop[0])
elf.moveTo(lollipop[1])
elf.moveTo(lollipop[2])
elf.moveUp(1)

// Level 4
for (var i = 0; i < 3; i++) {
  elf.moveLeft(3)
  elf.moveUp(40)
  elf.moveLeft(3)
  elf.moveDown(40)
}

// Level 5
elf.moveTo(munchkin[0])
var arr = elf.ask_munch(0)
var filtered = arr.filter(function (el) {
  return Number.isInteger(el)
});
elf.tell_munch(filtered)
elf.moveUp(2)

// Level 6
for (var i = 0; i < 4; i++)
  elf.moveTo(lollipop[i])
elf.moveTo(munchkin[0])
var js = elf.ask_munch(0)
elf.tell_munch(js["lollipop"])
elf.moveUp(2)
```

After solving:

```
Wow - are you a JavaScript developer? Great work!
Hey, you know, you might use your JavaScript and HTTP manipulation skills to take a crack at bypassing the Santavator's S4.
```

JavaScript developer? Thank God, no!

{{< imgcap title="Elevator unlock" src="02-elevator.png" >}}

**Quit!**