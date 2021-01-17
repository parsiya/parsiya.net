---
title: "Old ContextIS Challenge Solutions"
date: 2020-02-09T19:08:07-08:00
draft: false
toc: true
comments: true
twitterImage: forensics102-clipboard.png
categories:
- Writeup
- Reverse Engineering
- Crypto
---

A few years ago I did the [Context Information Security][context-url]
challenges. They used it for recruiting so I never published the results.
However, they have now switched to [Hack The Box][hackthebox-url] and the old
challenges are gone. So I am publishing what I did.

You can see the page with the old challenges using the Wayback Machine at:

* http://web.archive.org/web/20181012035146/https://www.contextis.com/en/careers/challenges

I also did some of their [xmas 2018 challenges]({{< relref "post/2018/2018-06-05-contextis-xmas-ctf/index.markdown" >}} "xmas 2018 challenges").

[context-url]: https://www.contextis.com/en/
[hackthebox-url]: https://www.hackthebox.eu/

<!--more-->

# Crypto

## Crypto1
Caesar's cipher. ROT19.

1. Paste in CyberChef.
2. Add `ROT13`.
3. Change `amount` until you get it right.

```
Hence! home, YoU idle creaTUres geT YoU home:
Is This a holidaY? WhaT! knoW YoU noT,
Being mechanical, YoU oUghT noT Walk
upon a laboUring daY WiThoUT The sign
Of YoUr profession? Speak, WhaT Trade arT ThoU?
* Shakespear
```

**Flag**:
`CONtExtIS{mlrUcniUc9dlZhl9dr4c8qifh0Z3nj0VUqTYW0so,TalenT@cTX.is}`

## Crypto2
It's repeated key XOR. We can already break it using our code from Cryptopals or
drop it in any cipher solver.

Key is: `akeycanopenalockeddoor`

**Flag**:
`cONTeXtiS{oTuaHUtgVI4yMRGkD24p1C1zmCnnBtUmM3Bkjzy2,CAReErs@coNteXtis.Com}(MAyBE Its CAse SenSITIVE?)`

# Binary Security

## Secret Recipe
File is base64 encoded. There's a bootleg way of base64 encoding/decoding files
on Windows without PowerShell using "certutil":

```
certutil -decode reversing-chal01.base64 decoded-chal01.exe
certutil -encode whatever.exe whatever.base64
```

After looking at the strings inside the file, it looks like a Python program
converted to standalone exe. Looking at the strings we can see
`.opyi-windows-manifest-filename binary-ctf.exe`.

Searching for `opyi-windows-manifest-filename` we get to these three posts by
Didier Stevens.

* https://isc.sans.edu/forums/diary/Python+Malware+Part+1/21057/
* https://isc.sans.edu/forums/diary/Python+Malware+Part+2/21085/
* https://isc.sans.edu/forums/diary/Python+Malware+Part+3/21265/

Seems like `pyinstaller` was used to create an executable.
`pyinstallerextractor` to the rescue:

* https://sourceforge.net/projects/pyinstallerextractor/
 
There are tons of files extracted. But we already know what we are looking for
`binary-ctf`. Inside that file again there are tons of things but we do not care
about them. There's a comment

```python
#keyy = "Brandy+Frigeo Ahoj Sherbet+Pizza Hawaii"
##echo -n "\n\n\n\n\n5\n11\n13\n\n" | python binary-ctf.py
```

Seems like it's decrypting a file using 3DES.
Choosing these will show (and also create a file with the same text):

```
whooohoo you found the flag.!! Great. Congratulations Flag: "K3epOnMoving"
Jazek: mhhh it tast like... Brandy with Frigeo Ahoj Sherbet and Pizza Hawaii
It's awful ..., but it reminds me on the good old time. (military secret).
```

At the end of `` there's this call:

```python
testfunc(f,s,t,r,"This is the Real Flag ;-)
    :"+flag, important+" are you from the" +flagg + ". Hello. Hello. McFly, Anybody home?")
```
The string is (`Welcme` is misspelled on purpose):

```
This is the Real Flag ;-)  :Idon'tKHOwToFuzz,
    Fl4g:WelcmeToC0ntext are you from the past?. Hello. Hello. McFly, Anybody home?
```

# Forensics 101
Decompress the file and you get a *nix (if I may interject!) file (note the
`0x0A` for new line instead of `0x0D 0x0A` on Windows). Each line has two chars
and the chars look like they are base64 encoded.

The file could be garbage but have some actual text inside. I grep-ed for `flag`
and `contextis` and could not find it.

Because I am obsessed with Go, I wrote a Go program to read the file, pass it to
a base64 stream decoder and then write the output to file. 

Result is a 7z file, after extraction we get a QED file.

Specification here: https://wiki.qemu.org/Features/QED/Specification.

We can convert and use it in Hyper-V or VirtualBox with:

* Hyper-V: `qemu-img.exe convert -f qed -O vpc 0.qed 0.vpc` 
* VirtualBox: `qemu-img.exe convert -f qed -O vdi 0.qed 0.vdi`

We can also mount it normally in VirtualBox. Long story short, flag is in a file called
`Untitled.dib` inside `root`.

{{< imgcap title="Forensics 101 challenge" src="forensics101.jpg" >}}

**Flag: CfxXM2mhqPeHsIjpKTV**

Go code for forensics 101.

``` go
package main
import (
    "encoding/base64"
    "flag"
    "fmt"
    "io"
    "os"
)
func main() {
    // This creates a flag parameter. Meaning we can call -file or --file.
    var filename string
    flag.StringVar(&filename, "file", "", "input file")
    flag.Parse()
    fmt.Println("reading input file, this may take a while")
    // Open file.
    i, err := os.Open(filename)
    // We are panic-ing with every error because we want to stop if things
    // go wrong.
    if err != nil {
        panic(err)
    }
    // Close input file
    defer i.Close()
    o, err := os.Create(filename + "-out.txt")
    if err != nil {
        panic(err)
    }
    // Close output file
    defer o.Close()
    // Create base64 stream decoder from input file. *io.File implements the
    // io.Reader interface. In other words we can pass it to NewDecoder.
    decoder := base64.NewDecoder(base64.StdEncoding, i)
    io.Copy(o, decoder)
    fmt.Println("storing base64 decoder input file")
}
```

# Forensics 102
I never solved it but I learned a lot about VirtualBox save state files. I think
I broke new ground there because no one had done anything about that format
before. I wrote some hands-on blog posts about what I learned:

* [Mounting Live Snapshots of Encrypted VMs in VirtualBox]({{< relref "post/2018/2018-01-23-mounting-live-snapshot-virtualbox.markdown" >}} "Mounting Live Snapshots of Encrypted VMs in VirtualBox").
* [VirtualBox Live State File Format]({{< relref "post/2018/2018-01-29-virtualbox-sav-file-format.markdown" >}} "VirtualBox Live State File Format").

## TL;DR

* VM credentials are `root/toor`.
* I managed to find a way to mount the VM in VirtualBox with the live snapshot,
  meaning I could just login. I did not see anything about it out there, so I
  assume it's (at least publicly) a new thing.
* VM has a file called `secret` which is a Luks container. Looking at the swap
  file (and live snapshot) I retraced some of the commands used to create it
  (some `token.txt` was used too).
* The truecrypt files and `untitled.dib` are all encrypted (or just random).
  `Untitled.dib` is 40960 bytes which is pretty curious.
* On desktop (also in bash_history via `cat Desktop/secret.txt`) is a 4096 byte
  file called `secret.txt` which seems to be key file but it's not. Could not
  open neither the Luks container not any of the other "encrypted" files.
* After logging in live, clipboard has a 33 char "password." Looks base64
  encoded but has an invalid length for a base64 string (tl;dr: the way base64
  formating works you can only have one or two or zero padding because one
  encoded will be 1 and 1/3). Read more at:
  https://parsiya.net/blog/2017-08-06-tldr-base64/

## Here we go
This is 5 stars. Inside the file we have a Debian qed file and a snapshot.
Opening the snapshot in a hex editor reveals it's a VirtualBox SavedState V2.0.

While we can start the qed file as hard disk in VirtualBox, we do not have the
user/pass. And the backdoor GRUB (28 backspaces) does not work on this version.
We will attach this as a normal hard disk to another Debian distro and open it
like Forensics101.

So inside `root` are a bunch of encrypted files.

* `/root/secret` is a 10 MB file. Running `file` on it returns:
    * `secret: LUKS encrypted file, ver 1 [aes, xts-plain, sha1] UUID: 770ac37d-60d1-437e-888b-9866bd525adf`
* `truecrypt-7.2-setup-console-x64`: Encrypted
* `Untitled.dib`: Encrypted
* `TrueCrypt-7.2-Linux-console-x64.tar.gz`: Encrypted
* `/Desktop/secret.txt`: Encrypted (but only `4096` bytes), perhaps the key?

If I have to guess, key to the file is `/Desktop/secret`.

No keys in `/etc/crypttab`.

```
$ sudo cryptsetup luksDump secret
LUKS header information for secret

Version:        1
Cipher name:    aes
Cipher mode:    xts-plain
Hash spec:      sha1
Payload offset: 4096
MK bits:        512
MK digest:      a8 2f 68 27 2a 25 3b 41 47 37 78 3a c4 80 85 46 55 90 d8 7f 
MK salt:        71 b1 d1 08 43 95 d0 6a a8 d9 13 69 42 b3 63 b9 
                d2 19 b4 0f 14 f2 e6 3a 73 ed 16 7d 63 75 08 98 
MK iterations:  121125
UUID:           770ac37d-60d1-437e-888b-9866bd525adf

Key Slot 0: ENABLED
    Iterations:             481202
    Salt:                   23 b3 c6 e6 be 13 99 cb e3 f5 42 e9 45 65 1c 27 
                            78 bc 20 b5 be 89 e6 c7 e7 3f 3c 36 03 c3 44 54 
    Key material offset:    8
    AF stripes:             4000
Key Slot 1: DISABLED
Key Slot 2: DISABLED
Key Slot 3: DISABLED
Key Slot 4: DISABLED
Key Slot 5: DISABLED
Key Slot 6: DISABLED
Key Slot 7: DISABLED
```

Seems like `secret.txt` is not the key file:

```
$ sudo cryptsetup luksOpen secret tmpData --key-file /Desktop/secret.txt
No key available with this passphrase.
```

Maybe there's something in the sav file?

### Cracking the hash?
Maybe we should crack the hash?

* `ENCRYPT_METHOD SHA512` inside `etc/login.defs`.
* `$6$bpWNT25M$6/r.d4a4G/wQX3/eSbBiTQluVQpmPSmAKvk0r5kS/LY7HS88.StLG06.3gR2rKXGXYryAjosq49ZJAPro1Emo0:16940:0:99999:7:::`

**password is toor** used hashcat and my GTX 1080 GPU took care of it.

```
hashcat64.exe -m 1800 -O -w 3 -a 3 [...hash]
```

* https://hashcat.net/wiki/doku.php?id=hashcat

### How do I trick VirtualBox into restoring our saved state?
We have no idea how the config file looks like with a saved state.

Right click on the machine `Show in Explorer`, open up `[machine-name].vbox` and
make a copy. Start the machine, close the Window and save the state. Close
VirtualBox and copy the file again. Compare these two. The value of `stateFile`
has changed. Change the value of `stateFile` to the file (maybe we should change
the `lastStateChange` too). Copy the file from the challenge zip. 

``` xml
<Machine uuid="{e6fe2819-7bc2-436c-a14f-e274aa4112ef}" name="Debian3"
    OSType="Debian_64" stateFile="Snapshots/2018-01-13T17-11-21-868995300Z.sav"
    snapshotFolder="Snapshots" lastStateChange="2018-01-13T17:11:21Z">
```

#### uApicMode
The desktop Was displayed for second and then we got this error, damn!

```
Failed to open a session for the virtual machine Debian3.

apic#0: Config mismatch * uApicMode: saved=2 config=3
    [ver=3 pass=final] (VERR_SSM_LOAD_CONFIG_MISMATCH).

Result Code: E_FAIL (0x80004005)
Component: ConsoleWrap
Interface: IConsole {872da645-4a9b-1727-bee2-5585105b9eed}
```

#### APIC I/O?
We need to find out what does `APIC` mode 2 mean. If I have to make a guess, we
need to disable `I/O APIC mode` in `Syetem`. Dicard the state, remove it and try
again.

This disappears from the config file (we could have probably just removed this
from the config file manually instead of discarding the state and doing it
again):

``` xml
<BIOS>
    <IOAPIC enabled="true"/>
</BIOS>
```

Add the saved state to the snapshot as we saw before and try again!

Whelp! That was the wrong APIC. Serves me right by taking quick action.

```
Failed to open a session for the virtual machine Debian3.

apic#0: Config mismatch * fIoApicPresent: saved=true  config=false
    [ver=3 pass=final] (VERR_SSM_LOAD_CONFIG_MISMATCH).

Result Code: E_FAIL (0x80004005)
Component: ConsoleWrap
Interface: IConsole {872da645-4a9b-1727-bee2-5585105b9eed}
```
### Back to uApicMode
Searching for `uApicMode` returns only a few results. Both of the errors that we
have seen come from this file:

* https://www.virtualbox.org/svn/vbox/trunk/src/VBox/VMM/VMMR3/APIC.cpp

``` cpp
static int apicR3LoadVMData(PVM pVM, PSSMHANDLE pSSM)
{
    PAPIC pApic = VM_TO_APIC(pVM);

    /* Load and verify number of CPUs. */
    uint32_t cCpus;
    int rc = SSMR3GetU32(pSSM, &cCpus);
    AssertRCReturn(rc, rc);
    if (cCpus != pVM->cCpus)
        return SSMR3SetCfgError(pSSM, RT_SRC_POS, N_("Config mismatch * cCpus: saved=%u config=%u"),
            cCpus, pVM->cCpus);

    /* Load and verify I/O APIC presence. */
    bool fIoApicPresent;
    rc = SSMR3GetBool(pSSM, &fIoApicPresent);
    AssertRCReturn(rc, rc);
    if (fIoApicPresent != pApic->fIoApicPresent)
        return SSMR3SetCfgError(pSSM, RT_SRC_POS, N_("Config mismatch * fIoApicPresent: saved=%RTbool config=%RTbool"), fIoApicPresent, pApic->fIoApicPresent);

    /* Load and verify configured max APIC mode. */
    uint32_t uSavedMaxApicMode;
    rc = SSMR3GetU32(pSSM, &uSavedMaxApicMode);
    AssertRCReturn(rc, rc);
    if (uSavedMaxApicMode != (uint32_t)pApic->enmMaxMode)
        return SSMR3SetCfgError(pSSM, RT_SRC_POS, N_("Config mismatch * uApicMode: saved=%u config=%u"),
                                uSavedMaxApicMode, pApic->enmMaxMode);
    
    return VINF_SUCCESS;
}
```

We are getting an error when comparing the `max APIC mode`. Ours is 3, config is
2. But what is this?

Searching for `max apic` sends us to a [reddit thread](https://www.reddit.com/r/linux/comments/6jepx3/intel_skylakekaby_lake_processors_broken/):

> Max APIC IDs reserved field is Valid. A value of 0 for HTT indicates there is
> only a single logical processor in the package and software should assume only
> a single APIC ID is reserved. A value of 1 for HTT indicates the value in
> CPUID.1.EBX[23:16] (the Maximum number of addressable IDs for logical
> processors in this package) is valid for the package.

But does it have anything to do what we want? How do we change it? What do we
need to change in our CPU config?

Inside [/VMM/include/APICInternal.h](https://www.virtualbox.org/svn/vbox/trunk/src/VBox/VMM/include/APICInternal.h):

``` cpp
/** The max supported APIC mode from CFGM.  */
    PDMAPICMODE                 enmMaxMode;
```

And later in [VBox/vmm/pdmdev.h](https://www.virtualbox.org/svn/vbox/trunk/include/VBox/vmm/pdmdev.h):

``` c
typedef enum PDMAPICMODE
{
    /** Invalid 0 entry. */
    PDMAPICMODE_INVALID = 0,
    /** No APIC. */
    PDMAPICMODE_NONE,
    /** Standard APIC (X86_CPUID_FEATURE_EDX_APIC). */
    PDMAPICMODE_APIC,
    /** Intel X2APIC (X86_CPUID_FEATURE_ECX_X2APIC). */
    PDMAPICMODE_X2APIC,
    /** The usual 32-bit paranoia. */
    PDMAPICMODE_32BIT_HACK = 0x7fffffff
} PDMAPICMODE;
```

This seems to be it. We have `X2APIC` (3) enabled but want `APIC`.

Inside the config file we have this:

``` xml
<CPU>
    <PAE enabled="false"/>
    <LongMode enabled="true"/>
    <X2APIC enabled="true"/>
    <HardwareVirtExLargePages enabled="true"/>
</CPU>
```

We are going to change it to `false` and then try again.

#### Different Enum
On a side-note, this threw me off inside
[/VBox/Devices/PC/BIOS/post.c](https://www.virtualbox.org/svn/vbox/trunk/src/VBox/Devices/PC/BIOS/post.c):

``` c
#define APICMODE_DISABLED   0
#define APICMODE_APIC       1
#define APICMODE_X2APIC     2
```

This enum is different by one compared to the other one (X2APIC is 3 there but 2
here).

#### Video Memory Size Error
After setting `<X2APIC enabled="false"/>` we get a different error.

```
Failed to open a session for the virtual machine Debian3.

vga#0: VRAM size changed: config=0x1000000 state=0xc00000
    [ver=16 pass=final] (VERR_SSM_LOAD_CONFIG_MISMATCH).

Result Code: E_FAIL (0x80004005)
Component: ConsoleWrap
Interface: IConsole {872da645-4a9b-1727-bee2-5585105b9eed}
```

* Config VRAM is `0x1000000` == `16777216` == `16MB`
* State VRAM is `0xc00000` == `12582912` == `12MB`

We can change it in the config file from 16 to 12 and try again:

``` xml
<Hardware>
    <Display VRAMSize="16"/>
</Hardware>
```
#### Primary Master Device Error
Another error, this time for the hard drive:

```
Failed to open a session for the virtual machine Debian3.

piix3ide#0: The target VM is missing a primary master device.
Please make sure the source and target VMs have compatible storage configurations
[ver=20 pass=final] (VERR_SSM_LOAD_CONFIG_MISMATCH).

Result Code: E_FAIL (0x80004005)
Component: ConsoleWrap
Interface: IConsole {872da645-4a9b-1727-bee2-5585105b9eed}
```

We have attached the VM disk as an SATA drive. We need to add it as IDE and
primary master. This time the config file is a bit more complicated, so we will
discard the state (which allows us to edit the VM via the GUI) and attach the
image as IDE. Just remember that you need to do the snapshot trick again.

It's now:

``` xml
<StorageControllers>
  <StorageController name="IDE" type="PIIX4" PortCount="2" useHostIOCache="true" Bootable="true">
    <AttachedDevice type="HardDisk" hotpluggable="false" port="0" device="0">
      <Image uuid="{401cb5a0-d3bf-4d40-83b8-e0f658d4d12f}"/>
    </AttachedDevice>
    <AttachedDevice passthrough="false" type="DVD" hotpluggable="false" port="1" device="0"/>
  </StorageController>
  <StorageController name="SATA" type="AHCI" PortCount="1" useHostIOCache="false"
        Bootable="true" IDE0MasterEmulationPort="0" IDE0SlaveEmulationPort="1"
        IDE1MasterEmulationPort="2" IDE1SlaveEmulationPort="3"/>
</StorageControllers>
```

First we get this error without any description.

```
Failed to open a session for the virtual machine Debian3.

The VM session was closed before any attempt to power it on.

Result Code: E_FAIL (0x80004005)
Component: SessionMachine
Interface: ISession {7844aa05-b02e-4cdd-a04f-ade4a762e6b7}
```

After discarding the state and trying again we get:

```
ahci#0: The target VM is missing a device on port 0. Please make sure the source
and target VMs have compatible storage configurations
    [ver=8 pass=final] (VERR_SSM_LOAD_CONFIG_MISMATCH).

Result Code: 
E_FAIL (0x80004005)
Component: 
ConsoleWrap
Interface: 
IConsole {872da645-4a9b-1727-bee2-5585105b9eed}
```

Looking around, this seems like a version issue. Seems like states created by
older versions get this error with newer ones. I either need to find a solution
or discover the VirtualBox version that the VM was created with. One way is to
look at the date of the snapshot (and the files inside the image) and get the
build number (it's 5.0.2 with SVN revision 102546, see below on how I got it).
Then we can try with that exact version.

**Solution to mounting the VM:**

So the trick was having another drive on primary master and not the qed image.
Guess what? It's VirtualBox and chances are, you mounted the **VB guest
additions CD**. So CDROM with guest additions loaded goes into primary master,
the drive goes into first SATA, and voila! (insert Poirot image). It works (not
the MLM). However, I did look at the `sav` file format. Feel free to read it
further down you want.

### WHAT's IN THE BOX?
We have already seen pretty much everything. Opening a terminal and looking at
history we can only see:

* `cat Desktop/secret.txt`
* `cryptsetup luksOpen secret tmpMe --key-file secret --key-slot 0`

`key-slot 0` seems to do something else. But still no bono.

### Inside the Swap File
The qed has two images, the drive and the swap file. Convert it to `vdi` format
with `qemu-img` as seen above and open it with 7-zip. There are two img files
inside, open the swap file in a hex editor like `HxD` and search for stuff.

It contains the commands you used to setup the thing. Hint: If you see `UU`, you
are about to see a command. I just searched for the text `secret`. Seems like
this appears before every command `F7 0x 55 55` (where `x` can be 2,3,4 etc.).

These start at offset `0x00F2F0C0` (comments are just friendly banter, do not
take it seriously)

```
ifconfig
sudo cryptsetup luksOPen /dev/loop0 container # Oops we do not have cryptsetup
ifconfig                                      # Oops we do not have internet
apt-get install cryptsetup                    # Install cryptsetup
nano -w /mnt/token.txt                        # Ah, a fellow nano fan
# I saw some color (like [0;10m) and control characters, I assume it's commands
# interacting with nano.
cryptsetup luksOpen /dev/loop0 container
poweroff
cat .bash_history
dd if=/dev/urandom of=secret bs=1M count=10   # Create the initial file
/usr/bin/mesg                                 # Why? Some util running cmds?
chmod +x truecrypt-7.2-setup-console-x64
mesg
startx
AX.G0.XT.U8.E0.E3.S0.TS.ka2.kb1.kb3.kc2       # No idea what this is
ifconfig
root@0:~#
/root/.terminfo
/root
/truecrypt-7.2-setup-console-x64
apt-cache search fuse
apt-cache search luks
apt-get install fuse
apt-get install luks
```

More stuff at `0x00F7C540` (these seem to be before the previous set):

```
tar xzvf TrueCrypt-7.2-Linux-console-x64.tar.gz
file truecrypt-7.2-setup-console-x64
wget "http://tenet.dl.sourceforge.net/project/truecrypt/TrueCrypt/Other/TrueCrypt-7.2-Linux-console-x64.tar.gz
losetup /dev/loop0 secret
startx
# some stuff here
losetup -f
mount -t ext4 /dev/mapper/container /mnt

```

Stuff at `0x00F29D00`:

```
mkfs.ext4 /dev/mapper/container
apt-get install xorg
XDG_RUNTIME_DIR=/run/user/0.

```

At `0x00F76000`:

```
cryptsetup -c aes-xts-plain -y -s 512 luksFormat /dev/loop0
/root/.terminfo./etc/terminfo./lib/terminfo./usr/share/terminfo./etc/terminfo
cryptsetup -c aes-xts-plain -y -s 512 luksFormat /dev/loop0
/bin/startx
startx # a bunch of these
```

At `0x1499730`:

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHT1OYnj7LsN3ZvtcF6xpQojuELJzUYM0sa/LurKaoHS.

root@0..SANtrq1/eNzyH7hC8RgnVPJcIWMWEuVEqPsz24i4rle8RYx8xUUNZiBBervbflV5SoV+8A=.root@0..qm+PPjrHaa4rmfJ/DkC1I+Uldr2kI3TAAAAFQCcBsZds4dQIqb6Zlx4Lurj4fjmPQAAAIBPFoAof1ao1lPuXHPQV7Vwn1AqBQ7NFAv9mz8q/qUCYFUYwGCnwxGKRv/ytK1n5DN9UI4bKfrF5yERoRswjM8K6V/xyRKPatN9HVqHHJzDLcgu0Qh8DRuNRRZSnQVKahawQ9boIS13u53I6EI5W2c708MKmeYTfbj9WNWa2ZwPrQAAAIBuzHcePHEdJ8+Lrqt62PErYw8wJvxWSZjrzmZgbO8MEhw+W4kgixqvzEDCc9j0+RddTYyeoTLcgVWaLtkvXMw2cJlWtZpyj3ANHLjPsVbvsUsz8jXEDe64tHoR3dN9qSng+I1yiv5m6p/w6+pJ6uvirAFpZiHzAnBRkGnc7x2taw==

root@0
```

`cryptsetup -c aes-xts-plain -y -s 512 luksFormat /dev/loop0`:

* `-c`: Cipher == `aes-xts-plain`
* `-y`: Ask for passwords twice
* `-s`: Key size == `512`
* `luksFormat /dev/loop0`
    * `luksFormat <device> [<key file>]`

## Clipboard
Shift+Insert in a terminal to get the clipboard:

* `d27a0102bV1uahFX6covGkTdKR6Li5BK5`

{{< imgcap title="Clipboard" src="forensics102-clipboard.png" >}}

This is the wrong length for a base64 encoded string. Base64 gives us 4 chars
for each 3 chars in input. So each char is 4/3 chars. Meaning you can never have
a string of length `4*n+1` because the last char is encoded into 2 chars. In
other words, a base64 string can only have zero, one or two padding chars.

Decoded from base64, there's an error because of 5. Removing 5 gives us this (in hex):

* `776edad35d366d5d6e6a1157e9ca2f1a44dd291e8b8b904a`

With Cyberchef we get:

`776edad35d366d5d6e6a1157e9ca2f1a44dd291e8b8b904a e4`

**Might be the creators SSH password.**

## Dive into sav
The sav format is pretty much undocumented but we have source files. This is a
pretty new thing, I am going to write a blog post on it.

According to [this
thread](https://www.virtualbox.org/pipermail/vbox-dev/2012-October/010986.html),
"A .sav file is created using the SSM (saved state manager) code. You find the
API in include/VBox/vmm/ssm.h and src/VBox/VMM/VMMR3/SSM.cpp."

* https://www.virtualbox.org/svn/vbox/trunk/include/VBox/vmm/ssm.h
* https://www.virtualbox.org/svn/vbox/trunk/src/VBox/VMM/VMMR3/SSM.cpp

### SSM File Header * SSMFILHDR
First 64 bytes are the file header.

```
00000000  7f 56 69 72 74 75 61 6c 42 6f 78 20 53 61 76 65  |.VirtualBox Save|
00000010  64 53 74 61 74 65 20 56 32 2e 30 0a 00 00 00 00  |dState V2.0.....|
00000020  05 00 00 00 04 00 00 00 92 90 01 00 40 08 08 00  |............@...|
00000030  28 00 00 00 01 00 00 00 00 10 00 00 28 6b b1 c8  |(...........(k±È|
```

Inside `ssm.cpp` search for `struct SSMFILEHDR`:

``` cpp
typedef struct SSMFILEHDR
{
    /** Magic string which identifies this file as a version of VBox saved state
     *  file format (SSMFILEHDR_MAGIC_V2_0). */
    char            szMagic[32];
    /** The major version number. */
    uint16_t        u16VerMajor;
    /** The minor version number. */
    uint16_t        u16VerMinor;
    /** The build number. */
    uint32_t        u32VerBuild;
    /** The SVN revision. */
    uint32_t        u32SvnRev;
    /** 32 or 64 depending on the host. */
    uint8_t         cHostBits;
    /** The size of RTGCPHYS. */
    uint8_t         cbGCPhys;
    /** The size of RTGCPTR. */
    uint8_t         cbGCPtr;
    /** Reserved header space * must be zero. */
    uint8_t         u8Reserved;
    /** The number of units that (may) have stored data in the file. */
    uint32_t        cUnits;
    /** Flags, see SSMFILEHDR_FLAGS_XXX.  */
    uint32_t        fFlags;
    /** The maximum size of decompressed data. */
    uint32_t        cbMaxDecompr;
    /** The checksum of this header.
     * This field is set to zero when calculating the checksum. */
    uint32_t        u32CRC;
} SSMFILEHDR;
```

First 32 bytes contain the `magic string`. For us it's:

``` cpp
/** Saved state file v2.0 magic. */
#define SSMFILEHDR_MAGIC_V2_0  "\177VirtualBox SavedState V2.0\n\0\0\0"
```

Note the `\177` is octal (base 8) or `0x7F` which is exactly what we are seeing
in the file:

```
00000020  05 00 00 00 04 00 00 00 92 90 01 00 40 08 08 00  |............@...|
00000030  28 00 00 00 01 00 00 00 00 10 00 00 28 6b b1 c8  |(...........(k±È|
```

And then we have the rest (in little-endian):

* `05 00`: Major version number == `5.0`.
* `00 00`: Minor version number == `0.0`.
* `04 00 00 00`: Build number == `04`.
* `92 90 01 00`: SVN revision == `102546`.
* `40`: Host bits == `64` (32 bit or 64 bit host).
* `08`: Size of RTGCPHYS (Guest physical memory address) == `08`.
* `08`: Size of RTGCPTR (Guest context pointer) == `08`. I have no idea what
  this does.
* `00`: Reserved header space * must be zero.
* `28 00 00 00`: Number of units that (may) have stored data in the file == `40`.
* `01 00 00 00`: Flags, discussed below. `01` == it was a live save.
* `00 10 00 00`: Maximum size of decompressed data == `4096`.
* `28 6b b1 c8`: CRC32 checksum of the header. Set to zero when calculating the
  checksum.

For some reason CyberChef does not show the correct CRC32 checksum while other
online calculators too. Some info might be lost when convert hex bytes to chars
and calculating the checksum (or I am simply using the wrong formula).

#### Flags
In short, flag is `01` if it was a live save (which was in our case) and `00` if
the stream is checksummed up to the footer.

Flags are defined as follows:

``` cpp
/** @name SSMFILEHDR::fFlags
 * @{ */
/** The stream is checksummed up to the footer using CRC-32. */
#define SSMFILEHDR_FLAGS_STREAM_CRC32           RT_BIT_32(0)
/** Indicates that the file was produced by a live save. */
#define SSMFILEHDR_FLAGS_STREAM_LIVE_SAVE       RT_BIT_32(1)
/** @} */
```

### Saved State Units
Then we can see a bunch of saved state units that conveniently have the text `Unit` in them.

Search for `typedef struct SSMUNIT` in `SSMInternal.h` for more info.

#### Unit Header * SSMFILEUNITHDRV2
Each unit has its own header.

``` cpp
typedef struct SSMFILEUNITHDRV2
{
    /** Magic (SSMFILEUNITHDR_MAGIC or SSMFILEUNITHDR_END). */
    char            szMagic[8];
    /** The offset in the saved state stream of the start of this unit.
     * This is mainly intended for sanity checking. */
    uint64_t        offStream;
    /** The CRC-in-progress value this unit starts at. */
    uint32_t        u32CurStreamCRC;
    /** The checksum of this structure, including the whole name.
     * Calculated with this field set to zero.  */
    uint32_t        u32CRC;
    /** Data version. */
    uint32_t        u32Version;
    /** Instance number. */
    uint32_t        u32Instance;
    /** Data pass number. */
    uint32_t        u32Pass;
    /** Flags reserved for future extensions. Must be zero. */
    uint32_t        fFlags;
    /** Size of the data unit name including the terminator. (bytes) */
    uint32_t        cbName;
    /** Data unit name, variable size. */
    char            szName[SSM_MAX_NAME_SIZE];
} SSMFILEUNITHDRV2;
```

Let's analyze the first unit after the header:

```
00000000  0a 55 6e 69 74 0a 00 00 40 00 00 00 00 00 00 00  |.Unit...@.......|
00000010  43 1d d4 81 b3 2b 74 a0 01 00 00 00 00 00 00 00  |C.Ô.³+t ........|
00000020  ff ff ff ff 00 00 00 00 04 00 00 00 53 53 4d 00  |ÿÿÿÿ........SSM.|
00000030  92 39 0a 00 00 00 42 75 69 6c 64 20 54 79 70 65  |.9....Build Type|
00000040  07 00 00 00 72 65 6c 65 61 73 65 07 00 00 00 48  |....release....H|
00000050  6f 73 74 20 4f 53 09 00 00 00 77 69 6e 2e 61 6d  |ost OS....win.am|
00000060  64 36 34 00 00 00 00 00 00 00 00 91 0e 01 00 b1  |d64............±|
00000070  c7 65 e5 4b 00 00 00 00 00 00 00                 |ÇeåK.......|
```

First 8 bytes contain the data unit magic header that can have two values:

``` cpp
/** Data unit magic. */
#define SSMFILEUNITHDR_MAGIC    "\nUnit\n\0"
/** Data end marker magic. */
#define SSMFILEUNITHDR_END      "\nTheEnd"
```

In this case we have `0a 55 6e 69 74 0a 00 00` or `\nUnit\n\0`.

* `40 00 00 00`: Offset of this unit in the stream. For this unit it's `0x40`.
  In other words, if we go this offset in the sav file, we will see this data
  unit.
* `00 00 00 00`: The CRC-in-progress value this unit starts at. No idea what
  this is. It could be default value of the CRC bytes when we are creating the
  CRC checksum (live above).
* `43 1d d4 81`: Checksum of the data unit with these bytes set to zero == `81 d4 1d 43`.
* `b3 2b 74 a0`: Data version == `a0 74 2b b3`. (?)
* `01 00 00 00`: Instance number == `01`. (?)
* `00 00 00 00`: Data pass number == `00`. (?)
* `ff ff ff ff`: **These 4 bytes do not appear in the spec.** Could be alignment
  for the data unit header? These appear in my new live states too.
* `00 00 00 00`: Flags reserved for future extensions. Must be zero.
* `04 00 00 00`: Size of null-terminated data unit name with bytes, `4` in this
  data unit.
* `53 53 4d 00`: Data unit name, `SMM`.

#### Unit Data
Going back up the `ssm.cpp` file we can see the data in each saved state unit.

```
00000030  92 39 0a 00 00 00 42 75 69 6c 64 20 54 79 70 65  |.9....Build Type|
00000040  07 00 00 00 72 65 6c 65 61 73 65 07 00 00 00 48  |....release....H|
00000050  6f 73 74 20 4f 53 09 00 00 00 77 69 6e 2e 61 6d  |ost OS....win.am|
00000060  64 36 34 00 00 00 00 00 00 00 00 91 0e 01 00 b1  |d64............±|
00000070  c7 65 e5 4b 00 00 00 00 00 00 00                 |ÇeåK.......|
```

00000030  92 39 0a 00 00 00 42 75 69 6c 64 20 54 79 70 65  |.9....Build Type|
00000040  07 00 00 00 72 65 6c 65 61 73 65 07 00 00 00 48  |....release....H|
00000050  6f 73 74 20 4f 53 09 00 00 00 77 69 6e 2e 61 6d  |ost OS....win.am|
00000060  64 36 34 00 00 00 00 00 00 00 00 91 0e 01 00 b1  |d64............±|
00000070  c7 65 e5 4b 00 00 00 00 00 00 00                 |ÇeåK.......|

"The first byte in the record header indicates the type and flags." We have
`0x92` or `1001 0010`:

* bits 0..3: Record type `0010`: type = Raw data record.
* bit 4: `1` if important and `0` if it can be skipped. This is an important data unit.
* bit 5, 6: Must be `0`.
* bit 7: Always `1`.

So we have an important raw data record.

"Record header byte 2 (optionally thru 7) is the size of the following data
encoded in UTF-8 style." We have `0x39` or `57` decimal. So we will read 57
bytes.

This part is easy. Read a little-endian uint32, that's field length. Then read
that many bytes for the field. This is a typical Pascal style string (on the
other side we have C style string without length where we read until we reach
the null terminator `0x00`). Note these strings do not have null terminators.

* `0a 00 00 00 42 75 69 6c 64 20 54 79 70 65`: 10 bytes * `Build Type`.
* `07 00 00 00 72 65 6c 65 61 73 65`: 7 bytes * `release`.
* `07 00 00 00 48 6f 73 74 20 4f 53`: 7 bytes * `Host OS`.
* `09 00 00 00 77 69 6e 2e 61 6d 64 36 34`: 9 bytes * `win.amd64`.
* `00 00 00 00 00 00 00 00`: 0 bytes * empty (?).

### File Footer * SSMFILEFTR
And finally we have the file footer. Bored now. Search in the VirtualBox source
code for it.

**RAGE QUIT LOL.**

<!-- Links -->