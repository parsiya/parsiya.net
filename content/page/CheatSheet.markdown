---
date: "2016-02-24T22:29:57-05:00"
draft: false
title: "Cheat Sheet"
url: "/cheatsheet/"
categories:
- Cheatsheet
---

You will find those commands and tips that I need from time to time (and usually
forget when I need them). This is a page to complement
[my clone at parsiya.io](https://parsiya.io) and gives me a simple repository of
how-tos I can access online. Look at the table of contents below or `ctrl+f` and
search for keywords.

{{< toc >}}

------

## Tar
Insert [XKCD 1168](https://xkcd.com/1168/), hur dur!

### Compress a Directory Using tar
`tar -zcvf target_tar.tar.gz directory_to_be_compressed`

### Decompress a tar.gz file
`tar -zxvf target_tar.tar.gz -C path/to/decompress/`

------

## OpenSSL

### Dump The TLS Certificate of a Domain with OpenSSL
`echo | openssl s_client -connect HOST:PORT 2>/dev/null | openssl x509 -text -noout`

### TLS Connection with a Specific Ciphersuite with OpenSSL
`openssl s_client -connect HOST:PORT -cipher cipher-name -brief`

* `-brief`: reduced output
* `cipher-name`: A cipher from output of `openssl ciphers` command

------

## AWS

### How to Use s3deploy
I have switched to s3deploy from s3cmd: https://github.com/bep/s3deploy. 

Create a file named `.s3deploy.yaml` (note the period) in the root of website. I
have:

``` yaml
routes:
    - route: "^.+\\.(js|css|svg|ttf|eot|woff|woff2)$"
      #  cache static assets for 20 years
      headers:
         Cache-Control: "max-age=630720000, no-transform, public"
      gzip: true
    - route: "^.+\\.(png|jpg)$"
      headers:
         Cache-Control: "max-age=630720000, no-transform, public"
      gzip: true
    - route: "^.+\\.(html|xml|json|js)$"
      gzip: true
```

The file is self-explanatory. Don't set `gzip` for `txt` files,
**it will break your keybase proof**.

Then run (change the region if needed):

`s3deploy -source=public/ -region=us-east-1 -bucket=[bucketname]`

To pass your AWS key and secret, you can either set them in an environment
variable or in this file:

`c:/Users/[your user]/.aws/credentials`

Like this:

```
[default]
aws_access_key_id=
aws_secret_access_key=
```

### Sync a Directory with an Amazon S3 bucket with s3cmd
These might be updated because I do not use s3cmd anymore.

`python s3cmd sync --acl-public --delete-removed --rr directory-to-sync/ s3://bucket-name`

E.g., uploading the Hugo generated public directory to my website:\\
`python s3cmd sync --acl-public --delete-removed --rr public/ s3://parsiya.net`

* `--acl-public`: Anyone can only read.
* `--delete-removed`: Delete objects with no corresponding local files.

### Change the MIME-Type of the CSS file After Upload to Fix CSS not Displaying Correctly
`python s3cmd --acl-public --no-preserve --mime-type="text/css" put public/css/hugo-octopress.css s3://parsiya.net/css/hugo-octopress.css`

{{< codecaption title="My runme.bat to upload my Hugo blog to the S3 bucket" lang="powershell"\\>}}
rd /q /s public
hugo
rd /q /s public\post
del /s /a .\*thumbs*.db
del /s /a public\categories\*index*.xml
del /s /a public\tags\*index*.xml
python s3cmd sync --acl-public --cf-invalidate --delete-removed -MP --no-preserve --rr public/ s3://parsiya.net
python s3cmd --acl-public --no-preserve --cf-invalidate --add-header="Expires: Sat, 20 Nov 2286 19:00:00 GMT" --mime-type="text/css" put public/css/hugo-octopress.css s3://parsiya.net/css/hugo-octopress.css
rd /q /s public
{{< /codecaption >}}

### Set the Website Index to a Non-Root file in a Static Website on S3
When setting up a static website in an S3 bucket, you need to specify an index
and an error page. The index cannot be in a subdirectory but the error page
can. Set the index to a non-existent file (e.g. `whatever.crap`) and set the
error page to the actual index page. The browser will be redirected to the error
page:

* Source: https://stackoverflow.com/a/20273548

If you are relying on error pages, this will mess with your site because every
error will be redirected to the index. Another way is to set a meta redirect in
the index file in the root directory and redirect to that page.

### Use AWS CLI Without Credentials
Use `--no-sign-request`. E.g., to list all items in a world-readable bucket:

* `aws s3 ls s3://bucket-name --no-sign-request --recursive`

------

## Windows

### Shortcut to IE (or WinINET) Proxy Settings

`control inetcpl.cpl,,4`

### where.exe
`where.exe` searches for files. If no location is passed it searches in the
local directory and then in PATH.

- `/R` searches recursively in a specific location.
- `/T` displays file size.
- `/?` for help.

### Delete File or Directory with a Path or Name Longer than the Windows Limit

```
mkdir empty_dir
robocopy empty_dir the_dir_to_delete /s /mir
rmdir empty_dir
rmdir the_dir_to_delete
```

* Source: http://superuser.com/a/467814

### Install 'Bash on Windows' - Outdated
`lxrun /install` does not work anymore.

1. Run the following command in an admin PowerShell and restart.
   * `Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux`
2. Search for `Ubuntu` in Windows store and install Ubuntu.
3. After Ubuntu is installed, search for `Ubuntu` in the start menu and run it.
4. Follow the prompts to choose a username and password.
5. Type `bash` in a command prompt to start it.

### Setup GitHub-GitLab SSH Keys in 'Bash on Windows'
Main instructions:

* https://help.github.com/en/articles/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent

1. Generate a key inside bash and save it at the default location inside `home`.
   * `ssh-keygen -t rsa -b 4096 -C "your_email@example.com"`
2. Make sure you have `ssh-agent` installed in WSL. It should be installed out
   of the box.
3. Add the following lines to `~/.bashrc` to start `ssh-agent` and add your key
   every time you run `bash`.

    ``` bash
    env=~/.ssh/agent.env
    agent_load_env () { test -f "$env" && . "$env" >| /dev/null ; }

    agent_start () {
        (umask 077; ssh-agent >| "$env")
        . "$env" >| /dev/null ; }

    agent_load_env

    # agent_run_state: 0=agent running w/ key; 1=agent w/o key; 2= agent not running
    agent_run_state=$(ssh-add -l >| /dev/null 2>&1; echo $?)

    if [ ! "$SSH_AUTH_SOCK" ] || [ $agent_run_state = 2 ]; then
        agent_start
        ssh-add
    elif [ "$SSH_AUTH_SOCK" ] && [ $agent_run_state = 1 ]; then
        ssh-add
    fi

    unset env

    # adding the GitHub key to ssh-agent
    # change if the private key file changes
    ssh-add ~/.ssh/id_rsa
    ```
4. Add the SSH key to Github/GitLab.
5. Navigate to your git folder in a normal command prompt and run `bash` and use
   git normally.

### Exit Status 3221225781
**TL;DR:** `exit status 3221225781` on Windows means a DLL is missing. In this
case, `diff.exe` was missing `libintl3.dll` and it made `gorename` stop working.
Get and install it from:

* http://gnuwin32.sourceforge.net/packages/libintl.htm

**The Actual Problem**:\\
`gorename` stopped working and I got the following error in the VS Code console:

```
Rename failed: gorename: computing diff: exit status 3221225781 gorename:
    computing diff: exit status 3221225781 gorename: failed to rewrite 2 files 
```

Searching for `3221225781` sent me to
[Rust language issue 42744](https://github.com/rust-lang/rust/issues/42744)
which means a DLL is missing. Run `where diff` to find out where it is and it
was in `\Go\bin\diff.exe`. Running `diff.exe` manually got this prompt.

```
The code execution cannot proceed because libintl3.dll was not found.
Reinstalling the program may fix this problem.
```

Go to http://gnuwin32.sourceforge.net/packages.html and click on `Setup` in
front of `DiffUtils`. It will download a package which contains the utils and
two DLLs: `libintl3.dll` and `libiconv2.dll`. Copy all of them to where the
original `diff.exe` was and it should work.

### Map a Drive to a Specific Directory
This is useful when you want to refer to a specific directory as a drive.

* `subst X: C:\path\to\source\code`

Two problems:

1. This is not persistent. To make it persistent, use the solutions [here][subst-so].
2. It cannot be shared with docker. E.g., The drive is not shared when trying to
   share a directory with source code with docker for
   [VS Code docker development][vscode-docker-dev].

[subst-so]: https://superuser.com/questions/29072/how-to-make-subst-mapping-persistent-across-reboots/926426
[vscode-docker-dev]: https://code.visualstudio.com/docs/remote/containers#_installation

We could use `net use` as follows but it does not show up in Docker's
`settings > Shared Drives`, either.

* `net use W: \\localhost\$c\path\to\source\code`

To share a drive, create a VHD mount and share it instead.

Create a VHD and mount it:

* https://gist.github.com/zaenk/97cb663738ca8e0225da25a28f2feb75#mount-a-vhd

Automount it at startup:

* http://woshub.com/auto-mount-vhd-at-startup/

### Prevent Monitors from Going to Sleep after Locking the Computer
After locking the computer the monitor might go to sleep. To disable:

1. Open the following registry key:
    ```
    HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\
    7516b95f-f776-4464-8c53-06167f40cc99\8EC4B3A5-6868-48c2-BE75-4F3044BE88A7
    ```
2. Look at the value `Attributes` and change it from `0x00000001` to `0x00000002`.
3. Open the Control Panel (control.exe) and go to `Power Options`.
4. Click `Change plan settings` in front of the selected power plan.
5. Click `Change advanced power settings`.
6. Now under `Display` there should be a new item: `Console lock display off timeout`.
7. Change this to whatever you want.

### Convert a plist File to XML on Windows
`plutil -convert xmlfile.xml com.apple.springboard.plist` where:

* `plutil` is installed with iTunes.
* `plutil` is in `C:\Program Files\Common Files\Apple\Apple Application Support`.

* Source: https://superuser.com/a/1264369

### Oneliner to Find Unquoted Service Paths
`wmic service get displayname,pathname|findstr /IV "C:\Windows"|findstr /IV """`

Unquoted service paths are usually not exploitable. See my
{{< xref path="/post/2020/2020-07-25-airtight-hatchway/"
    text="No, You Are Not Getting a CVE for That" >}}.

### Run Chromium Browsers with a Proxy
Chromium uses the WinINET proxy settings. Instead of redirecting everything to
the browser, we can set the proxy using the command line (also works for
Chrome/Edge and other browsers built on Chromium but not Electron):

* `"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --proxy-server="http://localhost:8080"`

The following does the same but falls back to direct connect if the proxy is not
available. Don't use this because you will not know if the fall back happens:

* `"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --proxy-server="http://localhost:8080,direct://"`

### Microphone does not Work in Discord
You might have enabled the privacy settings in Windows 10.

1. Settings.
2. Search for Privacy.
3. `Microphone privacy settings`.
4. Allow apps to access your Microphone.
5. Enable for `Win32WebViewHost`.
6. ???
7. Yell at ~~your raid group~~ DPS for standing in fire.

### Extract MSI Files
Use the built-in `msiexec` tool.

* `msiexec /a c:\path\to\file.msi /qb TARGETDIR=C:\absolute\path\to\extract\directory`
* Path to the msi file (the first path) can be relative. The second one must be
  absolute and does not accept `/` as path separator.
* The target directory must exist.
* If the path to the target directory (the second path) is not absolute, we
  will get this error: `Could not access network location 'xxx'`.

### Disable Autofocus for Microsoft Lifecam Cinema
If the "Microsoft Lifecam Cinema" webcam constantly autofocuses on Windows 10.

1. Open the Windows camera app.
    1. If the camera is already in-use (e.g., videoconferencing tool) turn it
       off in the other app.
2. Click the middle icon from the three icons to the left.
3. Drag the slider to make it manual focus.

You can also try in Skype which is where the old utility is accessible.

1. Open Skype.
2. Click on settings (gear to the right).
3. Select "Video Device" in the left side bar.
4. Select the "Microsoft LifeCam Cinema."
5. Click on "Camera Settings" (this will open the old utility that went away).
6. Click on the "Camera Control" tab and remove the "Auto" checkbox in front of
   focus.

* These are connected so if you have the camera app open and change the focus in
  Skype you can see the change immediately.
* **The setting is lost after restart**. Just opening the Camera app does the job.

### Install WinDbg as the Post-Mortem Debugger

1. Install WinDbg as part of the Windows 10 SDK.
    * https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools
    1. NYou do not need most of the stuff that the SDK installs. You will only
       need to install `Debugging Tools for Windows`.
2. Open an admin cmd and navigate to the following dir:
    * `C:\Program Files (x86)\Windows Kits\10\Debuggers\`
3. Go into each of the x64 and x86 directories and run the following command:
    * `windbg -I`
4. You should get a prompt that says WinDbg has been installed as the default
   post-mortem debugger.

### Remove WinDbg as the Post-Mortem Debugger
Delete some registry keys.

* 64-bit version
    1. Go to `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug`.
    2. Remove the `Debugger` key.
* 32-bit version
    1. Go to `HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug`.
    2. Remove the `Debugger` key.

### Open a Network Monitor cap File in Wireshark and Save is Disabled
This happens in two instances:

1. **Not fixable**: If the NetMon capture file contains IEEE 802.11 plus Network
   Monitor radio header encapsulated packets instead of Per packet encapsulated
   packets.
    * Seems like this happens outside of VMs when we are capturing traffic for a wireless network interface.
2. **Fix below**: If you save the display filter in the capture file. The filter
   will be first packet in the resulting cap file and that's what causes this
   issue.
   * Do not check the `Record display filter in capture file` when saving the
     file in Netmon.

If you already have a file with the display filter you can remove it.

1. Use the `netmon_filter` in Wireshark. You will most likely see one packet.
   It's the first packet and its ID is 1.
2. Close it and use `editcap` to remove it.
    * `C:\Program Files\Wireshark>editcap -F netmon2 C:\path\to\netmon.cap C:\path\to\modified.cap 1`
3. Open `modified.cap` in Wireshark and save it as pcap.

* Source: https://ask.wireshark.org/question/7163/my-save-and-save-as-are-grayed-out/

### Keyboard Shortcut to Run Applications Elevated
For example, running `notepad` as admin.

1. Open the start menu. E.g., Windows key.
2. Type `notepad`, now notepad is selected.
3. Alternatively, open the Run dialog with `Windows+R` and enter `notepad`.
4. Press `ctrl+shift+enter`.
5. UAC pops up.

This also works if you select a shortcut and press `ctrl+shift+enter`.

### Firewall Rules in the Registry
If you cannot delete firewall rules in the GUI, delete their corresponding rule
in the registry (user rules are represented by a GUID). Also helps with reading
the rules because the rule text might not say which executable is targeted:

Location:

* `Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules`

Format:

* https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpfas/2efe0b76-7b4a-41ff-9050-1023f8196d16

### Install Packages on Windows from the Command Line (Needs Admin)
To install `telnet client` in an admin command prompt:

```
pkgmgr /iu:"TelnetClient"
```

### Uninstall IE 11 from Windows 7 (and Install an Older Version)

1. Go to `Control Panel > Programs > Programs and features`.
2. Select `Installed Updated`.
3. Look for `Internet Explorer 11`.
4. Right click and uninstall.
5. Download older version of IE (e.g. IE 9) for Windows 7 and install it.

### Read Scheduled Task's DACL
Find the task name in the `PathToTask` registry key and use it in the command:

```powershell
$PathToTask = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\[replace with task]"
$SDBin =  ( (get-itemProperty $PathToTask).sd )

ConvertFrom-SddlString ([wmiclass]"Win32_SecurityDescriptorHelper").BinarySDToSDDL($SDBin).SDDL
```

* Source: https://serverfault.com/a/997929

### Find Users Under the HKEY_USERS Registry Hive
`HKEY_LOCAL_USER` is a subset of `HKEY_USERS` for the current user. Under
`HKEY_USERS` we see a bunch of directories. To figure out the users for these
directories we need to see them in the following location:

* `Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\`

For example, I have `HKEY_USERS\S-1-5-21-2868049494-289672223-1164028246-1001`
in a VM. So I go to
`Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-21-2868049494-289672223-1164028246-1001`
and look under the `ProfileImagePath` key to see which user it is.

* Source: https://stackoverflow.com/a/2919369

### Find The Open Handle to a File or Resource

1. Open `Resource Monitor`.
2. `CPU` tab.
3. `Associated Handles` section > enter the name of the file/resource in the
   search field. Look at the source for a screenshot.
4. Kill the process using t he handle.

* Source: https://superuser.com/a/643312

### powercfg

* `powercfg /requests`
    * See which programs have requested to keep the device display active.
    * Source: https://textslashplain.com/2020/10/05/images-keeping-you-awake/
* `powercfg /sleepstudy`
    * Generates a fancy HTML page.
    * Source: [Matt Thomlinson][mattt-twitter].

[mattt-twitter]: https://twitter.com/mattt_cyber

### WSL
See current distributions and their version: `wsl --list --verbose` or `wsl -l
-v`.

Set the default version to 2 for all new distributions: `wsl --set-default-version 2`

Convert a distro (e.g., `Ubuntu-18.04`) to version 2: `wsl --set-version
Ubuntu-18.04 2`

Moving to WSL2 will prevent your machine from talking to the internet with some
VPN software and if you are connected to the VPN. I think it's because WSL2 uses
Hyper-V and Hyper-V VMs have the same problem (on VPN they do not have network
connectivity).

------

## PowerShell

### List All Files (Including Hidden Files)
`Get-ChildItem "searchterm" -recurse -force -path c:\ | select-object FullName`

* `-recurse`: recursive. Loops through all directories
* `-force`: list hidden files.
* `select-object`: Selects each file from last point
* `FullName`: Only display file name

### Diff in PowerShell
`Compare-Object (Get-Content new1.txt) (Get-Content new2.txt) | Format-List >> Diff-Output`

Output will be in format of

* `InputObject`: `c:\users\username\somefile` -- line content
* `SideIndicator`: `=>` -- exists in new2.txt (second file, file to the right)

### Pseudo-grep in PowerShell
Alternatively, use [ripgrep][ripgrep-link] like `rg -i 'whatever'`.

[ripgrep-link]: https://github.com/BurntSushi/ripgrep

In PowerShell:

`findstr "something" *.txt`  will include filename and line (no number AFAIK).

`findstr /spin /c:"keyword" *.*`

* /s: recursive - will search through the current directory and all
  sub-directories.
* /p: skip binary files (or files with characters that cannot be printed).
* /i: case-insensitive - remove if you want case sensitive search.
* /n: print line number.

If you want to search for different keywords (with OR) remove the `/c:`

`findstr /spin "keyword1 keyword2" *.*`

will search for `keyword1 OR keyword2` in files

* Source: https://technet.microsoft.com/en-us/library/Cc732459.aspx

### grep in Command Results
`whatever.exe | Select-String -pattern "admin"`

### Get-Acl and icacls.exe
`Get-Acl -path c:\windows\whatever.exe | Format-List`

`icacls.exe c:\windows\whatever.exe`

### time in PowerShell
`Measure-Command {python whatever.py}`

### VHD File is Open in System (and Cannot be Deleted)
You clicked on a VHD file and now cannot delete it. Use this PowerShell command
to dismount it. The path to the VHD should be absolute.

`Dismount-DiskImage -ImagePath 'C:\full\path\to\whatever.vhd'`

### Base64 Encode and Decode without PowerShell
Use `certutil` for bootleg base64 encoding/decoding:

- `certutil -encode whatever.exe whatever.base64`
- `certutil -decode whetever.base64 whatever.exe`

### Load a Managed DLL from PowerShell

* Source: https://www.leeholmes.com/blog/2006/10/27/load-a-custom-dll-from-powershell/

### Zip a Directory with PowerShell

* `Compress-Archive -Path C:\path\to\folder\ -DestinationPath c:\path\to\destination\archive`

Note the destination file will be `archive.zip` but we don't need to provide the
extension in the command.

* Source: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.archive/compress-archive

------

## Hyper-V
Switching from VirtualBox for Hyper-V had its own set of tradeoffs.

### Cannot Create Virtual Switch
When creating a Virtual Switch in Hyper-V you get an error along the lines of
"failed adding ports to the switch" and "a parameter passed was invalid."

1. Open an admin command prompt and run `netcfg -d`.
2. Restart the host machine.

### Cloning VMs in Hyper-V
You cannot clone VMs in Hyper-V like VirtualBox. Create a copy of the vhd(x)
hard disk and use it in a new VM. Yes, it's as manual as it sounds.

### The Guest Has No Internet
The internet recommends creating an external virtual switch but it did not work
for me. I deleted the external switch and used the default switch and it somehow
worked so try doing that.

This also happens if you are using an active VPN connection on the host.

### Higher Resolution For Debian/Ubuntu Guest in Hyper-V
Seems like the highest resolution is 1080p.

1. `sudo nano /etc/default/grub`.
2. Change the line with `GRUB_CMDLINE_LINUX_DEFAULT` to
    * `GRUB_CMDLINE_LINUX_DEFAULT="quiet splash video=hyperv_fb:1920x1080"`
3. `sudo update-grub`.
4. Restart the VM.

* Source: https://askubuntu.com/a/745142

### Creating an Ubuntu VM in Hyper-V
Most important item, do not select `log in automatically` during setup.
Otherwise, xRDP will fail silently.

* https://www.hanselman.com/blog/UsingEnhancedModeUbuntu1804ForHyperVOnWindows10.aspx

### Windows DNS Cache is not Getting Populated in Hyper-V Guest
In a default Hyper-V guest networking setup the local DNS resolver cache is
empty.

* Symptom: `ipconfig /displaydns` prints nothing.
* Solution: Modify the DNS server for the network adapter and manually add a DNS
  server like `8.8.8.8` or `1.1.1.1`.

------

## VirtualBox

### Restart Clipboard Functionality in VirtualBox After Guest Resume
Sometimes disabling and enabling the clipboard in VirtualBox menu works.

Or in the Windows guest:

1. Kill `VBoxTray.exe` in task manager.
2. Start `VBoxTray.exe` again.

* Source: https://superuser.com/a/691337

### Change the Hardware UUID of Cloned Windows VMs to Avoid Windows Reactivation
You cloned a Windows VirtualBox VM and now you have to activate it again. This
script changes the hardware UUID of the cloned machine to the old one. No
reactivation needed.

``` powershell
$ORIGVirtualMachineName="Windows 10 - Base"   # Old VM name as it appears in VirtualBox
$clonedVirtualMachineName="Win10Clone"        # New VM name
$vboxDir="c:\Program Files\Oracle\VirtualBox" # Directory containing VBoxManage
cd $vboxDir
$uid=$($($(.\VBoxManage.exe showvminfo $ORIGVirtualMachineName|select-string "Hardware UUID:").ToString()).Split())[4]
.\VBoxManage modifyvm $clonedVirtualMachineName --hardwareuuid $uid
```

### Increase VM Disk Size
The default modern.ie VMs come with a 40GB vmdk hard drive and I want to resize
them to 100GB (because videogames are huge). VirtualBox cannot resize it. We can
clone it to vdi, resize it and convert it back to vdmk.

`VBoxManage` is at `c:\Program Files\Oracle\VirtualBox` (default installation).

1. Convert vmdk hard disk to vdi:
    * `VBoxManage clonemedium "MSEdge - Win10.vmdk" "MSEdge - Win10.vdi" --format vdi`
2. Resize vdi.
    * `VBoxManage modifymedium "MSEdge - Win10.vdi" --resize 102400`
3. Convert vdi back to vdmk (I usually just keep it as vdi).
    * `VBoxManage clonemedium "MSEdge - Win10.vdi" "MSEdge - Win10-resized.vdi" --format vmdk`
4. Extend the original partition in guest with `Disk Management` (Windows).
    1. Run `diskmgmt.msc`.
    2. Click on the existing partition and select `Extend`.
    3. Use the wizard and add the new empty space to the origin partition.
5. Delete unused vdi or vmdk files.
6. ???
7. Enjoy 100 GBs of space. Well, 83GB on a default Win10 x64 install.

* Source: https://stackoverflow.com/a/12456219

------

## Git
I know a total of 5-6 git commands.

### Create New Branch and Merge
This works with small branches (e.g. one fix or so). Adapted from a
[Bitbucket tutorial][bt-tut].

[bt-tut]: https://confluence.atlassian.com/bitbucket/use-a-git-branch-to-merge-a-file-681902555.html

1. Create a new branch and checkout - `git checkout -b fix-whatever`\\
   This will create a branch of your current one so make sure you are creating a
   branch from the branch you want. This is the same as `git branch whatever`
   and `git checkout whatever`.

2. Make changes and commit - `git add - git commit`\\
   Make any changes you want to do, then stage and commit.

3. Push the branch to the remote repo [optional] - `git push`\\
   This can be safely done because it's an obscure branch and no one else cares about it.

4. Switch to the original branch to merge - `git checkout master`\\
   The branch from step one.

5. Merge the branches - `git merge fix-whatever`.\\
   Alternatively, squash all commits into one `git merge --squash fix-whatever`
   and then `git commit -m "One message for all commits in merge"`.

6. Delete the branch - `git branch -d fix-whatever`\\
   We don't need it anymore. If it was pushed to remote, then we need to delete
   it there too.

### Only Clone a Certain Branch
`git clone -b <branch> <remote_repo>`

### Undo Remote git History after Push
Because this keeps happening to me.

1. Reset the head in local repo N commits back. - `git reset HEAD~N`\\
   Where N is the number of commits that you want to revert.

2. Make changes and stage them - `git add`

3. Commit the changes - `git commit`

4. Force push the local repo to remote - `git push -f`\\
   Note: This will force the update and erase the commit history online. I only
   do it for my solo repositories.

### Sync a Fork with the Original Repository
You have forked a repository a while ago. You want to sync the new changes.

1. Add the original repository as `upstream`.
    1. `git remote add upstream git@github.com:original-user/original-repo.git`
    2. `git remote add upstream https://github.com/original-user/original-repo/`
    3. Check with `git remote -v1`
2. `git fetch upstream`
3. Merge the `upstream/main` branch into the local `main` branch:
    1. `git merge upstream/main`

* Source: GitHub documentation.
    * [Configuring a remote for a fork][config-remote]
    * [Syncing a fork][sync-fork]

[config-remote]: https://docs.github.com/en/free-pro-team@latest/github/collaborating-with-issues-and-pull-requests/configuring-a-remote-for-a-fork
[sync-fork]: https://docs.github.com/en/free-pro-team@latest/github/collaborating-with-issues-and-pull-requests/syncing-a-fork

### Use Notepad++ as git Editor on Windows via Cygwin
Create a file called `npp` with the following content and copy it to
`cygwin\bin`. Modify the path of notepad++ to point to your installation.

``` bash
'C:/Program Files (x86)/Notepad++/notepad++.exe' -multiInst -notabbar -nosession -noPlugin "$(cygpath -w "$*")"
```

Run the following command in Cygwin to set it as the global git editor:

```
git config --global core.editor npp
```

### Change Remote for an Existing Git Repository
For example, moving `repository` from Bitbucket to GitHub or back.

```
git remote set-url origin git@github.com:parsiya/repository.git
```

### List All Authors in a Git Repository
I wanted to see if I was still showing up as `root` in old commits.

```
git shortlog -s | cut -c8-
```

### Rewrite Author for Older Commits
`parsiya.net` had commits as `root` from when I was using it offline. I wanted
to change everything to my own username.

1. If you want to start at root - `git rebase -i --root`
2. If you want to start from commit AAAA - `git rebase -i AAAA`
3. Change `pick` to `edit` for every commit with the old author and save. Rebase starts and pauses at every commit with `edit`.
4. Change the author: \\
`git commit --amend --author="Author Name <email@address.com>"`
5. Continue the rebase - `git rebase --continue`
6. Rinse and repeat.

* Source: https://stackoverflow.com/a/3042512

### Remove Uncommitted Files from Staging
You have added files with `git add` but have not committed them and want to
remove some (not all) instead of `git reset`.

```
git reset HEAD -- file/directory
```

### Make git Case Sensitive (with a Catch)
In a case-insensitive file system (Windows, Mac), git is case-insensitive by
default. So if you rename `Bob.jpg` to `bob.jpg` after it has already been
pushed, git doesn't change it because from a file-system perspective it's the
same file (although Windows shows the filename in lowercase).

To make git case sensitive on such an OS (Windows, OSX):

```
git config core.ignorecase false
```

**NOTE:** This introduces its own problems. Let's assume you have already
committed `Bob.jpg` and make git be case-sensitive. You rename it to `bob.jpg`
and push it. In the remote repo you will have two files `Bob.jpg` and `bob.jpg`.

The answer is to rename `Bob.jpg` to something else like `Bob-1.jpg`, push and
then rename it back to `bob.jpg`.

### Exclude a Committed File with gitignore
`.gitignore` only works on new `git add`s. If we have already pushed
`blah/whatever.cpp` to the repo, adding `whatever.cpp` to `.gitignore` does
nothing.

Do this first and then `gitignore` will work (not using `--cached` will remove
the file completely from the filesystem):

* `git rm --cached blah/whatever.cpp`
* Use `-r` for recursive change. Needed for directories.

* Source: https://stackoverflow.com/a/30227922

Note: Also overwrite history if the file had secrets/sensitive info.

### Sign git Commits
Follow this guide:

* https://withblue.ink/2020/05/17/how-and-why-to-sign-git-commits.html

------

## Visual Studio Code
My current (as of June 2019) editor of choice. Settings are at
https://parsiya.io/categories/configs/vscode/.

### Associate an Extension with a Specific Language
This allows us to have specific language highlighting for custom extensions. Add
the following to `settings.json`:

``` json
    "files.associations": {
        "*.whatever": "cpp",
        "*.generics": "go"  // lol
    }
```

### Install a Specific Version of an Extension
This also disables auto-update for that extension so you can keep an older
version of an extension.

1. Open the extensions tab.
2. Right-click on the extension.
3. Select `Install Another Version...`.
4. Select the version.
5. The extension will not auto-update.

* Source: https://github.com/microsoft/vscode/issues/30579#issuecomment-456028574

### couldn't start client gopls unsupported URI scheme
VS Code needs to open a workspace. Open the parent directory to the project.

Source: https://www.reddit.com/r/golang/comments/g6l6y9/couldnt_start_client_gopls_unsupported_uri_scheme/

------

## Sublime Text 3
Tips for using the Sublime Text 3 editor. I don't use Sublime Text anymore
although I bought it. This section is probably outdated.

### Fix "MarGo build failed" for GoSublime on Windows
GoSublime's executable has Go version in it. In most cases, it cannot grab the
version on Windows and the build will fail like this:

```
MarGo: MarGo build failed
cmd: `['C:\\Go\\bin\\go.exe', 'build', '-tags', '', '-v', '-o', 
       'gosublime.margo_r17.12.17-1_go?.exe', 'gosublime/cmd/margo']`
```

Where `?` is the Go version that is unknown.

Edit this file:

- `%AppData%\Sublime Text 3\Packages\GoSublime\gosubl\sh.py`

Find these lines:

``` python
cmd = ShellCommand('go run sh-bootstrap.go')
cmd.wd = gs.dist_path('gosubl')
cr = cmd.run()
raw_ver = ''
ver = ''     # Change this to '1'
```

Edit `ver` to whatever, I usually do `1`. Restart Sublime Text and MarGo will
build.

**This must to be done for every new GoSublime version.**

### Open the Same File in a New Tab
`File > New view into File`. Then drag the pane to a second screen/location.

------

## Burp

### Quality of Life Tips and Tricks for Burp

* See my blog post:
  {{< xref path="/post/2019/2019-10-13-quality-of-life-burp/"
    text="Quality of Life Tips and Tricks - Burp Suite" >}}

### Selected Text in Burp is Black
Usually happens in Virtual Box.

![Burp 3D rendering issue](/images/cheatsheet/burp-3d-issue.png)

Two options:

1. Disable 3D rendering in Virtual Box. Not recommended.
2. Run Burp with 3D disabled (make a shortcut): \\
    ```
    java.exe "-Dsun.java2d.d3d=false" -jar burp.jar
    ```
* The complete command for the default install on Windows is:
    ```
    "C:\Program Files\BurpSuiteCommunity\jre\bin\java.exe"
      "-Dsun.java2d.d3d=false"
      -jar "C:\Program Files\BurpSuiteCommunity\burpsuite_community.jar"
    ```

Source - credit to `floyd`:

* https://support.portswigger.net/customer/portal/questions/16802069-text-highlighted-in-black

### Using iptables to Proxy Android Apps with Burp
Technically this should work with any proxy.

1. Add Burp's CA certificate to the device.
2. If there's certificate pinning, bypass it.
3. Enable [invisible proxying][invisible-proxy] for the target listener.
4. Root the device, iptables needs root.

For example, we want to redirect all traffic to `443` and `80` to Burp's
listener at `192.168.137.1:8080`. This is the default IP address of a Windows
machine if the mobile hotspot network is enabled:

```
iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination 192.168.137.1:8080
iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination 192.168.137.1:8080

iptables -t nat -A POSTROUTING -p tcp --dport 80 -j MASQUERADE
iptables -t nat -A POSTROUTING -p tcp --dport 443 -j MASQUERADE
```

* Source: http://blog.dornea.nu/2014/12/02/howto-proxy-non-proxy-aware-android-applications-through-burp/

[invisible-proxy]: https://portswigger.net/burp/documentation/desktop/tools/proxy/options/invisible

### Regex to Search for URLs in Burp Responses
Not the best regex but does the job:

* `http([^"])*\.([^"])+`

Better but more expensive regex:

```
/(?:(?:https?|ftp|file):\/\/|www\.|ftp\.)
    (?:\([-A-Z0-9+&@#\/%=~_|$?!:,.]*\)|[-A-Z0-9+&@#\/%=~_|$?!:,.])*
    (?:\([-A-Z0-9+&@#\/%=~_|$?!:,.]*\)|[A-Z0-9+&@#\/%=~_|$])
```

------

## Linux
I'd just like to interject for a moment. What you're referring to as Linux, is
in fact, GNU/Linux, or as I've recently taken to calling it, GNU plus Linux.

### Python Module Installed with pip but Command is not Available
They are installed in `~/.local/bin`. Add it to your `$PATH`.

### Add a User to sudoers on Debian

1. `su -`: If you do `su` alone, you might not find `usermod` in your path.
    * "Starting su with the option " -" gives you the full path root would have
      when logging in to the system after startup. So directories like
      /usr/sbin, /sbin or /opt/kde/bin become part of roots path variable after
      doing su and will be searched for commands."
      [source](https://www.linuxquestions.org/questions/linux-newbie-8/command-usermod-not-found-385901/#post1967095)
2. `usermod -aG sudo user-name`
3. Restart (or logoff and login?).

### grep
Only search in files with specific extensions. E.g., only `md/markdown`.

`grep -ir "whatever" --include\*.md --include \*.markdown`

------

## Docker

### Commands

* Images:
    * All images: `docker images`
    * Delete image(s): `docker rmi img1 img2`
        * By name: `docker rmi whatever/blah`
        * By ID: `docker rmi f20d`
    * Build image from file:
        * `docker build . -f file -t whatever/blah`
        * `DockerFile` it does not need to be mentioned. `docker build -t whatever/blah`
        * `docker image` should display the image now.
* Containers:
    * All running containers: `docker container ls -a` - `docker ps -a`
    * Only show running containers: `docker ps`
    * Stop one container: `docker stop d194 3f4a`
    * Stop all containers:
        * PowerShell: `docker ps -a -q | ForEach { docker stop $_ }`
        * Bash: `docker stop $(docker ps -a -q)`
    * Delete container(s): `docker container rm d194 3f4a`
    * Run a container from an image:
        * `docker run -it whatever/blah [command]` where command is usually `/bin/bash`.
        * `--rm` to delete the container after it exits. This is useful when testing.
* centOS specific:
    * centOS cmd for `DockerFile`: `CMD ["/usr/sbin/init"]`
    * Create and run a centOS container: `docker run -it whatever/blah sh`

### Troubleshooting

* Error starting userland proxy: mkdir ... : input/output error.
    * Restart docker. On Windows, right click the docker tray icon and select `Restart...`.

------

## Python
These were written when I used Python 2, some might not work with newer versions.

### Create All Possible Combinations of Two Lists of Strings

```python
from itertools import product

if __name__ == "__main__": 
    set1 = ["https://example.net", "https://google.com"]
    set2 = ["/whatever", "/something"]
  
for e1, e2 in product(set1, set2):
    print(e1+e2)
```

### Multi-line String
Note the space on second line.

``` python
string1 = "This is line one of the string that is going to be over 80"
          " characters and thus needs to be broken into two or more lines."
```

### Main
Because I always forget.

```python
def main():
    # whatever

if __name__ == "__main__":
    main()
```

### Format String with {}

```python
"{}*{} = {}".format(x, y, x*y)
```

### bytearray
With Python 3, it's not that useful but still:

* [http://dabeaz.blogspot.com/2010/01/few-useful-bytearray-tricks.html](http://dabeaz.blogspot.com/2010/01/few-useful-bytearray-tricks.html)

### Cyclic XOR on bytearrays

```python
import itertools

def xor_byte(payload, key):
    """
    Get a bytearray, XOR it with a key (bytearray) and repeat the key
    Return bytearray
    """
    return bytearray((mybyte ^ keybyte) for (mybyte, keybyte) in
                     itertools.izip(payload, itertools.cycle(key)))
```

### Cyclic XOR on Strings
Same as above but string

```python
import itertools

def xor_str(payload, key):
    """
    Get a string, XOR it with a key (string) and repeat the key
    Return string
    """
    return "".join(chr(ord(mybyte) ^ ord(keybyte)) for (mybyte, keybyte) in
                   itertools.izip(payload, itertools.cycle(key)))
```

### Python One-Liners in Command Line
You can run Python one-liners from command line using `python-c "command"`.
Separate command with `;` and use `'` for strings. Remember that you need to
`import` things too.

For example a one-liner to encode something in base64:

``` python
python -c "from base64 import b64encode; print b64encode('HelloHello');"
```

More:

``` python
# Decrypt from AES (you need pyCrypto)
python -c "from Crypto.Cipher import AES; aes = AES.new(KEY, AES.MODE_ECB); print aes.decrypt(CIPHERTEXT));"
```

------

## Java

### Enable Log4j for a Java App
This usually happens when I am testing a Java app and it uses `log4j` but
logging is not enabled.

Create a file named `log4j.properties` by the main jar file and put the
following in it. Add `-Dlog4j.debug` to the app's command line parameters.

The app might already have the command to log but is just missing the file. Use
`procmon` to see which paths are searched to find this file.
The `Result is NAME NOT FOUND` filter is your friend.

```
log4j.rootLogger=debug, stdout, R

log4j.appender.stdout=org.apache.log4j.ConsoleAppender
log4j.appender.stdout.layout=org.apache.log4j.PatternLayout

# Pattern to output the caller's file name and line number.
log4j.appender.stdout.layout.ConversionPattern=%5p [%t] (%F:%L) - %m%n

log4j.appender.R=org.apache.log4j.RollingFileAppender
log4j.appender.R.File=example.log

log4j.appender.R.MaxFileSize=100KB
# Keep one backup file
log4j.appender.R.MaxBackupIndex=1

log4j.appender.R.layout=org.apache.log4j.PatternLayout
log4j.appender.R.layout.ConversionPattern=%p %t %c - %m%n
```

* Source: http://logging.apache.org/log4j/1.2/manual.html

------

## Misc

### Download Youtube Videos with Substitles with youtube-dl
I love Wuxia (Chinese martial arts if I am not mistaken) series and movies. The
following [youtube-dl](https://github.com/ytdl-org/youtube-dl) command will
download the 56 episode HQ quality Chinese TV series called `Xiao Ao Jiang Hu`
or `Laughing in the Wind` (also called `The Smiling Proud Wanderer` or
`Swordsman`).

`youtube-dl --ignore-errors --write-srt --sub-lang en --yes-playlist 'https://www.youtube.com/playlist?list=PLuGy72vdo4_ScwTYb1bAynhBs3KgowvvQ'`

```
--ignore-errors: continue after errors
--write-srt    : download substitles
--sub-lang     : subtitle language (in this case English)
--yes-playlist : link to a Youtube playlist
```

`Youtube-dl` can be downloaded using `pip`. For example on Windows:\\
`python -m pip install youtube-dl`.

It's also possible to download binaries from https://github.com/ytdl-org/youtube-dl/releases.

Sometimes, you need to pass `--no-check-certificate` to bypass certificate
errors.

### Download Different Qualities with youtube-dl
`youtube-dl -F https://www.youtube.com/watch?v=xKYIde5jh_8` will show use a list
of resolutions. The first column will be the `format code` which is a number.

```
$ youtube-dl -F https://www.youtube.com/watch?v=xKYIde5jh_8
...
format code  extension  resolution note
249          webm       audio only tiny   48k # note removed for most lines
...
247          webm       1280x720   720p  361k
136          mp4        1280x720   720p  482k
18           mp4        640x360    360p  282k
22           mp4        1280x720   720p  611k , avc1.64001F, 30fps, mp4a.40.2 (44100Hz) (best)
```

Then, we can download that format code (or best):

* 247: `youtube-dl -f 247 https://www.youtube.com/watch?v=xKYIde5jh_8`
* 22 or best: `youtube-dl -f best https://www.youtube.com/watch?v=xKYIde5jh_8`

### Print Envelopes with the Brother DW2280 printer and LibreOffice
I gave away the printer when I moved to Canada but I am keeping the instructions
just in case. Before printing, get to printer physically and use the following
instructions:

- http://support.brother.com/g/b/faqend.aspx?c=gb&lang=en&prod=hl2170w_all&faqid=faq00000063_025

1. Open the back.
2. Press the two green handles down.
3. Open manual feed in front.
4. Adjust the paper guide and put the envelope in.
5. Put the envelope face up (the side that has the addresses should be up).
6. Insert it until the printer says `Please Wait` and grabs the paper.

Now open LibreOffice and use these instructions:

- https://www.pcmech.com/article/how-to-print-an-envelope-with-libreoffice/

1. Create new document in LibreOffice Writer (Word).
2. `Insert > Envelope`.
3. Enter destination in `Addressee`.
4. Check `Sender` and enter your own address in the bottom textbox.
5. Select `Printer` tab.
6. Select printer and press `Setup`.
7. Select the Brother printer and press `Properties`.
8. Select the following options:
    * Paper Size: `Com-10`.
    * Media Type: `Envelopes`.
    * Paper Source > First Page: `Manual`.
9. Print

### Tab Size 4 in the Github Web Interface
Add `?ts=4` to end of the file URL.

### ffmpeg
To split a file with `ffmpeg`. Let's say we want to grab the first 200 seconds
of a file starting from second 100.

`ffmpeg -i input.mp4 -strict -2 -ss 100 -t 200 output.mp4`

I also use it to reduce the file size of my video proof-of-concepts:

1. Record the video with OBS Studio. The output file is `video.mkv`.
2. Use OBS Studio to remux the video `File (menu) > Remux Recordings` to get
   `video.mp4`.
3. Use `ffmpeg` to reduce the file size:
    1. `ffmpeg -strict -2 -ss 0 video-processed.mp4 -i video.mp4`.

* Source: https://unix.stackexchange.com/a/1675

I still need to experiment with different codecs to figure out which one is best
but this method reduces the file size dramatically without a noticeable change
in quality.

### Wrap Long Lines in Page Source in Firefox
Easier method: In the `View Source` page, right-click and select
`Wrap Long Lines`, or:

1. `about:config`
2. Set `view_source.wrap_long_lines` to `true`.

* Source: https://support.mozilla.org/en-US/questions/1208440

### Wireshark Not Equal Filter

* Right: `!tcp.port == 8080`
* Wrong: `tcp.port != 8080`

Source: https://thetechl33t.com/2015/06/01/wireshark-not-equal-to-filter/
