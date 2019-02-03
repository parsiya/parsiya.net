---
date: "2016-02-24T22:29:57-05:00"
draft: false
title: "Cheat Sheet"
url: "/cheatsheet/"
categories:
- cheatsheet

---

Often I need to do something that I have done many times in the past but I have forgotten how to do it. This is a page (or a series of pages if it grows large enough) to give me a simple repository of how-tos that I can access online. In this page you may find those commands and tips that I need from time to time (and usually forget when I need them).

- [Tar](#tar)
  - [Compressing a directory using tar](#compressing-a-directory-using-tar)
  - [Decompressing a tar.gz file](#decompressing-a-targz-file)
- [OpenSSL](#openssl)
  - [Dumping the TLS certificate using OpenSSL](#dumping-the-tls-certificate-using-openssl)
  - [TLS connection with a specific ciphersuite using OpenSSL](#tls-connection-with-a-specific-ciphersuite-using-openssl)
- [Amazon S3](#amazon-s3)
  - [Using s3deploy](#using-s3deploy)
  - [Syncing a folder with an Amazon S3 bucket using s3cmd](#syncing-a-folder-with-an-amazon-s3-bucket-using-s3cmd)
  - [Changing the mime-type of CSS file after upload to fix CSS not displaying correctly](#changing-the-mime-type-of-css-file-after-upload-to-fix-css-not-displaying-correctly)
  - [Setting the index to a non-root file in static website hosted on S3](#setting-the-index-to-a-non-root-file-in-static-website-hosted-on-s3)
- [Windows](#windows)
  - [Shortcut to IE (or WinINET) Proxy Settings](#shortcut-to-ie-or-wininet-proxy-settings)
  - [where.exe](#whereexe)
  - [Delete file or directory with a path or name longer than the Windows limit](#delete-file-or-directory-with-a-path-or-name-longer-than-the-windows-limit)
  - [Install "Bash for Windows" without Windows Store](#install-bash-for-windows-without-windows-store)
- [Powershell](#powershell)
  - [List all files (including hidden)](#list-all-files-including-hidden)
  - [Diff in Powershell](#diff-in-powershell)
  - [Pseudo-grep in Powershell](#pseudo-grep-in-powershell)
  - [grep in command outputs](#grep-in-command-outputs)
  - [Get-Acl and icacls.exe](#get-acl-and-icaclsexe)
  - [time in PowerShell](#time-in-powershell)
  - [VHD File is Open in System (and cannot be Deleted)](#vhd-file-is-open-in-system-and-cannot-be-deleted)
  - [Base64 encode and decode without PowerShell](#base64-encode-and-decode-without-powershell)
  - [Change the hardware UUID of cloned Windows VMs to avoid reactivation](#change-the-hardware-uuid-of-cloned-windows-vms-to-avoid-reactivation)
- [Git](#git)
  - [Create new branch and merge](#create-new-branch-and-merge)
  - [Only clone a certain branch](#only-clone-a-certain-branch)
  - [Undo remote git history after push](#undo-remote-git-history-after-push)
  - [Update local fork from original repo](#update-local-fork-from-original-repo)
  - [Use Notepad++ as git editor on Windows via Cygwin](#use-notepad-as-git-editor-on-windows-via-cygwin)
  - [Tab size 4 in Github web interface](#tab-size-4-in-github-web-interface)
  - [Change Remote for an Existing Git Repository](#change-remote-for-an-existing-git-repository)
  - [List All Authors in a Git Repository](#list-all-authors-in-a-git-repository)
  - [Rewrite Author for Older Commits](#rewrite-author-for-older-commits)
  - [Remove Uncommitted Files from Staging](#remove-uncommitted-files-from-staging)
- [Sublime Text 3](#sublime-text-3)
  - [Fix "MarGo build failed" for GoSublime on Windows](#fix-margo-build-failed-for-gosublime-on-windows)
  - [Open the same file in a new tab](#open-the-same-file-in-a-new-tab)
- [Burp](#burp)
  - [Selected text in Burp is black](#selected-text-in-burp-is-black)
- [Download Youtube videos with substitles](#download-youtube-videos-with-substitles)
- [Print Envelopes Using the Brother Printer and LibreOffice](#print-envelopes-using-the-brother-printer-and-libreoffice)
- [Microphone not working in Discord?](#microphone-not-working-in-discord)

------

## Tar
Insert xkcd, hur dur!

### Compressing a directory using tar
`tar -zcvf target_tar.tar.gz directory_to_be_compressed`

### Decompressing a tar.gz file
`tar -zxvf target_tar.tar.gz path/to/decompress/`

------

## OpenSSL

### Dumping the TLS certificate using OpenSSL
`echo | openssl s_client -connect HOST:PORT 2>/dev/null | openssl x509 -text -noout`

### TLS connection with a specific ciphersuite using OpenSSL
`openssl s_client -connect HOST:PORT -cipher cipher-name -brief`

* `-brief`: reduced output
* `cipher-name`: A cipher from output of `openssl ciphers` command

------

## Amazon S3

### Using s3deploy
I have switched to s3deploy from s3cmd. https://github.com/bep/s3deploy

To make it work, create a file named `.s3deploy.yaml` (not the period) in the root of your website. I use this:

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

The file should be self-explanatory. Don't set `gzip` for `txt` files, **it will break your keybase proof**.

Then run (change region if needed):

```
s3deploy.exe -source=public/ -region=us-east-1 -bucket=[bucketname]
```

To pass your AWS key and secret, you can either set them in an environment variable or in this file:

```
c:\Users\[your user]\.aws\credentials
```

Then inside the file:

```
[default]
aws_access_key_id=
aws_secret_access_key=
```

### Syncing a folder with an Amazon S3 bucket using s3cmd
`python s3cmd sync --acl-public --delete-removed --rr directory-to-sync/ s3://bucket-name`

For example uploading the Hugo public directory to my website:\\
`python s3cmd sync --acl-public --delete-removed --rr public/ s3://parsiya.net`

* `--acl-public`: Anyone can only read.
* `--delete-removed`: Delete objects with no corresponding local files.

### Changing the mime-type of CSS file after upload to fix CSS not displaying correctly
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

### Setting the index to a non-root file in static website hosted on S3
When setting up a static website in an S3 bucket, you need to specify an index and an error page. The index cannot be in a sub-directory but the error page can be. Set the index to a non-existent file (e.g. `whatever.crap`) and set the error page to the actual index page. Source: https://stackoverflow.com/a/20273548

If you are relying on error pages, this will mess with your site because every error will be redirected to the index. Another way is to set a meta redirect in the index file in the root directory and redirecting that page.

------

## Windows

### Shortcut to IE (or WinINET) Proxy Settings

`control inetcpl.cpl,,4`

### where.exe
`where.exe` searches for files. Without any locations, it searches in the local directory and then in PATH.

- `/R` searches recursively in a specific location.
- `/T` displays file size.
- `/?` for help.

### Delete file or directory with a path or name longer than the Windows limit
Answer from [superuser.com](http://superuser.com/a/467814).

```
mkdir empty_dir
robocopy empty_dir the_dir_to_delete /s /mir
rmdir empty_dir
rmdir the_dir_to_delete
```

### Install "Bash for Windows" without Windows Store
`lxrun /install`.

------

## Powershell

### List all files (including hidden)
`Get-ChildItem "searchterm" -recurse -force -path c:\ | select-object FullName`

* `-recurse`: recursive. Loops through all directories
* `-force`: list hidden files.
* `select-object`: Selects each file from last point
* `FullName`: Only display file name

### Diff in Powershell
`Compare-Object (Get-Content new1.txt) (Get-Content new2.txt) | Format-List >> Diff-Output`

Output will be in format of

* `InputObject`: `c:\users\username\somefile` -- line content
* `SideIndicator`: `=>` -- exists in new2.txt (second file, file to the right)

### Pseudo-grep in Powershell
`findstr "something" *.txt`

will include filename and line (no number AFAIK)

`findstr /spin /c:"keyword" *.*`

* /s: recursive - will search through the current directory and all sub-directories
* /p: skip binary files (or files with characters that cannot be printed)
* /i: case-insensitive - remove if you want case sensitive search
* /n: print line number

If you want to search for different keywords (with OR) remove the `/c:`

`findstr /spin "keyword1 keyword2" *.*`

will search for keyword1 OR keyword2 in files

https://technet.microsoft.com/en-us/library/Cc732459.aspx


### grep in command outputs
`whatever.exe | Select-String -pattern "admin"`

### Get-Acl and icacls.exe
`Get-Acl -path c:\windows\whatever.exe | Format-List`

`icacls.exe c:\windows\whatever.exe`

### time in PowerShell
`Measure-Command {python whatever.py}`

### VHD File is Open in System (and cannot be Deleted)
You clicked on a VHD file and now cannot delete it. Use this PowerShell command but the path to VHD should be full.

`Dismount-DiskImage -ImagePath 'C:\full\path\to\whatever.vhd'`

### Base64 encode and decode without PowerShell
Use `certutil` for bootleg base64 encoding/decoding:

- `certutil -encode whatever.exe whatever.base64`
- `certutil -decode whetever.base64 whatever.exe`

### Change the hardware UUID of cloned Windows VMs to avoid reactivation
You cloned a Windows VirtualBox VM and now you have to activate it again. This script changes the hardware UUID of the cloned machine to the old one. No reactivation needed.

``` powershell
$ORIGVirtualMachineName="Windows 10 - Base"   # Old VM name as it appears in VirtualBox
$clonedVirtualMachineName="Win10Clone"        # New VM name
$vboxDir="c:\Program Files\Oracle\VirtualBox" # Directory containing VBoxManage
cd $vboxDir
$uid=$($($(.\VBoxManage.exe showvminfo $ORIGVirtualMachineName|select-string "Hardware UUID:").ToString()).Split())[4]
.\VBoxManage modifyvm $clonedVirtualMachineName --hardwareuuid $uid
```

------

## Git
I know a total of 5-6 git commands and that is fine.

### Create new branch and merge
This works with small branches (e.g. one fix or so). Adapted from a [Bitbucket tutorial](https://confluence.atlassian.com/bitbucket/use-a-git-branch-to-merge-a-file-681902555.html).

1. Create new branch - `git branch fix-whatever`\\
This will create a branch of whatever branch you are currently on so make sure you are creating a branch from the branch you want.

2. Switch to the branch - `git checkout fix-whatever`

3. Make changes and commit - `git add - git commit`\\
Make any changes you want to do, then stage and commit.

4. Push the branch to remote repo [optional] - `git push`\\
This can be safely done because it's an obscure branch and no one else cares about it.

5. Go back to the original branch to merge - `git checkout master`\\
Master or whatever branch you were at step one.

6. Merge the branches - `git merge fix-whatever`.\\
Alternatively squash all commits into one `git merge --squash fix-whatever` and then `git commit -m "One message for all commits in merge"`.

7. Delete branch - `git branch -d fix-whatever`\\
We don't need it anymore. If it was pushed to remote, then we need to delete it there too.

### Only clone a certain branch
`git clone -b <branch> <remote_repo>`

### Undo remote git history after push
Because this keeps happening to me.

1. Reset the head in local repo N commits back. - `git reset HEAD~N`\\
Where N is the number of commits that you want to revert.

2. Make changes and stage them - `git add`

3. Commit the changes - `git commit`

4. Force push the local repo to remote - `git push -f`\\
Note this will force the update and erase the commit history online. If not one else is using the repo in between it's ok.

### Update local fork from original repo

1. See current remotes - `git remote -v`

2. Make original repo the new remote upstream -\\
`git remote add upstream https://github.com/whatever/original-repo/`

3. Now we should see the new upstream with - `git remote -v`

4. Fetch upstream - `git fetch upstream`

5. Switch to your local master branch - `git checkout master`

6. Merge upstream/master into local master - `git merge upstream/master`

7. Push changes - `git push`

### Use Notepad++ as git editor on Windows via Cygwin
Create a file called `npp` with the following content and copy it to `cygwin\bin`. Modify the path of notepad++ to point to your installation.

``` bash
'C:/Program Files (x86)/Notepad++/notepad++.exe' -multiInst -notabbar -nosession -noPlugin "$(cygpath -w "$*")"
```

Run the following command in Cygwin to set it as global git editor:

```
git config --global core.editor npp
```

### Tab size 4 in Github web interface
Yes I know Github != Git but cba to create a different category.

Add `?ts=4` to end of file URL.

### Change Remote for an Existing Git Repository
A.K.A. when moving `repository` from bitbucket to github or vice versa.

```
git remote set-url origin git@github.com:parsiya/repository.git
```

### List All Authors in a Git Repository
I wanted to see if I was still showing up as `root`.

```
git shortlog -s | cut -c8-
```

### Rewrite Author for Older Commits
`parsiya.net` had commits as `root` from when I was using it offline. I wanted to change everything to myself.

* Source: https://stackoverflow.com/a/3042512


1. If you want to start at root - `git rebase -i --root`

2. If you want to start from commit AAAA - `git rebase -i AAAA`

3. Change `pick` to `edit` for every commit with the old author and save. Rebase starts and pauses at every commit with `edit`.

4. Change the author - \\
`git commit --amend --author="Author Name <email@address.com>"`

5. Continue the rebase - `git rebase --continue`

6. Rinse and repeat.

### Remove Uncommitted Files from Staging
You have added files with `git add` but have not committed them and want to remove some (not all) instead of `git reset`.

```
git reset HEAD -- file/directory
```

------

## Sublime Text 3
Tips for using the Sublime Text 3 editor.

### Fix "MarGo build failed" for GoSublime on Windows
GoSublime's executable has Go version in it. In most cases, it cannot grab the version on Windows and the build will fail like this:

```
MarGo: MarGo build failed
cmd: `['C:\\Go\\bin\\go.exe', 'build', '-tags', '', '-v', '-o', 
       'gosublime.margo_r17.12.17-1_go?.exe', 'gosublime/cmd/margo']`
```

Where `?` is the go version that is unknown.

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

Edit `ver` to whatever, I usually do `1`. Restart Sublime Text and Margo will build.

**Unfortunately this needs to be done for every new GoSublime version.**

### Open the same file in a new tab
`File > New view into File`. Then drag the pane to a second screen/location.

------

## Burp

### Selected text in Burp is black
This might happen inside Virtual Box.

![Burp 3D rendering issue](/images/cheatsheet/burp-3d-issue.png)

You have two options:

1. Disable 3D rendering in Virtual Box. Don't.
2. Run Burp with 3D disabled (make a shortcut):

    ```
    java.exe "-Dsun.java2d.d3d=false" -jar burp.jar
    ```
3. The complete command for the default install on Windows is:

    ```
    "C:\Program Files\BurpSuiteCommunity\jre\bin\java.exe"
      "-Dsun.java2d.d3d=false"
      -jar "C:\Program Files\BurpSuiteCommunity\burpsuite_community.jar"
    ```

Source - credit to `floyd`:

* https://support.portswigger.net/customer/portal/questions/16802069-text-highlighted-in-black

------

## Download Youtube videos with substitles
I love Wuxia (Chinese martial arts if I am not mistaken) series and movies. The following [youtube-dl](https://github.com/rg3/youtube-dl/) command will download the 56 episode HQ quality Chinese TV series called `Xiao Ao Jiang Hu` or `Laughing in the Wind` (also called `The Smiling Proud Wanderer` or `Swordsman`).

`youtube-dl --ignore-errors --write-srt --sub-lang en --yes-playlist 'https://www.youtube.com/playlist?list=PLuGy72vdo4_ScwTYb1bAynhBs3KgowvvQ'`

```
--ignore-errors: continue after errors
--write-srt    : download substitles
--sub-lang     : subtitle language (in this case English)
--yes-playlist : link to a Youtube playlist
```

`Youtube-dl` can be downloaded using `pip`. For example on Windows:\\
`python -m pip install youtube-dl`.

------

## Print Envelopes Using the Brother Printer and LibreOffice
Before printing, get to printer physically and use the following instructions:

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

------

## Microphone not working in Discord?
You might have enabled the privacy settings in Windows 10.

1. Settings.
2. Search for Privacy.
3. `Microphone privacy settings`.
4. Allow apps to access your Microphone.
5. Enable for `Win32WebViewHost`.
6. ???
7. Yell at your raid group for standing in fire.
