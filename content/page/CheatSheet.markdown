---
date: "2016-02-24T22:29:57-05:00"
draft: false
title: "Cheat Sheet"
url: "/cheatsheet/"
categories:
- cheatsheet
tags:
- tips and tricks
---
Often I need to do something that I have done many times in the past but I have forgotten how to do it. This is a page (or a series of pages if it grows large enough) to give me a simple repository of how-tos that I can access online. In this page you may find those commands and tips that I need from time to time (and usually forget when I need them).

------
### Tar

**Compressing a directory using tar**  
`tar -zcvf target_tar.tar.gz directory_to_be_compressed`

**Decompressing a tar.gz file**  
`tar -zcvf target_tar.tar.gz path/to/decompress/`

------

### OpenSSL

**Dumping the TLS certificate using OpenSSL**  
`echo | openssl s_client -connect HOST:PORT 2>/dev/null | openssl x509 -text -noout`

**TLS connection with a specific ciphersuite using OpenSSL**  
`openssl s_client -connect HOST:PORT -cipher cipher-name -brief`

* `-brief`: reduced output
* `cipher-name`: A cipher from output of `openssl ciphers` command

------

### Amazon S3

**Synching a folder with an Amazon S3 bucket using s3cmd**  
`python s3cmd sync --acl-public --delete-removed --rr directory-to-sync/ s3://bucket-name`

For example uploading the Hugo public directory to my website:  
`python s3cmd sync --acl-public --delete-removed --rr public/ s3://parsiya.net`

* `--acl-public`: Anyone can only read.
* `--delte-removed`: Delete remove objects with no corresponding local files.

**Changing the mime-type of `css` file after it is uploaded to avoid [an old issue]({{< ref "2014-04-22-amazon-s3-and-css.markdown" >}} "Amazon S3 and CSS")**  
`python s3cmd --acl-public --no-preserve --mime-type="text/css" put public/css/hugo-octopress.css s3://parsiya.net/css/hugo-octopress.css`

{{< codecaption title="My runme.bat to upload my Hugo blog to the S3 bucket" lang="powershell"  >}}
rd /q /s public
hugo
rd /q /s public\post
del /s /a .\*thumbs*.db
del /s /a public\categories\*index*.xml
del /s /a public\tags\*index*.xml
python s3cmd sync --acl-public --delete-removed -MP --rr public/ s3://parsiya.net
python s3cmd --acl-public --no-preserve --mime-type="text/css" put public/css/hugo-octopress.css s3://parsiya.net/css/hugo-octopress.css
rd /q /s public
{{< /codecaption >}}

------
### Powershell

**List all files (including hidden)**  
`Get-ChildItem "searchterm" -recurse -force -path c:\ | select-object FullName`

* `-recurse`: recursive. Loops through all directories
* `-force`: list hidden files.
* `select-object`: Selects each file from last point
* `FullName`: Only display file name

**Diff in Powershell**  
`Compare-Object (Get-Content new1.txt) (Get-Content new2.txt) | Format-List >> Diff-Output`

Output will be in format of

* `InputObject`: `c:\users\cigital\somefile` -- line content
* `SideIndicator`: `=>` -- exists in new2.txt (second file, file to the right)

**Pseudo-grep in Powershell**  
`findstr "something" *.txt`

will include filename and line (no number AFAIK)

    findstr /spin /c:"keyword" *.*
    /s: recursive - will search through the current directory and all sub-directories
    /p: skip binary files (or files with characters that cannot be printed)
    /i: case-insensitive - remove if you want case sensitive search
    /n: print line number

If you want to search for different keywords (with OR) remove the `/c:`

`findstr /spin "keyword1 keyword2" *.*`

will search for keyword1 OR keyword2 in files

https://technet.microsoft.com/en-us/library/Cc732459.aspx

**grep in command outputs**  
`whatever.exe | Select-String -pattern "admin"`

**Get-Acl amd icacls.exe**  
`Get-Acl -path c:\windows\whatever.exe | Format-List`

`icacls.exe c:\windows\whatever.exe`

-----------

### Download Youtube videos with substitles  
I love Wuxia (Chinese martial arts if I am not mistaken) series and movies. The following [youtube-dl](https://github.com/rg3/youtube-dl/) command will download the 56 episode HQ quality Chinese TV  series called `Xiao Ao Jiang Hu` or `Laughing in the Wind` (also called `The Smiling Proud Wanderer` or `Swordsman`).

`youtube-dl --ignore-errors --write-srt --sub-lang en --yes-playlist 'https://www.youtube.com/playlist?list=PLuGy72vdo4_ScwTYb1bAynhBs3KgowvvQ'`

```
--ignore-errors: continue after errors (in the case of a playlist we do not want to be interrupted for one error)
--write-srt    : download substitles
--sub-lang     : subtitle language (in this case English)
--yes-playlist : link to a Youtube playlist
```

`Youtube-dl` can be downloaded using `pip`. For example on Windows:  
`python -m pip install youtube-dl`.

----------

### Delete file or directory with a path or name over the Windows limit

Answer from [superuser.com](http://superuser.com/a/467814).

``` posh
mkdir empty_dir
robocopy empty_dir the_dir_to_delete /s /mir
rmdir empty_dir
rmdir the_dir_to_delete
```

----------

### Some Git stuff because I keep forgetting them

**Create new branch and merge**  
This works with small branches (e.g. one fix or so). Adapted from a [Bitbucket tutorial](https://confluence.atlassian.com/bitbucket/use-a-git-branch-to-merge-a-file-681902555.html).

1. Create new branch - `git branch fix-whatever`  
This will create a branch of whatever branch you are currently on so make sure you are creating a branch from the branch you want.

2. Switch to the branch - `git checkout fix-whatever`

3. Make changes and commit - `git add - git commit`  
Make any changes you want to do, then stage and commit.

4. Push the branch to remote repo [optional] - `git push`  
This can be safely done because it's an obscure branch and no one else cares about it.

5. Go back to the original branch to merge - `git checkout master`  
Master or whatever branch you were at step one.

6. Merge the branches - `git merge fix-whatever`

7. Delete branch - `git branch -d fix-whatever`  
We don't need it anymore. If it was pushed to remote, then we need to delete it there too.

**Only clone a certain branch**  
`git clone -b <branch> <remote_repo>`

Otherwise master will be cloned.

**Undo remote git history after push**  
Because this keeps happening to me.

1. Reset the head in local repo N commits back. - `git reset HEAD~N`  
Where N is the number of commits that you want to revert.

2. Make changes and stage them - `git add`

3. Commit the changes - `git commit`

4. Force push the local repo to remote - `git push -f`  
Note this will force the update and erase the commit history online. If not one else is using the repo in between it's ok.

--------------

### Print Envelopes Using the Brother Printer and LibreOffice
Before printing, get to printer physically and use the following instructions:

* http://support.brother.com/g/b/faqend.aspx?c=gb&lang=en&prod=hl2170w_all&faqid=faq00000063_025

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
