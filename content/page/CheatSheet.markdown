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
**Compressing a directory using tar**  
`tar -zcvf target_tar.tar.gz directory_to_be_compressed`

**Decompressing a tar.gz file**  
`tar -zcvf target_tar.tar.gz path/to/decompress/`

------

**Dumping the TLS certificate using OpenSSL**  
`echo | openssl s_client -connect HOST:PORT 2>/dev/null | openssl x509 -text -noout`

**TLS connection with a specific ciphersuite using OpenSSL**  
`openssl s_client -connect HOST:PORT -cipher cipher-name -brief`

* `-brief`: reduced output
* `cipher-name`: A cipher from output of `openssl ciphers` command

------

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
python s3cmd sync --acl-public --delete-removed -MP --rr public/ s3://parsiya.net
python s3cmd --acl-public --no-preserve --mime-type="text/css" put public/css/hugo-octopress.css s3://parsiya.net/css/hugo-octopress.css
rd /q /s public
{{< /codecaption >}}

------
