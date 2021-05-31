---
title: "Public Remote File Share in The Cloud"
date: 2021-05-31T10:20:40-07:00
draft: false
toc: true
comments: true
categories:
- bug bounty
---

In
{{< xref path="/post/2021/2021-03-17-attack-surface-analysis-2-custom-uri/"
    text="Part 2 of the Attack Surface Analysis series"
    title="Attack Surface Analysis - Part 2 - Custom Protocol Handlers" >}}
I talked about how passing a remote file with a UNC path can lead to unexpected
results.

I am documenting how I created a share using an EC2 instance. This guide is for
AWS but, it's a Linux machine running in the cloud. You can easily replicate it.

<!--more-->

Note about automation: I like automation but, we should "automate as long as it
makes sense." In my opinion, I don't need more automation.

# Problem Statement
We want to pass a remote file as a UNC path (or other ways) to a program. For
example, we want to pass `app.exe -input \\10.20.30.40\myfile.txt`.

We need:

1. A public share.
2. The ability to upload files.
3. Static IP address for a reasonable amount of time (a few days).

# Research
The obvious solution for me is `the cloud`. Some people have their own
infrastructure but, I do not even have a home lab (lol)[^1].

[^1]: Infosec is not special, you do not have to study in your free time.

I had two options:

1. Deploying a custom EC2 instance.
2. The [AWS File Gateway][file-gateway].

[file-gateway]: https://aws.amazon.com/storagegateway/file/

**Spoiler:** AWS File Gateway is garbage for my use case. EC2 instance is the way
to go.

# EC2 Instance
A Linux EC2 instance checks all the boxes:

1. We can create a public share with samba.
2. We can upload files via SSH or other means.
3. The IPv4 address of the EC2 instance does not change while it is running and
   comes free with the instance.
4. Bonus: It can be deployed using the AWS free tier and is less than 5 USD a
   month for other accounts.

## EC2 Wizard
I used the Ubuntu 18.04 LTS image. Originally, I wanted a `t4g.nano` instance
but, the `t4g.micro` ARM instances are free until July 2021 (this was written in
April 2021 and published a month later). Free is better.

In the EC2 instance wizard you need to choose some specific options:

* Step 3: Configure Instance Details
    * `Auto-assign Public IP: Enable`
* Step 4: Add storage
    * The image needs 8 GB, I increased the storage to 10 GB.
* Step 6: Configure Security Group
    * Port 22 should already be open, if not open it.
    * Open SMB (port 445). The source should be `anywhere`.
* `Review and Launch` -> `Launch`.
* Create or reuse an SSH keypair.
    * We need it to SSH to the machine.

## After Instance Launch

1. Click `View Instance` (bottom right) to go the running instances page.
2. Grab the server's public IPv4 address.
3. Wait a few minutes for the instance to start running and the status check to
   complete and pass 2/2 checks.

## Setting Up SSH Access
We can set up SSH access while the instance is starting. I used WSL2 but it
should work everywhere.

```
# copy the SSH key
cp smb-ssh-key.pem ~/.ssh/smb-key.pem

# change ACL
chmod 700 ~/.ssh/smb-key.pem

# add the key to the SSH config file
nano ~/.ssh/config
```

This makes it easier to use. Add the following to the config file:

```yaml
Host publicshare # change this to something you like.
  User ubuntu    # change to your image's username.
  Hostname 10.20.30.40  # replace with the instance's IP address.
  PreferredAuthentications publickey
  IdentityFile ~/.ssh/smb-ssh-key.pem # change if needed.
```

Now, we can SSH into the instance with `ssh publicshare`.

## Setting Up Samba on the Machine
You should have root access to the machine.

```
# install samba
sudo apt install samba

# check if the service is running
sudo systemctl status smbd

# backup the current samba config
sudo cp /etc/samba/smb.conf{,.backup}

# create the share directory
sudo mkdir /var/samba

# give everyone read access
sudo chmod 755 /var/samba 

# create a random file in the share directory
sudo touch /var/samba/whatever.txt
```

### Configuring The Samba Share
We want everyone to connect to this share so we do not want to just bind it to
localhost or an internal IP address. I used the following as a guide (starting
from "Create Anonymous Share"):

* [https://linuxconfig.org/how-to-configure-samba-server-share-on-ubuntu-18-04-bionic-beaver-linux][samba-ubuntu-18]

[samba-ubuntu-18]: https://linuxconfig.org/how-to-configure-samba-server-share-on-ubuntu-18-04-bionic-beaver-linux

```
# edit the config
sudo nano /etc/samba/smb.conf
```

Add the following to the end of the config file:

```
[public]
  comment = public anonymous access
  path = /var/samba/
  browsable = yes
  create mask = 0660
  directory mask = 0771
  writable = no
  guest ok = yes
```

Restart the samba server with `sudo systemctl restart smbd` to see your changes.
Now, we can do `\\IP\public\` to access the share.

## Automation
I am not gonna continue because I don't need the automation here. But here's
some theorycrafting:

1. Store all payloads in a private Github repo.
2. After every push, start an action that does these:
    1. Use Terraform to provision and start the VM.
    2. We will need to get the SSH key and the instance's IP address somehow.
    3. Upload all the files in the Github repo or files from an S3 bucket to the share.
        1. We could also use something like [s3-fuse][s3-fuse-github] that
           mounts an S3 bucket as a file system.
3. (optional) A cron job that reads the S3 bucket every X hours and updates the shares.

[s3-fuse-github]: https://github.com/s3fs-fuse/s3fs-fuse

## Pricing
AWS pricing is a mystery but I crunched some numbers. In `calculator.aws` there
is an EC2 monthly cost and a storage cost. We do not need persistence storage
instances so I do not know if we need to pay for it, too. But, assuming we do,
10GB is more than enough (an Ubuntu 18 LTS image needs 8GB) and costs `1 USD/mo`
on `us-east-1`.

Without the free tier and the `t4g.micro` free promotion, running the EC2
instance for a month will cost a few dollars. I think `nano` or `micro`
instances will be enough for everyone. Their prices are:

* `t4g.nano`: `1.90 USD/mo`
* `t4g.micro`: `3.87 USD/mo`

So, worst case we will be paying less than **5 dollars a month**. This would
have been a significant sum when I was growing up but, if you are doing the kind
of bounties that need this kind of shares you should be able to make it.

# Issues
This approach has two problems:

1. Privacy: Anyone going to `\\IP` can see all of your different shares and all
   your super secret payloads.
2. User/password prompt: One of my Windows 10 VMs was asking for user/pass after
   trying to access `\\IP`.

## Privacy
This means you should not use the same server to host multiple payloads,
especially for different proof-of-concepts. Spin up a new instance for each
program and keep it up for a few days until the bug is triaged.

## Credential Prompt After Accessing the Share
I have no idea why it happens. Only one of my Windows VMs (some Win 10 1909) was
doing it. All my other Win 10 VM (including another 1909 and a 20H2) did not
have this issue. Maybe, it's a Windows config thing? I cannot reliably replicate
it. I thought it was "Network Discovery."

The prompt accepted any user/pass (e.g., user `a` and no password). For a while,
I thought this is because guest SMB 2.0 is disabled in Windows 10 but, no. I did
not get a prompt on a fresh Win10 install from modern.ie.

If such a prompt pops up in your VM then chances are the app is not going to
accept the remote file without it and this will interfere with your exploit.

# Failed Attempt: Amazon File Storage Gateway
AWS has [a service][file-gateway] that does this (of course, they do). In short,
files are stored in an S3 bucket and a machine acts as a gateway. This machine
can be an EC2 instance or anywhere else. AWS gives you an image that you can
download and deploy.

This service does a lot more than what I want. Furthermore, the EC2 instance
has a set of minimum requirements. If you create an instance that does not meet
those, it will not be recognized.

I am going to document my experience setting it up, anyways. It might be useful
for someone.

1. Go to [https://console.aws.amazon.com/storagegateway/home][storage-gateway-url].
2. `Get Started > File Gateway > Amazon EC2`.
3. Click on `Launch instance` to open a new window and the EC2 instance wizard.
4. Use [https://docs.aws.amazon.com/storagegateway/latest/userguide/ec2-gateway-file.html][ec2-file-gateway]
    1. Minimum instance size is `m4.xlarge` (comes with an 80GB volume): `90.45 + 8 USD/mo`
    2. An extra 150GB EBS volume as cache: `15 USD/mo`

[storage-gateway-url]: https://console.aws.amazon.com/storagegateway/home?region=us-east-1
[ec2-file-gateway]: https://docs.aws.amazon.com/storagegateway/latest/userguide/ec2-gateway-file.html

In the EC2 wizard, set:

* Step 3: Configure Instance Details
    * `Auto-assign Public IP: Enable`
    * We need the public IP. It does not change while the instance is running.
* Step 4: Add storage
    * 80 GB block for the image.
    * Extra 150 GB volume as cache.
* Step 6: Configure Security Group.
    * Open the following ports:
        * SSH (22 TCP): should already be open, if not open it.
        * HTTP (80 TCP)
        * HTTPS (443 TCP)
        * DNS (53 UDP)
        * SMB (445 TCP)
        * LDAP (3289 TCP)
        * NFS (2049 TCP)
        * Custom UDP 123
* Create or reuse an SSH keypair.
    * We will need it to SSH into the machine.

Launch the instance and wait for it to pass the 2/2 checks. Now, we can go back
to the File Gateway wizard.

* Select `Public` in `Service Endpoint` then `Next`.
* In `Connect to gateway` enter the IP address of the EC2 instance.
* In `Activate Gateway` put in the time zone and a name. E.g., `my-file-share`
* Click `Activate Gateway`.

**If the EC2 instance does not meet the minimum requirements** the `Preparing
local disk` cannot find local disks. **Rage quit**
