---
title: "Security Nightmares of Game Package Managers"
date: 2022-02-07T22:37:59-08:00
draft: false
toc: false
comments: true
# twitterImage: .png
categories:
- Attack Surface Analysis
---

Let's talk about the security nightmare of handling hundreds of different game
installations. Over the years I have become the de facto security engineer
responsible for EA's "game package managers" [Origin][origin-link] and the
[EA App][ea-app-link] and we have our own unique issues.

[origin-link]: https://www.origin.com/usa/en-us/store/download
[ea-app-link]: https://www.ea.com/ea-app-beta

<!--more-->

You can see all Attack Surface Analysis posts at
[https://parsiya.net/categories/attack-surface-analysis/](/categories/attack-surface-analysis/) 

# The Focus of this Article
You install a game at a specific location. How do you set the permissions for
the installation path? Do you give RWX to everyone? Do you only give RX to
standard users?

If you have restrictive permissions the game might not work. Permissive ACLs
might have security implications and might lead to Local Privilege Escalations
(LPEs).

I will assume the user can download the content they have access to[^1] and
there are license checks to prevent them from running a game they do not own.
These are security concerns, but I will not talk about them here.

[^1]: A mix of owned games + the subscription library + trials.

# What are Game Package Managers?
There are only a few "package managers" in the world. Your first reaction here
is probably "Not a few, I can recite half a dozen off the top of my head." True,
but mainly because there are no alternatives. How many different editors do you
use daily? Usually one or two. How many can you name? A dozen. How many more
editors can you find by searching? Thousands! 

There are only a few game package managers. Most gamers can name `Steam`,
`GOG Galaxy`, `Ubisoft Connect`, `Battle.Net`, `Epic Games Launcher`,
`Windows Store`, `Origin`, and `EA App`. Is there more? Probably, but I think
this covers most of the major games.

A game package manager allows you to buy, download, install, and run games
(among other things). I am going to focus on the installation part here. As a
package manager you usually get an installer or a compressed file with some
directives (dependencies, registry keys, special paths).

A game package manager has to install a wide range of games. Each of these games
might be from a different developer, packaged with a different installer, and be
new or from 20 years ago. Backwards compatibility is decent in Windows gaming[^2].

[^2]: See https://twitter.com/pwnallthethings/status/1363260064929362047

## Windows Software Installation Paths
Most games are made for Windows[^3] (pun not intended). Microsoft pays each of
us a monthly stipend to not work on Linux games :p. Windows is a lot more
permissive in its directory structure. There are mostly guidelines.

[^3]: Is "Games for Windows" still a thing?

### Program Files
Contains most game files that are usually not modified except when the game is
updated. Standard users cannot write to this path by default hence why most
updates need admin access.

There are two versions of this `Program Files` and `Program Files (x86)`
directory.

### ProgramData
Usually used when you need to modify a file frequently, but it's not a user file
(e.g., system-wide settings). Popular place to store updates before execution.
Standard users have write access here by default. It's usually located at
`C:\ProgramData`. More info at [Microsoft Docs][programdata-docs].

[programdata-docs]: https://docs.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-shell-setup-folderlocations-programdata

### AppData
This is a popular place to store user specific configuration files. Some apps
install themselves completely in this path to avoid dealing with
`Program Files`. `C:\%username%\Documents\` is another popular location for
save games and user configurations.

# Local Privilege Escalation Bugs and Game Package Managers
Local Privilege Escalation happens when you can go down this list:

1. Remote attacker.
2. Standard user.
3. Local admin/SYSTEM.

I have deliberately omitted domain connected machines because the overwhelming
majority of machines running games run on normal consumer machines.

In the context of game updates, we mostly care about going from standard user to
admin. You can make the case about MITM-ing the game update files as a remote
attacker, but in the current age of TLS that's usually not an issue.

Most bugs of this type happen when apps run something as admin from a path where
standard users have write access. It's very common for apps to store their
updates in `ProgramData` where users have write access and then execute them as
admin.

I even found a security bug where the updater wanted to run without admin
access so it had 
{{< xref path="/post/2021/2021-01-08-electron-sig-bypass/"
text="modified the program directory ACL in ProgramFiles"
anchor="my-undisclosed-bug-2---installer-modified-the-program-directory-acl">}}
and given write access to standard users.

## How do Game Package Managers Install and Update Games?
The software runs as standard user, but needs to run as admin/SYSTEM to install
and update games. This is usually done in two ways:

1. Most game package manager use a Windows service (e.g., `Origin`, `EA App`,
   and `Steam`). This is seamless.
2. The `Epic Games Launcher` appears to be the only exception I can think of. It
   just pops a manual UAC prompt and wants to run the installer as admin.

When using a Windows service we have to pay attention to two items:

1. **Where are the updates stored?** We will need to run them as admin/SYSTEM
   when updating the game. Can users modify the updates before they are
   executed?
2. **How do we trigger the Windows Service?** We need to signal the service to
   download and install and update from userland. Can an attacker just point the
   Windows Service to any random binary?

### Older Games and Installation Paths
Most modern games adhere to the path guidelines we saw before. You can install
them under `ProgramFiles` and have a Windows service (or pop a manual UAC) to
update the installations.

With `EA App` and `Origin` we try to take advantage of this. For example,
[Lost in Random][lost-in-random] is by default stored at
`C:\Program Files\EA Games\Lost In Random` and has correct permissions:

```
PS> Get-Acl -Path 'C:\Program Files\EA Games\Lost In Random' | Format-List

Path   : Microsoft.PowerShell.Core\FileSystem::C:\Program Files\EA Games\Lost In Random
Owner  : BUILTIN\Administrators
Group  : NT AUTHORITY\SYSTEM
Access : ...
         BUILTIN\Users Allow  ReadAndExecute, Synchronize
```

[lost-in-random]: https://www.ea.com/games/lost-in-random

Older games are a completely different ball game. Most of them should be run as
admin. They were designed in the age before `ProgramFiles` and write their
configuration files, save games, and similar to their root directory. Installing
these games under `ProgramFiles` with default ACLs will prevent them from
working if we execute them as standard users.

Most game package manager modify the ACLs of these games and give write access
to standard users. This is what `Steam` does. Check the security permissions for
`C:\Program Files (x86)\Steam\steamapps\common`.

```
PS> Get-Acl -Path 'C:\Program Files (x86)\Steam\steamapps\common\' | Format-List

Path   : Microsoft.PowerShell.Core\FileSystem::C:\Program Files (x86)\Steam\steamapps\common\
Owner  : Parsia-PC\Parsia
Group  : Parsia-PC\None
Access : BUILTIN\Users Allow  FullControl
```

**Custom paths** are another headache. If you install the game in a different
path, it's probably insecure and can lead to LPE.

## But This is Insecure!
I know! There's no good way to fix it. Additionally:

1. More than 90% of users run our desktop apps as admin. This is expected and I
   am sure other game companies see a similar pattern.
2. For old games, compatibility trumps security. Users just want a seamless
   experience (buy > download > play).
3. `Insecure system is insecure`. If you install games (or Origin/EA App) at an
   insecure location there's not much we can do.

Actually, the 3rd one is a lie. There are some things we can do. We store the
binaries associated with Windows services at
`C:\Program Files (x86)\Common Files\`. We already do some of this for modern
games. Look under `C:\Program Files\Common Files\EAInstaller` to see the cleanup
crew (the files are named `Cleanup`, har har!)