---
title: "Thick Client Proxying - Part 8 - Notes on Proxying Windows Services"
date: 2017-10-08T15:00:00-04:00
draft: false
toc: false
comments: true
categories:
- Thick Client Proxying
- Windows Service
tags:
- wininet
- winhttp
- netsh
aliases:
- "/blog/2017-10-08-thick-client-proxying---part-8---notes-on-proxying-windows-services/"
---

These are my notes about proxying Windows services. Being run from a different account (usually LocalSystem).

Proxy settings are usually configured per user and are not applicable to Windows services.

If you have to proxy a Windows service, here are some of the things you can try (and hope they work).

There are also some issues when using `netsh` to set WinHTTP proxies for 32-bit applications on Windows 7 64-bit.

<!--more-->

<!-- MarkdownTOC -->

- [Some Background Knowledge](#some-background-knowledge)
- [Traditional Techniques or "Try These Anyways"](#traditional-techniques-or-try-these-anyways)
  - [WinINET or Internet Explorer Proxy Settings](#wininet-or-internet-explorer-proxy-settings)
  - [WinHTTP Proxy Settings](#winhttp-proxy-settings)
    - [netsh winhttp for 32-bit Processes on Windows 7 64-bit](#netsh-winhttp-for-32-bit-processes-on-windows-7-64-bit)
  - [Run the Service Executable Manually](#run-the-service-executable-manually)
  - [Disable Per-User WinINET Proxy Settings](#disable-per-user-wininet-proxy-settings)
  - [.NET Config File](#net-config-file)
  - [.NET Framework Machine Configuration File](#net-framework-machine-configuration-file)

<!-- /MarkdownTOC -->


<a name="some-background-knowledge"></a>
# Some Background Knowledge

* [Understanding Web Proxy Configuration - MSDN][proxy-msdn]. This is a pretty useful read for Windows proxying. If you have to choose between this blog and that article, choose the MSDN article.
* [Part 6 - How HTTP(s) Proxies Work]({{< ref "2016-07-24-thickclient-proxying-6-how-proxies-work.markdown" >}} "Thick Client Proxying - Part 6: How HTTPs Proxies Work")

<a name="traditional-techniques-or-try-these-anyways"></a>
# Traditional Techniques or "Try These Anyways"
These are things that usually work for most Windows applications.

<a name="wininet-or-internet-explorer-proxy-settings"></a>
## WinINET or Internet Explorer Proxy Settings
Usually called the Internet Explorer proxy settings. These usually work for most [proxy-aware]({{<ref "2016-07-24-thickclient-proxying-6-how-proxies-work.markdown#5-proxy-aware-clients">}} "What are Proxy-Aware Clients") applications.

Shortcut `control inetcpl.cpl,,4`.

<a name="winhttp-proxy-settings"></a>
## WinHTTP Proxy Settings
WinHTTP is generally the proxy for Windows services. You can either set specific proxies or tell it to import IE proxy settings (see above).

Run in admin command prompt:

- Use IE: `netsh winhttp import proxy source=ie`. Note: You need to set WinINET settings **before** this command. This command uses a snapshot of IE settings and imports them. If you change IE settings after, it will not get updated and you have to run it again.
- Set proxy: `netsh winhttp set proxy proxy-server="http=localhost:8080;https=localhost:8443" bypass-list="*.whatever.com;localhost"`.
- Reset proxy: `netsh winhttp reset proxy`.

More info: [MSDN - Netsh Commands for Windows Hypertext Transfer Protocol (WINHTTP)][netsh-winhttp-msdn]

Location in registry:

- 64-bit (note the line-broken "Internet Settings"):
    * `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections\WinHttpSetting`
        * You will see something like this:

        ``` powershell
        0000  28 00 00 00 00 00 00 00 03 00 00 00 28 00 00 00  |(...........(...|
        0010  68 74 74 70 3d 6c 6f 63 61 6c 68 6f 73 74 3a 38  |http=localhost:8|
        0020  30 38 30 3b 68 74 74 70 73 3d 6c 6f 63 61 6c 68  |080;https=localh|
        0030  6f 73 74 3a 38 34 34 33 18 00 00 00 2a 2e 77 68  |ost:8443....*.wh|
        0040  61 74 65 76 65 72 2e 63 6f 6d 3b 6c 6f 63 61 6c  |atever.com;local|
        0050  68 6f 73 74                                      |host|
        ```
    * `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp`

- 32-bit: 
    * `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\Connections\WinHttpSettings`
    * `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp`

<a name="netsh-winhttp-for-32-bit-processes-on-windows-7-64-bit"></a>
### netsh winhttp for 32-bit Processes on Windows 7 64-bit
Due to the way 32-bit emulation works, they have their own registry and "system32":

- registry hive: `hive\Software\Wow6432Node`. E.g. `HKCU\Software\Wow6432Node\Microsoft\Windows`
- system32: `%WINDIR%\SysWOW64`. E.g. `C:\windows\SysWOW64`

On Windows 7, when you use `netsh` to write WinHTTP proxy settings, only the 64-bit registry keys are changed. For 32-bit apps you need to explicitly run `%WINDIR%\SysWOW64\netsh.exe`.

``` powershell
# change winhttp proxy setting
C:\>netsh winhttp import proxy source=ie

Current WinHTTP proxy settings:

    Proxy Server(s) :  localhost:8100
    Bypass List     :  (none)

# not modified for 32-bit applications
C:\>c:\Windows\SysWOW64\netsh.exe winhttp show proxy

Current WinHTTP proxy settings:

    Direct access (no proxy server).
```

Presumably this has been fixed for later versions of Windows, but double-check to be sure.

<a name="run-the-service-executable-manually"></a>
## Run the Service Executable Manually
This might help bring it under your "jurisdiction" and thus your proxy settings will apply. By default each user has their own proxy settings.

You can use [Process Explorer][procexp-link] or [Process Monitor][procmon-link] or other tools to discover the parameters to run the service (if any).

<a name="disable-per-user-wininet-proxy-settings"></a>
## Disable Per-User WinINET Proxy Settings
By default they are per-user, you set the following registry key to `0`:

- `HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ProxySettingsPerUser`

**But after this change you will need admin access to modify proxy settings.**

<a name="net-config-file"></a>
## .NET Config File
See detailed info in [part 7]({{<ref "2017-10-07-thick-client-proxying-7-proxying-dotNet-applications.markdown">}} "Thick Client Proxying")

.NET applications can read settings from config files. This is an XML file named `applicationName.exe.config`.

Add these settings (`configuration` is already present in existing config files):

``` xml
<configuration> 
  <system.net>  
    <defaultProxy>  
      <proxy  
        usesystemdefault="true"   // use IE proxy settings
        proxyaddress="http://192.168.1.10:3128"  // remember to keep "http://" here
        bypassonlocal="true"  
      />  
      <bypasslist>  
        <add address="[a-z]+\.contoso\.com" />  
      </bypasslist>  
    </defaultProxy>  
  </system.net>  
</configuration>  
```

Note `usesystemdefault` and `proxyaddress` are mutually exclusive.

- Keep `http://` in `proxy address` even if you are using an HTTPS proxy like Burp, it will proxy TLS.
- Often `usesystemdefault` does not work because your user and the user running the service are different and have their own proxy settings. Running the service binary manually may help.

Use tools like [process monitor][procmon-link] to detect if the application is looking for this or any other config file.

<a name="net-framework-machine-configuration-file"></a>
## .NET Framework Machine Configuration File
You can use a similar config file for the entire machine. Meaning any application running via that .NET framework will use those settings.

Location is `%WINDIR%\Microsoft.NET\Framework|Framework64\[version]\Config\machine.config`.

Note that you need to change the config for both 32 and 64-bit frameworks (Framework|Framework64) and each version (e.g. 2, 3 or 4) separately.

For example for 64-bit .NET Framework 4.x (anything 4.x is under 4):
- `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config`

To learn more about the config file (which is really recommended) see file `machine.config.comments` in the same location. It has comments and examples.

<!-- links -->
[proxy-msdn]: https://blogs.msdn.microsoft.com/ieinternals/2013/10/11/understanding-web-proxy-configuration/
[netsh-winhttp-msdn]: https://technet.microsoft.com/en-us/library/cc731131(v=ws.10).aspx#BKMK_5
[procexp-link]: https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer
[procmon-link]: https://docs.microsoft.com/en-us/sysinternals/downloads/procmon