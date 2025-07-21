---
title: "Thick Client Proxying - Part 7 - Proxying .NET Applications via Config File"
date: 2017-10-07T18:30:28-04:00
draft: false
toc: false
comments: true
categories:
- Thick Client Proxying
- .NET Framework
tags:
- .NET
aliases:
- "/blog/2017-10-07-thick-client-proxying-part-7-net-applications"
---

.NET applications use a configuration file to read some settings. It's an XML
file named `appName.exe.config`. We can pass a proxy address in this file.

These apps usually use WinINET or IE proxy settings. Sometimes, they do not. We
can either use an application specific config file or use one for the entire
.NET framework for a machine.

Look inside the decompiled code (or just grep the binary files) for references
to `System.Configuration` [MSDN-page][system-configuration-msdn]. Applications
use `ConfigurationManager` and `WebConfigurationManager` classes to access these
settings.

<!-- links -->
[system-configuration-msdn]: https://msdn.microsoft.com/en-us/library/system.configuration.configuration(v=vs.110).aspx
[procmon-link]: https://docs.microsoft.com/en-us/sysinternals/downloads/procmon

<!--more-->

# TL;DR

1. For `app.exe`, create or edit `app.exe.config`.
2. Add the following to it. If the config file exist, merge the inner tags
   (usually `system.net`).
3. Restart the app.

```xml
<configuration>
  <system.net>
    <defaultProxy enabled="true">
      <proxy
        proxyaddress="http://127.0.0.1:8080"
        bypassonlocal="false"
      />
    </defaultProxy>
  </system.net>
</configuration>
```

# Application specific config file.
Add these settings (`configuration` is already present in existing config files):

``` xml
<configuration>
  <system.net>
    <defaultProxy
      enabled = "true" [true|false]
      useDefaultCredentials = "false" [true|false]
      >
      <bypasslist>
          <add
            address = "" [String, Required, Collection Key]
          />
      </bypasslist>

      <module
          type = "" [String]
      />
      <proxy
        autoDetect = "Unspecified" [False | True | Unspecified]
        scriptLocation = ""
        bypassonlocal = "Unspecified" [False | True | Unspecified]    // whitelist
        proxyaddress = ""                                             // proxy address
        usesystemdefault = "Unspecified" [False | True | Unspecified] // IE proxy settings
      />
    </defaultProxy>
  </system.net>
</configuration>
```

Note `usesystemdefault` and `proxyaddress` are mutually exclusive. I think you
can have both but I am not sure which one will be used (probably
`usesystemdefault`)

For example: 

``` xml
<configuration>
  <system.net>
    <defaultProxy>
      <proxy
        proxyaddress="http://127.0.0.1:8080"
        bypassonlocal="false"
      />
      <bypasslist>
        <add address="[a-z]+\.contoso\.com" />
      </bypasslist>
    </defaultProxy>
  </system.net>
</configuration>
```

- Keep `http://` in `proxy address` even if you are using an HTTPS proxy like
  Burp, it will proxy TLS.
- If IE proxy settings are not working then `usesystemdefault` is useless for
  you as it does the same thing. For Windows services it will not work because
  proxy settings are per-user by default and different for the account running
  the service.

Use tools like [Process Monitor][procmon-link] to detect if the application is
looking for this or any other configuration files.

## .NET Framework Machine Configuration File
We can use a similar config file for the entire machine. Meaning any application
running via that .NET framework will use those settings (honoring them is
another matter but standard libraries usually do).

Location is `%WINDIR%\Microsoft.NET\Framework|Framework64\[version]\Config\machine.config`.

**Important note**: You need to change the config for both 32 and 64-bit
frameworks (Framework|Framework64) and each version (e.g. 2, 3 or 4) separately.

For example for 64-bit .NET Framework 4.x (anything 4.x is under 4):

- `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config`

To learn more about the config file (which is really recommended) see file
`machine.config.comments` in the same location. It has comments and examples.
**Read those**.
