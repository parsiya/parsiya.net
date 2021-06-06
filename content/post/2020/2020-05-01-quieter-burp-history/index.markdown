---
title: "Towards a Quieter Burp History"
date: 2020-05-01T23:13:24-07:00
draft: false
toc: true
comments: true
twitterImage: 04-domains-added.png
categories:
- Burp
---

This is how I reduce the noise in Burp's HTTP history when testing thick
clients. You can use the methods here to create your own Burp configuration file
or build upon the one I have created. I am going to identify common noisy
requests that appear in Windows and then ignore them in Burp.

<!--more-->

# TL;DR

1. Proxy the applications directly.
    1. Application and tech stack specific proxy settings.
    2. Browsers: Use Firefox or pass `--proxy-server="http://localhost:8080"` to Chrome and Edge.
2. Use a Virtual Machine.
3. Use Burp's scope and filter to hide requests in `HTTP History`.
4. Add domains to Burp's `TLS Pass Through`.
    1. Noisy domains. E.g., Windows update.
    2. Authentication/MFA domains. You do not want your credentials in Burp.
5. Hide `OPTIONS` requests in Burp's history with extensions.
6. Use this Burp config file as base and add your domains.
    1. https://github.com/parsiya/Parsia-Clone/blob/master/configs/burp-default-config.json

# Motivation
Noisy history == missing important requests.

## Noise in Burp's History
Often times when proxying thick clients I have to use the WinINET proxy settings
(also known as IE proxy settings). Burp's history will be full of noise.

## Other Applications Stop Working
A lot of miscellaneous applications are also proxied when you enable the Windows
proxy settings. They might stop working due to certificate pinning.

## Secrets/Credentials in Saved in the Burp Project
Other proxied applications might contain secrets and other sensitive
information. I keep my Burp projects forever so the secrets are now stored on
the machine and I do not want that to happen.

# Previous Work
Brian King talks about disabling some options in Firefox to reduce noise in Burp in
[Towards a Quieter Firefox - Blackhills Infosec][quieter-firefox]. He provides a
Firefox `user.js` file to add those options. It does not block all Firefox
requests and does not work for other browsers. 

[quieter-firefox]: https://www.blackhillsinfosec.com/towards-quieter-firefox/

I have also written about adding certain domains to Burp's
[TLS Pass through][burp-tls-pass-through] in another blog post named
{{< xref path="/post/2019/2019-10-13-quality-of-life-burp/"
    text="Quality of Life Tips and Tricks - Burp Suite" >}}
Domains in the pass through section are not proxied and do not appear in history.

[burp-tls-pass-through]: https://portswigger.net/burp/documentation/desktop/tools/proxy/options#tls-pass-through

# Reduce Incoming Requests
If we can prevent some requests from reaching Burp we have won.

## Proxy The Application Directly
Proxy the application directly. If we proxy the application we ignore traffic
for the rest of the system. Sometimes the app has proxy settings. These proxy
settings are not always visible in the application. They might be in a config
file. Search the internet and read the documentation/manual to see how it can be
done.

### Techstack Proxy Settings
The tech stack helps with proxying. Here are some quick tips:

* .NET: You can proxy these by using a config file. See
  {{< xref path="/post/2017/2017-10-07-thick-client-proxying-7-proxying-dotNet-applications.markdown"
    text="Thick Client Proxying - Part 7 - Proxying .NET Applications via Config File" >}}
* Java: You can [pass parameters][java-proxy-docs] that set a proxy. E.g.,
  `-Dhttps.proxyHost=127.0.0.1` and `-Dhttps.proxyPort=8080`.

[java-proxy-docs]: https://docs.oracle.com/javase/8/docs/technotes/guides/net/proxies.html

### Browsers
Browsers are special thick clients. We can directly proxy them.

* Firefox: I usually use Firefox or its clones because it has its own
  [proxy settings][firefox-proxy]. Also [FoxyProxy][foxyproxy] helps.
* Chromium based browsers such as Chrome and Edge use the Windows proxy settings
  but it is possible to point to a proxy using command line parameters.
    * E.g., Edge: `msedge.exe --proxy-server="http://localhost:8080"`
    * Create a shortcut that runs the browser with a specific proxy, this way
      you can run different instances of the browser for normal web browsing or
      proxying.
* [Electron][electron.js]: Usually honor Windows proxy settings. Chromium based
  but ignore `--proxy-server`.
    * Try these tips by [Paolo Stagno][paolo-stagno] on [blog.doyensec.com][blog-doyensec].
      [Instrumenting Electron Apps for Security Testing - Intercepting HTTP(s) traffic][doyensec-electron-proxy].

[firefox-proxy]: https://support.mozilla.org/en-US/kb/connection-settings-firefox
[foxyproxy]: https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/
[electron.js]: https://www.electronjs.org/
[doyensec-electron-proxy]: https://blog.doyensec.com/2018/07/19/instrumenting-electron-app.html#intercepting-https-traffic
[blog-doyensec]: https://blog.doyensec.com/
[paolo-stagno]: https://twitter.com/Void_Sec

## Use a Virtual Machine
For obvious reasons, VMs are a must for testing thick clients. They are
controlled environments. Your other applications do not break, the noise from
their traffic does not show up in Burp, and you do not have to change the proxy
settings because you need to attend a videoconference meeting.

## Use Burp's Scope
It's possible add endpoints used by the application to
{{< xref path="/post/2016/2016-03-29-thickclient-proxying-2.markdown"
    text="the Burp's scope" anchor="1-scope" >}}
and hide everything not in scope. But this is not feasible in the early stages
of recon because we do not know all the endpoints and we do not want to
miss anything when the app contacts a new one. I usually do not use this setting
at all.

# Use Burp's TLS Pass Through
If it's not possible to reduce the incoming requests we can also tell Burp not
to MitM some requests.

## Harvesting Noisy Domains
First, we must make a list of any traffic that should not be proxied. Some
examples are Windows specific traffic (e.g., telemetry), browsers calling
home, and other application updates.

To create this list I did the following:

1. Started Burp in a typical Windows 10 VM and set it in Windows proxy settings.
2. Added the
   {{< xref
     path="/post/2016/2016-02-23-installing-burp-ca-in-windows-cert-store.markdown"
     text="Burp's CA to the Windows certificate store"
     title="Installing Burp Certificate Authority in Windows Certificate Store" >}}
3. Opened every application and browser that I normally use and interacted with
   them a bit (e.g., checked for updates).
4. Left the VM idle for a few hours.
 
{{< imgcap title="Domains in the Target tab" src="01-domains-target.png" >}}

I switched to the `Target > Site map` tab and looked for a way to copy every
domain. Burp does not have an option to just copy the domains but there is a
trick:

1. Go to `Target > Scope` and check `Use advanced scope control`.
2. Go to `Target > Site map` and click on `Filter` and click the `Show all`
   button.
3. Use `ctrl+a` to select every target.
4. Right-click and select `Add to Scope`.
5. Switch back to the `Scope` tab.
6. Select one item in scope and use `ctrl+a` to select every domain scope. Then
   copy them with `ctrl+c`.
7. Paste the results in a text file and save it.

Now I had a list of regular expressions for the domains.

{{< imgcap title="Domain regexes" src="02-domain-regex.png" >}}

## Adding Domains to Burp's TLS Pass Through
`TLS Pass Through` has an option to paste URLs or load a list from a file. It
does not support the format we just created. The file should have one normal URL
per line (not regex). E.g., instead of `^accounts\.google\.com$` we
should have `accounts.google.com`. `*.google.com` does not work either.

{{< imgcap title="Error importing URLs" src="03-unrecognized-hosts.png" >}}

A series of searches and replaces converted the previous domain list to the
correct format. I went to `Proxy > Options` and scrolled down to `TLS Pass Through`
at the bottom of the tab. Clicked `Load ...` and selected the file my domains. 

{{< imgcap title="Domains added" src="04-domains-added.png" >}}

`Paste URL` only works if there is one URL in the clipboard or you have copied a
URL from another location in Burp.

### Adding More Domains
To update the list we must add new domains manually in `TLS Pass Through`.

Inside Burp:

1. Right-click on the request and select `Copy URL`.
2. Go to `TLS Pass Through` and click the `Paste URL` button.

Edit the config file directly:

1. Export the config file (or edit the one from below).
2. Add new items to `project_options > ssl_pass_through > rules`.
    1. Don't forget to escape backslashes in the JSON string
3. Reload the config file.

There were some domains that did not appear in the previous list. I added them
manually:

* `.*mozilla\\.(com|net|org)`
* `.*\.windows\.com`
* `.*\\.live\\.com`
* `.*\\.windowsupdate\\.com`
* `.*\\.microsoft\\.com`
* `.*visualstudio\\.com`

## Adding Authentication Domains
As I have explained in
{{< xref path="/post/2019/2019-10-13-quality-of-life-burp/"
    text="Burp Should Not Capture Corporate Credentials"
    anchor="burp-should-not-capture-corporate-credentials" >}},
you do not want to capture login credentials or other sensitive info in your
Burp projects.

Discover these endpoints for your organization and then add them to the pass
through section. For example, `auth.example.net` or Okta `example.okta.com`.

## What About HTTP?
It should have been obvious to me but I did not realize that HTTP requests still
get proxied. For example, `http://ocsp.digicert.com`.

There's not much we can do here. Fortunately, there are only a few of them
these days. A few suggestions:

1. Redirect those domains to localhost using the `hosts` file. This will break
   things down the road especially if you are not in a VM.
2. With `FoxyProxy` you can designate filters for passing data to the proxy.
3. Live with the noise.

If you figure out a way to tell Burp not to capture HTTP requests (other than
the nuclear option) please let me know.

# Burp's HTTP History Filter
The filter for HTTP History is another good ally in our war against noise. I
usually remove CSS and some file extensions like woff/woff2 (fonts). You can add
these to the `Filter by file extension > Hide` section and then turn it on/off
as needed. Bonus points for adding them to your default Burp config file. The
possibilities here are endless.

## OPTIONS
Burp's history filter does not have a way to hide HTTP verbs like OPTIONS. The
preflight requests will pollute your history. I described how I wrote an
extension to hide them in
{{< xref path="post/2019/2019-04-06-hiding-options/"
    text="Hiding OPTIONS - An Adventure in Dealing with Burp Proxy in an Extension" >}}.
You can use this methodology to hide any HTTP verb from history.

Note: [Capt. Meelo][capt-meelo] wrote an extension based on my blog post (seems
like mine has stopped working), you can see their blog post at
[Filtering the OPTIONS Method in Burp][options-2].

[capt-meelo]: https://twitter.com/CaptMeelo
[options-2]: https://captmeelo.com/pentest/2020/01/06/filter-options-method.html

# The Nuclear Option
You can drop any request that is not in scope.

1. Add all target domains to scope.
2. Go to `Project Options > Out-of-Scope Requests (at the bottom)` and select
   `Drop all out-of-scope requests`.

I really do not suggest this even after you feel you have everything in scope.
Thick client applications usually surprise me with new requests.

# The Resulting Project Config
After doing this for a while, you will have a good list of noisy domains. Save
the project config at `Project (menu) > Project options > Save project options`.
The domains will be in the config file (it's a JSON file) under
`ssl_pass_through`.

{{< imgcap title="Domains in the config file" src="05-domains-in-config.png" >}}

Add them to your default config file with the rest of the things you like:

1. Disable intercept at startup.
    1. `User options > Misc > Proxy Interception`
2. Disable pretty-print by default (added in v2020.4).
    1. `User options > HTTP Message Display > Pretty print by default`
3. Remove the default Burp Collaborator[^collab].
    1. `Project options > Misc > Burp Collaborator Server > Don't use Burp Collaborator`
4. Remove `If-Modified-Since` and `If-None-Match` headers to always avoid 304s.
    1. `Proxy > Options > Match and Replace > Enable built-in rules`.
    2. Why?
       {{< xref path="/post/2019/2019-10-13-quality-of-life-burp/"
           text="Disable Cached Responses"
           anchor="disable-cached-responses" >}}

Some of these are `User options` and do not appear in the JSON file that we
created above. User options can be exported at `Burp (menu) > User options >
Save user options`. This creates a second JSON file. Everything will be under a
key named `user_options`.

```json
{
    "user_options":{
        // removed
    }
}
```

The project options file has a similar structure. Everything is under `project_options`.

```json
{
    "project_options":{
        // removed
    }
}
```

## Combining User and Project Options
You can combine these two files. Add `user_options` and everything under it to
the other file. Note that `project_options` and `user_options` should be the two
top-level keys along with `proxy` and a few move. The final config file will
look like:

```json
{
    "project_options":{
        // removed
    },
    "user_options":{
        // removed
    },
    "proxy": {
        // removed
    },
    // removed
}
```

Now we can use this project file every time we create a new project. Save it
somewhere (e.g., git repo) and update it regularly.
{{< xref path="/post/2019/2019-10-13-quality-of-life-burp/"
    text="It will save you a lot of time"
    title="Use a Default Burp Config"
    anchor="use-a-default-burp-config" >}}

**Update June 2020**: I reviewed the rules and decided that using wildcards to
ban entire domains is better. For example, to ban pretty much every request to
`mozilla` we can use this regex `^.*mozilla\\.(com|net|org)$`. I updated the
burp config. It should be cleaner now.

**Update June 2021**: I have reduced the file size significantly. I compared the
final config file with the default values and removed the JSON keys that were
not modified. This does not have any performance effects.

See mine at:

* https://github.com/parsiya/Parsia-Clone/blob/master/configs/burp-default-config.json
* Raw download: https://raw.githubusercontent.com/parsiya/Parsia-Clone/master/configs/burp-default-config.json

# What Did We Learn Here Today?

1. How to reduce noise in Burp history using several techniques.
2. How to combine project and user config files.

Thanks for reading and hit me up if you have any suggestions.

[^collab]: We honestly do not know what Portswigger collects from the collaborator. This is a must if you are doing consulting for 3rd parties. You don't want to leak your clients' internal info. You do not want your fancy payload to be harvested either.