---
title: "Thick Client Proxying - Part 4: Burp in Proxy Chains"
comments: true
date: 2016-04-07T21:17:25-04:00 # change this later
draft: false
tags:
- Burp
- Tutorial
- Fiddler
- Charles Proxy
- SoapUI
- IBM Appscan
toc: true
categories:
- Burp
- Thick Client Proxying
aliases:
- "/blog/2016-04-07-burp-tips-and-tricks-for-non-webapp-testing---part-4-burp-in-proxy-chains/"
---
In this post I will talk about using Burp as part of a proxy chain. The number of applications that can be proxied by Burp and used with Burp in proxy chains is *infinite* for documentation purposes. Instead I am going to demonstrate how to use some of more used tools with Burp in proxy chain. All of this is going to happen on a Windows 7 Virtual Machine (VM).

These applications/utilities are:

* [Cygwin][cygwin-dl]: I will use cURL commands for demonstration purposes.
* IBM Appscan Standard: I will use the evaluation version.
* [Charles Proxy][charles-dl]: For when you have to use multiple proxies.
* [Fiddler][fiddler-dl]: Same as above.
* [SoapUI][soapui-dl]

You don't need Burp Pro to play along and apart from Appscan, all application are free to use. For Appscan we will use the evaluation version which is free for its demo test.

[charles-dl]: https://www.charlesproxy.com/download/latest-release/
[fiddler-dl]: https://www.telerik.com/download/fiddler
[cygwin-dl]: https://www.cygwin.com/
[soapui-dl]: https://www.soapui.org/downloads/soapui.html

<!--more-->

# 0. Setup
As a general rule, if the application has its own proxy settings or uses Internet Explorer (IE) proxy settings we should be able to point it to Burp's proxy listener.

Before starting, be sure to install Burp's root CA in your Operating System's certificate store. [Here's how to do it on Windows]({{< ref "2016-02-23-installing-burp-ca-in-windows-cert-store.markdown" >}} "Installing Burp Certificate Authority in Windows Certificate Store").

Burp's proxy listener is set to the default settings `127.0.0.1:8080`.

# 1. Cygwin
Think of [Cygwin][cygwin-dl] as a \*nix command line on Windows. Sometimes it's easier to run some utilities in Cygwin instead of Windows such as `git` or `cURL`. For an API test I was given a bunch of cURL commands. Being lazy, I just ran them via Cygwin, piped it to Burp and then did my testing in Burp using Repeater.

To install cURL on Cygwin we need to run the Cygwin setup file again and choose it from the list of available packages. It is *similar* to a package manager and supports search so finding and installing cURL is easy. The setup file also downloads dependencies.

I am going to use the GET request that retrieves the Google logo again. The easiest way to acquire some cURL commands that simulate this is through Burp. Pipe the browser to Burp and go to the Google homepage. Be sure to clear your browser's cache, otherwise you may not see the request. Select the request to [https://www.google.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png](https://www.google.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png). Now right click on the request in the `Request` tab and select `Copy as curl command`.

{{< imgcap title="Copy as curl command" src="/images/2016/burp-tips-4/01.gif" >}}

The result should be similar to this:

```
curl -i -s -k -X 'GET' \
-H 'Referer: https://www.google.com/' -H 'User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko' -H 'DNT: 1' \
-b 'NID=78=S4kjzm5kwP82gAN8xazSJCiG6UWZhRNEGEE_a3hHZ2OMcy5bPX1CjZisClbvBgPUodlcpywR6WyhVSRUykloTI3ay7jSy9fpgTG2tKV2s8eojpQmL_F5sYKyHP1exm8iwp0F_FEnnE_DaQ' \
'https://www.google.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png'
```

We do not need most of the items in the command to grab the picture. We can omit the `Referer`, `Cookie` and `User-Agent` and some other things.

`curl -i -s -k -X 'GET' 'https://www.google.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png'`

## 1.1 The -k or insecure switch
The `-k` switch stands for `--insecure` which means cURL will not validate the certificate. This is usually a must when using Burp, because Burp's self-signed certificate may not be valid. If you got the cURL commands from another source, be sure to add the this switch to avoid any problems.

## 1.2 Setting Burp as Proxy for Cygwin
This is easy. We can use the following commands:

    export  http_proxy=http://127.0.0.1:8080
    export https_proxy=http://127.0.0.1:8080

{{< imgcap title="Piping cURL command via Cygwin through Burp" src="/images/2016/burp-tips-4/02.gif" >}}

**This should work for most \*nix command lines.**

# 2. IBM Appscan Standard
IBM Appscan Standard or Dynamic (known as Appscan moving forward) is a web application scanner. ~~Redacted Appscan rant~~. There are times when we have to pipe it through Burp. In order to practice, we are going to use the evaluation version which at the time of writing, is version `9.0.3`. To get the software we will need a free IBM ID, I am sure you can either register or acquire one.

Having an evaluation version, we can only scan the IBM demo site at [http://demo.testfire.net](http://demo.testfire.net). That is enough for our demonstration.

In Appscan we can setup a proxy in `Scan Configuration > Connection > Communication and Proxy`. This is similar to Firefox proxy settings, we can either use the IE proxy settings or designate a specific proxy for Appscan. As a result we have two ways of piping Appscan traffic to Burp, one by using IE proxy settings or directly settings them in Appscan.

{{< imgcap title="Appscan proxy settings" src="/images/2016/burp-tips-4/03.PNG" >}}

Now we can pipe Appscan through Burp and do some manual explore. The trial software allows us to do it and save it but not add it to the scan. Now if we had a licensed version of Appscan and wanted to run a normal scan, we would see the traffic in Burp.

Alternatively if you want to pipe something **to Appscan**. For example using an external browser or some other tool (like cURL commands from Cygwin to Appscan) you can use the port listed at `Tools (menu) > Options > Recording Proxy (tab) > Appscan proxy port`. You can also choose your own port by disabling the `Let Appscan choose the port automatically` checkbox. Note that Appscan is only listening during manual explore.

{{< imgcap title="Appscan recording proxy settings" src="/images/2016/burp-tips-4/04.PNG" >}}

Notice that you can install and export Appscan's root CA here.

# 3. Charles Proxy
Sometimes you need to use two (or more) proxies in a chain. In this section and next I will talk about using two other popular HTTP proxies with Burp in a proxy chain.

First we download and install a free trial of [Charles Proxy][charles-dl]. Current version at the time of writing is `3.11.4`. For demonstration purposes I will use Internet Explorer and the usual Google home page. The source of traffic could be anything as far as we care. As long as we can proxy it, the rest is the same.

Be sure to install Charles' root CA. You can get it from `Help (menu) > SSL Proxying`.

## 3.1 IE -> Burp -> Charles
First we need to disable Charles' automatic Windows proxy settings by using `Proxy (menu) > Windows Proxy`. If Windows proxy is enabled then there is a small tick by this sub-menu item. Go to `Proxy (menu) > SSL Proxying Settings (sub-menu) > SSL Proxying (tab)` make sure `Enable SSL Proxying` is selected. Click `Add` and enter `*` in both host and port. This will enable SSL proxying for everything. Then open `Proxy (menu) > Proxy Setting (sub-menu) > Proxies (tab)` and see `HTTP Proxy` port (default is `8888`). Here we can designate another port.

{{< imgcap title="Charles SSL proxying" src="/images/2016/burp-tips-4/05.PNG" >}}

The trial version of Charles needs to be restarted every 30 minutes and it will enable Windows proxy again. Be sure to disable it and point it to Burp in IE again after each restart. Alternatively you can use Firefox to bypass IE proxy settings.

In Burp, go to `Options > Upstream Proxy Servers` and add Charles as an upstream proxy server at `127.0.0.1:8888`.

{{< imgcap title="Charles as upstream proxy in Burp" src="/images/2016/burp-tips-4/06.PNG" >}}

Now go to Google's homepage in IE and see the traffic in both Burp and Charles.

{{< imgcap title="Traffic in both Burp and Charles" src="/images/2016/burp-tips-4/07.PNG" >}}

## 3.2 IE -> Charles -> Burp
Restart Charles to reset the 30 minute trial clock. Now we can either let Charles change IE proxy settings automatically using the `Proxy (menu) > Windows Proxy` settings or disable this and manually set IE proxy settings to `127.0.0.1:8888`. Fortunately other Charles settings are not reset between restarts so we do not have to go through most of the options in the previous section.

In Charles go to `Proxy (menu) > External Proxy Settings (sub-menu)` and enable the `Use external proxy servers` checkbox. Now enable `Web Proxy (HTTP)` and `Secure Web Proxy (HTTPS)` and enter Burp's proxy listener for both (`127.0.0.1:8080`).

{{< imgcap title="Charles external proxy settings" src="/images/2016/burp-tips-4/08.PNG" >}}

Now open up Google's homepage in IE and we will see traffic in both Charles and Burp.

{{< imgcap title="Traffic from Charles to Burp" src="/images/2016/burp-tips-4/09.PNG" >}}

# 4. Fiddler
Fiddler is another popular web proxy. It has the added capability of scripting. We will start by [downloading Fiddler][fiddler-dl] v4.6.2.2.

## 4.1 IE -> Fiddler -> Burp
First we need to tell Fiddler to capture all HTTPS traffic at `Tools (menu) > Fiddler Options (sub-menu) > HTTPS (tab) > Decrypt HTTPS traffic`. This will install Fiddler's root CA in Windows certificate store (we will see the familiar pop-up). This will tell Fiddler to capture and decrypt all traffic going to a proxy (see the `Capture HTTPS CONNECTs` checkbox?). Finally enable `Ignore server certificate errors (unsafe)` in case Burp's certificate is not recognized.

{{< imgcap title="Fiddler HTTPS Options" src="/images/2016/burp-tips-4/10.PNG" >}}

Then switch to the `Gateway` tab. Select the radio button `Manual Proxy Configuration` and enter `http=127.0.0.1:8080;https=127.0.0.1:8080` in the top textbox (the one with the `Proxy string` text). This will pipe Fiddler traffic to Burp.

{{< imgcap title="Piping Fiddler to Burp" src="/images/2016/burp-tips-4/11.PNG" >}}

Now we can navigate to Google in IE see the traffic in both Fiddler and Burp.

{{< imgcap title="Traffic sent from Fiddler to Burp" src="/images/2016/burp-tips-4/12.PNG" >}}

You can also manually set Fiddler's proxy listener in the `Tools > Fiddler Options > Connections (tab)`. To disable Fiddler's automatic proxying, uncheck `File (menu) > Capture Traffic (sub-men)` or press `F12`.

{{< imgcap title="Fiddler Options Connections tab" src="/images/2016/burp-tips-4/13.PNG" >}}

## 4.2 IE -> Burp -> Fiddler
First we have to disable Fiddler's automatic proxying and remove Burp in the `Gateway` tab. Otherwise we will have a pretty nice loop between Burp and Fiddler :D. Remember to choose `No Proxy` otherwise we will go back to Burp if we use IE proxy settings. Then we set Burp as Proxy in IE and finally set Fiddler as upstream proxy in Burp. Fiddler's default port is `8888` (like Charles) but as we saw that can be changed.

# 5. SoapUI
I have already talked about this before in [Piping SSL-TLS Traffic from SoapUI to Burp]({{< ref "2014-06-25-piping-ssl-slash-tls-traffic-from-soapui-through-burp.markdown" >}} "Piping SSL-TLS Traffic from SoapUI to Burp").

# 6. Plans for Part Five
We are going to actually start proxying. First we will start with easy application and then harder. One big problem is finding freely available applications that allow us to use the different functionalities that we have talked about. For example if I am able to find an application that needs a custom Burp extension to see its traffic, that would be great experience for me (and maybe even you). I can show how to do some basic traffic reverse engineering and then create a Burp plugin from scratch (I need the experience).

So if you have any suggestions about interesting applications please let me know but keep in mind that the applications should be freely available. This is going to be pure proxying and seeing legitimate traffic without any testing (because we do not want to get in trouble).

As usual, if you have any feedback you know where to find me.

<!-- Links: -->
