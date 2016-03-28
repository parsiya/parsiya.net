---
date: "2016-02-21T14:42:41-05:00"
draft: false
title: "Installing Burp Certificate Authority in Windows Certificate Store"
categories:
- Burp
- Tutorial
tags:
- Burp
- Certificate Authority
- TLS certificate
---

I was writing another blog post and I realized that I keep repeating how to do the same things, so I decided to write some tutorial-ish things and just link them.

Burp uses custom certificates to Man-in-the-Middle (MitM) the traffic. All of these certificates are signed by Burp's root Certificate Authority (CA). Each installation of Burp generates its own root CA that needs to be installed in the browser or Operating System's certificate store to be recognized properly. Otherwise browsers will return warnings and some thick client applications will not recognize these certificates as valid.

Each installation of Burp generates its own root CA so it is unlikely that others can gain access to it and sign certificates to MitM your connection. To get the certificate's private key, the attackers need to get to your local machine and if so they have better ways to look at your traffic anyway.

Alternate instructions by Portswigger: [https://support.portswigger.net/customer/en/portal/articles/1783075-installing-burp-s-ca-certificate-in-your-browser](https://support.portswigger.net/customer/en/portal/articles/1783075-installing-burp-s-ca-certificate-in-your-browser)

For instructions on installing/removing Burp's CA in other browsers and devices please use Portswigger's website:  [https://support.portswigger.net/customer/en/portal/articles/1783075-installing-burp-s-ca-certificate-in-your-browser](https://support.portswigger.net/customer/en/portal/articles/1783075-installing-burp-s-ca-certificate-in-your-browser).

**Note**: These instructions are for Burp version 1.6.37 Pro and 1.6.32 Free. As long as I remember (v1.5) these instructions have not changed, although they may change in the future but I really doubt it.

<!--more-->

### Obtaining the Root CA
This tutorial assumes you have already installed Burp (both free and pro version have the same) and you are running Windows. Although accessing the certificate is OS agnostic.

#### Using a Browser
Open up your browser and navigate to the following URL [http://burp/](http://burp/) or [http://127.0.0.1:8080](http://127.0.0.1:8080) (default settings for Burp's proxy listener), If you have set-up Burp's proxy listener on a different port, use that instead of `8080`. Please not that if you have disabled the Burp's web interface in `Proxy > Options > Miscellaneous > Disable web interface at http://burp`, this method will not work. You either have to enable the web interface or use the other method.

{{< imgcap title="Burp's web interface" src="/images/2016/burp1/01.png" >}}

Click on `CA Certificate` to begin downloading the certificate.

{{< imgcap title="Downloading Burp's CA" src="/images/2016/burp1/02.png" >}}

#### Using Burp's Certificate Export Functionality
If you have disabled Burp's web interface, you can use Burp to export the certificate directly. This functionality also allows you to export the certificate along with its private key to use in other applications. This is useful if you want to sign your own custom certificates but do not want to generate a new root CA like I did for [Hipchat]({{< ref "2015-10-19-proxying-hipchat-part-3-ssl-added-and-removed-here.markdown#generatingtlscert" >}} "Proxying Hipchat Part 3: SSL Added and Removed Here :^\)").

Open Burp and navigate to `Proxy > Options`. Look under `Proxy Listeners` at the top of the page for a button named `Import / export CA certificate`. Notice that you can also re-generate the certificate.

{{< imgcap title="Burp's import/export funcationality" src="/images/2016/burp1/03.png" >}}

Click the button and you can use the wizard to export Burp's root CA. At this stage we only need the certificate (and not the private key). Select the top option under `Export` which is `Certificate in DER format`.

{{< imgcap title="Exporting the certificate in Burp" src="/images/2016/burp1/04.png" >}}

Click next and then click on `Select file`.

{{< imgcap title="Select file" src="/images/2016/burp1/05.png" >}}

Now select a filename and path for the certificate.

{{< imgcap title="Select path and filename" src="/images/2016/burp1/06.png" >}}

Click `Next` and then finally `Close`.

### Installing Burp's Root CA in Windows Certificate Store
Double click the certificate and then c lick `Install Certificate`.

{{< imgcap title="Install certificate button" src="/images/2016/burp1/07.png" >}}

Click `Next` only once until you reach the following screen where you can choose the certificate store to save the certificate. Select `Place all certificates in the following store` and then select `Browse`.

{{< imgcap title="Selecting the certificate store" src="/images/2016/burp1/08.png" >}}

Select `Trusted Root Certification Authorities`. And press `Ok` and then `Next`.

{{< imgcap title="Selecting the root CA certificate store" src="/images/2016/burp1/09.png" >}}

If you did not have Burp's CA installed, you will get a security warning screen after clicking `Finish`.

{{< imgcap title="Security warning when installing a root CA" src="/images/2016/burp1/10.png" >}}

Press `Yes` and you should get a `Import was successful` message.

Now any certificate signed by Burp will be valid in most thick client applications, Internet Explorer and Chrome. Note that Firefox has its own certificate store and proxy settings.
