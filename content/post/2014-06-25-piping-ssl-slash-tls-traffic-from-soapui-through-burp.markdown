---
categories:
- Burp
tags:
- SoapUI
- Proxy
comments: false
date: 2014-06-25T22:04:53Z
title: Piping SSL/TLS Traffic from SoapUI to Burp
---

Recently I was trying to test a web service. The traffic was over SSL/TLS and everything was fine. As I am better with Burp than SoapUI, I wanted to use Burp as a proxy for SoapUI. This should be an easy matter. Burp will create a custom certificate (signed by its root CA) for each site and effectively Man-in-the-Middle the connection. But this time it was different, I was getting the dreaded ``Peer not Authenticated`` error. This meant that SoapUI did not recognize Burp's custom certificate.

I Googled and found some solutions such as adding Burp's CA to my certificate store (already done), adding it to SoapUI's keystore (didn't work) or using custom versions of SoapUI created for exactly this reason (again didn't work).

After a suitably long period of weeping and gnashing of teeth I achieved salvation.

Here's how to do it:


1. Set Burp as proxy for SoapUI.  
In SoapUI go to ``File > Preferences > Proxy Settings``.

2. Modify target address to http from https  
* 2.a. In SoapUI, modify the ``Service Endpoint.`` Change ``https://example.com`` to ``http://example.com``.  
Or  
* 2.b. Modify the WSDL and change ``wsdl:address location`` similarly and import it into SoapUI.

3. Edit Burp's listener and check ``Force use of SSL`` under ``Request Handling.``  
Notice that the ``Redirect to port`` input field will be automatically populated with 443. If your service endpoint is using a different port, modify that accordingly.

4. Now you can send requests from SoapUI and intercept them in Burp. Responses will appear in both SoapUI and Burp like any proxied application.

5. Be sure to remove the ``Force use of SSL`` after you are done. Otherwise you will be wondering why gmail is available under http in your browser (like <s>me</s> someone I know).
