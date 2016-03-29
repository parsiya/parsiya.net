---
date: 2016-03-29T19:57:53-04:00
# change the date and file name before publishing
title: "Burp Tips and Tricks for Non-Webapp Testing - Part 2: History, Intruder, Scanner and More"
draft: false
categories:
- Burp
- Tutorial
tags:
- Burp
- Tutorial
---
In [part1]({{< ref "2016-03-27-burp-tips-and-tricks-for-non-webapp-testing-part-1.markdown" >}} "Burp Tips and Tricks for Non-Webapp Testing - Part 1: Interception and Proxy Listeners") I talked about some of Burp's functionalities. I did not expect it to be that long, originally I had intended to just shared some quick tips that I use. Now you are forced to read my drivel.

Let's continue, in this part I will talk about `Target > Scope`, `Proxy > HTTP History` and `Intruder`. I will discuss a bit of `Scanner`, `Repeater` and `Comparer` too. The reason behind skipping scanner is that it is mostly geared towards web application. It is still useful for testing the endpoints but using it quite straightforward.

<!--more-->

## Table of Contents:

<ul>
<li><a href="#1-scope:25f066f89e2edc84b94fa691f7424bd1">1. Scope</a></li>
<li><a href="#2-http-history:25f066f89e2edc84b94fa691f7424bd1">2. HTTP History</a></li>
<li><a href="#3-scanner-only-available-in-pro-version:25f066f89e2edc84b94fa691f7424bd1">3. Scanner (only available in Pro version)</a>
<ul>
<li><a href="#3-1-live-scanning:25f066f89e2edc84b94fa691f7424bd1">3.1 Live Scanning</a></li>
<li><a href="#3-2-options:25f066f89e2edc84b94fa691f7424bd1">3.2 Options</a></li>
</ul></li>
<li><a href="#4-intruder-rate-limited-in-free-version:25f066f89e2edc84b94fa691f7424bd1">4. Intruder (rate limited in Free version)</a>
<ul>
<li><a href="#4-1-positions:25f066f89e2edc84b94fa691f7424bd1">4.1 Positions</a></li>
<li><a href="#4-2-payloads:25f066f89e2edc84b94fa691f7424bd1">4.2 Payloads</a>
<ul>
<li><a href="#4-2-1-payload-sets-and-payload-options:25f066f89e2edc84b94fa691f7424bd1">4.2.1 Payload Sets and Payload Options</a></li>
<li><a href="#4-2-2-payload-processing:25f066f89e2edc84b94fa691f7424bd1">4.2.2 Payload Processing</a></li>
</ul></li>
<li><a href="#4-3-options:25f066f89e2edc84b94fa691f7424bd1">4.3 Options</a>
<ul>
<li><a href="#4-3-1-grep-match:25f066f89e2edc84b94fa691f7424bd1">4.3.1 Grep - Match</a></li>
</ul></li>
</ul></li>
<li><a href="#5-repeater-decoder-comparer:25f066f89e2edc84b94fa691f7424bd1">5. Repeater - Decoder - Comparer</a>
<ul>
<li><a href="#5-1-repeater:25f066f89e2edc84b94fa691f7424bd1">5.1 Repeater</a></li>
<li><a href="#5-2-decoder:25f066f89e2edc84b94fa691f7424bd1">5.2 Decoder</a></li>
<li><a href="#5-3-comparer:25f066f89e2edc84b94fa691f7424bd1">5.3 Comparer</a></li>
</ul>
</ul>


## 1. Scope
Ideally you want to add the application's endpoints to scope, this helps you filter some of the noise is other parts of Burp.

Adding an endpoint to scope is easy. Right click a request and select `Add to scope`. Then you can navigate to `Target > Scope` and see the newly added item to scope. There is one big catch. Only *that* URL is added to scope. For example if I select the request to `GET` Google's logo and add it to scope. The rest of Google.com are not in scope and have to be added manually.

{{< imgcap title="Adding Google's logo to scope" src="/images/2016/burp-tips-2/01.gif" >}}

Another way to add it is a to copy the URL and then paste it. If you right click on any request almost anywhere in Burp (HTTP History, Repeater, Intruder, etc.) you have an option called `Copy URL`. This will copy the URL. We can use the `Paste URL` button to paste it to scope. This button appears in other places in Burp and does similar things everywhere.

{{< imgcap title="Using Paste URL to add items to scope" src="/images/2016/burp-tips-2/02.gif" >}}

We usually do not want to have only one request in scope. Usually it's either the whole endpoint (`*.google.com`) or a certain directory (`google.com/images/`). Luckily for us we can use regex when selecting scope. What I usually do is to add an item to scope via one of the above methods and then modify the scope by using the `Edit` button.

There are four options in scope:

* Protocol: Can be `Any`, `HTTP` or `HTTPS`. I usually go with `Any`.
* Host of IP range: Supports regex as we have seen.
* Port: Unless you are looking at a special port, I usually keep it empty. Empty means it does not filter anything by port. Supports regex.
* File: This is the rest of the URL minus the domain. Supports regex.

If we want to add Google and all its subdomains in scope, we add the logo (or any other item from Google) to scope and then edit it. We will change the scope as follows:

{{< imgcap title="Adding `*.google.com` to scope" src="/images/2016/burp-tips-2/03.PNG" >}}

## 2. HTTP History
HTTP History accessed at `Proxy > HTTP History` is where we will see all captured requests/responses. Roughly half of my time in Burp is spent here. One big part of the history is using the filter to reduce the noise. The filter can be opened by clicking on the tab with the text `Filter: Showing all items` (depending on your default settings this may be different). I usually like start with a clean slate and filter more.

{{< imgcap title="HTTP History filter options" src="/images/2016/burp-tips-2/04.PNG" >}}

The most effective item in reducing the noise is selecting `Show only in-scope items`. This will hide anything not in scope. Let's see it in action.

{{< imgcap title="Hiding out of scope items" src="/images/2016/burp-tips-2/05.gif" >}}

As you can see in the screenshot, the filter has a good number of options. Most of these options are simple to use. I am going to point out the ones that I usually use in non-webapps.

* In `Filter by MIME type` keep everything active until you are sure you are not losing any requests by hiding them. The MIME-type is not always stated correctly in responses. The `Other binary` is needed to see most binary or unusual payloads (it is not active by default).
* `Filter by file extension` is more accurate but not always. I only use the `Hide` feature and usually add some extra extensions to it (for example fonts) that I am not interested in.
* `Filter by listener` is especially useful when the application is communicating on different ports and does not support proxy settings. In these cases we have to redirect the endpoint to localhost (for example using the `hosts` file) and create a different proxy listener for each port. Using this feature we can see traffic for select listeners.

## 3. Scanner (only available in Pro version)
The Burp has a decent scanner. It is not as good as IBM Appscan Standard in terms of coverage and accuracy but it has a lot advantages especially for non-webapp testing.

* Burp is much easier/faster to set-up. I can login, scan a single request and be done with it. While in Appscan I have to do the whole app at once (condiure the scan, record login sequence, manual explore, automatic explore and then finally full scan). This does not take into the fact that more often than not I have to troubleshoot Appscan because it cannot record some special login (you are shit out of luck if login needs a random token) sequence. ~~More rants about Appscan.~~
* Burp is much cheaper. $300/year for Burp vs. $20,000/year for Appscan.

Results appear in `Issue activity` tab (a better place to observe the results is `Target > Site map`) sand requests being scanned are in `Scan queue`.

### 3.1 Live Scanning
Burp has two scanning modes: active and passive. These two can be active at the same time.

In passive scanning, it just looks at requests/responses and essentially greps according to its rule set. It does not send any requests to the server. In active scanning, it actually generates payloads and sends them to the server (and analyzes requests/responses).

In this tab you can configure these modes:

* **Never** turn `Live Active Scanning` on. **Seriously don't**. You are going to wreck something or get locked out of the application. Always scan each request individually.
* Having `Live Passive Scanning` to `Scan everything` is fine but increases noise. If you have setup the scope (which you should have) properly you can set it to `Use suite scope`. You can also select `Use custom scope` and select a scope similar to the scope tab.

{{< imgcap title="Live scanning options" src="/images/2016/burp-tips-2/06.PNG" >}}

### 3.2 Options
Here you can configure the scanner options. Although I do not use live active scanning, these options need to be configured for individual request scanning.

* `Attack Insertion Points`: You can select injection points.
* `Active Scanning Engine`: If makes sense to throttle the scanner. You don't want to kill the server or get IP-banned.
* `Active Scanning Areas`: As you can see, they are more geared towards webapps. I de-select everything and just add the ones that I think are relevant. This saves a lot of time during scanning.
* `Passive Scanning Areas`: De-select everything and only add relevant items to reduce the noise.
* `Static Code Analysis`: Enables static analysis on JavaScript files. You can probably drop this for non-webapps (not always though).

## 4. Intruder (rate limited in Free version)
Intruder is the semi-automatic scanning place. It's pretty straightforward to use. Right click on any request and select `Send to Intruder`. In Intruder you can designate injection points and then either scan them using the internal scanner or use your own payloads.

`Payload Encoding` instructs Burp to URL-encode special characters.

### 4.1 Positions
After sending the payload to Intruder open up the `Intruder > Positions` tab and see the injection points. I usually just `Clear` everything and then use the `Add` button to highlight my own injection points.

{{< imgcap title="Using Burp Intruder" src="/images/2016/burp-tips-2/07.gif" >}}

As you can see, I selected the familiar Google logo request and sent it to Intruder. Then cleared all pre-defined injection points and added the file name. Now we can right click and select `Actively scan defined insertion points` which sends this request to the Scanner but only scan this injection point or I can use the `Start Attack` button to start an attack on this injection using my own payloads. As I have not selected any payloads, the second option does not work yet.

### 4.2 Payloads
Now we can set our payloads for the custom Intruder attack. Switch to the `Payloads` tab.

#### 4.2.1 Payload Sets and Payload Options
Here we can use different payloads. Burp has some complex payload sets that you can use in special circumstances. For example there is `Recursive grep`, which means that you can grab each payload from the response to the previous payload. `Case modification`, `Character substitution`, `Dates` and `Numbers` are some of the others. I usually use the following:

**Simple list** allows you to use your own payloads for all injection points. Copy all the payloads from a source (it's one payload per line) and paste them in `Payload Options`. You can also directly use the file by selecting **Runtime file**. Using a file is the same as clicking the `Load` button and loading the file. You can also use some of Burp's internal payload lists which I think are only available in the Pro version.

{{< imgcap title="Simple list and Burp's internal payloads" src="/images/2016/burp-tips-2/08.PNG" >}}

The **Custom iterator** option allows Burp to do generate more complex payloads. For example if I want to simulate 2 bytes in hex (4 characters). I select position 1, use items 0-9 and a-f for it, then select positions 2-4 and do the same. Burp allows you to have 8 positions. If you want to add usernames after that, I can select position 5 and add my list of usernames. As you can see it also supports separators between positions.

{{< imgcap title="Custom iterator" src="/images/2016/burp-tips-2/09.PNG" >}}

One popular payload list is `FuzzDB` at [https://github.com/fuzzdb-project/fuzzdb][fuzzDB-github]. Be advised that it contains some payloads that are flagged by most Anti-Virus software.

#### 4.2.2 Payload Processing
Allows you to transform the payloads before injection into the request. For example you can encode all payload to base64 or send their hashes instead.

{{< imgcap title="Payload Processing" src="/images/2016/burp-tips-2/10.PNG" >}}

### 4.3 Options
We can throttle the Intruder (similar to the Scanner) in `Request Engine` or delay it.

#### 4.3.1 Grep - Match
We can grep for specific items in the responses. For example if we have injected SQLi payload, we can instruct Burp to search for words in SQL error messages. For XSS I usually use payloads that inject `9999` (e.g. `alert(9999)`) and then grep for it in responses.

FuzzDB has its own regex patterns to analyze the responses. [This page][fuzzDB-regex] shows how to use them with Burp.

## 5. Repeater - Decoder - Comparer
While these tabs do not have a lot of functionalities, they are quite useful.

### 5.1 Repeater
In order to send a request to repeater, right click and then select `Send to Repeater`. Repeater is where the completely manual testing happens. We can modify request and observe the responses.

Here I choose the logo GET request, send it to Repeater and forward it. Then modify it and see the 404 response. Then undo with `Ctrl+Z` to revert to the original request.

{{< imgcap title="Using Burp Repeater" src="/images/2016/burp-tips-2/11.gif" >}}

Note than you can send modified items from Repeater to Intruder for scanning.

### 5.2 Decoder
Allows encoding/decoding to different formats. Also supports creating hashes. Double click any parameter to select it and then right click and select `Send to Decoder`. You can also select and item and copy it by pressing `Ctrl+C` and then paste it in decoder.

{{< imgcap title="Using Burp decoder" src="/images/2016/burp-tips-2/12.gif" >}}

### 5.3 Comparer
Comparer is used for comparing two payloads. Again select, right click and `Send to Comparer`. Comparing can be done at a byte (for binary blobs) level or by words (usually for text).

------------

That was it, in the next part I will talk about the items in the `Options` menu.

<!-- Links -->
[fuzzDB-github]: https://github.com/fuzzdb-project/fuzzdb
[fuzzDB-regex]: https://github.com/fuzzdb-project/fuzzdb/wiki/regexerrors
[trustwave-1]: https://www.trustwave.com/Resources/SpiderLabs-Blog/%E2%80%9CReversing%E2%80%9D-Non-Proxy-Aware-HTTPS-Thick-Clients-w/-Burp/
