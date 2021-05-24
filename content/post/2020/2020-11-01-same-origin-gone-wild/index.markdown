---
title: "The Same-Origin Policy Gone Wild"
date: 2020-11-01T20:02:53-08:00
draft: false
toc: true
comments: true
twitterImage: 01-json-tweet.png
categories:
- Websec
---

I will talk about some edge cases of the Same-Origin Policy (SOP). It affects
browser based thickclient platforms so it's not just for web application
security. This is a more detailed dive into this topic that I touched briefly in
the [localghost][localghost-link] talk.

[localghost-link]: https://youtu.be/Cgl51ZcACLg?t=90

<!--more-->

If you know the foundations please  jump directly to the
[SOP Gone Wild](#sop-gone-wild) section below.

# Foundations
These definitions are not exactly correct and I have omitted some exceptions.
SOP is one of the most well-studied topics in the browser security model so
there is ample reading material.

## The Origin Header
The `origin` header is set by the browser for cross-origin requests. It contains
the origin of the request. An origin has three parts:

* Protocol or scheme: Usually `http` or `https`.
* Domain: E.g., `whatever.example.net`. Domain does not include the path.
* Port: Usually omitted. Assume the default port not present. E.g., 443 for `https`.
  Internet Explorer does not care about port.

## Forbidden Headers
`Origin` is a forbidden header. Forbidden headers are set by browsers and cannot
be altered by JavaScript.

* https://developer.mozilla.org/en-US/docs/Glossary/Forbidden_header_name

## Same-Origin Policy Simplified
SOP means a script from one origin cannot send most requests to another origin
or read the responses to cross-origin requests that were sent absent any other
mechanism (e.g., CORS). For more information please read:

* https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy
* https://portswigger.net/web-security/cors/same-origin-policy

## Cross-Origin Resource Sharing (CORS)
CORS allows a script from an origin to bypass the SOP and interact with another
origin. This usually happens when the server on the other side adds a bunch of
headers to the response. The most important header is
`Access-Control-Allow-Origin`[^1]. If this header contains the value of the
sender's origin then the browser allows the sender to see the response or in
some cases actually send a request to the other side.

[^1]: There are more CORS headers but they are not important for this discussion.

If this header is missing then CORS is not enabled. The value of this header can
be:

* An exact origin (or number of origins) like `whatever.example.net`.
* `*` that matches everything.

In practice, the remote server looks at the `Origin` header in the incoming
request. If it's in the allowlist then the response will contain the exact
origin in the value of the `Access-Control-Allow-Origin` header in the response.

Burp's scanner has a simple check for this. It sets the `Origin` header to some
arbitrary value. If the response contains that value or the `*` wild card then
it creates and issue.

## Simple Requests
The browser allows an origin to send "simple" requests to another origin without
any checks[^2]. The request goes through but in the absence of CORS headers the
browser might not let the sender see the response.

[^2]: This is why CSRF exists.

A simple request is:

* Only has one of these three methods:
    * `GET`
    * `HEAD`
    * `POST`
* Only has certain headers that are not set by the browser. The only important
  header for this discussion is `Content-Type`. It can only contain these values:
    * `application/x-www-form-urlencoded`
    * `multipart/form-data`
    * `text/plain`

There are more requirements but they are not important here. More information:

* https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#Simple_requests

## Preflighted Requests
Other requests are not sent without checks. The browser sends an `OPTIONS`
request with some headers to the endpoint and reads the response headers. If
these headers allow CORS then the browser sends the actual request.

This can become an unintentional CSRF protection. If your webapp uses POST
requests with JSON payloads. The requests will have `Content-Type: application/json`.
This means without CORS these POST requests are not vulnerable to CSRF. Because
when phished users click on links in a typical CSRF scenario, the browser sends
the preflight request which fails and the actual CSRF request is never sent.

For more information please see:

* https://developer.mozilla.org/en-US/docs/Glossary/Preflight_request

A couple of quick tricks:

1. Change the `Content-Type` to `text/plain` (or remove the header completely)
   to make it a simple request.
2. Change the verb of the request to `HEAD`.
3. Change the payload from JSON to `url-encoded`. E.g.,
   `{"param1":"val1","param2":val2}` becomes `param1=val1&param2=val2`. This
   works only occasionally and nested JSON objects do not work. But it's worth a
   try.

# SOP Gone Wild
Let's talk about the edge cases.

## Origin Does Not Always Have Three Items
Origin consists of protocol, domain, and port.
**Internet Explorer does not care about port.**

In addition, Internet Explorer does not care about SOP when dealing with `Highly
Trusted Zones`. In most corporate environments the internal domains are added to
this zone.

## If The Port Is Missing From the Origin Then the Default Port Is Implied
`https://example.net:443` and `https://example.net` are the same.

## WebSockets Are Not Bound By The SOP
This is a common issue and the most important item in this blog. Websockets
start with a handshake. The handshake is a GET request which satisfies the
`simple request` criteria. So it's sent cross-origin.

If the request is cross-origin and no CORS policy is defined, the sender cannot
see the response of the handshake. But it really does not matter. The browser
does it for us.

For more information please read the following article by Independent Security
Evaluators:

* https://blog.securityevaluators.com/websockets-not-bound-by-cors-does-this-mean-2e7819374acc#e8bc

A couple of tricks:

1. The `Sec-WebSocket-Key` in the handshake request has nothing to do with
   security.
2. One of the headers in the request is `Sec-Websocket-Protocol`. Sometimes you
   can change the protocol of the websocket with this header. An application was
   using protobuf. I noticed the value of this header in the request is also set
   to `protobuf` so I changed this value to `json` and it switched to neatly
   formatted JSON.

{{< imgcap title="WebSocket magic or something" src="01-json-tweet.png" >}}

## The Origin Header Is Not Always Set
The browsers only set the `origin` header for some requests. Generally, the
header is only set for cross-origin requests. This is not completely correct but
going into the details will just complicate things.

## Cross-Origin Simple Requests Are Sent Without Checks
We usually do not think the request is sent because the browser does not allow
access to the response. GET requests and some POST requests are sent anyways. We
might not be able to see the response but the action is probably already
executed. Hence, why CSRF exists even if there is no CORS because the POST
request performs some action.

Look at this bug from [TavisO][taviso-twitter] at
https://bugs.chromium.org/p/project-zero/issues/detail?id=693.

[taviso-twitter]: https://twitter.com/taviso

TrendMicro was running a local webserver. You can execute commands by sending a
GET request like
`https://localhost:49155/api/openUrlInDefaultBrowser?url=c:/windows/system32/calc.exe`.
You will not be able to see the response but the code is already executed and
you got remote code execution.

A similar issue happened in my
{{< xref path="/post/2019/2019-06-18-rce-asa" title="Attack Surface Analyzer RCE" anchor="xss-root-cause-analysis" >}}
A "simple" GET request was used to inject the XSS to RCE payload in an Electron
app.
