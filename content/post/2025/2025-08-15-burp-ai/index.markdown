---
title: "How Burp AI Works"
date: 2025-08-15T00:10:43-07:00
draft: false
toc: true
twitterImage: 17-ai-login-1.webp
aliases:
- /blog/2025-burp-ai
categories:
- DEF CON
- Burp
- AI
---

This is a quick peek inside Burp AI. I'll show how to proxy its requests, what
actually happens when you trigger a feature. This knowledge allows us to
redirect Burp AI to your own AI instance. As far as I know, this is not publicly
documented.

I covered a shorter version in my DEF CON 33 Bug Bounty Village talk
`The Year of the Bounty Desktop: Bugs from Binaries`. See the
[extended slides (pages 14–22)][bb-slides] (placeholder for video).

[bb-slides]: https://github.com/parsiya/Presentations/blob/main/defcon-33-bugs-binaries/defcon-33-bugs-binaries-all-slides.pdf

<!--more-->

# Quick Start

1. Run two Burp instances.
2. In the first (Burp client), set the upstream proxy to `localhost:9000`.
3. In the second (Burp server), create a listener on port `9000`.
4. Add the Burp CA to the JRE `cacerts`.
5. Use AI in Burp client; watch results in Burp server.

# Quick Facts

1. AI is off by default (props to PortSwigger).
2. All AI traffic goes to `ai.portswigger.net`. Block it to disable Burp AI.
  1. This is also mentioned in the documentation, but I wanted to confirm.
3. Requests/responses are JSON.
4. Burp had "agentic behavior" pre‑hype. E.g., AI can ask Repeater or the login
   recorder to act.

# Motivation
I wanted to see how Burp AI works internally: where traffic goes and what is
sent. A big Burp AI flaw (to me) is the lack of a configurable endpoint. I trust
PortSwigger; I'm running their software. Still, I can't send internal data to
an outside service.

# Proxying Burp
I'll walk through what I tried. What worked, what didn't, and what I'd have
tried next.

## Checking the Logs
Burp has a built-in Logger, so I started there. Only _some_ Burp AI requests
show up there. When I clicked `Explore Issue` for "Exploring Strict transport
security not enforced on example.net" I saw only one AI request.

Here's how the issue looks in Burp after exploration:

{{< imgcap title="Exploring HSTS in example.net" src="01-explore-hsts.webp" >}} 

And this is the only request Logger captured:

{{< imgcap title="Only request captured in Logger" src="02.webp" >}}

I've not investigated this, but Logger likely uses the same APIs extensions use,
so an extension won't see everything either. Those APIs are:

* Legacy API: [void registerHttpListener(IHttpListener listener)][reg-listener]
* Montoya API: [Registration registerHttpHandler(HttpHandler handler)][reg-handler]

[reg-listener]: https://portswigger.net/burp/extender/api/burp/iburpextendercallbacks.html#registerHttpListener-burp.IHttpListener-
[reg-handler]: https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/http/Http.html#registerHttpHandler(burp.api.montoya.http.handler.HttpHandler)

## Upstream Proxy
Burp supports an upstream proxy, so we can intercept outbound traffic. It's
"proxy‑aware" and sends the `CONNECT` request properly. For background, see my
2016 post [Thick Client Proxying - Part 6: How HTTP(s) Proxies Work][proxy-6].

For more about proxying Burp (and other similar tools), read my
[Thick Client Proxying - Part 4: Burp in Proxy Chains][proxy-4] blog.

[proxy-6]: https://parsiya.net/blog/2016-07-28-thick-client-proxying-part-6-how-https-proxies-work/
[proxy-4]: https://parsiya.net/blog/2016-04-07-thick-client-proxying-part-4-burp-in-proxy-chains/

1. Run two instances of Burp. Let's call them Burp client and server.
2. Set the Upstream Proxy for Burp client to `localhost:9000`.
3. Create a proxy listener in Burp server on port `9000`.

{{< imgcap title="Burp client and server setup" src="03-upstream.webp" >}}

After wiring this up I clicked the purple magic icon (bottom right) to check my
Burp balance. Surprisingly, it failed.

{{< imgcap title="Failed Burp balance check" src="04-balance.webp" >}}

I'd already added Burp's CA to the Windows certificate store. So what broke?

## JRE cacerts File
Burp is written in Java. The Windows version bundles a Java Runtime Environment
(JRE). The executable wraps `java -jar ...` plus flags from `.vmoptions` files.

The JRE has its own certificate trust store at `JAVA_HOME/lib/security/cacerts`.
On Windows it's located at:
`%LocalAppData%/Programs/BurpSuitePro/jre/lib/security/cacerts`.

We can import the Burp CA with `keytool`. Keytool is conveniently bundled with
JRE at `JAVA_HOME/bin/keytool`.

1. Extract the Burp CA in DER format.
2. (Optional) cd into `.../jre/lib/security/` for convenience.
3. Run the following command. Adjust the paths as needed.

```
..\..\bin\keytool.exe -importcert -alias burp -keystore cacerts
    -storepass changeit -file /path/to/burpca.crt
```

On Linux (credit: [Nico][nico]):

```
./bin/keytool -importcert -cacerts -alias burp -file /path/to/burpca.crt
```

[nico]: https://hackademy.agarri.fr/contact

Done. Now the balance request shows up in Burp server. GET to
`https://ai.portswigger.net/burp/balance` with a base64 token in the 
`Portswigger-Burp-Ai-Token` header.

{{< imgcap title="Burp balance check request" src="05-balance2.webp" >}}

Token size is 864 bytes base64 and 648 bytes decoded. High entropy (7.61
Shannon) so likely random/encrypted.

{{< imgcap title="Entropy of the token in CyberChef" src="06-token.webp" >}}

# What's Inside Burp AI
Burp has quite a few AI features. Let's look at some of them.

## Explore Issue
Each issue has an `Explore Issue` button. Here I use the HSTS finding on
example.net.

{{< imgcap title="The 'Explore HSTS' button" src="07-explore-issue.webp" >}}

First request: POST to
`https://ai.portswigger.net/ai/hakawai-explore-service/api/v1/start`. Values are
replaced with `{{ }}` placeholders, but you can guess them.

```json
POST /ai/hakawai-explore-service/api/v1/start HTTP/2
Host: ai.portswigger.net

{
  "issue_definition": {
    "name": "Strict transport security not enforced",
    "type": "STRICT_TRANSPORT_SECURITY_NOT_ENFORCED",
    "detail": null,
    "background": "{{ description from PortSwigger KB}}",
    "evidence": [
      {
        "type": "REQUEST_RESPONSE",
        "request": "{{ request }}",
        "response": "{{ response }}",
        "request_highlights": [],
        "response_highlights": []
      }
    ]
  }
}
```

We see:

1. Finding name and type (same).
2. Description from the Burp KB (description section of [this page][hsts-kb]) as HTML.
3. Full originating request and response.

We don't see any prompts. It's injected later by the Burp AI proxy. They are
easy to guess.

[hsts-kb]: https://portswigger.net/kb/issues/01000300_strict-transport-security-not-enforced

The response instructs Burp to send a request. It looks like a Repeater action,
but nothing appears there. This is the same request we saw in Logger earlier.

{{< imgcap title="'Explore HSTS' response" src="08-explore-resp.webp" >}}

Response structure:

```json
{
  "exploration_id": "{{ some guid }}",
  "step_title": "Check for security headers and HTTPS redirect",
  "step_action": "I'm sending a basic GET request to examine the server's security headers and see if there's any HTTPS redirect mechanism in place. This will help us understand what security controls are missing and how we might exploit this weakness. Specifically, I'm looking for:\n1. Absence of HSTS header\n2. Lack of automatic HTTPS redirect\n3. Any other security headers that might be present or missing\nThis is the most logical first step as it directly relates to the reported vulnerability and will help us understand the server's security posture.",
  "tool_calls": [
    {
      "id": "toolu_01SDWeJPzMZptuCBFmb7uRtA",
      "tool_name": "repeater",
      "arguments": {
        "request": "GET / HTTP/1.1\nHost: example.net\nAccept-Language: en-US,en;q=0.9\nUpgrade-Insecure-Requests: 1\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\nSec-Ch-Ua: \"Not.A/Brand\";v=\"99\", \"Chromium\";v=\"136\"\nSec-Ch-Ua-Mobile: ?0\nSec-Ch-Ua-Platform: \"Windows\"\nSec-Fetch-Site: none\nSec-Fetch-Mode: navigate\nSec-Fetch-User: ?1\nSec-Fetch-Dest: document\nAccept-Encoding: gzip, deflate, br\nPriority: u=0, i\nConnection: keep-alive",
        "learnings": "This is the first step, so there are no previous learnings to evaluate. However, from the initial evidence, we can see that the application responds to HTTP requests without enforcing HTTPS, which confirms the reported vulnerability.",
        "progress": "This is the first step in our investigation. We'll start by examining the server's response headers to understand what security measures are in place and what might be missing.",
        "knowledge": "From the initial response, we can see that the server supports HTTP/2 and offers alternative services including h3 (HTTP/3) and QUIC on port 443. The server appears to be a standard web server serving static content.",
        "step_title": "Check for security headers and HTTPS redirect",
        "step_action": "I'm sending a basic GET request to examine the server's security headers and see if there's any HTTPS redirect mechanism in place. This will help us understand what security controls are missing and how we might exploit this weakness. Specifically, I'm looking for:\n1. Absence of HSTS header\n2. Lack of automatic HTTPS redirect\n3. Any other security headers that might be present or missing\nThis is the most logical first step as it directly relates to the reported vulnerability and will help us understand the server's security posture."
      }
    }
  ]
}
```

Next `/continue` request: includes the prior response, same GUID, adds
`X-Forwarded-Proto: http`.

{{< imgcap title="'Explore HSTS' request #2" src="09-explore-req-2.webp" >}}

```json
POST /ai/hakawai-explore-service/api/v1/continue HTTP/2
Host: ai.portswigger.net

{
  "exploration_id": "{{ same guid as before }}",
  "tool_results": [
    {
      "tool_id": "toolu_01SDWeJPzMZptuCBFmb7uRtA",
      "result": "{{ response }}"
    }
  ]
}
```

The response adds a description and the next action (send another request).

{{< imgcap title="'Explore HSTS' response #2" src="10-explore-resp-2.webp" >}}

Structure:

```json
{
    "exploration_id": "{{ same guid as before }}",
    "step_title": "Test proxy header behavior",
    "step_action": "From the previous response, we confirmed that the server:\n1. Lacks HSTS headers\n2. Doesn't force HTTPS redirects\n3. Has minimal security headers\n4. Serves content over HTTP/2 despite being accessed via HTTP\n\nI'm adding the X-Forwarded-Proto header set to 'http' to see if the server's behavior changes when it believes the request came through a proxy. This could reveal if there's any proxy-aware security logic that might help us understand how the server handles SSL/TLS decisions. This is important because many applications implement HTTPS enforcement at the proxy level, and understanding this behavior could reveal additional attack vectors.",
    "tool_calls": [
        {
            "id": "toolu_01JRsZBtYYhoUsrYXasMkWTY",
            "tool_name": "repeater",
            "arguments": {
                "request": "{{ request}}",
                "learnings": "From the previous response, we confirmed that the server:\n1. Lacks HSTS headers\n2. Doesn't force HTTPS redirects\n3. Has minimal security headers\n4. Serves content over HTTP/2 despite being accessed via HTTP",
                "progress": "We're making progress in understanding the server's security configuration. Now we'll test if the server behaves differently when it thinks the request came through a proxy, which could reveal additional vectors for exploitation.",
                "knowledge": "The server is running a modern stack with HTTP/2 and HTTP/3 support, but lacks basic security headers. It also appears to be a static content server with no obvious signs of a complex application stack.",
                "step_title": "Test proxy header behavior",
                "step_action": "I'm adding the X-Forwarded-Proto header set to 'http' to see if the server's behavior changes when it believes the request came through a proxy. This could reveal if there's any proxy-aware security logic that might help us understand how the server handles SSL/TLS decisions. This is important because many applications implement HTTPS enforcement at the proxy level, and understanding this behavior could reveal additional attack vectors."
            }
        }
    ]
}
```

Final `/continue` contains the previous response.

```json
POST /ai/hakawai-explore-service/api/v1/continue HTTP/2
Host: ai.portswigger.net


{
  "exploration_id": "{{ same guid as before }}",
  "tool_results": [
    {
      "tool_id": "toolu_01JRsZBtYYhoUsrYXasMkWTY",
      "result": "{{ response }}"
    }
  ]
}
```

That response ends the conversation.

{{< imgcap title="'Explore HSTS' response #3" src="11-explore-resp-3.webp" >}}

If you want to copy the structure:

```json
{
  "exploration_id": "{{ same guid as before }}",
  "step_title": "Report findings on HTTPS enforcement vulnerability",
  "step_action": "The server consistently serves content over HTTP without any security redirects or headers, regardless of the protocol or proxy headers used. This behavior persists even when explicitly indicating HTTP traffic through proxy headers.\n\nAfter confirming the lack of HTTPS enforcement through multiple test cases, including direct requests and proxy-aware testing, it's appropriate to report our findings. The vulnerability has been fully verified and its impact understood, making this the logical conclusion to our testing.",
  "tool_calls": [
    {
      "id": "toolu_01FUxXnvkaDVNNK6NYDkMikj",
      "tool_name": "reporter",
      "arguments": {
        "report": "We have confirmed that the server accepts HTTP traffic without enforcing HTTPS, lacks HSTS headers, and does not implement any form of SSL/TLS redirect mechanism, even when accessed through a proxy. This vulnerability allows an attacker to perform SSL stripping attacks, potentially intercepting all traffic between users and the server, including any sensitive data or authentication credentials that may be transmitted.",
        "learnings": "The server consistently serves content over HTTP without any security redirects or headers, regardless of the protocol or proxy headers used. This behavior persists even when explicitly indicating HTTP traffic through proxy headers.",
        "progress": "We have thoroughly tested the server's behavior regarding HTTPS enforcement and confirmed the vulnerability. Further testing would not reveal additional information about this specific issue.",
        "knowledge": "The server runs a modern stack with HTTP/2 and HTTP/3 support (on port 443) but lacks fundamental security headers and HTTPS enforcement. It appears to be primarily serving static content.",
        "step_title": "Report findings on HTTPS enforcement vulnerability",
        "step_action": "After confirming the lack of HTTPS enforcement through multiple test cases, including direct requests and proxy-aware testing, it's appropriate to report our findings. The vulnerability has been fully verified and its impact understood, making this the logical conclusion to our testing."
      }
    }
  ]
}
```

Task view shows the summary, results, and the request/responses.

{{< imgcap title="'Explore HSTS' task summary" src="12-task-summary.webp" >}}

## 'Explain This' Context Menu Item
In Repeater (and elsewhere) highlight text and right‑click. Select `Explain
This` (top of the context menu). Here I highlighted the full request to
`example.net`.

{{< imgcap title="'Explain This' button" src="13-explain-button.webp" >}}

This results in a POST request to
`https://ai.portswigger.net/ai/hakawai-explain-this/api/v1/explainthis`.

{{< imgcap title="'Explain This' request #1" src="14-explain-req.webp" >}}

```json
POST /ai/hakawai-explain-this/api/v1/explainthis HTTP/2
Host: ai.portswigger.net

{
  "text": "{{ request }}",
  "context": "REQUEST_HEADERS"
}
```

Note the context. When I changed this request to POST and added some dummy
values, the value of context changed to `REQUEST`.

The response just explains the issue.

{{< imgcap title="'Explain This' response" src="15-explain-resp.webp" >}}

Response structure:

```json
{
  "content": "{{ removed }}"
}
```

And this appears in the sidebar.

{{< imgcap title="'Explain This' results in the side bar" src="16-explain-sidebar.webp" >}}

## AI Recorded Login
When scanning APIs Burp can record a login sequence with AI. Here I use
[Google's Gruyere][gru-link], an intentionally vulnerable app.

[gru-link]: https://google-gruyere.appspot.com/

First I created an instance and account `gru_user:gru_password`. Instance URL is
`https://google-gruyere.appspot.com/[numbers]/`. Then I started a scan and
chose AI recorded login.

{{< imgcap title="Recording a new login with AI" src="17-ai-login-1.webp" >}}

Supply URL, username, and password. I could speed it up by starting at the login
page, but I wanted to see the discovery process.

{{< imgcap title="Info for AI recorded login" src="18-ai-login-2.webp" >}}

In the first step, Burp sends the following information to
`https://ai.portswigger.net/ai/hakawai-recorded-login-generator/api/v1/start`
in a POST request:

* URL
* Title
* Page text
* An array of elements (links, inputs, buttons, etc.)
* A screenshot of the page in base64

```json
POST /ai/hakawai-recorded-login-generator/api/v1/start HTTP/2
Host: ai.portswigger.net

{
  "page_description": {
    "url": "https://google-gruyere.appspot.com/{{ gruyere-instance-id }}/",
    "title": "Gruyere: Home",
    "text": "Home Sign in | Sign up Gruyere: [removed]",
    "interactive_elements": [
      {
        "id": 15,
        "text": "Home",
        "attributes": "href=/{{ gruyere-instance-id }}/",
        "input_value": null,
        "accepts_input": false
      },
      {
        "id": 18,
        "text": "Sign in",
        "attributes": "href=/{{ gruyere-instance-id }}/login",
        "input_value": null,
        "accepts_input": false
      }, // removed the rest
    ],
    "screenshot": "data:image/png;base64,{{removed screenshot data}}"
  }
}
```

The response tells the recorder to click `Sign in`:

```json
{
  "recorded_login_id": "{{ guid }}",
  "tool_call": {
    "id": "toolu_01KLBGYsdH6JBvrcf6ircZkx",
    "tool_name": "click_element",
    "arguments": {
      "id": 18,
      "reason": "Clicking the \"Sign in\" link to navigate to the login page since we need to log in with existing credentials"
    }
  }
}
```

We've reached the login page. The next request has similar info about this page.

```json
POST /ai/hakawai-recorded-login-generator/api/v1/continue HTTP/2
Host: ai.portswigger.net

{
  "recorded_login_id": "{{ same guid }}",
  "tool_result": {
    "tool_id": "toolu_01KLBGYsdH6JBvrcf6ircZkx",
    "result": true
  },
  "page_description": {
    "url": "https://google-gruyere.appspot.com/{{ gruyere-instance-id }}/login",
    "title": "Gruyere: Login",
    "text": "Home Sign in | Sign up Gruyere: Login User name: Password: Login",
    "interactive_elements": [
      // removed
      {
        "id": 160,
        "text": "",
        "attributes": "type=password",
        "input_value": "",
        "accepts_input": true
      },
      {
        "id": 165,
        "text": "Login",
        "attributes": "type=submit",
        "input_value": "Login",
        "accepts_input": true
      }
    ],
    "screenshot": "data:image/png;base64,{{ removed }}"
  }
}
```

Username and password are never sent to AI (another point to PortSwigger). The
response from AI tells the recorder to enter the username.

```json
{
  "recorded_login_id": "{{ same guid }}",
  "tool_call": {
    "id": "toolu_018auKHege7thfnHrVQSsb2f",
    "tool_name": "input_text",
    "arguments": {
      "id": 154,
      "text": "USERNAME_PLACEHOLDER",
      "reason": "Entering username in the username field"
    }
  }
}
```

After that, this request goes out.

```json
POST /ai/hakawai-recorded-login-generator/api/v1/continue HTTP/2
Host: ai.portswigger.net

{
  "recorded_login_id": "b416611a-16d5-492d-8a4f-7826774dfec3",
  "tool_result": {
    "tool_id": "toolu_018auKHege7thfnHrVQSsb2f",
    "result": true
  },
  "page_description": {
    "url": "https://google-gruyere.appspot.com/{{ gruyere-instance-id }}/login",
    "title": "Gruyere: Login",
    "text": "Home Sign in | Sign up Gruyere: Login User name: USERNAME_PLACEHOLDER Password: Login",
    "interactive_elements": [
      // removed
      {
        "id": 154,
        "text": "USERNAME_PLACEHOLDER",
        "attributes": "type=text",
        "input_value": "USERNAME_PLACEHOLDER",
        "accepts_input": true
      },
      {
        "id": 160,
        "text": "",
        "attributes": "type=password",
        "input_value": "",
        "accepts_input": true
      },
      {
        "id": 165,
        "text": "Login",
        "attributes": "type=submit",
        "input_value": "Login",
        "accepts_input": true
      }
    ],
    "screenshot": "data:image/png;base64,{{ removed }}"
  }
}
```

AI tells Burp to enter the password.

```json
{
  "recorded_login_id": "{{ same guid }}",
  "tool_call": {
    "id": "tooluse_DDIbQfI0TiGlRbSCTIw67g",
    "tool_name": "input_text",
    "arguments": {
      "reason": "Entering password in the password field",
      "id": 160,
      "text": "PASSWORD_PLACEHOLDER"
    }
  }
}
```

Next request shows the entered password.

```json
POST /ai/hakawai-recorded-login-generator/api/v1/continue HTTP/2
Host: ai.portswigger.net

{
  "recorded_login_id": "b416611a-16d5-492d-8a4f-7826774dfec3",
  "tool_result": {
    "tool_id": "tooluse_DDIbQfI0TiGlRbSCTIw67g",
    "result": true
  },
  "page_description": {
    "url": "https://google-gruyere.appspot.com/{{ gruyere-instance-id }}/login",
    "title": "Gruyere: Login",
    "text": "Home Sign in | Sign up Gruyere: Login User name: USERNAME_PLACEHOLDER Password: •••••••••••• Login",
    "interactive_elements": [
      // removed
      {
        "id": 154,
        "text": "USERNAME_PLACEHOLDER",
        "attributes": "type=text",
        "input_value": "USERNAME_PLACEHOLDER",
        "accepts_input": true
      },
      {
        "id": 160,
        "text": "••••••••••••",
        "attributes": "type=password",
        "input_value": "PASSWORD_PLACEHOLDER",
        "accepts_input": true
      },
      {
        "id": 165,
        "text": "Login",
        "attributes": "type=submit",
        "input_value": "Login",
        "accepts_input": true
      }
    ],
    "screenshot": "data:image/png;base64,{{ removed }}"
  }
}
```

Then AI tells Burp to click the login button.

```json
{
  "recorded_login_id": "b416611a-16d5-492d-8a4f-7826774dfec3",
  "tool_call": {
    "id": "toolu_015P9EuahD1iuQR3ETzyU1q4",
    "tool_name": "click_element",
    "arguments": {
      "id": 165,
      "reason": "Clicking the Login button to submit the login form now that both username and password have been entered"
    }
  }
}
```

After clicking login we reach the app and Burp reports back to AI.

```json
{
  "recorded_login_id": "b416611a-16d5-492d-8a4f-7826774dfec3",
  "tool_result": {
    "tool_id": "toolu_015P9EuahD1iuQR3ETzyU1q4",
    "result": true
  },
  "page_description": {
    "url": "https://google-gruyere.appspot.com/{{ gruyere-instance-id }}/login?uid=gru_user&pw=gru_password",
    "title": "Gruyere: Home",
    "text": "Home | My Snippets | New Snippet | Upload USERNAME_PLACEHOLDER <USERNAME_PLACEHOLDER> | Profile | Sign out Gruyere: Home Refresh Most recent snippets: Cheddar Mac Gruyere is the cheesiest application on the web. All snippets  Homepage Brie Brie is the queen of the cheeses!!! All snippets  Homepage",
    "interactive_elements": [
      // removed the elements on the page
      {
        "id": 230,
        "text": "Sign out",
        "attributes": "href=/{{ gruyere-instance-id }}/logout",
        "input_value": null,
        "accepts_input": false
      },
    ],
    "screenshot": "data:image/png;base64,{{ removed }}"
  }
}
```

For some reason, AI never sends a response here and Burp cannot complete the
login sequence. I tried multiple times and it always stops here.

Video capture below. I trimmed ~15 seconds between steps.

<video controls>
  <source src="output.webm" type="video/webm">
  Your browser does not support the video tag.
</video>

# What is This Useful For?
You can build an extension to run on the 2nd instance (Burp server) and redirect
AI traffic to your endpoint. Recreate the prompts (they're obvious) and ensure
the responses are in the correct JSON format. Then you can run Burp AI flows
with your own local or remote AI instance.

Extension developers can create a simple wrapper for AI calls and let users
choose a custom instance or Burp AI. I vibecoded a helper library for this in
~15 minutes.

## Suggestion to PortSwigger
Let users configure the AI endpoint and include the prompts. The OpenAI API
(e.g., `chat/completions`) is the de facto standard so it should not require a
lot of customization. You're not in the business of selling AI compute :)

# Other Solutions
This section lists failures and ideas I didn't get to try. I am documenting them
because they might help you or me in the future.

## Other Java Proxy Settings
In 2019 I (unsuccessfully) tried to disable the Burp 2.0 update nag and went
down a similar rabbit hole. See
[Disabling Burp's Update Screen - Part 1 - Analysis and Failures][burp-update].

[burp-update]: https://parsiya.net/blog/2019-04-21-disabling-burps-update-screen-part-1-analysis-and-failures/#proxying-burp-with-burp

Run Burp with these switches. Either add them to `BurpSuitePro.vmoptions` or
pass manually:

```
-Dhttp.proxyHost=127.0.0.1
-Dhttp.proxyPort=9000
-Dhttps.proxyHost=127.0.0.1
-Dhttps.proxyPort=9000
```

JVM also has proxy settings at `.../jre/conf/net.properties`. Set
`java.net.useSystemProxies=true` to reuse system settings or define per‑
protocol values:

```
http.proxyHost=localhost
http.proxyPort=9000
https.proxyHost=localhost
https.proxyPort=9000
```

That blog also covers other hooking methods.

## Hooking
I also considered runtime hooking. Remember old Echo Mirage (if you can find a
clean copy)? `JavaJournal` by Jason Geffner is solid (I social engineered him
into hiring me at some point). See "Java Journal & Pyresso: A Python-Based
Framework for Debugging Java":

* [Slides][jj-slides]
* [Video from Oxa Recon 2016][jj-video]
* [github.com/CrowdStrike/pyspresso][jj-code]

[jj-slides]: https://www.slideshare.net/CrowdStrike/java-journal-pyresso-a-pythonbased-framework-for-debugging-java
[jj-video]: https://www.youtube.com/watch?v=-CCjruYx6Y0
[jj-code]: https://github.com/CrowdStrike/pyspresso
