---
title: "Tiredful API - Part 1 - Burp Session Validation with Macros"
date: 2018-12-11T00:15:07-05:00
draft: false
toc: true
comments: true
twitterImage: .png
categories:
- Burp
- Writeup
---

[Tiredful API](https://github.com/payatu/Tiredful-API) is an intentionally vulnerable REST API. I am going to use it to practice a bunch of Burp tricks.

In this part, I want to show how to use Burp macros to detect invalid session and add a custom bearer token header to the requests.

* Session validation with Bearer tokens.

<!--more-->

I used the instructions to spin up a [docker container][tiredful-docker] and used it with the free Burp Community Edition 1.7.36.

# Session Validation Using Macros
Often times the session times out in the middle of testing or scanning. I only use Burp's scanner on individual requests but session can still time out. Sometimes the application log users out after sending funny payloads. Burp allows you to detect invalidated sessions and run a macro (which is a series of requests) to update the session automagically.

Usually, the session is maintained by cookies and Burp's cookie jar can be automatically updated to refresh the session. In the case of this API, we are using a Bearer token. But this method can be used for any custom header containing a token.

## Login Request
The login request is simple. While this example has only one request, the process for multiple-step requests is similar. The application has two registered users. We are using `batman:Batman@123`.

{{< imgcap title="Successful login request" src="01-login.png" >}}

The `access_token` must be added to every authenticated request like `Authorization : Bearer [token]`.

## Invalid Session Response
We also need to detect invalidate sessions. To do so, navigate to http://192.168.99.100:8000/api/v1/advertisements/ to see the response.

{{< imgcap title="Invalid request" src="04-invalid-session.png" >}}

We are going to use the header `401 Unauthorized` to detect invalid requests.

## Login Macro
We should create a login macro to login as `batman`. This macro will be executed when Burp detects an invalid/expired session.

1. Go to `Project Options > Sessions` and scroll down to `Macros`.
2. Select `Add` to create a new macro. Macros are created from existing requests.
3. Select a successful login request (for multi-step logins, select all steps in the login flow) and press `Ok`.
{{< imgcap title="Selecting the login request in macro recorder" src="02-macro1.png" >}}
1. Select a name and press `Ok` in `Macro Editor` to create the macro. If the request had specific parameters (e.g. a CSRF token), we could designate it in `Configure item`. This example does not need it.
{{< imgcap title="Finish macro recording" src="03-macro2.png" >}}

## Session Validation
We need to make Burp perform two action:

1. Create a session handling rule. Burp should run the macro whenever a session is invalid.
2. Add the `access_token` as a custom header to that request and resend it.

### Add Custom Header Extension
In order to accomplish number two, we need to use an extension. Burp vanilla does not support adding headers to requests in session validation rules. However, cookies and normal GET/POST parameters (e.g. `form-urlencoded` ) can be updated.

1. Install the `Add Custom Header` extension at https://github.com/lorenzog/burpAddCustomHeader. It's also available in the Burp App Store.
2. Navigate to the `Add Custom Header` tab. It's pre-populated with some sane defaults.
3. The original regex is `access_token":"(.*?)"`. The underline does not show up in the input field but you can click on `Update Preview` to see it.
4. We need to change the regex. Our response is a bit different. Ours has an extra space after `access_token":`. Our regex will be `access_token": "(.*?)"` instead.
{{< imgcap title="Add Custom Header setup" src="08-add-custom-header.png" >}}

### Session Handling Rule

1. In the same screen (`Project Options > Sessions`) click `Add` under `Session Handling Rules`.
2. Type in a rule description. E.g., `session-validation`.
3. Under `Rule Actions` click `Add` and select `Check session is valid`.
{{< imgcap title="Session validation rule - 1" src="05-session-rule-1.png" >}}
4. In the next screen, select `Issue current request` under `Make request(s) to validate session`. This tells Burp to modify the same request with the new header and resend it.
5. Under `Inspect response to determine session validity`, select `HTTP headers` and enter `401 Unauthorized` in the `Look for expression` field. This section determines how Burp detects invalid sessions. We are telling Burp that the session is invalid if `401 Unauthorized` appears in the response header.
6. Keep the rest of the options. We want exact match and case-insensitive.
7. `Match indicates` must be set to `invalid session`. We are telling Burp how to detect invalid sessions after all.
{{< imgcap title="Session validation rule - 2" src="06-session-rule-2.png" >}}
8. Under `Define behavior dependent on session validity` check `If session is invalid, perform the action below`, check `Run a macro` and select the login macro.
9. Uncheck both `Update current request` boxes (doesn't matter in this example, we are not using cookies or parameters).
10. And finally, check `After running the macro, invoke a Burp extension action handler:` and select `Add Custom Header`. Response of the last request in the macro is passed to `Add Custom Header`. The extension extract sthe token using the regex (remember the match group) and adds it as a header to the request.
{{< imgcap title="Session validation rule - 3" src="07-session-rule-3.png" >}}
11. Press `Ok` and we're back at the first screen. Now we need to select the scope.
12. Click the `scope` tab and select any tool that needs this rule under `Tools Scope`. We will go with the default.
13. Under `URL Scope` select `Use suite scope`. We will set it later.
{{< imgcap title="Setting scope" src="09-session-rule-4.png" >}}

### Alternate Session Handling Rule
Instead of detecting the session, we can use an easier rule and run the macro and add the header to every request. I went with the more complicated process because I wanted to practice setting it up.

1. The alternate rule is the same in every aspect, except the `Rule Actions` which is `Add (button) > Run a Macro`.
2. Select the macro.
3. Uncheck both update checkboxes.
4. Enable `After running the macro` and select `Add Custom Header`.
{{< imgcap title="Alternate rule" src="10-alternate-rule.png" >}}

### Setting the Scope
In this example, we do not have to set the scope. But usually, we want to only operate in a specific scope. In my VM, the address is `http://192.168.99.100:8000` so I added it in `Target > Scope` tab. I also excluded the login and logout API endpoints.

{{< imgcap title="Scope" src="11-scope.png" >}}

## Burp in Action
Now it's time to see the fruit of our labor. Right click the request to `http://192.168.99.100:8000/api/v1/advertisements/` in Burp history and send it to Repeater. Click `Send` and see the header added to the request and get a valid response. It's empty but it's valid.

{{< imgcap title="Burp in Action" src="12-burp-in-action.gif" >}}

Tune in for the next section, where I talk about using Burp's sitemap comparison.

<!-- Links -->
[tiredful-docker]: https://github.com/payatu/Tiredful-API#docker-container
