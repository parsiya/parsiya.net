---
title: "Tiredful API - Part 2 - Comparing Site Maps with Burp"
date: 2018-12-17T01:11:11-05:00
draft: false
toc: true
comments: true
twitterImage: .png
categories:
- Burp
- Writeup
---

In [Part 1 - Burp Session Validation with Macros]({{< relref "/post/2018-12-11-tiredful-api-1/index.markdown" >}} "Burp Session Validation with Macros") I discussed using Burp macros to validate sessions. In this part, I will show how to use Burp's sitemap comparison to detect forced browsing/access control/direct object reference issues and the like.

The flow is straightforward:

1. Navigate around the application as user1. Personally, I just do my normal testing for a couple of days.
2. Set a session handling rule to do one of the two:
   1. Update the cookie from the cookie jar. In this case you login as user2 first and let Burp update cookies.
   2. Run a macro to create a valid session for user2 and use the token.
3. Tell Burp to compare site maps.

Also, read these:

* https://portswigger.net/burp/documentation/desktop/tools/target/site-map/comparing
* https://support.portswigger.net/customer/portal/articles/1969844-using-burp-s-site-map-to-test-for-access-control-issues

<!--more-->

# Exams - Insecure Direct Object Reference
In the test API, `Insecure Direct Object Reference` lists the API call for viewing exams. Results can be retrieved with a GET request (our endpoint is `192.168.99.100:8000`):

* `http://192.168.99.100:8000/api/v1/exams/{{ exam_id }}/`

where `exam_id` is a base64 encoded number. Exams `MQ==` (1) and `Mg==` (2) belong to Batman. There's no access check and we can see any exam results by directly referencing its ID as Superman.

The solution to this exercise is trivial. We can solve it with Intruder and going through exam IDs 1 to 100. The only trick is to base64 encode the payload with a rule under `Intruder > Payload Processing`.

{{< imgcap title="Payload processing rule" src="01-encode-rule.png" >}}

# Using Site Map Comparison

1. Modify the old Batman (user1) session handling rule to include Burp's "Proxy."
2. Navigate to Batman's two exam results.
3. Create a second macro to login as Superman (user2).
4. Compare sitemaps.

## Login Macros
Login macros are the same as [part 1]({{< relref "/post/2018-12-11-tiredful-api-1/index.markdown#login-macro" >}} "Login Macro"). This macro logs in as Batman and gets the authorization token.

{{< imgcap title="Login as Batman macro" src="02-login-as-batman-macro.png" >}}

We will make a similar one for Superman.

## Session Handling Rules
We will reuse the session handling rule from [part 1]({{< relref "/post/2018-12-11-tiredful-api-1/index.markdown#session-validation" >}} "Session Validation") with one modification:

* Under `Scope` (in the session handling rule editor), check `Proxy (use with caution)`. This will apply the rule to the requests coming from the browser. Unlike Repeater, we will not see the updated request in history.

{{< imgcap title="Add Proxy to scope of session handling rule" src="02-session-handling-scope.png" >}}

Make a second one for Superman named `superman-session` and disable it.

## Setup Scope
Scope is the same as before.

Include:

* http://192.168.99.100:8000

Exclude:

* http://192.168.99.100:8000/oauth/token/
* http://192.168.99.100:8000/oauth/revoke_token/

{{< imgcap title="Scope" src="03-scope.png" >}}

## Add Custom Header
If you are running Burp free (like me in this example), the settings for the `Add Custom Header` extension have most likely reset. Go back and set them correctly. The magic string is `access_token": "(.*?)"` (note the space after `:`).

{{< imgcap title="\"Add Custom Header\" settings" src="04-extension.png" >}}

## Cleaning Site Map
Obviously, we do not do this step in a real engagement but I want to have a clean slate here.

1. Navigate to `Target > Site map`.
2. Click on the `Filter` bar and click the `Show All` button. This will show everything.
3. Select all hosts and delete them.

## Browsing Exams
Double-check:

* Session handling rules are working.
* `batman-session` is enabled and `super-session` is disabled.

Navigate to these URLs in browser:

* http://192.168.99.100:8000/api/v1/exams/MQ==/
* http://192.168.99.100:8000/api/v1/exams/Mg==/

Both belong to `user: 1` who is `Batman`.

## Comparing Site Maps

1. In `Project Options > Sessions > Session Handling Rules`, disable `batman-session` and enable `superman-session`.
2. Right click on `192.168.99.100:8000` and select `Compare site maps`.
3. A new window opens up. Free edition does not support using other projects or states. Our only choice is `Use current site map`.\\
   {{< imgcap title="Use current site map" src="05-compare-1.png" >}}
4. Keep `Use all items with responses` (in a real engagement, you might want to select `Use only selected branches`) and check `Include in-scope items only` (remember I excluded login/logout from scope).\\
   {{< imgcap title="Include settings" src="06-compare-2.png" >}}
5. No choices here.\\
   {{< imgcap title="Select source" src="07-compare-3.png" >}}
6. The rest of the screens have a lot of options for performance and matching requests/responses. Let's not worry about them and go with default values.
7. And it's working.

{{< imgcap title="Site map comparison results" src="08-sitemap.png" >}}

We can access both exams with both users. It should not be the case.

The only difference between the requests is the authorization header in the Superman session. This happened because the headers are not added to the requests in `HTTP History` but the default settings tell Burp to ignore request headers.

# Conclusion
Someone recently asked me about this, so I decided to write about it. There you go `Reviewer #2`, I did my duty.