---
title: "On Username Enumeration"
date: 2018-05-26T21:51:48-04:00
draft: false
toc: false
comments: true
twitterImage: 01-invalid-username.png
categories:
- Enumeration
tags:
- tags2
---

Enumeration is *identifying valid resources in a target address space*. This sounds academic and I hate academic mumbo jumbo but bear with me.

Username enumeration is *identifying valid user identifiers in an application*. These are typically usernames or account IDs.

Enumeration is an interesting topic. The concept of enumeration is straightforward but not always obvious. In this post I will explain username enumeration using an example.

<!--more-->

# Login Requests and Username Enumeration
One of the easiest places to check for username enumeration (and one of the first things I check) is the login request.

Send two unsuccessful login requests, one with a valid username (and invalid password because we do not want to login) and the other with an invalid one. **Compare the responses and see if you can spot a difference**. It there is a difference then you got username enumeration.

Sometimes it's part of the business logic. For example, Google or Amazon don't care about username enumeration. You enter your username and if valid, you are redirected to password page.

Sometimes the difference in the response message is pretty obvious. Something like "this username does not exist." Often times it's a bit more subtle and there's some numeric error code that gives it away.

# The Curious Example
In this application, usernames are emails. This is pretty typical in most web application.

First I sent a login request with an invalid username. Here's the response displayed in Burp's Repeater tab.

{{< imgcap title="Response to login with invalid username" src="01-invalid-username.png" >}}

Then sent a request with a valid username and got a response.

{{< imgcap title="Response to login with valid username" src="02-valid-username.png" >}}

This two look very similar. To easily spot differences, I used Burp's `Comparer`. Right click on each, `Send to Comparer` and we can compare `by words` there.

{{< imgcap title="Comparing two responses" src="03-comparer.png" >}}

Well they are pretty much the same. The `Request-Context` is redacted from the image but the value is the same for both responses.

There is username enumeration there, it's not just as visible as it is. But don't worry, this is not some complex math. You will be able to spot it after it's pointed out forever.

## Side-Channel Attacks
Side-channels are, well side-channels. These are channels from which the system can leak information. The most popular side-channel is time. This results in timing attacks.

Apart from the request/response, Burp shows us the response time. Unfortunately, this does not show up in `Comparer`. Let's put those initial responses together and look at the response times again.

{{< imgcap title="Response difference highlighted" src="04-time.png" >}}

Login with valid username takes around 250ms while invalid usernames take 10x more around 2.5s. This can be effectively used to weed out valid/invalid usernames/emails.

# Appendix: Some Tips and Tricks
I have seen some timing attacks. I have read about others. This section shares what I have learned.

## Reducing the Address Space
**Know your address space.** Research the address space of the what you are trying to attack. If the application uses emails, random strings do not work. Emails have specific formats. Same can be said about other structured data. Credit cards are 16 digits and the first six digits are predictable based on the issuer. Last digit is the `check digit` based on the [Lunh Algorithm][luhn-wiki].

Like fuzzing, you don't want to pass invalid data. You want to bruteforce intelligently.

## Bruteforcing
Side-channel attacks and bruteforcing are very closely connected. Usually a side-channel attack allows you to bruteforce something. In this case, we are bruteforcing email addresses. Reducing the address space allows us to bruteforce much better.

Let's assume we want to bruteforce a number. If our number is an `int`, we have a much easier time compared to `float`s. Theoretically the number of *Natural Numbers* is infinity and the number of floats between two ints is the same. In action, you can only implement so many decimal and floating points. The total number of ints is lower than total number of floats.

# Conclusion
**LOOK AT THE RESPONSE TIME.**

<!-- Links -->

[luhn-wiki]: https://en.wikipedia.org/wiki/Luhn_algorithm

