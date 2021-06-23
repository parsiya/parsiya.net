---
title: "Semgrep: The Surgical Static Analysis Tool"
date: 2021-06-22T18:42:06-07:00
draft: false
toc: true
comments: true
twitterImage: .png
categories:
- Automation
- Soapbox
---

# Why are We Here?
What this blog is about:

1. Why I like Semgrep.
2. Why I think you should use it.
3. How I use Semgrep.

What this blog is not about:

1. What static analysis is.
2. Semgrep tutorial.

<!--more-->

# Static Analysis In The Real World
I look at many different things at my day job. Every game we release (on seven
distinct hardware platforms), game engines, desktop apps for multiple operating
systems, `surprise mechanics`, and more. That's a lot of code!

{{< blockquote author="Douglas Adams" source="The Hitchhiker's Guide to the Galaxy" >}}
Space is big. You just won't believe how vastly, hugely, mind-bogglingly big it
is. I mean, you may think it's a long way down the road to the chemist's, but
that's just peanuts to space.
{{< /blockquote >}}

This is a lot different from the advice of appsec thought leaders. Like, we
cannot even go through all of our code, let alone "audit 3rd party libraries."

How do I sift through all this code? With ~~static analysis tools~~ grep.

## Just Use grep
Ironically, `grep` (or [ripgrep][ripgrep]) is the best static analysis tool in
my arsenal. I have found 90% of my bugs in code with `grep` and IDE/editor code
navigation (e.g., click on a function in VS Code to go to its definition or see
its references) rather than a static analysis product.

[ripgrep]: https://github.com/BurntSushi/ripgrep

`grep` has its limitations. It's a text analysis tool. Let's say I want to
search in code for an imaginary bad function named `exec`.  grep does not
differentiate between `exec` as a function, variable, string, or comment. A
workaround is to grep for `exec(` (or a regex that takes into account the
allowed whitespace between `c` and `(`).

But, what if this function has multiple overloads and I am only looking for one
that uses two parameters (or specific types of parameters). `grep` doesn't
understand context. If you have ever tried to parse structured text (e.g., code)
you probably know what a dumpster fire it is. Once I tried to parse markdown
with regex and it did not end well.

# Enter Semgrep
With Semgrep I can specify which kind of `exec` should be found.
[Semgrep][semgrep.dev] is a fantastic piece of technology. I am not gonna write
a tutorial. Start at [https://semgrep.dev/learn][semgrep-tutorial] and view any
of [Clint's][clint-twitter] presentations about it.

[semgrep.dev]: https://semgrep.dev/
[semgrep-tutorial]: https://semgrep.dev/learn
[clint-twitter]: https://twitter.com/clintgibler

## Semgrep is Bean from Ender's Game
If you have read `Ender's Game` you probably remember Bean. Turns out Bean is a
mutant (and super smart) in `Ender's Shadow`. In the original book Ender
describes him as:

{{< blockquote author="Orson Scott Card" source="Ender's Game" >}}
Bean, who couldn't control large groups of ships effectively but could use only
a few like a scalpel, reacting beautifully to anything the computer threw at him
{{< /blockquote >}}

That's Semgrep. Why? Glad you asked.

> Semgrep does a few things and does them pretty well.

## The Good

1. Easy-to-write rules.
2. Doesn't need buildable code.
3. Not tied to a platform.
4. Great team and community.

## The Bad
I can live with both of these, these might be deal-breakers for you.

1. Works per file so some issues cannot be detected without false positives.
2. C++ is not supported. I don't blame them. C++ is a nightmare.

# Scaling: The Application Security Endgame
Semgrep is a means to help with the endgame of appsec. **Scaling**. There are
tons of thought leadership articles about scaling but in my opinion as a product
security engineer, it boils down to:

1. Create secure defaults.
2. Involve dev teams in security via security champions.
3. Deploy automated tooling.

How does Semgrep help with this? Let's look at its positives from above.

## Easy-to-Write Rules
You should read [Manual Work is a Bug][manual-work-bug] if you haven't already
(it has changed my professional life). It describes the last phase of automation
as `self-service and autonomous systems`. If we can have the dev teams write
their own rules and experiment we have reached this phase.

[manual-work-bug]: https://queue.acm.org/detail.cfm?id=3197520

Semgrep is great for this purpose. The rules look similar to the code pattern
you are looking for. This is intuitive for devs.

Things like CodeQL on the other hand are not great for this purpose. Don't get
me wrong. CodeQL is powerful but it's hard to learn. You have to invest a lot of
time into it. Maybe it works for software giants like MSFT who have dedicated
teams but not us. Asking devs to learn this new language to use our expensive
and fancy tool is a recipe for disaster.

This also allows us to create secure defaults. Clint explains it a lot better
than me in [Embrace Secure Defaults, Block Anti-patterns, and Kill Bug
Classes with Semgrep][enable-secure-defaults].

[enable-secure-defaults]: https://www.youtube.com/watch?v=GoeONtFx0bA

## Doesn't Need Buildable Code
Some static analysis products require you to build the code. They need to
observe the build process to do all their fancy things (e.g., taint analysis).
This is great but doesn't work for me.

Building the code is a pain in the neck. If you have ever done a 3rd party
security engagement you know what I am talking about. If by some very lucky
accident you get code (even when it's a source code review engagement), it's
just a snapshot of the code without build instructions or the dependencies.
Chances are there are internal dependencies you cannot pull access.

The hardest part of "videogame preservation" is not storing the source code.
It's creating and maintaining a snapshot of the build environment. Look,
video games are built with magic talismans and offerings to Gods. I cannot just
run `npm install`.

> Shit's hard, yo!

Semgrep works on one file at a time. It loses some capabilities. For example, it
cannot detect if a constant string is defined in another file. But, it also
gains a lot of speed (files can be processed in parallel), and more importantly,
we do not need to build the code.

How can Semgrep help the dev teams? An excellent Semgrep injection point is
running on the merge request review. We can run it on the modified/new code. If
we do not need to build the code we can:

1. Run Semgrep on the code quickly.
2. Break the build if some really bad thing happens. **Be very very frugal with this.**
3. Add the results as a comment to the request. Now, the results can be reviewed
   as part of the code review process because it's just there.

## Not Tied to a Platform
Semgrep is open source (but buy their cloud stuff if you can, they have pretty
nifty features there). We can run it everywhere we can run a command-line tool
or via a docker container. We don't have to pay for it or buy a specific
platform (e.g., CodeQL and GitHub enterprise).

But, Parsia, don't you use GitHub? Git in the videogame industry? Good joke!

## Great Team and Community
Look, I like these folks. I am a fan. But, seriously, every time I have had a
question, the Slack channel has been super helpful. Join their Slack and see
what's up.

The community contributes a lot of rules. See them at
https://semgrep.dev/explore or https://github.com/returntocorp/semgrep-rules.
There are also some 3rd party rules from smart folks like `Trail of Bits` at
https://semgrep.dev/p/trailofbits. This is enabled by the team helping people
along the way and the easy rule syntax.

# Important Semgrep Thought Leadership!
By now, I have hopefully hyped you up to start using Semgrep. Let's talk about
how to use it.

## How Many Rules Should I Have?
**TL;DR: Start small and keep it simple.** You want to have and add a few rules
at a time.

1. Target one single vulnerability.
2. Write a couple of high-impact rules with few false positives.
    1. These are usually anti-patterns that result in vulnerabilities in custom
       frameworks/technologies.
3. Pass the results to the developers to get them fixed.
4. Write guidance for these issues. E.g., `don't do X, do Y`.
5. Rinse and repeat.

[Adrian Stone][adrian-twitter] was the head of my organization at EA (currently,
CISO at Peloton)." We were talking static analysis and he said (paraphrasing)
"if your tools finds something then you are on the hook for triaging it,
recommending a fix and then chasing down the fix." And he is right.

[adrian-twitter]: https://twitter.com/adrian_stonez

The dominant mentality in the static analysis world is the complete opposite. I
mean, they want to detect everything. What does happen if I throw the kitchen
sink at a game's code (remember, it's a lot of code)?

1. Find hundreds of issues.
2. Triage each one.
3. Prioritize and write up valid bugs.
4. Find and write recommendations for each bug.
5. Send it to the developers.
6. Chase down the fixes (developers, understandably have different priorities).

Your devs will hate you!

**Remember: Don't break the build except as a last resort.**

## Where Should I Use Semgrep?
Everywhere you have code but, as I mentioned above, I like to run Semgrep on
merge requests and add the results as a comment to the request. I have written
my own custom code to do this. Here's a public example:

* https://www.abhaybhargav.com/building-a-diy-automatedpull-request-static-analysis-workflow-with-gitlab/

The new [integration with GitLab][semgrep-gitlab] was just announced and it
automagically [comments on merge requests][semgrep-gitlab-mr].

[semgrep-gitlab]: https://r2c.dev/blog/2021/introducing-semgrep-for-gitlab/
[semgrep-gitlab-mr]: https://semgrep.dev/docs/notifications/#gitlab-merge-request-comments

# What Did We Learn Here Today?
Semgrep rocks! You should use it.
