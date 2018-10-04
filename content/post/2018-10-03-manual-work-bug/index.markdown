---
title: "Reflections on \"Manual Work is a Bug\""
date: 2018-10-03T00:48:17-04:00
draft: false
toc: false
comments: true
twitterImage: .png
categories:
- Not Security
- Clone
tags:
- Automation
---

I recently read [Manual Work is a Bug](https://queue.acm.org/detail.cfm?id=3197520) by Thomas A. Limoncelli. It's a great article in my opinion. I realized I had been doing some of what it mentions.

If you know me, you know I am a great fan of knowledge bases or `clones` as I call them. I have my own external clone at [parsiya.io](http://parsiya.io). It's also somewhat [automated]({{< relref "/post/2018-04-25-pain-free-cloning.markdown" >}} "Semi-Automated Cloning: Pain-Free Knowledge Base Creation"). I have had an internal one for more than two years.

But the automation was not what rhymed with me. It was the documentation.

<!--more-->

> The first time he did something manually, he documented the steps. That may not be code in the traditional sense, but writing the steps in a bullet list is similar to writing pseudocode before writing actual code. It doesn't run on a literal computer, but you run the code in your head. You are the CPU.

This is what I loved about the article. I write steps that I can later follow mindlessly, this helps when I am strapped for time (hint: always).

I code but I am not a developer. I also do a lot of non-development activities but I am not a sysadmin either. As a security consultant, I am something in between. I am usually on short-term projects (think 2-3 weeks max) so I do a lot of context switching when starting/finishing projects. These usually take a lot of time and it's in my incentive to automate them as much as I can.

## How I Cloned Myself
Around two years ago, I started documenting my knowledge and troubleshooting solutions in an internal git repository. Using the web interface to render markdown files (and images) was ideal since I could also store code besides them. I started calling it `Parsia-clone`.

Every time one of the following happened, I added them to the clone:

* Solved a problem during a test.
* Learned something.
* Someone asked a question.

I am not going to hide that part of the incentive was being selfish. I get a somewhat distracting amount of questions. Now I just send people to my clone. Sometimes it takes care of the problem and if not, it buys me some time to finish what I am doing at that time.

## Clone Maintenance
The most boring part of the clone was maintaining the index. This was fixed when I moved it to an internal CMS. The CMS takes care of the index. I did a similar thing with my external clone at [parsiya.io](http://parsiya.io). Instead of using Github and having to manually update the index in the main `README.md`, I use a modified Hugo theme to generate the index.

I have given myself 3 hours a week (mainly on Fridays or over the weekend) for clone maintenance. The basic automation that I have done saves me more than that per week. During this time, I add anything I have learned, add new topics, or just do general clean-up. A clone is not a one-time thing, it needs to be kept updated. Maintain it, but do not fuss over it.

## Lessons Learned
True to my word, I need to document what I learned from the article.

* **Automate everything you can**, even if it's just a series of manual steps in your documentation with a bunch of code snippets. Let your mind be the CPU. Follow these directions and improve them when you can.
* **Use an existing platform** for documentation (e.g. git or confluence or whatever). Use whatever exists.
* **Stop the glorification of bash/PowerShell one-liners**, pick a typed programming language for automation (Hint: Go).
    * On a side note: Stop the editor wars. Who cares what you use? I use VS Code and I am happy.
* **Don't automate all the easy parts**, otherwise, the hard parts will remain. Automate the boring and repetitive parts. Keep some easy parts for human (similar to handlers letting rescue dogs some corpses when they do not find one for a while, humans also need to feel they are accomplishing something).
* **Do not obsess about automation**. Convert these automation steps to self-service programs if only it makes sense.
