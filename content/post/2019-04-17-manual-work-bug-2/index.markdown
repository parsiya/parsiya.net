---
title: "The Dark Side of \"Manual Work is a Bug\""
date: 2019-04-17T19:12:33-07:00
draft: false
toc: false
comments: true
twitterImage: jedi-fallen-order.jpg
categories:
- Not Security
- Clone
- Automation
---

This is a revisit of [Manual Work is a Bug](https://queue.acm.org/detail.cfm?id=3197520)
during my ramp up at my [new job](https://twitter.com/CryptoGangsta/status/1109185306295746563).
I will discuss my experience doing some automation at my previous job and the
flip side to the utopia painted by the article.

<!--more-->

{{< imgcap title="Your technical debt" src="jedi-fallen-order.jpg" >}}

- [Why The Revisit?](#why-the-revisit)
- [Time, It Needs Time, To Win Back Your Love Again](#time-it-needs-time-to-win-back-your-love-again)
- [But Automation Gives You Time](#but-automation-gives-you-time)
- [Should Everyone Automate?](#should-everyone-automate)
- [What Did We Learn Here Today?](#what-did-we-learn-here-today)


## Why The Revisit?
I discovered the article last year. I love it. You can read my initial observations in
[Reflections on "Manual Work is a Bug"]({{< relref "/post/2018-10-03-manual-work-bug" >}} "Reflections on \"Manual Work is a Bug\"").

Recently, I left my job after almost six years (70 months to be exact).
By the end, I had automated some of my weekly routines and had this huge
knowledge on the internal network called `Parsia-Clone` (it dwarfs my external one).
We had this running joke that the clone will become sentient one day and do my job.

I realized I have forgotten why I made some important decisions and why I was
doing things a certain way.

Most importantly, I had forgotten the pains. I was in the happy phase of the
process where my automation had given me free time. About one day every two
weeks (sometimes every week) I sat down, documented what I had learned and
performed maintenance.

With a clean slate:

* I can do some things better this time.
* I can adapt my routine to our processes here.
* I can think about why I made some decisions.
* I have time to do stuff.

## Time, It Needs Time, To Win Back Your Love Again
Having time. That's kind of important. And that is my biggest issue with the
original article. It tells the tale of two sysadmins. Both are busy, intelligent
and can write code.

> Let me tell you about two systems administrators I know. Both were overloaded,
> busy IT engineers.

But they do things differently

> The successful person had the same pressures but somehow managed to write a lot of code.

**Stop! Hammertime!**

Both sysadmins are overworked and under pressure but one (let's call them The Automator)
manages to write a lot of code/documentation.

* How does The Automator find the time?
* Can they even manage to finish assigned work? 

Remember both sysadmins are already overloaded.

Writing documentation/steps/code takes time. A lot of time. Especially when you
are just starting and getting into the mindset. Even format and medium is a huge
timesink. Hint: Your corporation probably has something like Confluence.

The time has to come from somewhere.

* Work time: You are likely overloaded, you do other stuff instead of your job.
* Personal time: RIP work/life balance.

So The Automator most likely:

* Got fired because they wrote documentation instead of closing tickets.
* Burned out because they worked after hours.

I was the second person. I worked long hours and almost burned out. People with
family and obligations cannot do this and let's be honest, no one should.

**Even the mythical Russian build engineer had this problem.** \\
The myth started in [bash.im][bash.im]. Read the translation at [jitbit][jitbit].
It's about this legendary Russian build engineer who had [scripts][hacker-scripts]
for everything. For example, one:

> sends a text message "late at work" to his wife (apparently). [...]
> The job fires if there are active SSH-sessions on the server after 9pm with his login.

Seems like even automation legends overwork. Our ideal person is someone who has
automated his excuses for working long hours. SAD!

## But Automation Gives You Time
Sure it does, it's most likely a net benefit in the long run. Automation will
give you some free time to do more automation (well, hopefully).

But The Automator probably had no life for a while (assuming not fired).

## Should Everyone Automate?
Each person needs to figure out if it's worth the time and energy.

Ask yourself the following questions:

* Can things be automated?
  * This is important, not everything can/needs to be automated.
* Do you have the extra time?
* Do you like doing it?
  * It shouldn't be a hassle and a second job.
* What do you get out of it?
  * Does corporate care?
  * Does it help you and other people?

There's also the option of automating your job but not sharing it. See the
following urban legends:

* [Is it unethical for me to not tell my employer I’ve automated my job?][automated-stack-exchange]
* [Finally fired after 6 years - reddit][fired-after-six-years]

## What Did We Learn Here Today?
The original article is nice but it glossed over a very important part of the
process and let's say its Achilles' heel.

Starting and continuing automation has a very significant time investment. This
time has to come from somewhere. Either you get it through your corporation
(congrats, you and me are some of the very few lucky ones) or it comes out of
your time.

<!-- Links -->
[manual-work-link]: https://queue.acm.org/detail.cfm?id=3197520
[automated-stack-exchange]: https://workplace.stackexchange.com/questions/93696/is-it-unethical-for-me-to-not-tell-my-employer-i-ve-automated-my-job
[fired-after-six-years]: http://archive.is/uW2OK#selection-1779.0-1779.27
[bash.im]: https://bash.im/quote/436725
[jitbit]: https://www.jitbit.com/alexblog/249-now-thats-what-i-call-a-hacker/
[hacker-scripts]: https://github.com/NARKOZ/hacker-scripts

