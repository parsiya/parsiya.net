---
title: "Manual Context is a Bug"
date: 2026-03-31T02:55:00-07:00
draft: false
toc: true
comments: true
url: /blog/manual-context-is-a-bug/
twitterImage: 02.webp
categories:
- AI
- Soapbox
---

I wake up and read the news. Daniel Miessler has only declared my job dead three
times this week. Another frontier lab has found a bazillion bugs. Half of
LinkedIn is "SAST is dead." The war is, well. Welcome to the age of AI.

In this blog I reflect on "Manual Work is a Bug" and on how AI has changed my
workflow. I introduce the (not so novel concept) of "AI-Docs." A knowledge base
for both humans and AI. Similar to our manual knowledge base, you should not
have to manually fill the context except during the initial creation; the LLM
should have everything it needs on hand.

<!--more-->

Note: I will use LLM and AI interchangeably in this post. Please don't tell
Yann LeCun. He has 1 billion in seed funding and powerful friends.

# .nfo
I've decided to write more and more loosely. I've become this sort of influencer
wanna-be that writes "only the good stuff that gets into [tl;dr sec][tl]." Your
newsletter is super awesome, Clint, and being included is an honour, but it's
the bonus, not the goal.

[tl]: https://tldrsec.com/

I never had an online edgy teenage phase because I chose the wrong country and time
to be born in. I programmed on paper until 19 and my family got our first
computer at 25[^ph]. So please bear with me as I cosplay as a scene hacker 20
years too late.

[^ph]: I've actually written something about paper programming that I might submit to phrack.

## [greetz]
Those who made this possible:

* Me: Your illustrious host.
* Song: [Mai Yamane - Tasogare][mai].
* Book: [John Joseph Adams - Anthology - Dead Man's Hand][dead].

[mai]: https://www.youtube.com/watch?v=IhCDK_pSjnk
[dead]: https://parsiya.io/literature/bookreviews/#deadmanshand

## [anti-greetz]
New AI-Slop patterns:

* `it's not ___, it's ___.`
* `→`, the new em-dash.

# Why Should I Read This?
[Manual Work is a Bug][man] is my favorite technical post of all time. It's a
permanent link on top of the blog. I want to use LLMs to create, consume, and
cultivate clones so I fill LLM context with correct info automatically. Because
`Manual Context is a Bug`.

[man]: https://queue.acm.org/detail.cfm?id=3197520

{{< imgcap title="Image Credit: (apparently) Boyhood (2014)" src="01.webp" >}}

I was living in VS Code and wrote everything in markdown before it was cool. You
can read my few blog posts about creating clones at
https://parsiya.net/categories/clone/. This website, https://parsiya.io and a
load of wikis/docs at every job I've had are the results.

A clone is an index of knowledge for me so I don't have to remember things.
Everything I do and learn is documented. If you've worked with me (or at the
places I've worked), you've seen my work wiki.

I am not AGI-pilled (lol)[^agi]. I think LLMs are very useful at specific tasks
like summarization, and mimicking instructions (agents/skills are just
documentation). The clone can be a supercharged knowledge base for both you and
your AI.

[^agi]: Allegedly, if you want to work at one of the frontier labs, you have to be AGI-pilled, or at least pretend to be, lmao.

Whether you like this or not depends on your use case. GenAI is a great and
versatile tool. This means people will use it for a large variety of tasks and
unlike what LinkedIn says, there's no single correct way to use it.

# Rough Blueprint
We have one thing going for us. LLMs are chat bots and have been trained on
natural language so they don't really care how the documentation is
written[^gu]. Our clone can be readable to humans and still be useful
for agents.

> You're not gonna get left behind mate, it's all markdown, anyways!

[^gu]: Maybe?

This process has three steps:

1. Clone creation: Capturing knowledge.
2. Clone consumption: Retrieving and applying knowledge.
3. Clone cultivation: Refining knowledge.

## Clone Creation
Before, if I wanted to learn something, I would:

1. Search a topic.
2. Read docs/blogs and learn how to do something.
3. Document it in a series of steps.
4. Store it in my clone.

With LLMs:

1. Search a topic. Skim through the results to get a high-level understanding (this is key).
   1. Agents can search the results and do the summary for you, but I do not
      trust them until I've learned the high-level concepts to judge the output.
2. Ask AI how to do something and supply the model memory with docs/blogs.
3. Tell AI to document it.
4. Review it. Edit it manually and iterate with AI until I am satisfied.
5. Task AI to document it in the clone.

## Clone Consumption
Before, I used my knowledge base like this:

1. Search for something in the clone.
2. Read it and follow the steps.

After LLMs:

1. Ask AI a question.
2. AI searches in the clone.
3. AI summarizes the result.
4. If correct, have AI do the task or better yet, write code to do the task.
   1. Do the manual tasks myself.

## Clone Cultivation
Knowledge becomes outdated and usually I can improvise when repeating the task.
So we need to reiterate. This is generally a subset of clone creation so I will
not reiterate (har har).

# Human in the Loop
I don't just yolo write text to the clone. I am a strong believer in "human in
the loop." Users should be responsible for AI output created by them, on their
behalf, or by systems they have created. AI is a tool, not a sentient being (at
least not yet). You willed the output into existence, tag, you're it! To quote
President Truman "The Buck Stops Here."

<a id='J-dN5lwdS_9btjb0n5m3mw' class='gie-single' href='https://www.gettyimages.com/detail/515403964' target='_blank' style='color:#a7a7a7;text-decoration:none;font-weight:normal !important;border:none;display:inline-block;'>Embed from Getty Images</a><script>window.gie=window.gie||function(c){(gie.q=gie.q||[]).push(c)};gie(function(){gie.widgets.load({id:'J-dN5lwdS_9btjb0n5m3mw',sig:'brZjkG--EHb7DfbghyGm9s9XE9yNQAdFXnYudvMk-WU=',w:'300px',h:'451px',items:'515403964',caption: true ,tld:'com',is360: false })});</script><script src='//embed-cdn.gettyimages.com/widgets.js' charset='utf-8' async></script>

The internet and by proxy, infosec is flooded by AI-generated content. My
manager posted to LinkedIn about an opening on our team a few months ago. By
accident, I found this completely AI-generated article
[Your Ticket to Microsoft’s SERPENT: How to Build the Skills They're Actually Hiring For + Video][serp].

[serp]: https://undercodetesting.com/your-ticket-to-microsofts-serpent-how-to-build-the-skills-theyre-actually-hiring-for-video/

While I am thrilled to be called "elite internal red team," we're not even a red
team and the stuff mentioned in the article is, well, not really that useful
for us. I don't remember the last time I ran nmap (imagine running that on our
internal network), did XDR evasion, or created a C2.

**Moral of the story: You're responsible for stuff published under your name. I
will not read your AI-generated shit, at best I will pass it to AI to
summarize.**

# Tools and Customization
There's a growing pile of gizmos to make AI do actions and make it
"deterministic." MCP, agents, skills, and instructions to name a few. MCPs are
the future, actually no, skills are, wait, agents are the end game, just tell AI
to call the API. Who knows, maybe by the time you read this, there will be
another new hot thing.

Tip: Prune the list of MCPs. It eats into your tokens.

I use GitHub Copilot Chat in VS Code. It comes with quite a few tools via MCP. I
mostly use the built-in categories like search, edit, and url-fetch. There are,
of course, terminal commands (WSL and PowerShell) and Python.

I have a few extra tools in the instructions like using [markitdown][mm] to
convert PDF and other file types to markdown. It actually works better than I
expected even for PDFs.

[mm]: https://github.com/microsoft/markitdown

I also have [formatting instructions for markdown][mark] (click to see) when AI
is reformatting my blog. For example, I hate that AI puts an empty line between
the heading and the text like this:

```markdown
## Heading

Lorem ipsum ...
```

so I have:

```markdown
- Do not add empty lines between headings and the content that follows.
- Add one empty line between a heading and another heading or a list.
- Add one empty line between normal text and a list.
```

I also hate AI using `-` for lists and spamming **bold**:

```markdown
- **important thing**: blah blah
```

So I have:

```markdown
- Use one space after `*` or numbered list markers.
- Do not use bold text inside lists, use backticks instead.
```

I also have a skill named [refine][refine] to edit the text. I highlight the
text and then call the skill. It checks for typos, grammatical errors, and the
like.

[refine]: https://github.com/parsiya/parsiya.net/tree/main/.github/skills/refine/SKILL.md
[mark]: https://github.com/parsiya/parsiya.net/tree/main/.github/instructions/markdown.instructions.md

# The Concept of AI-Docs
But not all knowledge needs to be in the clone. Some are local to a repo. So I
create an `ai-docs` directory in the repo and store everything there.

Let's use an example. It's a stormy night and you are coding ...

## AI Needs to Learn Something
You want to use a library, but the LLM doesn't know how to use it or is not
using the latest version. This is a common practice if you're dealing with an
internal API.

Why is this a thing? LLMs have knowledge cut-off dates. Both Claude Opus 4.6 and
GPT-5.4 have knowledge cut-off dates of August 2025. Allegedly they don't know
anything after. As for internal stuff, they were not in the training data.

LLMs are great at reading instructions and mimicking them. It's what they were
made for. If you show them examples, they can "learn." We just need to give AI
access to documentation and/or example code.

1. Find the documentation.
   1. Sometimes AI knows or can guess the pattern of the URL for public libraries.
2. Start a new session.
3. Pass the URL to the LLM to read.
4. Work with AI to do the thing.

You're done, but what about next time? LLMs have no memory. I don't know why no
one has used this example yet (at least nowhere I've seen). Conversations with
LLMs are like "50 first dates." You have to send the entire conversation to the
LLM with every message. Hence, why sending "thank you" is expensive, because
it's not just sending two words but your entire conversation.

So how do we document this? 

1. Ask AI to write a document with:
   1. What the thing is.
   2. How to do the thing.
   3. Anything else it has learned.
   4. Anything else I learned.
2. Review the document and edit it (yourself + AI).
3. When you are satisfied, store the document:
   1. If it's project-specific, I add it under `ai-docs` in the same project.
   2. If not, I add to my clone repository.

This document is very personal and subject-specific. You want to create
something that is useful for you and AI the next time you have to do the thing.
Hence why you should take some time to review and edit it.

This is not a novel concept. LLM wrappers/agents can already do it for you.
E.g., GitHub Copilot Chat's [Repository Custom Instructions][repo-cust]. You can
generate "repo specific" instructions. I've not found the automatic generation
to be very useful.

[repo-cust]: https://docs.github.com/en/copilot/how-tos/configure-custom-instructions/add-repository-instructions

## I Need to Learn Something
Sometimes I need to learn something. For example, I need to use an internal
thing to create my own tool, because there are 20 new AI things at my job every
day. You find the hot new thing, generate a wrapper around it and march off into
the sunset, because we all know, the path to corporate glory is paved with new
things[^kr].

[^kr]: My boss will vehemently disagree, but we all know I am right. You're on my side, right?

I do this whole song and dance:

1. Find the thing on internal documentation.
2. Ask AI to go through it, follow the links, and "learn it."
3. Ask questions to understand what it is.
4. Finally ask AI to document the knowledge in one of two forms:
   1. Tutorial for things I need to learn more.
   2. Documentation usually in a series of steps for things I need to do.
5. Review and edit the output to make it concise and make sure it makes sense.
6. Store in my clone or the team wiki.

# How do I Get Started?
It's your clone. You are the main customer of your own clone so it needs to be
compatible with you and your workflow.

I do everything in VS Code using GitHub Copilot Chat. If I need to access
sensitive stuff, I use {{< xref path="/post/2025/2025-09-03-litellm-aad/"
   text="an OpenAI model in our own subscription" >}}, otherwise, the stuff in
the GitHub Copilot subscription does the trick. Which model? People like to use the
Claude 4.6 1M context model. I've actually gotten great results from the "free
models" like GPT-4.1 and GPT-5-Mini. We're not trying to find 0-days, we're just
trying to summarize text, which is LLM 101, not a lot of reasoning involved.

Sometimes I even use the M365 Copilot for its connections to internal data
sources. I sound like a shill, but it's actually useful. It can search in many
sources like ADO, SharePoint, and all the Office files in it. So when I wanted
to see how to file a hotel expense, it found a Word document with the exact
info.

I never got into the whole "make links between documents" and second brain stuff
like Obsidian. I don't even think the whole "context graph" thing is overblown.
Humans relate things with keywords and the simple and trusty grep does the job.

# What Did We Learn Here Today?
This was a different post, because I want to start writing for myself and not
others. But I documented how I create my clone with LLMs and how I cultivate it
so that I do not have to pass the context to the LLM and it can read it from the
repository.

Any and all feedback will be heard the 2nd Tuesday of next week. You know where
to find me.
