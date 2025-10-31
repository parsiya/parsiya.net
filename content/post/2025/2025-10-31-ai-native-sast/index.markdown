---
title: "WTF is ... - AI-Native SAST?"
date: 2025-10-31T01:00:00-07:00
draft: false
toc: true
twitterImage: 05.webp
url: /blog/wtf-is-ai-native-sast
categories:
- AI
- Static Analysis
---

Ladies and gentlemen, my name is Parsia and I'm here to ask and answer one
simple question: WTF is AI-Native SAST? (RIP TotalBiscuit).

Spoiler: It's SAST+AI. But that doesn't make it useless. Quite the opposite,
I'll make the case for passing all your code to AI while tokens are cheap. Don't
believe the marketing, though. Current LLMs need serious hand-holding to go
beyond surface-level bug discovery, and that hand-holding comes from static
analysis.

<!--more-->

Disclaimers: Not related to or endorsed by past, present, or future employers.

# The Promise (Or the Premise)
You've seen it, read it. The world has changed forever. Those other SAST tools
are bad; our AI-Native tool can replace all your tools and engineers. "Are we
gonna lose our jobs?" I yelled as I jumped like a maniac into the XBOW huddle at
DEF CON.


I get lots of marketing emails like this. First, I have no purchase authority,
besties. Second, "Gentlemen, you can't fight in here! This is LinkedIn!" Tag
your competition on Twitter and insult them directly instead of my inbox.

A few weeks ago I read this excellent blog,
[Hacking with AI SASTs: An overview of 'AI Security Engineers'/'LLM Security Scanners' for Penetration Testers and Security Teams][bl]
(Joshua, could I possibly interest you in shorter titles?). It's a hands-on
comparison of multiple SAST+AI tools and a great primer on getting started in
this space.

[bl]: https://joshua.hu/llm-engineer-review-sast-security-ai-tools-pentesters

Instead of passing that blog to an LLM and asking it to rewrite it in my style
like the norm these days, I want to explain what _I_ would do to create a new
static analysis tool in "the age of AI." But first, you need to sit through some
of my rants. Because if you cannot handle my rants, you do not deserve my
thought leadership (lol).

# Why You Should Try SAST+AI!
If you know me, you know I love static analysis. For employment reasons, I'm
obligated to say I also love AI and dream of adding Copilot to Windows
Calculator. I've been disappointed in the SAST+AI space. I don't mean the people
"with AI in their Twitter bio" (grifters gonna grift), but actual static
analysis companies are doing, well, not much?!

We need progress in this space while VCs throw money at AI. In my opinion, if
you are interested in static analysis you should experiment with AI because:

1. The Price is Right! Tokens are heavily subsidized right now.
2. This might be your only chance to run AI tools on all your code.
3. We need AI to review all this AI-generated code.
4. AI can catch bug classes that are hard to detect with traditional SAST.

The hype is useful. Convince your employer to let you review all your code with
AI. You won't get this chance again. Run it before they start caring about costs
(not legal advice).

{{< imgcap title="Boss can AI review all of our code?" src="06.webp" >}}

Companies claim X% of their code is AI-generated. There's a tsunami of
AI-generated code. Our only chance to secure it is more AI!

{{< imgcap title="The only thing that can stop bad AI-generated code is good AI-generated code" src="01.png" >}}

Image credit: By Unknown author - Chrysopoea of Cleopatra (Codex Marcianus graecus 299 fol. 188v), [Public Domain from wikimedia][img1-credit]

[img1-credit]: https://commons.wikimedia.org/w/index.php?curid=36915535

## Complementing Traditional SAST
Traditional static analysis has been historically bad at catching some bug
classes like authorization and business logic issues. AI is promising here.
Sometimes AI can understand the code's intent. In other words, you explain what
the code needs to do and ask AI "chat, is this true?"

In other words, I do not believe current AI-native SAST products are a direct
replacement. Here's another simple question: are you catching all I catch with
Semgrep, CodeQL, and more? I have hand-crafted artisanal Semgrep rules (lol) and
a treasure trove of CodeQL queries at my disposal. I am not being adversarial;
it's completely OK to create a product to fill those gaps instead of doing
everything.

# What Hurdles Await You!
I've hyped AI up like a prompt engineering course hawker, now listen to my AI
H8R side.

## Cost
Tokens are cheap, but not that cheap. Human-generated code still dwarfs
AI-generated code. "There's a lot of software out there, Parsia! More
repositories than stars in the sky!"

{{< imgcap title="Paraphrasing princess Kahm from Outlanders" src="03.webp" >}}

Recently, I read [Secret Detection Tools Comparison][sec] by FuzzingLabs. While
I'm impressed by LLMs, look at the run times. GPT-5 mini took more than 10
minutes to find 32 secrets! This is not "web scale" (lol). While AI processed
one log file, 10 more were added to the backlog.

[sec]: https://github.com/FuzzingLabs/fuzzforge_ai/blob/master/backend/benchmarks/by_category/secret_detection/results/comparison_report.md

## Context Rot
Models advertise longer context windows and users think it's a good thing,
right? Wrong. Initial tokens are more important. You can feel this in
conversations. The AI forgets older prompts and data.

{{< imgcap title="Older tokens, saluting goodbye!" src="04.webp" >}}

Image credit: My Hero Academia manga, chapter 333.

I read two studies recently that deal with this phenomenon. Even when the model
advertises a large context window, you need to get things done within the first
few 10K tokens. So while we can fit entire projects or modules into a context
window, the model won't actually understand all of them.

1. [Evaluating Long Context (Reasoning) Ability][ct-1]
    1. "What do 1M and 500K context windows have in common? They are both actually 64K." lol.
2. [Context Rot: How Increasing Input Tokens Impacts LLM Performance][ct-2]

[ct-1]: https://nrehiew.github.io/blog/long_context/
[ct-2]: https://research.trychroma.com/context-rot

## Non-Determinism
Half the industry's effort goes into making LLMs deterministic. Prompts,
instruction files, context management, MCPs, and now skills all try to rein in
this non-deterministic beast and fix its Gene Wolfe level of unreliability. This
hits hard in code reviews where AI gives different answers depending on the time
of day. It's funny that I have to run it multiple times to get consistent
answers.

# A Blueprint for SecurityTooling+AI?!
Enough soapboxing, let's talk solutions. Why say cliches like "POC||GTFO" when
you can quote [Saadi][saadi-wiki]?

> عالم بی عمل به چه ماند؟ به زنبور بی عسل
>
> What a scholar without practice resembles? A bee without honey.
> - Saadi Shirazi. Golestan. Chapter 8: On Rules for Conduct in Life. Maxim 74[^ft-maxim].

[^ft-maxim]: For some reason this maxim is numbered 74 in the Persian version and 50 in English translations.

[saadi-wiki]: https://en.wikipedia.org/wiki/Saadi_Shirazi

Here's my proposed blueprint for SAST+AI.

## Ingredients
We pass one or ideally all of these to AI:

1. Main input: The data we're examining.
2. Prompt: How we set the objective.
3. RAG: Extra information passed to the model.
4. Context: More information about the input itself (not the AI context).

Note that RAG and context are different. RAG contains general information about
the vulnerability class we're hunting. Context provides specifics about the
input like surrounding code.

We can apply this paradigm (using big words now) to DAST (Dynamic Application
Security Analysis), fuzzing, and probably other security domains. Jason Haddix's
article [Building AI Hackbots, Part 1][jh1] is about DAST and a great read for
making "XBOW at home." We can learn from it and use it in SAST.

[jh1]: https://executiveoffense.beehiiv.com/p/ai-hackbots-part-1

| Item    | SAST                    | DAST                              | Fuzzing                         |
| ------- | ----------------------- | --------------------------------- | ------------------------------- |
| Input   | Code                    | Request response pair             | Crashdump or app state          |
| Prompt  | Does the code have XSS? | Is the request vulnerable to XSS? | Is this dump/state exploitable? |
| RAG     | Vulnerable code samples | Payloads and 'What is XSS?'       | Vulnerable dumps and inputs     |
| Context | Data flow               | Related request responses         | Related exploitable dumps/input |

## Input
This is our main data: the suspected vulnerable code, the HTTP request/response
pair, or the latest crash dump. Million-token context windows are tempting, but
as we saw above, they're not real. We need to be selective. This is where
traditional static analysis comes in (take that, marketing!).

The tooling generates and filters both `Input` and `RAG`. For SAST, we need
tools that retrieve specific code pieces with tree-sitter (or ANTLR if you hate
yourself). DAST needs something that sends HTTP requests and receives responses.
While there are other fuzzers than AFL, it's funnier to continue the wrapper
joke.

```
| Item    | SAST                | DAST         | Fuzzing     |
| ------- | ------------------- | ------------ | ----------- |
| Tooling | tree-sitter wrapper | cURL wrapper | AFL wrapper |
```

### RAG
Retrieval Augmented Generation (RAG) is technically a technique or framework,
but almost everyone (including me) treats it as a database. Jason Haddix
discusses collecting write-ups and payloads for RAG. For XSS detection, we can
pass the following from our RAG to AI:

1. XSS payloads.
2. "What is XSS" articles.
3. Some vulnerable XSS responses.

"But why do I need RAG? Surely the model has been trained on more XSS data than
I can gather?" Yes, but your silicon genie has also been trained on a lot more,
especially crap from Reddit. Depending on how it ~~feels~~ vibes, it might not
reach the XSS corner of the state machine. RAG lets you fill the context with
relevant information of your choosing.

{{< imgcap title="Now you know Context Engineering!" src="05.webp" >}}

Manual and AI edited screenshot from Dagashi Kashi anime. I replaced
"JavaScript" with "Context Engineering."

In SAST+AI, RAG typically contains vulnerable code examples. I use two main
sources:

1. Bugs and write-ups.
2. AI-generated code based on documentation.

Sounds easy, right? "Just scrape the internet" and "ask AI to generate code!"
It's not, lol!

1. Few public write-ups (compared to DAST bugs) include vulnerable code.
2. We need to remove noise and isolate patterns in existing samples.
3. There are many different ways to do the same thing in code.

The last item is especially frustrating. I recently tried documenting all the
ways to create a hash object in C#. This became a long doc titled "How many ways
can you generate a hash anyway?" I learned two things: there are many ways to
create hash objects in C#, and AI hallucinates even for well-documented
languages like C# (this is not a sponsored post, lol).

# How Many Ways Can You Do SAST+AI Anyway?
Let's focus on SAST. In rough order of complexity and effectiveness, the current
methods are (this is a personal list):

1. Prompt + code
    1. "Find security issues in this code block."
    2. "Does this code have security issues?"
2. Prompt + agent
    1. "Hey GitHub Copilot Chat, find security issues in this project open in VS Code."
3. Tailored prompt + SAST result
    1. "Is this code block with `.innerHTML` vulnerable to XSS?"
4. Agent + code graph + SAST MCP
    1. "Find issues in this code graph and here's a bunch of tools you can use
       to get more information about the codebase"

## Prompt + Code
Send a generic prompt with code to AI
and get an answer in a one-shot interaction. These were very popular when LLMs
started, and some companies still claim this is the way.

Do I think you should skip this? Absolutely not! AI can understand more and
probably find more issues than uncustomized bare bones SAST. If your options are
"run AI on code" vs. not, then run AI on code. This is the easiest way to get
started especially with cheap tokens.

> Running AI with a generic prompt on your code is better than running Semgrep
> with r/all. Any exercise is better than none.

That was cringe! LinkedIn is down the hall and to the left, Parsia. 

### Analyzing Pull Requests with AI
Use this method to complement your more complex reviews. Running quick SAST on
PRs is one of the best bang-for-buck activities (vulnerable patterns, secret
detection). Everyone should be doing this. All big and probably medium-size tech
companies do.

Even a simple action that adds an "explain this PR" comment is a huge win. It
helps reviewers understand the code faster. The risk? Engineers getting used to
it and blindly trusting AI.

At this point, every PR will have two comments:

1. What does this PR do?
2. Does it have any bugs and if so, how do I fix them?

If you want to go one step further, you can ask AI to create a commit to fix the
bug. Great start, straightforward to set up. Welcome to your new baseline.

### AI as Classifier/Triager
This method is also popular for creating LLM classifiers. Use a lightweight
model as first pass to determine vulnerability. If the AI decides the code is
vulnerable, scan it with a more expensive model.

Theori (3rd place in AIxCC 2025) does this. Here's an excerpt from a
[series of tweets by Tim Becker][t-t]. Note "off-the-shelf static analyzers."
We'll see more of this.

> We start by passing every function in the source code into LLMs, asking them
> to consider a wide-range of vulnerability classes and explicitly accept/reject
> each class. We also run off-the-shelf static analyzers.

[t-t]: https://x.com/tjbecker_/status/1955678196097290618

With a huge code base, pass each function to AI for a quick look. This helps you
discover vulnerability types that might be present in each block for more
advanced analysis later. Great first step.

## Prompt + Agent
As an application security engineer (well, my title is Offensive Security
Engineer but the terminally online have made Red Team cringe), here's
what I do with a new codebase:

1. Open the project in VS Code (normie doesn't use Vim/Emacs!).
2. Search for sensitive keywords (e.g., route annotations in C#).
3. Highlight interesting blocks and ask AI to document analysis in a local markdown file.
4. AI in Agent Mode has access to the codebase and can grep at will. It
   analyzes and documents.
5. Review the analysis and ask follow-ups. Start fresh if needed.
6. ???
7. Rinse and Repeat.

This manual workflow has served me well. For automation, change the request
limit in VS Code so AI never stops and let it run for a few hours.

1. Ask AI to create a list of keywords to grep for security issues. Save to file.
2. Edit to taste.
3. Ask AI to summarize what to look for in each keyword.
4. Edit and iterate a few times.
5. Ask AI to go through the list one by one and document issues.
6. ???
7. Profit

I've tried this process with OpenAI models from 3.5 to 5. They're eager to find
issues but produce a lot of noise. YMMV. You could enhance this process with
RAG, but RAG contains 1. vulnerable code patterns and 2. description of the bug.
If so, why not just use static analysis to extract those patterns in the first
place?

In August 2025, Anthropic released [/security-review][sec-rev-tw] for static
analysis ([GitHub repo][sec-rev-gh]) and the usual crowd marked it as the end of
code review. I have not played with it, but here's a nice experiment by
[@IceSolst][sec-rev-ice] [^ft-ice]. It's been less than three months and, 
[has anyone else run experiments with it?][sec-rev-hm], looks like no?

[^ft-ice]: One of the few anime pfp accounts on Twitter w/o shitty tech opinions.

[sec-rev-tw]: https://x.com/claudeai/status/1953125698081833346
[sec-rev-gh]: https://github.com/anthropics/claude-code-security-review
[sec-rev-ice]: https://x.com/IceSolst/status/1953299793645568231
[sec-rev-hm]: https://x.com/hkashfi/status/1972397906784317929

While finalizing this blog, OpenAI introduced [Aardvark][aard]. Will it shut
down every AI-Native startup (as the usual crowd claim) or be forgotten in a few
months? According to the architecture, the agent creates a threat model, finds
issues, and fixes them. More advanced, allegedly.

[aard]: https://openai.com/index/introducing-aardvark/

## Tailored Prompt + SAST Result
Instead of asking AI "what are the security issues here?" run static analysis
first and target specific code with tailored prompts. The simplest approach is
running AI on SAST findings as a classifier/triager. Congratulations! Add
AI-Native SAST to your resume.

But this misses things. If you're allergic to noise like me, you've tailored
your SAST rules to be very specific. When my main ruleset hits, I'm almost sure
it's an issue. Triage becomes somewhat redundant. Those rules are not good
candidates for this approach. This is where
{{< xref path="/post/2022/2022-03-31-semgrep-hotspots/"
    text="hotspot rules"
    title="Code Review Hot Spots with Semgrep">}}
come in. Here's an example: for API security issues, create a rule to extract
routes[^ft-route-ai] (even AI-generated regex works) and spend tokens on those
looking for specific issues. Another example: For cryptographic issues, extract
pieces of code with specific imports containing these objects (e.g.,
`System.Security.Cryptography` in C#) then pass them to AI asking specific
questions. This reduces token usage.

[^ft-route-ai]: While tempting, don't ask AI to extract the routes. Don't use AI to accomplish tasks that can be done with way less compute.

If you've done these, you're probably way ahead of everyone else. But we can
still do better.

Got data flow from CodeQL or Semgrep? You can pass the entire flow, but as we
saw above, large context windows are a myth. It's been hit and miss for me. I've
seen 20+ step CodeQL flows cause AI hallucinations. With current models, I think
we get more value from splitting flows into smaller chunks and asking AI if a
function is vulnerable assuming tainted input.

## Agent + Code Graph + SAST MCP
At this point you're almost "AI-Native." What's the path forward? I haven't
experimented enough to have a good answer, so let's learn from others. ZeroPath
has a blog [explaining how it works][zeropath].

[zeropath]: https://zeropath.com/blog/how-zeropath-works

### How ZeroPath Works
Interesting read. They're telling us what they do. Their method is not
surprising. This is what every SAST+AI tool must do. First they parse the code
with tree-sitter (get the "tree-sitter wrapper" joke now?) to generate the AST.
Then they create a filtered function call graph where only the _important_
functions appear (e.g., route method for listing users calls render).

The ZeroPath blog shows this graph, but it's tiny because of page margins. It's
also a rendered mermaid diagram as svg so it's text and I can't view it in full
size. I had to delete the sidebar elements in DevTools and change the width to
take a screen shot. Right-click and open the image in a new tab like an NFT to
see a readable graph.

{{< imgcap title="What is this? A graph for ants?" src="07.webp" >}}

You can create this graph with pure static analysis; no AI needed (yet). I've
done it with both
{{< xref path="/post/2024/2024-01-21-semgrep-fun/"
    text="Semgrep"
    title="Go Function Call Chain with Semgrep"
    anchor="06-go-function-call-chain" >}}
and
{{< xref path="/post/2024/2024-04-09-tree-sitter-2/"
    text="tree-sitter."
    title="Function Call Chains with tree-sitter CST"
    anchor="function-call-chains" >}}.
It's much easier than it sounds (not trying to discredit ZeroPath here). Create
a list of each function's callees (e.g., function A calls B and C, C calls D).
The rest is a simple process that creates a connectivity graph (A -> C -> D).

Tools like [scabench-org/hound][hound] do this with AI (yet another anime
mascot? 'what the hell, sure'.png). I've not dog ('Fozzie Bear waiting for
applause'.gif) deep into the code, but looking at requirements.txt I can't see a
parser. When a tool claims to be "language-agnostic" it's not parsing code. IMO,
static analysis is better than AI for this step. ZeroPath is on the correct path
(har har).

[hound]: https://github.com/scabench-org/hound

Next, the graph is "enriched with AI." At this point, I'm sure ZeroPath's UI
designers want to blind us because this graph is even less readable.

{{< imgcap title="Diagrams in their original size" src="09.webp" >}}

With magic and cunning, I've stolen their graph, again. Right-click and open in
a new tab NFT style to see the large image. Sorry about the joke, folks, but
those diagrams are really unreadable.

{{< imgcap title="Enjoy my truly unique non-AI art!" src="08.webp" >}}

Now we can look at parts of this graph. Here we have the routes, their methods,
the HTTP verbs, and what they do. This is the extended call chain most likely
passed to AI to make the connections (e.g., creates a response or interacts with
the DB using the ORM).

{{< imgcap title="A section of the enriched graph" src="10.webp" >}}

The pink boxes on the graph probably represent a separate system or security
specifics. Not sure honestly. That's a great example of what we can do to make
my tool better. Thanks for the information.

{{< imgcap title="Pink boxes" src="11.webp" >}}

Next, they introduce papers for exploring the graph but I've learned what I
wanted.

A different tool, [Slice: SAST + LLM Interprocedural Context Extractor][slice]
works similarly. It uses CodeQL queries and tree-sitter to extract vulnerable
code, triages with gpt-5-mini, then uses GPT-5 on the survivors.

[slice]: https://noperator.dev/posts/slice/

### MCPs
MCPs are the current rage and the latest weapon in the "make AI deterministic"
war. MCP gives AI access to tools. If we give AI access to a SAST MCP like
Semgrep, it can query the data itself. This beats grep since AI can request
specific code parts. You still need to create and expose Semgrep rules
individually unless you trust AI to write them on the fly.

Bottom line: The more you hold AI's hand (AKA add more relevant information in
the context), the better.

### Embedding Models
The ZeroPath graph is an example of code converted to something AI can
understand for better retrieval. This is another one. GitHub Copilot
recently introduced a new embedding model (`copilot-embedding`) that is supposed
to improve code retrieval. See
[GitHub Copilot gets smarter at finding your code: Inside our new embedding model][copilot].

[copilot]: https://github.blog/news-insights/product-news/copilot-new-embedding-model-vs-code/

What does an embedding model do? It converts the data into a point in
multidimensional space (e.g., 1024 floating point numbers). Feed it your code
in chunks (models have token limits). To retrieve, feed search criteria to the
same model and find which code chunks are closest to the input with some basic
matrix math.

Will embedding models outperform static analysis pattern matching? We threw away
decades of information retrieval research for embedding models and AI summaries,
so who knows. The real breakthrough would be a model that understands code
intent. Explain what the code should do, compare it with the actual intent to
find vulnerabilities. Much better than pattern matching for bug classes like
business logic flaws and AuthN/AuthZ. If you know any research in this space,
let me know :)

# What Did We Learn Here Today?
Here's the summary of my 3800-word yap session:

Even the most basic approach (prompt + code) is better than nothing. Time and
cheap tokens won't last forever. Go do this in your org and get that promotion.
Build that startup to get the VC money. These AI capex subsidies will be gone
before you know it.

In my opinion, AI-native SAST can't replace traditional SAST yet. Current LLMs
cannot understand code that well. We need to show them where to look with static
analysis. Hand-holding through context engineering, targeted prompts, and
filtered inputs makes AI exponentially more useful than generic "find bugs"
requests.

As usual, if you have feedback, you know how to contact me. If you can't find
me, you don't deserve to yell at me :)