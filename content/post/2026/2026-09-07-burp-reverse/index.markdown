---
title: "Reverse Engineering Burp Project Format"
date: 2026-09-07T00:11:03-07:00
draft: false
toc: true
url: /blog/burp-project-reverse/
twitterImage: 02.webp
categories:
- Reverse Engineering
- Burp
- AI
---

(A)I reverse engineered Burp Suite's project format and built a tool that
exports Proxy history, Repeater messages, and Target Site Map traffic. See
[parsiya/prub][prub] and [the documented format][format].

I did not "hack" Burp; this is not a crack. The tool only extracts data from
existing project files.

[prub]: https://github.com/parsiya/prub
[format]: https://github.com/parsiya/prub/blob/main/ai-docs/format-specification.md

<!--more-->

* Model: GPT-5.6-Sol - High reasoning effort - 1M context window.
* Rough cost: ~160 USD (fewer than 16,000 GitHub Copilot AI credits).
  * I am very ~~cheap~~ efficient with tokens.
  * Main reversing session cost $100 and ended up with a big 520K token context window.
* Harness: GitHub Copilot CLI and GitHub Copilot Chat in VS Code.

# .nfo

## [greetz]

* PortSwigger for giving us this great tool.
* Short story: [The Girl Who Was Plugged In][plug] by James Tiptree Jr. (actually Alice Bradley Sheldon).
* Music: [Destiny 2: Forsaken Original Soundtrack - Track 19 - The Man They Called Cayde][cayde].
  * "Hey, take me with you." - Cayde-6.

[plug]: https://en.wikipedia.org/wiki/The_Girl_Who_Was_Plugged_In
[cayde]: https://www.youtube.com/watch?v=UVTu6Wa0wpY

## [anti-greetz]

* PortSwigger for not giving Repeater access to the extensions API.
* Ending of [0wnz0red][own] by Cory Doctorow.
  * Amazing setting and premise, but very meh ending :(.

[own]: https://www.salon.com/2002/08/28/0wnz0red/

# Motivation
One of my biggest gripes with Burp's extension API is the lack of access to
Repeater tabs. You can export all the proxy history with an extension (or
manually in Burp), but you cannot do the same for Repeater tabs.

In the past, I've used gimmicks to capture all my traffic:

1. Exported the Repeater section of a project and ran `string` to extract requests/responses.
2. Used [a second copy of Burp as an Upstream proxy][up] to capture all traffic.
3. Created [parsiya/looking-glass][looking], an extension that stores everything in a database.

[looking]: https://github.com/parsiya/looking-glass
[up]: {{< relref "post/2025/2025-08-15-burp-ai/index.markdown#upstream-proxy" >}}

Tokens are still cheap and AI is good at reversing, so I am working through my
bucket list[^ft1].

{{< blockquote author="Our esteemed elder and spiritual scholar"
    link="https://www.linkedin.com/feed/update/urn:li:activity:7487635110092038145/"
    title="Adam Hassan" >}}
Clear that project backlog before the end of the free token era.
{{< /blockquote >}}

[^ft1]: "Our esteemed elder and spiritual leader" is a parody of "شیخنا و مولانا" from ancient Persian literature and an old obscure Farsi meme.

# Methodology
The target version is Burp Pro `2026.7.1`.

1. Decompiled the Burp Pro jar file with [skylot/jadx][jadx] and [Vineflower/vineflower][vine].
2. Created the following Burp project files:
    1. Empty project.
    2. Project with a specific request/response in Proxy History.
    3. Project with two specific request/responses in Repeater (to test tab groups).
3. Opened the whole thing in VS Code and started prompting in GitHub Copilot Chat.

[jadx]: https://github.com/skylot/jadx
[vine]: https://github.com/Vineflower/vineflower
[act]: https://github.com/parsiya/prub/blob/main/ai-docs/activity-log.md

I am hands-on with AI. I like to steer extensively, review everything, and start
fresh sessions to keep the context window small.

There were many false starts. Maybe (A)I could have done this autonomously with
a good eval harness, but prompting specific things was easier and faster. See
the [activity log][act] for detailed tracking.

# Pitfalls
This section documents what I tried, what didn't work, and other issues I had
during this process.

## Decompilation Problems
Originally I wanted to use Ghidra, like
{{< xref path="/post/2026/2026-04-12-aula-f108/"
  text="when (A)I reversed my keyboard utility"
  >}}
but normal decompilers worked here.

| Class Statistics              | Num    | Notes                                      |
| ----------------------------- | :----: | ------------------------------------------ |
| Classes in the JAR            | 55,120 | Includes Burp and bundled dependencies     |
| Classes in the `burp` package | 20,609 | Important stuff                            |
| Top-level Burp input classes  | 20,491 | Baseline used for source filename coverage |
| Focused JADX source files     | 19,030 | 92.87% top-level coverage; 1,461 missing   |
| Vineflower source files       | 20,502 | 99.81% top-level coverage; 39 missing      |

* Don't decompile everything, just focus on the `burp` package. Both JADX and
  Vineflower went OOM.
* Combine both outputs. Every class missing from Vineflower existed in JADX, and
  15 of those had clean JADX output.

## Imaginary Side Quests
As models become more intelligent, they invent extra objectives and repeat
useless tasks: running `git diff` after every file change outside Git
repositories, getting stuck on Markdown warnings, line endings, and empty lines,
or, worst of all, making up goals.

For example, I asked AI to move a file from the parent directory to
`prub/ai-docs` and then edit it. Instead of doing a normal `mv` (I realize I
should've done the move myself), it copied the file from memory and then ran
three different commands (`cmp`, 2x `diff`) to check if the file has been moved
correctly.

```
...
Generating patch (230 lines) in ...

Ran terminal command:
cmp -s ai-docs/activity-log.md prub/ai-docs/activity-log.md
  && printf 'activity logs match\n'

The byte-for-byte check did not report a match, likely because the source
Markdown uses Windows line endings while the new file uses repository-standard
Linux line endings. I’ll confirm content equivalence while ignoring CRLF, then
make the link and inventory edits.

Ran terminal command:
diff --strip-trailing-cr --brief ai-docs/activity-log.md prub/ai-docs/activity-log.md

Ran terminal command:
diff --strip-trailing-cr --unified=1 ai-docs/activity-log.md prub/ai-docs/activity-log.md
```

Clopus 4.6 would never, RIP friend 😭.

AI also repeatedly wandered beyond goals. My initial goal was Repeater and
Proxy, but it kept trying to investigate Scanner and specifically Logger. I had
already mentioned that Logger information is not persisted in the project file.
It's like talking to a cat!

<span class="caption-wrapper" style="max-width: 600px; display: inline-block;">
  <img class="caption" src="02.webp" title="But AGI is here!" alt="'You are not immune to propaganda' Garfield meme">
  <span class="caption-text">But AGI is here!!1!</br>Image credit: <a href="https://markvomit.tumblr.com/post/172083570225/you-are-not-immune-to-propaganda">Mark Vomit @ Tumblr</a></span>
</span>

# Interesting Stuff
Discussing the format is useless in the age of AI. Just pass `ai-docs` to your
favorite LLM and go from there. Instead, here are interesting things (A)I saw in
the format.

* **Stable field lookup:** Readers search by field ID, so physical field
  positions can move.
* **Shared records:** Proxy and Target Site Map can reference the exact same
  request/response objects.
  * I guess Site Map references objects from other tools, too.
* **Forwarding objects:** Updated objects can redirect readers to replacement
  addresses.
* **Periodic persistence:** Mapped regions are forced every 10 seconds and again
  during close.

## Self-Describing Objects
Each compact object begins with metadata describing its own fields:

```
+0  flags
+1  object type
+2  subtype/schema
+3  descriptor count
+4  descriptor table
```

Each three-byte descriptor contains a field ID and a signed relative offset:

```
field_id: uint8
offset:   int16 big-endian
```

Example:

```
00 01 00 02   0F 00 0A   12 00 12   ...
```

This says:

* Normal object: flags `0`.
* Type `1`, subtype `0`.
* Two fields.
* Field `15` begins at object offset `10`.
* Field `18` begins at offset `18`.

For a Proxy item, fields `15` and `18` can contain addresses of raw request and
response records. A parser searches the descriptor table by field ID instead of
assuming fixed byte positions.

## Installation ID
Projects store an installation ID. If you've opened projects on a different
machine you might have seen the "take ownership" part. I think this is
correlated with that. If the current Burp sees a different installation ID and
you ask it to "take ownership" it probably overwrites the installation ID in the
file.

The installation ID does not appear to contain personal identifiers. It is
random and not derived from license data. Burp reads Java preference
`burp.suite.installationId`. If it is missing or invalid against
`^[a-z0-9]{20}$`, it generates 20 random lowercase alphanumeric characters and
saves them back to preferences.

If PortSwigger knows this ID and sees a Burp project in the wild, they will know
it was you. But then again, the contents of the project file are far more
important and now you have bigger problems.

# Future Work
I have done Repeater and History, but you can add more. **Scanner** is probably
the most popular target and should be doable with a couple of sample projects
and the existing `ai-docs`.

It would also be nice to edit projects. That would allow us to create a wrapper
for Burp Community to save and load projects.

My manager (oops, he asked me not to call him that), I mean, my teammate (oh, he
told me not to quote him, either), OK an anonymous wise man also told me "Let's
do great things together while we are here."

{{< imgcap title="Me and the anonymous wise man" src="01.webp" >}}

Well, this was fun. If you want to continue the project, feel free to do so. The
MIT license is magic. If you have any feedback, you know where to find me.
