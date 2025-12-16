---
title: "AI-Native SARIF"
date: 2025-12-11T19:00:00-07:00
draft: false
toc: true
comments: true
url: /blog/ai-native-sarif/
twitterImage: 04.webp
categories:
- AI
- Static Analysis
---

The "radical" idea to add prompts and code context directly into SARIF files for
AI triage.

<!--more-->

Write the clickbait title and then immediately give away the whole thing in the
preview. Pick a struggle, gurrl!

Special thanks to [Krishna][krishna-lnk] from Microsoft and [Lewis][lewis-lnk]
from Semgrep for reviewing the post and giving me feedback.

[krishna-lnk]: https://www.linkedin.com/in/krishnachaitanyatelikicherla/
[lewis-lnk]: https://www.linkedin.com/in/theoriginalenglishbreakfast/

# Abstract
In
{{< xref path="/post/2025/2025-10-31-ai-native-sast/"
    text="WTF is ... - AI-Native SAST" >}}
I proposed four phases of AI-Native SAST in increasing complexity:

1. Prompt + Code
2. Prompt + Agent
3. Tailored Prompt + SAST Result
4. Agent + Code Graph + SAST MCP

The last two methods work on the results of SAST tooling. AI needs code, static
analysis results, tailored prompt, and context to be effective. Keeping track of
these and mashing them all together is an added layer of unnecessary headache.
In this blog I will explore how a SARIF file can act as the single source of
truth for AI triage.

## What is SARIF?
SARIF is [Static Analysis Results Interchange Format][sarif-spec]. It's a format
for storing static analysis results, oh wait, the name actually tells us what it
does. It's a JSON file with a specific schema. Your static analysis tool should
be able to output the results in this format, if not, call your vendor!

I am not going to propose modifying the SARIF format. Run-on blogs are more my
thing than corporate whitepapers. So I will try to find opportunities without
breaking the current specification.

[sarif-spec]: https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html

# What Should I Add to the SARIF File?
While I want this blog to concentrate on the _how_ rather than the _what_, I
will still expand a little on the
{{< xref path="/post/2025/2025-10-31-ai-native-sast/"
    text="Tailored Prompt + SAST Result section"
    anchor="tailored-prompt--sast-result" >}}
section of the previous blog. I propose AI triage needs this info in the SARIF
file:

1. Rule context. Generated for each static analysis rule.
    1. Tailored prompt.
    2. Good and bad usage/code.
2. Code context. Generated for each individual finding.
    1. Code snippet.
    2. Code metadata.

Let's use a hypothetical static analysis rule for SSRF in C#. Usually, I start
by looking for `HttpClient.GetAsync` and then figure out if the input can be
influenced by users. Here's a [Semgrep rule for it][sem].

[sem]: https://github.com/semgrep/semgrep-rules/blob/develop/csharp/lang/security/ssrf/http-client.yaml

And I know many of you will just fixate on the contents so I will preemptively
state this is just an example and your bike-shedding will fall on deaf ears.
Save it for the promotion committee.

## Rule Context
This is the context that explains the rule and helps AI triage the result
correctly.

For our SSRF example, _the tailored prompt_ explains what SSRF is, how
`HttpClient.GetAsync` works, and why it might be vulnerable to SSRF if user
input can influence the URI.

_Good and bad code patterns_ can be liberated from your SAST tests. Show AI
examples of true and false positives.

{{< imgcap title="You do know you're using this meme format incorrectly, right?" src="02.webp" >}}

## Code Context
_Code context_ is based on the matched code and generated independently of the
rules.

Should the actual code be in the file? "Don't put the code in the file, Parsia!"
said my manager. But the results of static analysis ARE also sensitive info.
More importantly, they are a direct result of static analysis so access to the
files likely includes access to code anyway.

But OK, be careful putting sensitive info in the magic file. Alas, yet another
piece of red tape holding civilization back!

{{< imgcap title="Contrary to popular belief I actually value feedback (don't tell them)." src="01.webp" >}}

_Code metadata_ is the extra information about the matched code and its
surrounding context. You should use a combination of static analysis and AI
here. For example, static analysis identifies all API routes based on
decorators/keywords and AI summarizes them.

At a minimum, I need the AI generated description of the surrounding function
block[^ft-fun]. I could also include more context about the code's functionality
(for example, this is an API route that retrieves user's info from another
microservice).

[^ft-fun]: Everything is ~~computer~~ function!

## The Feedback Loop
You should refine the aforementioned data as time goes by. While it is tempting
to add the false positives to per-rule context, your first line of defense is
tweaking your SAST rule to filter these out. That is not always possible so 
some false positives will eventually end up in the context.

A function that was misidentified as an API route should refine the system
(prompt + SAST as we discussed above) that generates the _code metadata_. It
will most likely work result in a modified prompt.

But enough about the data, I want to focus on the actual format here.

# Where Does the ~~Soda~~ Data Go?[^ft-soda]
I needed to analyze the SARIF structure to find suitable locations for this
info. I've written a good chunk of code for processing SARIF output in
[Go][semgrep-go] and [Rust][semgrep-rs] and even did some
{{< xref
path="/post/2024/2024-01-21-semgrep-fun/" text="fun Semgrep experiments" >}}.
This was a chance to look at other parts of the format.

[semgrep-go]: https://github.com/parsiya/semgrep_go
[semgrep-rs]: https://github.com/parsiya/semgrep-rs

[^ft-soda]: https://www.reddit.com/r/WhereDidTheSodaGo

## Rule Context
The `runs > tool > rules` section is perfect for the rule context. It has a list
of all rules executed by the tool. According to section
[3.19.23 rules property][spec-rules] of the specification, it can have one or
more [reportingDescriptors][spec-desc].

[spec-rules]: https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html#_Toc141790806
[spec-desc]: https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html#_Toc141791086
 
I will be using an example from running
[Marco Ivaldi's (0xdea) Semgrep rules][marco-rules] against OWASP Juice Shop.
I've removed some parts to make things easier to read. I will look at the
 [c.command-injection rule][inj-rule].

[marco-rules]: https://github.com/0xdea/semgrep-rules
[inj-rule]: https://github.com/0xdea/semgrep-rules/blob/main/rules/c/command-injection.yaml

```json
{
  "runs": [
    {
      "tool": {
        "driver": {
          "rules": [
            {
              "fullDescription": {
                "text": "The program invokes a potentially dangerous function ..."
              },
              "help": {
                "markdown": "The program invokes ...",
                "text": "The program invokes ..."
              },
              "id": "semgrep-rules.c.raptor-command-injection",
              "name": "semgrep-rules.c.raptor-command-injection",
              "properties": {
                "precision": "very-high",
                "tags": [
                  "HIGH CONFIDENCE"
                ]
              },
              "shortDescription": {
                "text": "Semgrep Finding: semgrep-rules.c.raptor-command-injection"
              }
            }
            // removed
```

The `help` property is tempting. It's a 
[3.12 multiformatMessageString object][spec-multi] with two keys: `text` and
`markdown`. Semgrep populates the `text` portion with the rule message and the
markdown section has the rule message + the references (maybe more?). This is
not a good choice, because it will be overwritten by Semgrep and probably other
tools.

[spec-multi]: https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html#_Toc141790723

I decided to use [3.8 Property Bags][spec-prop] instead. The format defines them
as "an unordered set of properties with arbitrary names." More importantly, they
can be part of any tag:

[spec-prop]: https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html#_Toc141790698

> every object defined in this document MAY contain a property named properties
> whose value is a property bag. This allows SARIF producers to include
> information about each object that is not explicitly specified in the SARIF
> format.

We will use camelCase keys to remain compliant with the specification:

> The components of the property names SHOULD be camelCase strings ...

Semgrep has populated the property bag in our example with some data. I will add
the _rule context_ there.

```json
{
  "runs": [
    {
      "tool": {
        "driver": {
          "rules": [
            {
              // removed
              "id": "semgrep-rules.c.raptor-command-injection",
              "name": "semgrep-rules.c.raptor-command-injection",
              "properties": {
                "aiPrompt": "...", // ZZZ: triagePrompt?
                "codeContext": "...", // ZZZ: need better name
              },
            }
            // removed
```

## Code Context
The code context should be part of each finding. The findings are
[3.27 result objects][spec-result] and look like:

[spec-result]: https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html#_Toc141790888

```json
{
  "runs": [
    {
      "results": [
        {
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "juice-shop/.eslintrc.js",
                  "uriBaseId": "%SRCROOT%"
                },
                "region": {
                  "endColumn": 17,
                  "endLine": 37,
                  "snippet": {
                    "text": "// FIXME warnings below this line need to ..."
                  },
                  "startColumn": 12,
                  "startLine": 37
                }
              }
            }
          ],
          "message": {
            "text": "The code contains comments ..."
          },
          "properties": {},
          "ruleId": "semgrep-rules.generic.raptor-bad-words"
        },
        // removed
```

Note the `snippet > text` key with the value of the captured code. So much for
not having sensitive info in the SARIF file 😜.

This object also supports a property bag that we can reuse:

```json
{
  "runs": [
    {
      "results": [
        {
          // removed
          "properties": {
            "code": "_gasp_",
            "codeMetadata": "..."
          },
          "ruleId": "semgrep-rules.generic.raptor-bad-words"
        },
        // removed
```

# When Do I Modify the SARIF File?
Ideally static analysis tools should do it. I've modified my toy static analysis
tool to generate these new SARIF files. A unique feature according to this chart.

{{< imgcap title="Accepting funding at 1 billion valuation!" src="04.webp" >}}

It's easy to process rule context data. Create the prompt and the code samples
for each rule (I use Semgrep tests) and store them by rule ID in a database.
Then use the rule ID in the SARIF file to retrieve them.

_Code context_ matching sounds much harder but it's not. Store the code context by
"function" or "file" along with the code address (file path and function offset)
in the database. Use the location and file path of each finding to match which
file and function contain the match. To make things easier, especially in the
beginning of your AI journey, don't worry about functions. Just generate and
pass the code and context of the entire file to AI and let it do the heavy
lifting.

The implementation is pretty simple. I wrote it by hand and without LLMs. It
didn't even need library support. I encourage you to do the same to exercise
your coding muscles. It's just parsing JSON and adding data to the `properties`
key of specific items.

Just as I was finalizing the blog, LinkedIn published an article about their
[SAST pipeline][sast-lnk]. They mention a "SARIF enrichment" step.

> We enrich SARIF alerts with additional metadata and remediation information
> specific to LinkedIn’s environment.

This is inline with my idea. I like the name "SARIF enrichment."

[sast-lnk]: https://www.linkedin.com/blog/engineering/security/modernizing-linkedins-static-application-security-testing-capabilities

# Where Does the Data Come From?
That is the million dollar question. The secret sauce or better yet, the
so-called "Potter's Puff." What's that? It's my transliteration of the Persian
idiom فوت کوزه‌ گری.

In ancient times an apprentice studied under a master potter. The apprentice
left the master after thinking they had learned it all. But their pottery came
out ruined with muddy colors. Turns out dust would accumulate on the pottery so
the master would blow on each piece before firing it in the kiln.

{{< imgcap title="No, not like that!" src="03.webp" >}}

> Tired: Secret sauce. Pedestrian and overused. Probably LLM generated.  
> Wired: Potter's Puff. Unique and exquisite. 100% organic.

So no one is going to give away the magic. Least of all me, I am very expensive
financially and emotionally, just ask my boss. Jokes aside, I am still
experimenting here. Static analysis is not my main job and I do this on the side
so I cannot compete with actual companies. Still I've made some progress like
reusing Semgrep tests and I have some fun ideas for automagically generating
tailored prompts, too.

# What Did We Learn Here Today?
The article suggests including the data needed for AI triage in the SARIF file.
I proposed adding two types of data: per rule and per finding. I identified
practical locations in the SARIF format for them. I also discussed some ways to
generate this data, but my experiments are still ongoing. And last but not
least, we learned a new idiom to differentiate our writing from AI slop.

I am very curious to connect with others in this field and learn what they are
doing and finally, whether this is a path worth pursuing. Please reach out, you
know where to find me.