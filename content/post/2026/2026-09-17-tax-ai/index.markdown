---
title: "Preparing My Taxes with AI"
date: 2026-09-17T00:11:03-07:00
draft: false
toc: true
url: /blog/tax-ai/
twitterImage: 01.webp
categories:
- Not Security
- AI
---

How I used LLMs to put together a packet for my tax preparer and review my
return. What worked and what didn't. I also created a public skill.

This is not tax or investment advice. This is not about "filing taxes with AI."
I have an awesome tax preparer because my taxes are complicated and FBAR/FATCA
penalties are steep. I need the human in the loop for my threat model (the IRS).

<!--more-->

Skills are at https://github.com/parsiya/parsia-plugins.

[Worldwide taxation rant omitted because I am channeling my inner patio11].

# Motivation and Problem Statement
My taxes are complicated. You think yours are, too, and I am sure they are, but
being a US citizen living abroad or holding foreign assets adds another
difficulty level. You have to worry about things like FBAR, FATCA, PFIC, FEIE,
and FTC.

In my opinion, the US government (regardless of administration or party) doesn't
want US citizens to move abroad, work abroad, or marry abroad.

{{< blockquote author="Anonymous teammate" >}}
ngl, ur lowkey cooked
{{< /blockquote >}}

The best things you can do are 1. find a great CPA (and immigration attorney)
and 2. become very familiar with the tax treaty between the US and the country
where you live or hold assets (and the US immigration system).

I am American-Canadian[^ft-cad], among other things, and have financial accounts
in Canada. Fortunately, I have a great preparer and know the US-Canada tax
treaty (and our immigration system) to some extent. I am lucky because it's
probably one of the most comprehensive tax treaties (as far as these go).

[^ft-cad]: Associate European as of today.

# Methodology
LLMs excel at categorization, summarization, and data extraction. Every year I
gather information from many forms. This year I used AI to:

1. Convert all tax forms from PDF to Markdown.
2. Verify that the conversion was correct.
3. Organize the information into a packet for my tax preparer.
4. Check the previous year's filed return as a blueprint for things I might have forgotten.
5. Review the draft return from the preparer against the source documents.

This sounds straightforward. It was not.

## Steps 1 and 2: PDF Conversion and Audit
Tax returns and source forms are mostly PDFs. Fortunately, all my tax forms are
"True PDFs," not image-based PDFs.

1. True PDF: You can select the text.
2. Image-based PDF: Scans.

Source: https://nlsblog.org/2020/06/12/three-types-of-pdfs/

True PDFs convert well to text. I used [microsoft/MarkItDown][markit] to convert
my tax forms to Markdown. Here's a section of my converted W-2.

[markit]: https://github.com/microsoft/markitdown

```
| 5  Medicare wages and tips |     |      | 6  Medicare tax withheld        |      |
| -------------------------- | --- | ---- | ------------------------------- | ---- |
|                            |     | 1234 |                                 | 123  |
| 7  Social security tips    |     |      | 8  Allocated tips               |      |
| 9                          |     |      | 10 Dependent care benefits      |      |
| 11 Nonqualified plans      |     |      | 12a See instructions for box 12 |      |
|                            |     |      | C                               | 111  |
|                            |     |      |                                 |      |
|                            |     |      | 12b D                           | 1122 |
| 14 Other                   |     |      | 12c W                           | 3344 |
```

But our work is not finished. We need to confirm the conversion is actually
correct because:

1. Not all forms are true PDFs.
2. Even true PDFs can contain text rendered as images.
3. Tax forms have complicated layouts with many boxes.
4. The numbers are the most important thing in taxes and they have to be right.
5. Some PDFs have highlights, strikeouts, and annotations.

I ended up creating two skills[^ft-skill] in my own plugin marketplace[^ft-mar]:

* [Render PDF pages to PNG][sk-pdf] and check the original layout.
* [Convert the PDF with MarkItDown][sk-mark] and audit it for correctness.
  * Compare the Markdown with independent text from `pdftotext -layout`.

[^ft-skill]: Dedicated to a certain teammate who loves skills :)

[^ft-mar]: My private marketplace is just one plugin with all skills. It's easier to keep updated.

[sk-mark]: https://github.com/parsiya/parsia-plugins/blob/main/plugins/pdf-to-markdown/skills/pdf-to-markdown/SKILL.md
[sk-pdf]: https://github.com/parsiya/parsia-plugins/blob/main/plugins/pdf-to-image/skills/pdf-to-image/SKILL.md

Converting PDFs to images might seem like overkill, but AI reads them well. This
was a cost-effective way to add another number check for a total of three:

1. PDF to markdown by deterministic tooling.
2. Image rendering by AI.
3. Manual checks by a human (me).

{{< imgcap title="The unfashionable 'Human in the loop'" src="01.webp" >}}

### IRS Wage and Income Transcript
The IRS website lets you download past tax information (10 years, I think?). The
"Wage and Income Transcript" consolidates forms the IRS has for you.
Unfortunately, these generally become available towards the end of the following
year, after you've finished your taxes. If you apply for an extension like me,
you may be able to use them. This is how my W-2 looks on that form followed by
an ESPP form (you need those numbers when you sell the shares).

{{< imgcap title="Redacted W-2" src="02.webp" >}}

I've redacted parts of the screenshot, but each number appears next to its box
name. This true PDF shows only the relevant fields and is much easier to convert
and read than the original. Still, double-check it against your own records to
see if the IRS has the correct info or not.

You can also download previous years' returns and transcripts as similar forms.

## Step 3: Creating the Packet for the Tax Preparer
The packet is not a tax return. It is a summary of the source documents and the
facts the preparer needs.

I organize it by the categories the preparer expects:

* Taxpayer information and filing status.
  * E.g., names, address, SSN.
* W-2 wages and withholding.
* Dividends.
* Interest.
* Capital gains and basis.
* Retirement distributions.
* HSA contributions and distributions.
* Estimated payments and withholding.
* Foreign income and foreign accounts.
* Carryovers and unusual transactions.

This is useful for me (and hopefully them). Most places issue a consolidated
1099 which has all the info (e.g., 1099-DIV and 1099-INT). But these go into
separate places on the return. Having all interest values in one place helps
both reading and preparing.

I attach the original forms as the main source of truth. The packet summarizes
useful numbers and explains anything the forms don't make obvious. For example,
here's the dividend table (random numbers).

|  Source  | Account | 1a Ordinary | 1b Qualified |
| -------- | ------- | ----------- | ------------ |
| Bank 1   | Z67-123 | $7.13       | $0           |
| Bank 2   | 1122334 | $375.03     | $809.02      |
| Totals   |         | $382.16     | $809.02      |

### Estimated Tax Payments and Extensions
As a US citizen abroad or with assets abroad, **you should always file an
extension**. Late tax payments incur penalties and interest for normies, but
late FBAR and FATCA filings carry steep penalties. Overseas taxpayers [get an
automatic two-month extension][ext-1], but filing an extension is free and punts
the return to October. This gives you more time to file those forms (FATCA
penalties start at $10K USD).

An extension gives you more time to file; taxes are still due April 15th. For
some reason, I always owe more. While I do not ask AI to file or create a return
for me, it's very good at estimating the taxes owed that I need to pay
before April 15th to avoid penalties and interest.

[ext-1]: https://www.irs.gov/individuals/international-taxpayers/us-citizens-and-resident-aliens-abroad-automatic-2-month-extension-of-time-to-file

## Step 4: Using the Previous Return as a Blueprint
The previous year's filed return is a record of:

* Income sources.
* Foreign accounts.
* Forms and schedules.
* Carryovers.
* Prior decisions from the preparer.

Generally, my situation rarely changes dramatically between years. Big changes,
like moving from Canada to the US, are memorable so there is little chance of
forgetting (if I forget moving countries then we have a bigger problem). AI is
good at checking last year's return for the smaller things I might forget.

I use the previous return as a completeness check. If an account, form, or
income source is missing or a new thing has appeared in this year's return, I
need to know why. Watch for the LLM adding last year's numbers to the current
packet; it happened to me. The VS Code diff editor helps me track each change.

The return also helps answer AI's questions, such as how to report a Registered
Retirement Savings Plan (RRSP or a more robust version of a 401(k)) on FBAR and
FATCA forms. AI thought it should not be reported because it is a tax-registered
account recognized by the tax treaty. While you do not pay taxes on it absent a
withdrawal, it should appear on both forms.

These answers went into the private tax return skill so we don't have to argue
next year. Without prior notes, AI could revisit this question every year and
give a different answer.

### Currency Conversion Needed Its Own Check
Foreign income and foreign-account reporting don't necessarily use the same
exchange rate.

For each foreign amount, I record:

* Original value.
* Original currency.
* Conversion rate.
* Rate date and source.
* Converted U.S. dollar value.

Foreign income may use an annual-average or transaction-date rate. Foreign
account values for FBAR and FATCA use the December 31 rate. Reusing one rate
everywhere can produce the wrong result. AI knew how to get the published
conversion rates from `api.fiscaldata.treasury.gov`.

### States and US-Canada Tax Treaty
This was a big surprise, the US-Canada tax treaty is between the federal
governments. While every Canadian province (not sure about Quebec) honours it,
not every US state does. I live in Washington, which has no state income tax, so
I am not worried about this.

If your state doesn't recognize tax treaties for income tax purposes, add that
to your skill. California is a well-known example: it doesn't recognize an RRSP
as a tax-registered account. This means you should calculate your RRSP's
distributions, dividends, and gains at year-end and include them in your
California tax return.

{{< imgcap title="Why does California do this?" src="03.webp" >}}

## Step 5: Reviewing the Draft Return
Once the preparer sends the draft, (A)I review it manually and with the
[us-tax-return][us-tax] skill.

[us-tax]: https://github.com/parsiya/parsia-plugins/blob/main/plugins/us-tax-return/skills/us-tax-return/SKILL.md

I check amounts, ownership, identifiers, omitted or duplicated items,
checkboxes, institution names, addresses, foreign-account values, and treatment
across related forms.

The review separates three things:

1. Corrections directly supported by the source documents.
2. Questions that need the preparer's judgment.
3. Important items that were checked and matched.

### The Mega Backdoor Roth Example
[Mega backdoor Roth][meg] (not to be confused with "backdoor Roth") is a popular
way to funnel extra money into a Roth account to grow tax-free regardless of
income.

[meg]: https://www.fidelity.com/learning-center/personal-finance/mega-backdoor-roth

1. You max out your 401(k) contribution with pre-tax money.
2. Add after-tax money up to the IRS limit.
    1. 401(k) contribution + employer match + mega backdoor Roth amount <= $72000 for 2026.
3. Call your financial institution to transfer the after-tax money to a Roth account.

Here's where it gets tricky. I keep the after-tax contributions in a money
market fund inside my normal 401(k) and convert once a year. The interest earned
before conversion also goes into the Roth account, but this interest is taxable.
Some people convert after every paycheck to minimize this tax. For me, less than
$100 in taxes is worth not having to call every other week.

My mega backdoor Roth maneuver produced two Forms 1099-R: one with Code G and
one with Code H. One reported only the principal; the other reported principal
and interest. Both appear on the return, so the rollover can look doubled. I
thought this was wrong, but it's how these transactions are reported and the
result went to the skill so (A)I know how it's reported.

# What Did We Learn Here Today?
AI was useful for:

* Searching large tax packets.
* Comparing the same value across several forms.
* Recalculating totals and currency conversions.
* Finding recurring typos and unchecked boxes.
* Turning findings into concise questions for the preparer.
* Checking whether requested corrections appeared in revised documents.

AI also made several mistakes during this process:

* It inferred a taxable part of the mega backdoor Roth rollover from the number
  of forms instead of using my description of what happened.
* Instead of gathering data for the packet, it started creating forms and
  filing the return. This is unfortunately common with "smarter" models.
* It added unnecessary process and large templates instead of following the
  packet that had already worked.

# The Final Workflow
I packaged the process as three marketplace plugins:

1. [pdf-to-markdown][sk-mark] for conversion and extraction verification.
2. [pdf-to-image][sk-pdf] for visual checks.
3. [us-tax-return][us-tax] for the preparer packet, prior-year comparison, and draft return review.
    * I also have a private version with specific personal info.
