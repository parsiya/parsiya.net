---
title: "Documentation Writing for System Administrators - Notes"
date: 2020-02-06T23:21:57-08:00
draft: false
toc: true
comments: true
twitterImage: merrin-cal.jpg
categories:
- Not Security
- Automation
- Documentation
---

These are my notes for the booklet `Documentation Writing for System Administrtors`.
It's from 2003, so some of the tools and procedures are old. However, somethings
never change and it's still useful.

* https://www.usenix.org/short-topics/documentation-writing-system-administrators

<!--more-->

{{< imgcap title="Do you have the documentation for this planet, Cal?" src="merrin-cal.jpg" >}}

[Image credit: Electronic Arts - Star Wars Jedi: Fallen Order](https://www.ea.com/games/starwars/jedi-fallen-order/media).

# Introduction
Follow five simple rules when setting out to write your documentation:

1. Know your audience.
    1. Know who will be reading your documentation.
    2. Know what they need to get out of it.
2. Know your content.
    3. Know what type of information you’re going to present and what level of detail is appropriate for your audience.
3. Know your requirements.
    4. Define requirements before you start.
4. Make it a habit.
    5. All documentation should be viewed as “living” documentation.
    6. Keep maintaining it and modify it if changes happen.
5. Advertise.
    7. Tell people about it.

# 1. Documentation Content
There are two basic types of documentation:

* Procedural
    * Offers a set of instructions, telling the reader how to achieve some goal.
* Informational
    * Records the state of an object or collectivity.
    * E.g., System configuration, network diagrams.
Good quote:
“Approach each day with the assumption that anything not written down will be forgotten.”

## Procedural Documentation
Producing documentation as you work has several other benefits:

1. Creating a record of your work that will come in handy down the road
2. Producing a tangible product of your labor. This is useful for job reviews.
3. Giving yourself small breaks in your work to review it. Catching small mistakes before they become big problems.
Procedural documentation addresses multiple goals:

* Standardize departmental behavior.
* Provide a means to automate and optimize tasks.
    * Procedural documentation is usually a means to automation.
* Facilitate troubleshooting.
    * Easier to fix problems with documentation.
* Assist others who must accomplish the same or similar tasks in the future.

## Informational Documentation

* Configuration data, software inventories, etc.
* Looks static but it’s not. Changes all the time.
* If it changes a lot, consider using another way of documenting it.
    * E.g., automation.

# 2. Writing Good Documentation

## Know Your Audience

* What are you documenting and for whom?
* Define your audience in writing when beginning a new document until you are finished.
    * Might even keep it in an appendix.

## The Keys to Good Documentation

### The Components of Good Documentation
Good documentation is:

* Useful
    * Serves a purpose and addresses a need.
* Accessible
    * Communicates clearly.
    * Its purpose and audience are obvious to the reader.
* Accurate
    * Factually correct and complete.
    * Kept current as the subject matter changes.
* Available
    * There when you need it.

### Reviewing

* Review the documentation regularly to ensure that it continues to meet these criteria.
* First review immediately after writing and before publication.
* Reviews whenever changes are made that directly impact the document’s content.
* Allow users to submit feedback.

# 3. Documentation Format

* Biggest problem with documentation is that it seems like extra work.
* Routinize writing documentation:
    * Do it as you research a new procedure.
    * Do it when you change anything.
    * Do it when you successfully solve an issue.
Three formats:

* Paper
    * Did not take any notes for the paper section because I do not use paper most of the time.
* Web-based

## Web-Based Documentation

* Searchable
* Easy maintenance
    * Can even be automated (usually for informational documentation).
* Easier presentation. Can highlight, add comments, code blocks.
* Easy hierarchies, links, etc.
* Bookmarks.

## Flat-File Documentation

* Everything in one file and freeform.
* Useful for quick notes and simple tasks.
* Source code comments are an example of this type of documentation.

# 4. Documentation Tools
Skipped over most of this section because the document is old and does not have a lot of newer tools that are in use today.

## Testing the Documentation
Provide it to the following people in order:

1. Yourself
2. One or more members of the target audience.
3. At least one person outside the target audience.

# 5. Documentation Strategy
What if there’s no documentation and no policy?

1. Identify what’s necessary.
    1. For a week or two write down anything you need to do.
2. Identify what’s available.
    2. Gather everything that is available and categorize it.
    3. Can you reuse anything here for tasks in the last step?
        1. Re-examine it and revise it if needed.
    4. Is there something here that you do not need?
        2. Might be there for a reason.
    5. Now you have three categories:
        3. Documents that are necessary and adequate.
        4. Documents that are necessary but need work.
        5. Unnecessary documents.
3. Identify what’s important.
    6. Prioritize documentation.
        6. Some are more important.
        7. Some are easy work.
4. Establish policy and procedure.
    7. Setup as a framework for documentation efforts moving forward.

## Documentation Maintenance and Designated Responsible Individual (DRI)
DRI is the person that ensures documentation is:

* Complete
* Accurate
* Necessary

DRI also needs to review the documentation at intervals.
