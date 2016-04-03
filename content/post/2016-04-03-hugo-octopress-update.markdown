---
categories:
- Not Security
- Migration to Hugo
date: 2016-04-03T13:13:39-04:00
draft: false
tags:
- Hugo
- Blog
- Hugo-Octopress
title: Hugo Octopress Update
---
I have made a good number of changes to the [Hugo-Octopress](https://github.com/parsiya/hugo-octopress) theme. As I have been using the theme more and more, I have realized there were a bunch of bugs (some were pointed out on Github).

I had also hardcoded too many settings in the theme. For example, modifying the text in the sidebar had to be done by modifying the theme. Ideally using the theme should not need the user to modify anything in theme and can configure it by just using the config file. I created a bunch of issues and then closed them myself. I am not quite sure if this is correct but eh :D

<!--more-->

# Changelog:

* Number of recent posts in sidebar is now fetched from the config file. Default is five.
* Users can override theme css using their own css file.
* Sidebar header and text can be customized in the config file.
* Replaced hardcoded generator tag in header with Hugo function.
* Reduced blockquote font size.
* Reduced H1 and H2 sizes in article body. They can now be used in articles to generate a proper table of contents.
* Theme now supports adding Table of Contents to posts. It can be either set globally in the config file or added in the page frontmatter using `toc: true`.
* 404.html page can be customized via the config file.
* Disqus template will only be injected into posts if disqus shortname is set in the config file. Comments can be disabled for each page by adding `comments: false` in its frontmatter.

There's one big problem, I cannot use Hugo variables in the config file, because I pass everything to the `markdownify` function.

That was it, if you want a feature or find a bug please create an issue on Github.
