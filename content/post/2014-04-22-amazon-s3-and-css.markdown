---
categories:
- Amazon S3
tags:
- Amazon S3
- CSS
- content-type
comments: true
date: 2014-04-22T14:03:32Z
title: Amazon S3 and CSS
---

After I deployed my blog to Amazon S3, I realized that there was no CSS applied to the pages. In Octopress, the look and feel of website is managed by ```stylesheets/screen.css```. It was fine in ```rake preview``` but not on the S3 bucket. I looked around for a few hours to no avail. There was one other person who had the same issue on [stackoverflow] [stackoverflowlink] but no answers. Relevant [xkcd] [xkcdlink]:

{{< imgcap  src="http://imgs.xkcd.com/comics/wisdom_of_the_ancients.png" title="Wisdom of the Ancients" >}}

I finally found my answer. There are other static websites out there so I removed Octopress from my search terms (facepalm! I got my first MSc. in query expansion). This [stackoverflow answer] [stackoverflowlink2] sent me to [Adam Wilcox's website] [adamwilcoxlink] and saved the day. Thanks Adam.

Simple fix, go to Amazon S3 bucket web interface. Find ```stylesheets/screen.css```. Go to metadata tab and change ```content-type``` to ```text/css```. This has to be repeated every time ```screen.css``` is updated (unless I can find how to do this with ```S3cmd```). Usually this is not the case, when I generate my blog again I can see the following indicating that ```screen.css``` is not changed (unless you change the theme?):

``` bash
root@kali:~/Desktop/octopress# rake generate
## Generating Site with Jekyll
identical source/stylesheets/screen.css 
Configuration from /root/Desktop/octopress/_config.yml
Building site: source -> public
Successfully generated site: source -> public
```

[stackoverflowlink]: http://stackoverflow.com/questions/17138615/discrepency-in-rake-preview-vs-rake-deploy
[stackoverflowlink2]: http://stackoverflow.com/a/14807743
[xkcdlink]: https://xkcd.com/979/
[adamwilcoxlink]: http://www.adamwilcox.org/2012/05/04/css-on-amazon-s3/

