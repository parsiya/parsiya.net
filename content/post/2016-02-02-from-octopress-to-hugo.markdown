---
date: "2016-02-02T22:58:26-05:00"
draft: false
title: "From Octopress to Hugo"
categories:
- migration to Hugo
tags:
- Octopress
- Hugo
---

In [last post]({{< ref "2016-01-31-why-hugo.markdown" >}} "Why Hugo?") I talked about why I moved from Octopress to Hugo. In this post I am going to talk about how I managed the migration and any interesting things that I encountered in the process. I will also introduce the [Hugo-Octopress][hugo-octopress-link] theme (you are looking at it), which is the classic Octopress theme ported to Hugo.

You can also see the last archive of my Octopress blog (previously a private repo on Bitbucket) on github: [https://github.com/parsiya/Octopress-Blog](https://github.com/parsiya/Octopress-Blog).

[hugo-octopress-link]: https://github.com/parsiya/hugo-octopress/
<!--more-->

### hugo import jekyll
Hugo has an [Import from Jekyll][hugo-import-jekyll] feature. Octopress is also built on Jekyll but its directory structure is a bit different from Jekyll. Just running `hugo import jekyll` in will not work. In Jekyll posts are usually stored in `jekyll-blog/posts/` while in Octopress they are in `octopress-blog/source/_posts/`. When importing from Octopress you have to point it to the `source` directory like this:

```
root@debian:~/Desktop/octopress-blog# hugo import jekyll source/ hugo-import/
Importing...
Congratulations! 23 posts imported!
Now, start Hugo by yourself:
$ git clone https://github.com/spf13/herring-cove.git hugo-import//themes/herring-cove
$ cd hugo-import/
$ hugo server -w --theme=herring-cove
```
Converted Markdown posts will be in `hugo-import/content/posts/` and almost everything else will in `hugo-import/static/`.

```
# before conversion
---
layout: post
title: "Proxying Hipchat Part 3: SSL Added and Removed Here :^)"
date: 2015-10-19 21:42:10 -0400
comments: true
categories: ['Hipchat','Proxying','Burp', 'Python']
---
```

```
# after conversion
---
categories:
- Hipchat
- Proxying
- Burp
- Python
comments: true
date: 2015-10-19T21:42:10Z
title: 'Proxying Hipchat Part 3: SSL Added and Removed Here :^)'
url: /2015/10/19/proxying-hipchat-part-3-ssl-added-and-removed-here/
---
```

The only thing I needed to remove was `url` because I wanted my URLs to be similar to `/blog/2015-10-19-proxying-hipchat-part-3-ssl-added-and-removed-here/`. This can be accomplished by adding the following to the config file:

```
[permalinks]
post = "/blog/:year-:month-:day-:title/"
```

I deleted almost everything else in the `static` directory apart from the following:

* `images` directory
* `favicon.png`: because I wanted to keep the Octopress feel
* `stylesheets/screen.css`: needed for porting the themes, although I moved it to `css\hugo-octopress.css`

Perhaps I did not use it properly, it is not built for Octopress anyways but the import process did not do much for me other than creating the basis for a  hugo blog (e.g. empty `layouts` directory). I could have copied the Markdown files and use a bunch of `sed` commands to replace the headers.

### Shortcodes
I needed captions for images and codeblocks. Hugo does not have this by default but offers [shortcodes][hugo-shortcodes] which are very very simple create. Compared to plugin creation for Jekyll, Octopress or Pelican, it's a walk in the park. I managed to create these two shortcodes in a few minutes. Granted Octopress and Jekyll already have these plugins.

#### Codecaption
The codecaption block was quite simple. You can also see the result here.

{{< codecaption lang="html" title="codecaption shortcode" >}}
<figure class="code">
  <figcaption>
  	<span>{{ .Get "title" }}</span>
  </figcaption>
  <div class="codewrapper">
    {{ highlight .Inner (.Get "lang") "linenos=true" }}
  </div>
</figure>
{{< /codecaption >}}

The `highlight` function in Hugo, passes everything between the opening and closing tags `.Inner` to `pygments` along with the language and an option to enable line numbers. The output of the `highlight` function is a table with two rows:

``` html
<table class="highlighttable">
  <tbody>
    <tr>
      <td>
        <div class="linenodiv" style="background-color: #f0f0f0; padding-right: 10px">
          <pre style="line-height: 125%">
             <!-- line numbers go here -->
          </pre>
        </div>
      </td>
      <td class="code">
        <div class="highlight" style="background: #002B36">
          <pre style="line-height: 125%">
            <!-- highlighted code -->
          </pre>
        </div>
      </td>
    </tr>
  </tbody>
</table>
```

I needed to do something for when the code overflowed. By adding code-wrap in `css`, line numbers and code would lose alignment. By adding `overflow-x: auto` to the `highlight` div, it would get a horizontal scrollbar but that would again mess with the alignment with line numbers.

The solution was to wrap the whole table in a div and then give the div the following properties in css:

``` css
div.codewrapper {
    overflow-x: auto;
    overflow-y: hidden;
    background-color: #002B36;
}
```

And that enables a horizontal scrollbar as you can see below:

{{< codecaption lang="html" title="" >}}
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
{{< /codecaption >}}

Normal backtick blocks are converted into something like the following:

``` html
<div class="highlight" style="background: #002B36">
  <pre style="line-height: 125%">
    <!-- highlighted code -->
  </pre>
</div>
```
To give them the same capability for overflow would mean that I had to modify the css for `div.highlight`. But that interfered with the div.highlight in the codecaption output. Instead I used the following that only applies to div.highlights inside `div.entry-content` (which contains the contents of each post):

``` css
div.entry-content > div.highlight {
    border-color: #002B36;
    overflow-x: auto;
    overflow-y: hidden;
    margin-bottom: 0.4em;
}
```
Finally codecaption's output is similar to this:

``` html
<figure class="code">
  <figcaption>
  	<span>codecaption shortcode</span>
  </figcaption>
  <div class="codewrapper">
    <table class="highlighttable"></table>
  </div>
</figure>
```

#### imgcap
Image caption was similarly simple. I tried to imitate the output of `imgcap` plugin in Octopress.

{{< codecaption lang="html" title="imgcap" >}}
<span class="caption-wrapper">
  <img class="caption" src="{{ .Get "src" }}" title="{{ .Get "title" }}"
   alt="{{ .Get "title" }}">
  <span class="caption-text">{{ .Get "title" }}</span>
</span>
{{< /codecaption >}}

It can be used as follows (replace the space in `{{ <`): `{{ < imgcap title="image caption" src="/images/" >}}`












### Replacing Liquid tags
The next step was to replace the liquid tags used in Markdown files. I had a few different types of tags for images and codeblocks. I used a few `sed` commands to search and replace them



[hugo-import-jekyll]: https://gohugo.io/commands/hugo_import_jekyll/
[hugo-shortcodes]: https://gohugo.io/extras/shortcodes/
