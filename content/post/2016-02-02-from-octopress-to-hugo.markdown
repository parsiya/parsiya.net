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

In [my previous post]({{< ref "2016-01-31-why-hugo.markdown" >}} "Why Hugo?") I talked about why I moved from Octopress to Hugo. You can also see the last archive of my Octopress blog (previously a private repo on Bitbucket) on [github](https://github.com/parsiya/Octopress-Blog) and this is the new site. If I had wanted to use an already existing Hugo theme, it would have not taken more than a few hours.

In this post I am going to talk about how I managed the migration and any interesting things that I encountered in the process. I will also introduce the [Hugo-Octopress][hugo-octopress-link] theme (you are looking at it), which is the classic Octopress theme ported to Hugo. If you like what you see, please go ahead and use it. If there are any issues please use the [Github issue tracker](https://github.com/parsiya/Hugo-Octopress/issues) or contact me another way. I will try my best to fix them but please remember that I am not a developer and do not know much about css :).

[hugo-octopress-link]: https://github.com/parsiya/hugo-octopress/
<!--more-->

### hugo import jekyll
Hugo has an [Import from Jekyll][hugo-import-jekyll] feature. Octopress is also built on Jekyll but its directory structure is a bit different from Jekyll. Just running `hugo import jekyll` in will not work. In Jekyll posts are usually stored in `jekyll-blog/posts/` while in Octopress they are in `octopress-blog/source/_posts/`. When importing from Octopress you have to point it to the `source` directory like this:

```
$ hugo import jekyll source/ hugo-import/
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

Perhaps I did not use it properly, it is not built for Octopress anyways but the import process did not do much for me other than creating the basis for a hugo blog (e.g. empty `layouts` directory). I could have copied the Markdown files and use a bunch of `sed` commands to replace the headers.

### Octopress Classic Theme or Hugo-Octopress
Unlike [Pelican](https://github.com/duilio/pelican-octopress-theme), Hugo did not have an Octopress theme. I tried other themes such as [Hyde-X][hyde-x-link] (which I got a few good ideas from) and [Red Lounge][red-lounge-link]. Hugo has a nice [theme showcase][hugo-theme-showcase] that you can check out. Not all themes are in the showcase, you can see a lot of them [here](https://github.com/spf13/hugoThemes/).

Unfortunately none of them were to my liking. I like the Octopress classic theme. So I decided to port my own. I learned a lot about Hugo's internals and I also learned some `css`. Hugo's template system should be praised. It's very easy to modify page structure and add/remove elements. Essentially I took the css file from Octopress and then tried to re-create the same structure in Hugo. I also modified the theme to add [Font Awesome](http://fontawesome.io) icons (seen in Hyde-x) in the sidebar. After a lot of tinkering, I have a theme that is decently similar to the classic Octopress theme. The css is a mess and I may never even clean it up. I do not know where to start to be honest so if you decide that is what you want to do, please go ahead and fork the repo.

You can find the theme on github named [Hugo-Octopress](https://github.com/parsiya/hugo-octopress/). These days I use Bitbucket for my private repos and major backup while Github is for public repos (not that I have much open source stuff).

### Shortcodes
I needed captions for images and codeblocks. Hugo does not have this by default but offers [shortcodes][hugo-shortcodes] which are very very simple to create. Compared to plugin creation for Jekyll, Octopress or Pelican, it's a walk in the park. I managed to create these two shortcodes in a few minutes. To their credit, Octopress and Jekyll already had these plugins. Pelican supports image captions in [reStructuredText](http://docs.getpelican.com/en/3.6.3/content.html) but not in Markdown.

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

By using the `highlight` function in Hugo, I passed everything between the opening and closing tags through `.Inner` to `pygments` along with the language and an option to enable line numbers. The output of the `highlight` function is a table with two rows:

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

{{< codecaption lang="html" title="Overflowwwwwwwwww" >}}
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
{{< /codecaption >}}

Normal backtick blocks are converted into html code similar to the following:

``` html
<div class="highlight" style="background: #002B36">
  <pre style="line-height: 125%">
    <!-- highlighted code -->
  </pre>
</div>
```
To give them the same horizontal scrollbar, I had to modify the css for `div.highlight`. But that interfered with the div.highlight in the codecaption output. Instead I used the following properties that only applies to div.highlights inside `div.entry-content` (which contains the contents of each post):

``` css
div.entry-content > div.highlight {
    border-color: #002B36;
    overflow-x: auto;
    overflow-y: hidden;
    margin-bottom: 0.4em;
}
```
codecaption's final output is similar to this:

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
Image caption was also simple. I tried to imitate the output of `imgcap` plugin in Octopress.

{{< codecaption lang="html" title="imgcap" >}}
<span class="caption-wrapper">
  <img class="caption" src="{{ .Get "src" }}" title="{{ .Get "title" }}"
   alt="{{ .Get "title" }}">
  <span class="caption-text">{{ .Get "title" }}</span>
</span>
{{< /codecaption >}}

It can be used as follows (replace the space in `{{ <`): `{{ < imgcap title="image caption" src="/images/" >}}`.

### Replacing Liquid tags
Mext step was to replace the liquid tags used in Markdown files. I had a few different types of tags for images and codeblocks. I used a few `sed` commands to search and replace the items.

``` bash
sed -i -- 's/{% imgcap \([^ ]*\) \(.*\) %}/{{ < imgcap src="\1" caption="\2" >}}/' content/post/*.markdown

sed -i -- 's/{% imgpopup \([^ ]*\) [^ ]* \(.*\) %}/{{ < imgcap src="\1" caption="\2" >}}/' *.markdown

sed -i -- 's/{% codeblock lang:\([^ ]*\) \(.*\) %}/{{ < codecaption lang="\1" title="\2" >}}/' *.markdown

sed -i -- `s/{% endcodeblock %}/{{ < /codecaption >}}` *.markdown
```
In almost all commands, I have modified the opening tag to `{{ <` to avoid triggering the shortcode so please modify them accordingly.

----------

This was a nice distraction. I hope to re-start writing about security stuff again. Maybe I should write shorter posts instead of going on and on forever.


[hugo-import-jekyll]: https://gohugo.io/commands/hugo_import_jekyll/
[hugo-shortcodes]: https://gohugo.io/extras/shortcodes/
[hyde-x-link]: https://github.com/zyro/hyde-x
[red-lounge-link]: https://github.com/tmaiaroto/hugo-redlounge
[hugo-theme-showcase]: http://themes.gohugo.io/
