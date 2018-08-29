---
date: "2016-02-14T20:52:45-05:00"
draft: false
title: "Archive Page in Hugo"
categories:
- Migration to Hugo
- Not Security
tags:
- Octopress
- Hugo
- Blog
---

This is a re-hash of my answer on Hugo forums about creating a custom archive page. You can see the answer [here](https://discuss.gohugo.io/t/blog-archives-page/2577/16).

Creating a custom archive page in Hugo is pretty simple. I think there are better ways to do this but this works as of version 0.15.

<!--more-->
Content types in Hugo are determined in two ways:

* Directory structure: For example in my blog, every blog post is in `content\post` and as a result is of type `post`. The template used to create each post is in `themes\Hugo-Octopress\layouts\post\single.html.` You can learn more by reading the [Content Types](https://gohugo.io/content/types/) section in Hugo documentation.

* Through a variable named `type` in [front matter](https://gohugo.io/content/front-matter). For example `type: mycustomtype` in the front matter will assign this type to the page. In this case, the page can be anywhere in the `content` directory and the directory structure is irrelevant.

To create an archive page, create a Markdown file in `content` and create a new type for it. The name of the file is going to determine the path of the generating file. If the file is named `content\archive.markdown` then it will be located at `baseurl/archive/` in my case. The name of the type does not have any effect on the path. Here's what I have in this file:

{{< codecaption lang="" title="content\archive.markdown" >}}
---
title: "Archive page"
type: myarchivetype
---
Blog archive
{{< /codecaption >}}

Another way to assign a URL to a page is through the `url` parameter in front matter. This overrides the path set before.

{{< codecaption title="markdown file with url tag" lang=""  >}}
---
title: "Archive page"
type: myarchivetype
url: "/path/to/archive/"
---
{{< /codecaption >}}

This makes the page to appear in `baseurl/path/to/archive/`.

The template used to generate this file is going to be located in `layouts\myarchivetype\single.html` (or `themes\theme-name\layouts\myarchivetype\single.html`). I have the following code in my this file:

``` html
{{ partial "header.html" . }}
<div id="main">
  <div id="content">
    <div>
      <article role="article">
        <header>
          <h1 class="entry-title">
            {{ .Title }}  <!-- title, in this case it will be "Archive page" -->
          </h1>
        </header>
        <div id="blog-archives" class="category">
          {{ .Content }} <!-- content of the markdown file. note that inside the range .Content will point to each page's content -->
          {{ range (where .Site.Pages "Type" "post") }}
          <h2>
            {{ .Date | dateFormat "2006"}} <!-- print publish year -->
          </h2>
          <article>
            <h1>
              <a href="{{ .Permalink }}" title="{{ .Title }}">{{ .Title }}</a>
            </h1>
            <time>
              <span class="month">{{ .Date | dateFormat "Jan" }}</span> <!-- print publish month -->
              <span class="day">{{ .Date | dateFormat "2" }}</span> <!-- print publish day -->
            </time>
              <!-- if you want pages summary you can print it here {{ .Summary }} -->
          </article>
          {{ end }}
        </div>
      </article>
    </div>
    {{ partial "sidebar.html" . }}
  </div>
</div>
{{ partial "footer.html" . }}
```

Notice that I have used `{{ range (where .Site.Pages "Type" "post") }}` to only iterate through pages of type `post`. You can use `{{ range .Site.Pages }}` to go through every markdown file. You can also use pagination (similar to the index page).

The `{{ .Content }}` variable points to the content of the `archive.markdown` page outside the `range` and to each page's content inside it.

You can see it in action at [Archive page]({{< ref "/archive.markdown" >}}).
