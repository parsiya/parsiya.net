---
categories:
- Octopress
- Not Security
tags:
- imgpopup
- Blog
comments: true
date: 2015-07-26T23:02:58Z
title: Image Popup and Octopress
---

**Update**: I have migrated the blog to [Hugo](https://gohugo.io) and I do not use this anymore. However, it is still in the repository.

I finally realized that I need an image popup plugin. The image plugins that I usually use do not support this. They are fine for normal images but not for larger ones. When I see an screenshot of a tool, I want to be able to zoom in. In my quest I looked at a few plugins and methods and finally decided to use [https://github.com/ctdk/octopress-image-popup][original repo]. It creates resized thumbnails automatically and the installation procedure is short and simple.

However, it did not work for me out of the box. I created a test post with just an image and while the plugin worked, there are things that I did not like about it.

[original repo]: https://github.com/ctdk/octopress-image-popup
<!--more-->

{{< imgcap src="/images/2015/popup1/pew1.jpg" title="test post" >}}

There is this text "Click the image for a larger view." and there is also an unresized copy of the image on the page.

By inspecting these two elements, we can find the culprits in the page source (comments are mine).

{{< codecaption lang="html" title="page source" >}}
...
<div class="imgpopup screen">
  <!-- caption -->
  <div class="caption">Click the image for a larger view.</div>
  <a href="javascript:void(0)" style="text-decoration: none" id="image-1">
    <img src="/images/2015/pew.jpg" width="300" height="221" alt="Click me." />
  </a>

...
<!-- unresized copy -->
<div class="illustration print">
  <img src="/images/2015/pew.jpg" width="600" height="441" />
</div>
{{< /codecaption >}}

During installation we have only copied two files (apart from editing `head.html`): `img_popup.rb` and `img_popup.html.erb`. The html file is probably your first guess to and you are right. Inside we can see html tags (original copy is at [https://github.com/ctdk/octopress-image-popup/blob/master/plugins/img_popup.html.erb][img_popup.html.erb]):

{{< codecaption lang="html" title="img_popup.html.erb" >}}
...

<div class="imgpopup screen">
  <div class="caption">Click the image for a larger view.</div>
  <a href='javascript:void(0)' style="text-decoration: none" id="image-<%= id %>">
    <img src="<%= scaled_image %>"
         width="<%= scaled_width %>" height="<%= scaled_height %>"
         alt="Click me."/>
  </a>

...

<div class="illustration print">
  <img src="<%= image %>" width="<%= full_width %>" height="<%= full_height %>"/>
</div>

{{< /codecaption >}}

I am not quite sure what this `erb` file does but it looks like to be a blueprint for the final html content. We can just remove those parts that we want: the caption and the "illustration print" class.

Another problem is after we click on the image. There is no space between image title and the "close" link.

{{< imgcap src="/images/2015/popup1/pew2.jpg" title="pew pew popup" >}}

To fix this we need to modify `img_popup.rb` (original at [https://github.com/ctdk/octopress-image-popup/blob/master/plugins/img_popup.rb][img_popup.rb]):

{{< codecaption lang="html" title="img_popup.rb" >}}

...
vars = {
  'id'      => @@id.to_s,
  'image'   => @path,
  'title'   => @title
}

...
{{< /codecaption >}}

We can see `title` saved in `vars['title']`. So we can just add a space to the end of it using the following line:  
`vars['title'] += " "`

And that's it, it works as you can see in this post. Modified code is at: [https://bitbucket.org/parsiya/octopress-image-popup-forked][modified_code]. I hope I did not mess up the licensing and such :).

Update August 1, 2015: The tag adds this annoying extra line(s) before the image on the page. I have not had time to look into removing it. To be honest I do not like it that much. I will be using the image caption tag if the image is big enough to not need a pop-up.

[original repo]: https://github.com/ctdk/octopress-image-popup
[img_popup.html.erb]: https://github.com/ctdk/octopress-image-popup/blob/master/plugins/img_popup.html.erb
[img_popup.rb]: https://github.com/ctdk/octopress-image-popup/blob/master/plugins/img_popup.rb
[modified_code]: https://github.com/parsiya/Random-Code/tree/master/octopress-image-popup-forked
