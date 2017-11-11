---
categories:
- Not security
comments: true
date: 2017-07-08T11:56:58-04:00
draft: false
tags:
- Sublime Text
- Atom
title: From Atom to Sublime Text
toc: true
---

I have moved from Atom to Sublime. Atom is a nice editor with a lot of features but it has a lot of performance issues for what I want to do.

Below is my setup for reference. When I want to do it again in a year (or a new machine) I can just use everything here or just use the config files. You can find a repo with the config files here: https://github.com/parsiya/sublime-config

<!--more-->

# Install Package Control
Install package control using: https://packagecontrol.io/installation.

#  Install Packages
Now you can install packages.

1. Press `Ctrl+Shift+P` to open the command palette.
2. Type `Install` and then select `Package Control: Install Package`.
3. Type the name of the package you are looking for to search for it.
4. Select the package and press Enter.

#  Markdown Packages

1. Markdown Extended: Syntax highlighting.
2. Markdown Preview.
3. Markdown Editing: Shortcut keys (e.g. ctrl+1 means heading 1).
4. Monokai Extended: Needed for highlighting.
5. LiveReload: For live markdown preview.
6. MarkdownTOC: Automatically generate clickable table of contents to markdown documents.
7. TOML: TOML highlighting.

# How to Use the Config Files
After installing packages, just copy the config files to the user package settings directory. On Windows it will be `"%Appdata%\Sublime Text 3\Packages\User\"` (don't forget the double quotes if you want to just paste it into the run prompt).

#  Package Settings and Locations
Generally sublime and each package have two types of settings, default and user. User settings are used to override default ones. Both are in JSON.

Settings can be opened via `Preferences > Package Settings > Settings Default/User`. I usually copy from default file to user, remove the unneeded settings and override the rest.

Package settings on Windows are at `%Appdata%\Sublime Text 3\Packages\User\package-name.sublime-settings`.

Main settings can be overridden in `Preferences.sublime-settings` or accessed via `Preferences > Settings`. This will open two files in one window. Left are the defaults settings and right is the user settings file. Copy from left pane to the right one and override.

#  Markdown Highlighting and Spell Check
`Markdown Editing` has its own color scheme. I don't like it. Instead I use `Monokai Extended`. It can be selected from `Preferences > Color Scheme > Monokai Extended > Monokai Extended`.

In order for it to kick in, the document type need to be set to `Markdown Extended`. This can be set by clicking on document type (bottom right).

Next you want to set all markdown files to be opened as `Markdown Extended` for syntax highlighting (including code blocks). This can be done by:

- `View (menu) > Syntax > Open all with current extension as > Markdown Extended`.

This method only sets it for the current extension (e.g. md).

Go to `Preferences > Settings - Syntax Specific` or edit package settings `Markdown Extended.sublime-settings` and add the following:

``` json
{
  "extensions":
  [
    "md",
    "markdown",
    "moreextensions"
  ],
  "spell_check": true	// enable spell check
}
```

Note that `Markdown Editing` has added itself for `.mdown` files. You can just delete the file `Markdown.sublime-settings` and add the extensions in the previous file.

#  Setting up Markdown Live Preview

##  Enable LiveReload via Settings
Add the following to user settings for the LiveReload package `LiveReload.sublime-settings`:

``` json
{
  "enabled_plugins": [
   "SimpleReloadPlugin",
   "SimpleRefreshDelay"	// use SimpleRefresh for reload without delay
  ]
}
```
This way it does not need to be re-enabled after every start.

##  Enable LiveReload Manually (need to do after every Sublime launch)
1. Open command palette and type `livereload`.
2. Select `LiveReload: Enable/disable plug-ins`.
3. Select `Enable - Simple Reload with delay(400ms)`.
4. You should see a console message saying it was enabled. Note that the menu will say `Enable` whether it's enabled or not, if it's already enabled choosing the menu will disable it so make sure to look at the console messages.

##  Configure Markdown Preview
Supposedly these two plugins work out of the box. It was not in my case. I had to add autoreload in markdown preview. I removed the `github` parser because it sends the markdown file to Github to be processed.

Add the following to `MarkdownPreview.sublime-settings`:

``` json
{
  "enable_autoreload": true,
  "enabled_parsers": ["markdown"],
  "enable_highlight": true
}
```

##  Preview Files
1. Open command palette and select `Markdown Preview: Preview in Browser`.
2. A new browser window will open to display the rendered document.
2. Browser should update after every save.

## Preview Keybind
Add the following to `Default (Windows).sublime-keymap` or open it via `Preferences > Key Bindings`.

``` json
[
  {
  "keys": [
    "alt+p"
  ],
  "command": "markdown_preview",
  "args": {
    "target": "browser",
    "parser": "markdown"
  }
  }
]
```

#  Markdown Table of Content
1. Install package `Markdown TOC`.
2. Add the following user settings to `MarkdownTOC.sublime-settings`:

``` json
{
  "default_autoanchor": true,  // adds anchor to headings in not present
  "default_autolink": true,	 // make the ToC linkable
  "default_bracket": "round",  // use parentheses for link (e.g. [linktext](linkreference)) otherwise both will be brackets (square)
  "default_depth": 0  // 0 = unlimited depth
}
```
3. In any markdown document, put the cursor where you want the T0C. Then `Tools > MarkdownTOC > Insert TOC`.
4. All settings can also be controlled in the T0C by adding them to the top comment. For example:

```
<!-- MarkdownTOC style="round" autolink="true" depth=0 -->

- [Heading 1]
- [Heading 2]

<!-- /MarkdownTOC -->
```

## TOC Keybind
Add the following to the keymap `Default (Windows).sublime-keymap`:

``` json
{
  "keys": [
    "alt+t"
  ],
  "command": "markdowntoc_insert"  // update is markdowntoc_update
}
```

# Change Bold and Italic Markers
By default in markdown editing, bold marker is `__` and italic is `_`. I am more used to `**` for bold and `*` for italic.

Simply add a file named `Bold and Italic Markers.tmPreferences` and put it in the usual User directory.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>name</key>
  <string>Bold and Italic Markers</string>
  <key>scope</key>
  <string>text.html.markdown</string>
  <key>settings</key>
  <dict>
    <key>shellVariables</key>
    <array>
      <dict>
        <key>name</key>
        <string>MD_BOLD_MARKER</string>
        <key>value</key>
        <string>**</string>
      </dict>
      <dict>
        <key>name</key>
        <string>MD_ITALIC_MARKER</string>
        <key>value</key>
        <string>*</string>
      </dict>
    </array>
  </dict>
  <key>uuid</key>
  <string>E3F0F1B0-53C8-11E3-8F96-0800200C9A66</string>
</dict>
</plist>
```

# Snippets vs. Completions
Essentially both do the same.

1. Snippets are XML while Completions are JSON.
2. Snippets are easier to read because you can have new lines in `CDATA` tags while you have to escape doublequotes and use special characters for new lines (e.g. `\n`).
3. Only one snippet is allowed per file while you can have multiple completions in one file.

Mainly as a result of 3, I went with completions because it's just one file and easier to manage (although harder to read).

## Snippet
`Tools > Developer > New Snippet` will create and open a template. Files are stored in the `User` directory similar to config files (although packages can have their own snippets). Extension for snippets is `sublime-snippet`.

Unofficial documentation page: http://docs.sublimetext.info/en/latest/extensibility/snippets.html.

Actual snippet is in the `content` tag which supports new lines inside `CDATA`.

For example the Snippet for my Hugo shortcode `codecaption` [(link)][hugo-codecap-link]. Remove the space in `{{[space]<` to get the actual snippet or look at the repo (otherwise my theme's shortcode would break the codeblock).

``` xml
<snippet>
  <content><![CDATA[{{ < codecaption title="$1" lang="$2" >}}
${3:default text}
{{ < /codecaption >}}
    ]]></content>
  <!-- Optional: Set a tabTrigger to define how to trigger the snippet -->
  <tabTrigger>codecap</tabTrigger>
  <!-- Optional: Set a scope to limit where the snippet will trigger -->
  <scope>text.html.markdown</scope>
  <!-- Optional: Description to show in the menu -->
  <description>Codecaption Hugo Shortcode</description>
</snippet>
```

`$1` means the cursor will be there after the snippet is activated, after typing and pressing `tab` we will jump to `$2`. `$3` has a default text which will be highlighted after cursor jumps to it and can be overwritten.

`scope`is where the snippet will be active. Without a scope, it's active in all documents. To get the current scope press `ctrl+alt+shift+p` or through `Tools > Developer > Show Scope Name`.

Same thing can be done for `imgcaption` [(link)][hugo-imgcap-link]. Remove the space in `{{[space]<` to get the actual snippet.

``` xml
<snippet>
	<content><![CDATA[{{ < imgcap title="$1" src="/images/2017/${2:imagepath}" >}}]]></content>
	<!-- Optional: Set a tabTrigger to define how to trigger the snippet -->
	<tabTrigger>imgcap</tabTrigger>
	<!-- Optional: Set a scope to limit where the snippet will trigger -->
	<scope>text.html.markdown</scope>
	<!-- Optional: Description to show in the menu -->
  <description>Imagecaption Hugo Shortcode</description>
</snippet>
```
## Completions
I prefer completions because all can be in one file. For most purposes we can treat them like snippets. They are JSON files so escape `"` with `\"` and new line is `\n`.

Link to unofficial wiki: http://docs.sublimetext.info/en/latest/reference/completions.html.

Completions are stored in the `User` directory with extension `.sublime-completions`.

Sample completion file for markdown for the same shortcodes. Note the triggers are the same as the ones in snippet examples above. Snippets always have priority over completions. Remove the space in `{{[space]<`.

``` json
{
   "scope": "text.html.markdown - source - meta.tag, punctuation.definition.tag.begin",

   "completions":
   [
      { "trigger": "codecap\tCodecaption Hugo Shortcode", "contents": "{{ < codecaption title=\"$1\" lang=\"$2\" >}}\n${3:default text}\n{{ < /codecaption >}}" },
      { "trigger": "imgcap\tImagecaption Hugo Shortcode", "contents": "{{ < imgcap title=\"$1\" src=\"/images/2017/${2:1.png}\" >}}" }
   ]
}
```

Note the `trigger`, the first part is the actual trigger and everything after `\t` is the hint that appears in the autocompletion list similar to snippet descriptions.

There are tons of `completion` files for different languages and frameworks online and in package control.

## Snippet and Completion Triggers
In short type the trigger (or parts of it if it's unique) and press `tab`. If there are snippets and completions with the same triggers, snippets always have priority.

- Typing `codecap` and pressing `tab` will activate the snippet/completion.
- Typing `code` and `ctrl+space` will show it in the auto-complete menu.
- Typing `snippet` in the command palette will show all snippets for the current scope along with their triggers.

<!-- Reference links -->

[hugo-codecap-link]: https://github.com/parsiya/Hugo-Shortcodes#codecaption-codecaptionhtml
[hugo-imgcap-link]:  https://github.com/parsiya/Hugo-Shortcodes#image-caption-imgcaphtml
