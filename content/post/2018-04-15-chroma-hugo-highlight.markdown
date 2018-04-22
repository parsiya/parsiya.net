---
title: "Adding Custom Chroma Styles to Hugo Themes"
date: 2018-04-15T13:38:57-04:00
draft: false
toc: false
comments: true
categories:
- Hugo
- Not Security
tags:
- Chroma
- CSS
---

Update: [Chroma][chroma] now [supports][solarized-pull] `solarized-dark` families. Currently, this version is not used in Hugo.

Hugo has switched to [Chroma][chroma] for syntax highlighting from Pygments. While it still supports Pygments, it appears Chroma is much faster. However, Chroma does not support the [solarized dark][solarized-dark-github] theme that is used by [Hugo-Octopress][hugo-octopress-github]. So I had to generate the CSS and add it manually.

The process is decently simple because Chroma has a [built-in tool for converting styles][chroma-styles] `_tools/style.py`. You can see the files inside my clone:

- https://github.com/parsiya/Parsia-Clone/tree/master/clone/random/chroma-pygments-convert

<!-- Links before summary -->

[chroma]: https://github.com/alecthomas/chroma
[hugo-octopress-github]: https://github.com/parsiya/Hugo-Octopress
[chroma-styles]: https://github.com/alecthomas/chroma#styles
[solarized-dark-github]: https://github.com/john2x/solarized-pygment/
[solarized-pull]: https://github.com/alecthomas/chroma/pull/140

<!--more-->

## Instructions
These steps are for an Ubuntu 16 machine, but can be adapted for any OS.

1. Install Go, configure `GOPATH` and the rest.
2. Install Chroma with `go get github.com/alecthomas/chroma`.
3. Install Python 3.
4. Install Pygments for Python 3: `sudo apt-get install python3-pygments`.
5. Install Pystache for Python 3: `sudo apt-get install python3-pystache`.
6. Clone `solarized dark`: `git clone https://github.com/john2x/solarized-pygment/` (do not need to install it).
7. (Optional) Rename the three py files inside `solarized=pygment/pygments_solarized` to more descriptive names. For example `dark.py` might become `solarized-dark.py`.
8. Open each of them and note the style class name. For example for `dark.py` it's `SolarizedDarkStyle`.
9. Copy the files to the `pygments` installation path. On my machine it was:
    * `/usr/local/lib/python3.5/dist-packages/Pygments-2.2.0-py3.5.egg/pygments/styles`.
10. Use the `_tools/style.py` to generate `go` files from styles:
    * `python3 style.py [style-name] pygments.styles.[py-file-name].[style-class-name] > style-name.go`
        - `style-name` is a string with new style's name. E.g. `solarized-dark`.
        - `py-file-name` is the name of the `py` file (w/o extension) that was copied to the Pygments directory. E.g. `dark`.
        - `style-class-name` is the name of the python class inside the style. E.g. `SolarizedDarkStyle`.
11. My example command was:
    *  `python3 style.py solarized-dark pygments.styles.dark.SolarizedDarkStyle > solarized-dark.go`
12. Repeat for any other styles.
13. Copy the resulting `go` files to `$GOPATH/Go/src/github.com/alecthomas/chroma/styles`.
    * You can open the file to double-check the style name passed to `chroma.MustNewStyle`:
    * `var SolarizedDark = Register(chroma.MustNewStyle("solarized-dark", chroma.StyleEntries{`
14. Now create the following Go application (or copy `createCSS.go`). Modify the file and style names as needed and execute it:
{{< codecaption title="createCSS.go" lang="go" >}}
package main

import (
    "os"

    "github.com/alecthomas/chroma/formatters/html"
    "github.com/alecthomas/chroma/styles"
)

func main() {
    f, _ := os.Create("solarized-dark.css")
    defer f.Close()

    formatter := html.New(html.WithClasses())
    if err := formatter.WriteCSS(f, styles.Get("solarized-dark")); err != nil {
        panic(err)
    }
}
{{< /codecaption >}}

15. Copy/paste the CSS files to your theme's CSS.
16. Inside your site's config file:
    * Remove `pygmentsUseClassic`: This will tell Hugo to use Chroma.
    * `pygmentsuseclasses = true`: Use CSS for highlighting.
    * `pygmentscodefences = true`: This adds code highlight to code fences.
