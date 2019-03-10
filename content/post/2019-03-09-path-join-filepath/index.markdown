---
title: "path.Join Considered Harmful"
date: 2019-03-09T20:43:40-05:00
draft: false
toc: false
comments: true
twitterImage: .png
categories:
- Go
tags:
- filepath
- path
---

Credit goes to my friend [Stark Riedesel](https://www.linkedin.com/in/stark-riedesel-4162b846). Check out his [github profile](https://github.com/starkriedesel/). One of these days I will bully him into reviving his blog.

TL;DR: Instead of [path.join](https://golang.org/pkg/path/#Join) use [filpath.Join](https://golang.org/pkg/path/filepath/).

<!--more-->

# What's Wrong with path.Join?
[path.Join][path.join] joins a bunch of paths together. Problem is, it uses `/` as separator regardless of operating system. We can see it in its source at https://golang.org/src/path/path.go?s=4034:4066#L145:

``` go
func Join(elem ...string) string {
	for i, e := range elem {
		if e != "" {
			return Clean(strings.Join(elem[i:], "/")) // <---
		}
	}
	return ""
}
```

This is problematic on Windows where your paths (or some of them) use `\` as separators. Consider this minimal example [Go playground link][playground1]:

``` go
package main

import (
	"fmt"
	"path"
)

func main() {
	// Create the path to the hosts file.
	path1 := "c:\\windows\\system32"
	path2 := "drivers\\etc\\hosts"

	fmt.Println(path.Join(path1, path2))
}
```

You would expect it to create the correct path. Instead, you get:

* `c:\windows\system32/drivers\etc\hosts`

# What Should We Use Instead?
Use [filpath.Join][filepath.join] instead. It uses OS specific separators.

Note 1: If you modify the example on the playground to `filepath.Join` you still get the same result. Obviously, Go playground is not running on Windows.

Note 2: Alternatively, you could convert all paths to use `/` as the separator. `c:/windows/system32/drivers/etc/hosts` is an acceptable Windows path. This is what I did in [borrowed time][bt-commit] after Stark told me about this issue.


<!-- Links -->
[path.join]: https://golang.org/pkg/path/#Join
[playground1]: https://play.golang.org/p/TcVY--mt8L9
[filepath.join]: https://golang.org/pkg/path/filepath/#Join
[bt-commit]: https://github.com/parsiya/borrowedtime/commit/e35b32d891bb160e8b03903de5ebdfd3f2db083b