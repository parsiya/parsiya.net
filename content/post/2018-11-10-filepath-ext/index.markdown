---
title: "filepath.Ext Notes"
date: 2018-11-10T00:59:58-05:00
draft: false
toc: false
comments: true
twitterImage: main.png
categories:
- Go
tags:
- filepath
---

The [filepath][godoc-filepath] package has some functions for processing paths and filenames. I am using it extensively in a current project. You can do cool stuff with it, like [traversing a path recursively with filepath.Walk]({{< relref "/post/2018-10-06-gophercises-lessons-learned/index.markdown#filepath-walk" >}} "filepath.Walk").

[filepath.Ext][godoc-filepath-ext] returns the extension of a filename (or path). It returns whatever is after the last dot. It has some gotchas that might have security implications.

Code is at: https://github.com/parsiya/Parsia-Code/tree/master/filepath-ext

[godoc-filepath]: https://golang.org/pkg/path/filepath/
[godoc-filepath-ext]: https://golang.org/pkg/path/filepath/#Ext

<!--more-->

# Source
https://golang.org/src/path/filepath/path.go?s=6131:6159#L207

``` go
// Ext returns the file name extension used by path.
// The extension is the suffix beginning at the final dot
// in the final element of path; it is empty if there is
// no dot.
func Ext(path string) string {
	for i := len(path) - 1; i >= 0 && !os.IsPathSeparator(path[i]); i-- {
		if path[i] == '.' {
			return path[i:]
		}
	}
	return ""
}
```

# Example
To demonstrate the tips, we are going to create a simple example. Let's assume we have a file hosting service. We have created a blacklist of banned extensions. It checks the files by extension. This is not really a good way to do this:

1. It's better to default to deny and then use a whitelist.
2. Detecting file types by extension is easily bypassed by changing the extension. However, this might render some attacks invalid. Consider an attack where a user downloads a file, if the attacker has been forced to rename the file from `exe` to `txt` or another random extension, the user needs to manually rename it back and execute it.
   
But let's use it for demonstrating our points. This is the blacklist function:

``` go
// Blacklist returns true if a file is one of the banned types by checking its extension.
func Blacklist(filename string) bool {
	if filepath.Ext(filename) == ".exe" {
		return false
	}
	return true
}
```

# Ext Keeps the Case of Input
The input's letter case does not change. Everything is just passed through. Consider the following code (`case.go`):

``` go
package main

import (
	"fmt"
	"path/filepath"
)

func main() {
    fmt.Println("filepath.Ext(\"whatever.txt\"):", filepath.Ext("whatever.txt"))
    // filepath.Ext("whatever.txt"): .txt

    fmt.Println("filepath.Ext(\"whatever.TXT\"):", filepath.Ext("whatever.TXT"))
    // filepath.Ext("whatever.TXT"): .TXT

    fmt.Println("filepath.Ext(\"whatever.Txt\"):", filepath.Ext("whatever.Txt"))
    // filepath.Ext("whatever.Txt"): .Txt
}
```

To bypass the blacklist, we can just change the case `case_blacklist.go`:

``` go
func main() {
    fmt.Println("Blacklist(\"whatever.exe\"):", Blacklist("whatever.exe"))
    // true

    fmt.Println("Blacklist(\"whatever.ExE\"):", Blacklist("whatever.ExE"))
    // false
}
```

# Ext Returns the dot with the Extension
In our mind, the extension of a file is just the letters after the dot. It does not include the dot. However, Ext returns the dot. This is really unintuitive and has caught me off guard a few times.

``` go
package main

import (
	"fmt"
	"path/filepath"
)

func main() {
    fmt.Println("Blacklist(\"whatever.exe\"):", Blacklist("whatever.exe"))
    // true
}

// Blacklist returns true if a file is one of the banned types by checking its extension.
func Blacklist(filename string) bool {
	// Developers did not expect the dot to be part of the output.
	if filepath.Ext(filename) == "exe" {
		return false
	}
	return true
}
```

This blacklist is useless, the condition is never true.

# Returns an Empty String if Input has no Dots
This is mentioned in the docs but aI did not expect it.
