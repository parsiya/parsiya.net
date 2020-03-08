---
title: "Pointers Inside for"
date: 2018-11-18T16:57:24-05:00
draft: false
toc: false
comments: true
twitterImage: 01.png
categories:
- Go
---

Do not directly assign the for counter/range variables to a slice as pointers. Read this by Jon Calhoun [Variables declared in for loops are passed by reference](https://www.calhoun.io/gotchas-and-common-mistakes-with-closures-in-go/#variables-declared-in-for-loops-are-passed-by-reference). "[...] the variables aren’t being redeclared with each iteration [...]".

I have written so much buggy code that I am going to write this down.

<!--more-->

Here's a sample program to reproduce it. In this case, we are creating a slice of int pointers, then assigning items in a for loop. The expectation is that it will contain references to 0-9 but it's not. `i` is not redeclared after each iteration, it's the same variable and we are storing a pointer to it in each iteration regardless of value. Run it on Go playground https://play.golang.org/p/EyS0KwWxf9g

``` go
package main

import "fmt"

func main() {
    // Create a slice of int pointers.
	var pInt []*int

    // Assign items in a counter.
	for i := 0; i < 10; i++ {
		pInt = append(pInt, &i)
	}

    // Print the slice.
	fmt.Println(pInt)
    
    // Print the values.
	for _, i := range pInt {
		fmt.Printf("%v ", *i)
	}
}
```

And the result is:

```
[0x416020 0x416020 0x416020 0x416020 0x416020 0x416020 0x416020 0x416020 0x416020 0x416020]
10 10 10 10 10 10 10 10 10 10 
```

This happens a lot when I am reading items from a slice with `range` and then `append`ing them to another slice. The solution is simple, create a  variable inside the `for` and then assign a pointer from that. Run it on Go playground https://play.golang.org/p/jDg8ruAtdA_r

``` go
package main

import "fmt"

func main() {
    // Create a slice of int pointers.
	var pInt []*int

    // Assign items in a counter.
	for i := 0; i < 10; i++ {
		// Temp variable.
		tempInt := i
		pInt = append(pInt, &tempInt)
	}

    // Print the slice.
	fmt.Println(pInt)
    
    // Print the values.
	for _, i := range pInt {
		fmt.Printf("%v ", *i)
	}
}
```

And it works:

```
[0x416020 0x416024 0x416028 0x41602c 0x416030 0x416034 0x416038 0x41603c 0x416040 0x416044]
0 1 2 3 4 5 6 7 8 9 
```