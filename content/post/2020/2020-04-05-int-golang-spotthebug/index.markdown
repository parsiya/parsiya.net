---
title: "The Golang int and the Overlooked Bug"
date: 2020-04-05T01:19:36-07:00
draft: false
toc: true
comments: true
twitterImage: 06-duty_calls.png
categories:
- go
---

This blog is about a [GitHub Security Lab][ghseclab-web] `Spot The Bug`
challenge that had an overlooked bug. [Github Security Lab's Twitter account][ghseclab-twitter]
tweets code snippets from time to time. The challenge is to spot the bug.

**Disclosure**: I might be completely wrong because we only have access to the
snippet in the picture and people at the GitHub Security Lab are better than me
in static analysis.

[ghseclab-web]: https://securitylab.github.com/
[ghseclab-twitter]: https://twitter.com/GHSecurityLab

<!--more-->

# The Challenge
On April 1st, 2020 they [tweeted][bug-tweet] the following code snippet:

{{< codecaption title="Can you #spotthebug in this Go code? What can be the consequences? How would you fix it?" lang="go" >}}
num, err := strconv.Atoi(s)

if err != nil { // not a number, search by name
    number, err := util.LookupNumberByName(registry, s)
    if err != nil {
        return nil, err
    }
    num = int(number)
}
target, err := util.LookupTarget(config, int32(num))
if err != nil {
    return nil, err
}

// convert the resolved target number back to a string
s = strconv.Itoa(int(target))
{{< /codecaption >}}

# int vs. int
The answer is not that obvious unless you have been bitten by it.
**The size of `int` in Go is dependent on the system architecture**. Looking up
`int` in the [docs][int-doc]:

> int is a signed integer type that is at least 32 bits in size. It is a
> distinct type, however, and not an alias for, say, int32.

This does not give us much information. I think the docs could be clearer than
`at least 32 bits in size` and `not an alias`. We can get our answer in [A Tour
of Go - Basic Types][tour-of-go-11].

> The int, uint, and uintptr types are usually 32 bits wide on 32-bit systems
> and 64 bits wide on 64-bit systems.

And then it continues with the bad advice that results in the bug above.

> When you need an integer value you should use int unless you have a specific
> reason to use a sized or unsigned integer type.

You really shouldn't use just `int` if you want to avoid bugs in different
machines. Again, if you have not encountered this bug you really do not know
what to look for.

## The Go Playground
I was trying something in [The Go Playground][go-playground] and realized the
execution is different than my own machine. After a few hours of
troubleshooting, I realized the playground is running on a 32-bit machine. We
cannot run `uname` on it but we can see the size of an `int` there.

{{< codecaption title="Go Playground int size" lang="go" >}}
package main

import (
	"fmt"
	"unsafe"
)

func main() {
	var int1 int
	fmt.Println(unsafe.Sizeof(int1))
}
{{< /codecaption >}}

You can run it on the playground at https://play.golang.org/p/4NhqnMKeXTh.

{{< imgcap title="int on the Go playground is 4 bytes" src="01-playground-int-size.png" >}}

On my own machine which is running a 64-bit OS, it's 8 bytes (64 bits).

{{< imgcap title="int on my machine is 8 bytes" src="02-my-machine-int-size.png" >}}

# The "Official" Answer
Now, we can trace the bug. [strconv.Atoi][strconv.atoi] returns `(int, error)`.
So `num` is of type `int`. On a 64 bit system, it will be an `int64`. It is then
converted to `int32` on line 10.

* `target, err := util.LookupTarget(config, int32(num))`

On a 64 bit system, if the value inside `num` is bigger (or smaller if negative)
than what can be stored in an `int32` we will encounter an integer overflow. An
`int32` can store values between `-2^31` and `2^31-1`.

We store `2^31` on the `int` value and then convert it to `int32`. Let's see
what happens:

{{< codecaption title="int64 to int32 integer overflow" lang="go" >}}
package main

import (
	"fmt"
)

func main() {
	var intVar int
	var int32Var int32

	intVar = 1 << 31 // 2^31
	int32Var = int32(intVar)
	fmt.Printf("int: %v - int32: %v", intVar, int32Var)

    // You could condense it to this unclear code
	// fmt.Printf("int: %v - int32: %v", int(1<<31), int32(int(1<<31)))
}
{{< /codecaption >}}

This code prints:

* `int: 2147483648 - int32: -2147483648`

{{< imgcap title="integer overflow" src="03-integer-overflow.png" >}}

Funnily enough, if you try to run something like `int32(int(1<<31))` the compiler
throws this error:

* `constant 2147483648 overflows int32`

{{< imgcap title="Compiler error for integer overflow" src="04-compiler-error.png" >}}

## The "Official" Fix
The fix is to replace `strconv.Atoi` with `strconv.ParseInt`. After all,
according to the docs:

> Atoi is equivalent to ParseInt(s, 10, 0), converted to type int.

Looking at the [source][atoi-source] this is not exactly correct. There is a
"quick path" when the length of the string is less than 10 on 32-bit and less
than 19 on 64-bit systems.

```go
	if intSize == 32 && (0 < sLen && sLen < 10) ||
		intSize == 64 && (0 < sLen && sLen < 19) {
        // Fast path for small integers that fit int type.
```

# But Why Are You Disagreeing?
Let's say we have a 32-bit system. `s` could contain a number that does not fit
in `int32` (`int` for this system). Note that `s` is a string and could have any
large value. You can see it on the Go playground (remember it's a 32-bit
machine) at https://play.golang.org/p/QEKtDWB7SFd.

{{< codecaption title="strconv.Atoi on 32-bit machines" lang="go" >}}
package main

import (
	"fmt"
	"strconv"
)

func main() {
	s := "2147483648"
	_, err := strconv.Atoi(s)
	if err != nil {
		fmt.Println(err)
	}
}
{{< /codecaption >}}

`strconv.Atoi` returns an error message.

* `strconv.Atoi: parsing "2147483648": value out of range`

{{< imgcap title="strconv.Atoi error on the Go playground" src="05-atoi-error.png" >}}

Going back to our original code on a 32-bit system:

{{< codecaption title="Original code" lang="go" >}}
// s := "2147483648"
num, err := strconv.Atoi(s)

if err != nil { // not a number, search by name
    // On a 32-bit system we land here with the error message `value out of range`
    // Then we call LookupNumberByName with `2147483648`
    number, err := util.LookupNumberByName(registry, s = "2147483648")
    if err != nil {
        return nil, err
    }
    num = int(number)
}
target, err := util.LookupTarget(config, int32(num))
if err != nil {
    return nil, err
}

// convert the resolved target number back to a string
s = strconv.Itoa(int(target))
{{< /codecaption >}}

`strconv.Atoi` returns the `value out of range` error and we land in the error
block. Because the code assumes `s` is not a number and the name of the target,
it tries to call `LookupNumberByName` with `2147483648`.

I do not know how `LookupNumberByName` works and that is *why I might be wrong*.
However, if I were creating such a function that tries to look up a name from a
registry I would return an error if I could not find it (remember errors are
values in Go). That means there is a good chance that we land in the error block
on line 9 and we never reach where the "official" answer is.

# What Did We Learn Here Today?

* `int` in Go is dependent on the machine. It's 32 bits on a 32-bit machine and
  64 bits on 64-bit machines.
* The Go playground is running on a 32-bit machine.
* Don't use `int`.

I finished this blog at 3 AM and I feel like the below XKCD does the trick.
Notice the `WRONG` with underscores, the person on the internet might not be
really wrong here but the writer feels like they are.

{{< imgcap title="Source: https://xkcd.com/386/" src="06-duty_calls.png" >}}

<!-- Links -->
[bug-tweet]: https://twitter.com/GHSecurityLab/status/1245501198628614144
[int-doc]: https://golang.org/pkg/builtin/#int
[tour-of-go-11]: https://tour.golang.org/basics/11
[go-playground]: https://play.golang.org/
[strconv.atoi]: https://golang.org/pkg/strconv/#Atoi
[atoi-source]: https://golang.org/src/strconv/atoi.go?s=5654:5686#L214
