---
title: "Go Slices and Their Oddities"
date: 2020-05-17T22:37:21-07:00
draft: false
toc: true
comments: true
categories:
- Go
---

A friend pointed me to this [Go quiz about slices][go-quiz] by
[Serge Gotsuliak][serge-github]. It's an interesting exercise and points out the
intricacies of Go slices. I decided to explore it in detail. These oddities
might have security implications.

[go-quiz]: https://medium.com/@gotzmann/so-you-think-you-know-go-c5164b0d0511
[serge-github]: https://github.com/gotzmann

<!--more-->

**TL;DR**: If you want to modify a slice in the function, return it.

# Slices
The Golang blog has two great posts about slices:

* [Arrays, slices (and strings): The mechanics of 'append'][slice-blog.golang.org]
* [Go Slices: usage and internals][slice-intro]

[slice-intro]: https://blog.golang.org/slices-intro
[slice-blog.golang.org]: https://blog.golang.org/slices

They have everything we need to know to answer the questions.

## Slice has an Underlying Array
A slices in Go points to an underlying array. That array is like any other Go
array, it has a length and a capacity. We will call it the slice capacity and
length.

* Length: Number of items in the slice.
* Capacity: Number of items the slice can hold.

### A Slice is a Header
A `slice` is defined as:

```go
type slice struct {
	array unsafe.Pointer
	len   int
	cap   int
}
```

It's a struct and `array` points to the underlying array for that slice. Read
the rest of the source code file to see how the underlying array is created:

* https://golang.org/src/runtime/slice.go

If we print the pointer to the slice, it will print the address to the array.
E.g., `fmt.Printf("%p", slice1)`. Note, if you pass `&slice` you will print a
pointer to the slice and not the array.

I wrote a small function that helps with understanding what is happening. It
prints some info about an int slice. Note the `%p`.

```go
func printSlice(s string, a []int) {
	fmt.Printf("%p - %v\tlen:%d\tcap:%d\t%s\n", a, a, len(a), cap(a), s)
}
```

# Questions
Now we get to the [questions][go-quiz]. It had links to the Go playground to run
them. I modified them and added my own function to see what happens.

## Quiz 1
`surprise` gets a slice and then assigns `5` to all of its members. My modified
code is:

* https://play.golang.org/p/oXjDcyrxnRw

```go
package main

import "fmt"

func printSlice(s string, a []int) {
    fmt.Printf("%p - %v\tlen:%d\tcap:%d\t%s\n", a, a, len(a), cap(a), s)
}

func surprise(a []int) {
    printSlice("Inside surprise, before assignment", a)
    for i := range(a) {
        a[i] = 5
    }
    printSlice("Inside surprise, after assignment", a)
}
// Quiz #1
func main() {
    a := []int{1, 2, 3, 4}
    printSlice("Inside main, before surprise", a)
    surprise(a)
    printSlice("Inside main, after surprise", a)
}
```

Because in Go everything is passed by value, you would expect the slice in
`main` to remain untouched by the modifications inside the function. But it does
not:

```
0xc000014020 - [1 2 3 4]	len:4	cap:4	Inside main, before surprise
0xc000014020 - [1 2 3 4]	len:4	cap:4	Inside surprise, before assignment
0xc000014020 - [5 5 5 5]	len:4	cap:4	Inside surprise, after assignment
0xc000014020 - [5 5 5 5]	len:4	cap:4	Inside main, after surprise
```

We can see the address to the array does not change before, inside, and after
the function. This means we are operating on the same array.

### Slices Can Be Modified in functions
[There is no pass-by-reference in Go][pass-reference] by Dave Cheney explains
that in Go every parameter is passed by value. We can pass pointers and modify
what the pointer points to but the pointers are also passed by their value
(which is a memory address).

[pass-reference]: https://dave.cheney.net/2017/04/29/there-is-no-pass-by-reference-in-go

"But Parsia, a slice is not a pointer." Yes, but it's a header and contains a
pointer to the underlying array. When the slice is modified inside the function,
the underlying array is also modified. **On a side note, if we change `len` and
`cap` inside the function, the changes will not reflect outside.**

The following link from the `slices` blog post describes it with an example:

> the contents of a slice argument can be modified by a function, but its header
> cannot.

* [https://blog.golang.org/slices#TOC_4.](https://blog.golang.org/slices#TOC_4.)

Note: maps and channels can also be modified inside functions. They are actually
pointers but we treat them like normal variables. Read more about this
in [If a map isn’t a reference variable, what is it?][map-reference].

[map-reference]: https://dave.cheney.net/2017/04/30/if-a-map-isnt-a-reference-variable-what-is-it

## Quiz 2
In quiz 2 there is an `append(a, 5)` inside `surprise`. A new value is added to
the slice. We also expect that slice after `surprise` to be the same because we
can change slices inside functions.

* https://play.golang.org/p/ixiIKZ6_pWx

```go
package main

import "fmt"

func printSlice(s string, a []int) {
	fmt.Printf("%p - %v\tlen:%d\tcap:%d\t%s\n", a, a, len(a), cap(a), s)
}

func surprise(a []int) {
	printSlice("Inside surprise, before append", a)
	a = append(a, 5)
	printSlice("Inside surprise, after append", a)
	printSlice("Inside surprise, before assignment", a)
	for i := range a {
		a[i] = 5
	}
	printSlice("Inside surprise, after assignment", a)
}

// Quiz #2
func main() {
	a := []int{1, 2, 3, 4}
	printSlice("Inside main, before surprise", a)
	surprise(a)
	printSlice("Inside main, after surprise", a)
}
```

But it does not happen. The slice outside is not modified.

Let's look at the addresses. The address of the array in the original slice is
`0xc000014020`. It's passed to the function but it's modified after the
`append`. When return to `main` we work with the original address again.

```
0xc000014020 - [1 2 3 4]	len:4	cap:4	Inside main, before surprise
0xc000014020 - [1 2 3 4]	len:4	cap:4	Inside surprise, before append
// Address, len and cap change after append
0xc00007c040 - [1 2 3 4 5]	len:5	cap:8	Inside surprise, after append
0xc00007c040 - [1 2 3 4 5]	len:5	cap:8	Inside surprise, before assignment
0xc00007c040 - [5 5 5 5 5]	len:5	cap:8	Inside surprise, after assignment
// Back in main, using the old slice
0xc000014020 - [1 2 3 4]	len:4	cap:4	Inside main, after surprise
```

### Append Might Create a New Slice
"But Parsia, slices are like dynamic arrays. I can add items to them with
`append` and it will grow big like [Clifford the big red dog][clifford-wiki]."
YES!

[clifford-wiki]: https://en.wikipedia.org/wiki/Clifford_the_Big_Red_Dog

The [append][append-docs] function appends an item (or a set of items) to an
slice and returns a new slice. The [Go Slices: usage and internals][slice-intro]
blog post explains how the append function works by writing code

[append-docs]: https://golang.org/pkg/builtin/#append

The following block from the [Go specification][go-spec-append] has the answer:

[go-spec-append]: https://golang.org/ref/spec#Appending_and_copying_slices

> If the capacity of [the underlying array] is not large enough to fit the
> additional values, append allocates a new, sufficiently large underlying array
> that fits both the existing slice elements and the additional values.
> Otherwise, append re-uses the underlying array.

Because we initialized the slice, the capacity of the original slice was the
same as its number of members (see the capacity was `4`). With `append` inside
the function, we are exceeding the capacity so it creates a new slice with a new
underlying array that is larger (capacity is `8` for the new slice). The
assignment is done on this new slice.

Outside `surprise` we are still dealing with the old slice which only has the
original four members so nothing was modified.

## Quiz 3
Quiz 3 adds a new `append` inside `main`. We can already guess the printed
values will not be the same because the `append` in `main` is done on the
unmodified slice.

```go
package main

import "fmt"

func printSlice(s string, a []int) {
	fmt.Printf("%p - %v\tlen:%d\tcap:%d\t%s\n", a, a, len(a), cap(a), s)
}

func surprise(a []int) {
	printSlice("Inside surprise, before append", a)
	a = append(a, 5)
	printSlice("Inside surprise, after append", a)
	printSlice("Inside surprise, before assignment", a)
	for i := range a {
		a[i] = 5
	}
	printSlice("Inside surprise, after assignment", a)
}

// Quiz #3
func main() {
	a := []int{1, 2, 3, 4}
	printSlice("Inside main, before surprise", a)
	surprise(a)
	printSlice("Inside main, after surprise", a)
	printSlice("Inside main, before append", a)
	a = append(a, 5)
	printSlice("Inside main, after append", a)
}
```

* https://play.golang.org/p/fCJ_cMXU8dM

And our guess is correct. There is nothing new to learn here.

```
0xc000014020 - [1 2 3 4]	len:4	cap:4	Inside main, before surprise
0xc000014020 - [1 2 3 4]	len:4	cap:4	Inside surprise, before append
// Address, len and cap change after append
0xc00007c040 - [1 2 3 4 5]	len:5	cap:8	Inside surprise, after append
0xc00007c040 - [1 2 3 4 5]	len:5	cap:8	Inside surprise, before assignment
0xc00007c040 - [5 5 5 5 5]	len:5	cap:8	Inside surprise, after assignment
// Back in main, using the old slice
0xc000014020 - [1 2 3 4]	len:4	cap:4	Inside main, after surprise
0xc000014020 - [1 2 3 4]	len:4	cap:4	Inside main, before append
// Address, len and cap change after append
0xc00007c080 - [1 2 3 4 5]	len:5	cap:8	Inside main, after append
```

Note: How the capacity and the address of the array has changed for both slices
after `append`.

## Quiz 4
Quiz 4 does the `append` in `main` before calling `surprise`. This is tricky and
I was baffled even after using my helper function to print the slice fields.

* https://play.golang.org/p/gnfZ7W1pDG3

```go
package main

import "fmt"

func printSlice(s string, a []int) {
	fmt.Printf("%p - %v\tlen:%d\tcap:%d\t%s\n", a, a, len(a), cap(a), s)
}

func surprise(a []int) {
	printSlice("Inside surprise, before append", a)
	a = append(a, 5)
	printSlice("Inside surprise, after append", a)
	printSlice("Inside surprise, before assignment", a)
	for i := range a {
		a[i] = 5
	}
	printSlice("Inside surprise, after assignment", a)
}

// Quiz #4
func main() {
	a := []int{1, 2, 3, 4}
	printSlice("Inside main, before append", a)
	a = append(a,5)
	printSlice("Inside main, after append", a)
	printSlice("Inside main, before surprise", a)
	surprise(a)
	printSlice("Inside main, after surprise", a)
}
```

We expect the modified slice to have six members. We know:

1. We added a member the slice inside the function.
2. We know we can modify slices in functions.
3. The append inside the function does not create a new slice because the slice has enough capacity
 
BUT the slice back in main only has five members again.

```
// Initialized slice
0xc00010c000 - [1 2 3 4]	len:4	cap:4	Inside main, before append

// New slice after append in main because capacity
0xc000114040 - [1 2 3 4 5]	len:5	cap:8	Inside main, after append
0xc000114040 - [1 2 3 4 5]	len:5	cap:8	Inside main, before surprise
0xc000114040 - [1 2 3 4 5]	len:5	cap:8	Inside surprise, before append

// Slice modified in surprise and a new item appended. Check the length
0xc000114040 - [1 2 3 4 5 5]	len:6	cap:8	Inside surprise, after append
0xc000114040 - [1 2 3 4 5 5]	len:6	cap:8	Inside surprise, before assignment
0xc000114040 - [5 5 5 5 5 5]	len:6	cap:8	Inside surprise, after assignment

// Slice back in main has the same address but different length
0xc000114040 - [5 5 5 5 5]	len:5	cap:8	Inside main, after surprise
```

So what happened here?

1. The initial slice had a capacity of 4.
2. Appending `5` to it creates a new slice with a capacity of 8.
3. Inside surprise, we append another member to it, the slice does not change
   because it has a capacity of 8.
4. **Back in main, we get the modified slice but len and cap were passed as
   values so they do not retain their modified value from inside surprise.**
5. This means the slice only has 5 members and not 6.

### Length And Capacity Are Not Modified Inside Functions
The last point is important. Let's look at the slice struct from before:

```go
type slice struct {
	array unsafe.Pointer
	len   int
	cap   int
}
```

The underlying array is a pointer so if it gets modified inside `surprise` we
retain those changes. However, `len` and `cap` were passed by value so **changed
a COPY of them inside `surprise`**. When we return we will still see the old
`len`.

But as far as the program is concerned, the slice only has 5 members. But I am
willing to bet that if we look at the memory for the array, we will see the
extra member there. 

# What Did We Learn Here Today?
If you want to change a slice in a function, return the modified slice. Do not
pass it as a parameter in order to reuse the original copy. The original copy
might contain the changes.
