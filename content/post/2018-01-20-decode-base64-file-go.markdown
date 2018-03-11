---
title: "Decoding Large Base64 Files with Go"
date: 2018-01-19T22:45:55-05:00
draft: false
toc: false
comments: true
categories:
- Go
tags:
- base64
- io.Reader
---

I am working on this challenge and it has a large base64 file. Each line has 2 characters and it has 150+ million lines.

Luckily we can use the [Base64 stream decoder](https://golang.org/pkg/encoding/base64/#NewDecoder). It reads from an `io.Reader` and returns one that can be copied into an `io.Writer`. It also takes care of the new lines.

Sample code is at:

- [https://github.com/parsiya/Go-Security/blob/master/base64-stream-decoder/b64-stream-decoder.go](https://github.com/parsiya/Go-Security/blob/master/base64-stream-decoder/b64-stream-decoder.go).

<!--more-->

This code will accept a base64 encoded file (whitespace does not matter) with `-file/--file` and store the decoded bytes in `filename-out`: 

{{< codecaption title="Base64 stream decoder" lang="go" >}}
// Example to demonstrate base64 stream decoder on large files.
package main

import (
    "encoding/base64"
    "flag"
    "fmt"
    "io"
    "os"
)

func main() {
    // This creates a flag parameter. Meaning we can call -file or --file.
    var filename string
    flag.StringVar(&filename, "file", "", "input file")
    flag.Parse()

    fmt.Println("reading input file, this may take a while")

    // Open input file
    input, err := os.Open(filename)
    // We are panic-ing with every error because we want to stop if things
    // go wrong.
    if err != nil {
        panic(err)
    }
    // Close input file
    defer input.Close()

    // Open output file
    output, err := os.Create(filename + "-out")
    if err != nil {
        panic(err)
    }
    // Close output file
    defer output.Close()

    // Create base64 stream decoder from input file. *io.File implements the
    // io.Reader interface. In other words we can pass it to NewDecoder.
    decoder := base64.NewDecoder(base64.StdEncoding, input)
    // Magic! Copy from base64 decoder to output file
    io.Copy(output, decoder)

    fmt.Println("storing base64 decoder input file")
}

{{< /codecaption >}}

Two interesting things:

1. The file handle is of type `*io.File` that implements `io.Reader`, meaning we can pass it to any function that can use one.
2. Because the output of decoder is also `io.Reader`, we can use `io.Copy` to copy it to the output file directly.

The code is pretty simple, we open the input file and the output file, pass the input file to the base64 stream decoder and copy its output to the output file and we're done.

Now this code is pretty fast and simple. For example our input file of 150+ million lines was decoded and written to disk in less then three seconds ([Measure-Command](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-powershell-1.0/ee176899(v=technet.10)) == `time`):

``` powershell
PS> Measure-Command{go run .\base64streamdecoder-example.go -file base64file}

Days              : 0
Hours             : 0
Minutes           : 0
Seconds           : 2
Milliseconds      : 960
Ticks             : 29604607
TotalDays         : 3.42645914351852E-05
TotalHours        : 0.000822350194444444
TotalMinutes      : 0.0493410116666667
TotalSeconds      : 2.9604607
TotalMilliseconds : 2960.4607
```

Such is the magic of `io.Reader`.