---
title: "Windows Filetime Timestamps and Byte Wrangling with Go"
date: 2018-11-01T08:05:47-04:00
draft: false
toc: true
comments: true
twitterImage: filetime.png
categories:
- Go
- category2
tags:
- filetime
---

For a side project, I have to parse timestamps in a file. These timestamps are in the Windows Filetime format. This post documents what I have learned about them and how they can be converted to a Golang [time.Time][godoc-time-time] and then converted to any desirable format after that.

We will start by looking at endian-ness and use a real-world example to practice our newly acquired knowledge.

**TL;DR: To convert a Windows Filetime to Go's time.Time:**

1. Read 8 bytes in LittleEndian from the file.
2. Create a `syscall.Filetime`.
	* Assign the first 4 bytes to `LowDateTime` field and the other four to `HighDateTime`.
3. Convert the resulting Filetime to nanoseconds with [Filetime.Nanoseconds()][godoc-windows-syscall-nanoseconds].
4. Convert the resulting value to [time.Time][godoc-time-time].

The code is at:

* https://github.com/parsiya/Parsia-Code/tree/master/filetime-bytewrangling

[godoc-windows-syscall-nanoseconds]: https://godoc.org/golang.org/x/sys/windows#Filetime.Nanoseconds
[godoc-time-time]: https://golang.org/pkg/time/#Time

<!--more-->

# Endianness with Useful Examples
You probably already know about endianness. It's how the bytes are ordered. Literals are almost always written in big-endian like `0xAABBCCDD`. In math, numbers are stored and read in big-endian (e.g. `1337`). In little-endian, they are stored with LSB being first. So the result is `DD CC BB AA` on disk. When reading from disk, we read four bytes and then reverse it.

Network protocols usually deal with the big-endian order. When sending data, we read and send the first byte first. When we look at the data on the wire, LSB is seen first and then the rest.

What infuriates me are the examples. Every tutorial uses only four bytes (like I did above). But what if we want to read a `dword` (a double-word is usually 8 bytes) from disk (little-endian). Do we read all bytes and reverse them? What about two `word`s?

Let's try to read these 8 bytes into a `uint64` `D0 E9 EE F2 15 15 C9 01`. Run `01-littleendian-uint64.go`:

``` go
package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

func main() {
    // Simulate 8 bytes BigEndian.
    cr, _ := hex.DecodeString(strings.Replace("D0 E9 EE F2 15 15 C9 01", " ", "", -1))
    // Read them into a uint64
    u64 := binary.LittleEndian.Uint64(cr)
    // Print the bytes
    fmt.Printf("%016x", u64)
    // 01c91515f2eee9d0
}
```

Using `BigEndian` would give us the order in the original string.

# binary.Read
When reading from a file, we are mostly dealing with an `io.Reader`. They are great for file parsing. We can read as we go and do not have to worry about keeping track of the offset. Another advantage is using [binary.Read][godoc-binary-read]. We can pass a data structure to it (as a pointer), it will detect the size and try to fill it. Run `02-littleendian-uint64-reader.go`:

``` go
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

func main() {
	// Simulate 8 bytes BigEndian.
	cr, _ := hex.DecodeString(strings.Replace("D0 E9 EE F2 15 15 C9 01", " ", "", -1))
	// Create an io.Reader from []byte for simulation.
	buf := bytes.NewReader(cr)
	var u64 uint64
	err := binary.Read(buf, binary.LittleEndian, &u64)
	if err != nil {
		panic(err)
	}

    fmt.Printf("%016x", u64)
    // 01c91515f2eee9d0
}
```

But what if we want to read two little-endian `uint32`s? That is similar. Run `03-littlendian-two-uint32.go`:

``` go
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

func main() {
	// Simulate 8 bytes BigEndian.
	cr, _ := hex.DecodeString(strings.Replace("D0 E9 EE F2 15 15 C9 01", " ", "", -1))
	// Create an io.Reader from []byte.
	buf := bytes.NewReader(cr)
	var u32One, u32Two uint32
	err := binary.Read(buf, binary.LittleEndian, &u32One)
	if err != nil {
		panic(err)
	}
	err = binary.Read(buf, binary.LittleEndian, &u32Two)
	if err != nil {
		panic(err)
	}

	fmt.Printf("u32-1: %08x\n", u32One) // u32-1: f2eee9d0
	fmt.Printf("u32-1: %08x\n", u32Two) // u32-1: 01c91515
}
```

Both approaches pretty much give us the same results.

## Reading []byte or [...]byte
We can also fill `[]byte` from `io.Reader` with `binary.Read`. In these cases, we need to create a `[]byte` of a specific length and read those many bytes. Let's get the entire 72 bytes from the original example `04-read-byte-slice.go`:

``` go
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

func main() {
	cr, _ := hex.DecodeString("4C0000000114020000000000C000000000000046" +
		"9B00080020000000D0E9EEF21515C901D0E9EEF21515C901D0E9EEF21515C90100" +
		"0000000000000001000000000000000000000000000000")
	// Create an io.Reader from []byte.
	buf := bytes.NewReader(cr)

	headerLittleEndian := make([]byte, 72)
	err := binary.Read(buf, binary.LittleEndian, &headerLittleEndian)
	if err != nil {
		panic(err)
	}
	fmt.Println("headerLittleEndian")
	fmt.Println(hex.Dump(headerLittleEndian))

	// Reset the reader.
	buf = bytes.NewReader(cr)
	headerBigEndian := make([]byte, 72)
	err = binary.Read(buf, binary.BigEndian, &headerBigEndian)
	if err != nil {
		panic(err)
	}
	fmt.Println("headerBigEndian")
	fmt.Println(hex.Dump(headerBigEndian))
}
```

And the result is the same in both cases.

```
headerLittleEndian
00000000  4c 00 00 00 01 14 02 00  00 00 00 00 c0 00 00 00  |L...............|
00000010  00 00 00 46 9b 00 08 00  20 00 00 00 d0 e9 ee f2  |...F.... .......|
00000020  15 15 c9 01 d0 e9 ee f2  15 15 c9 01 d0 e9 ee f2  |................|
00000030  15 15 c9 01 00 00 00 00  00 00 00 00 01 00 00 00  |................|
00000040  00 00 00 00 00 00 00 00                           |........|

headerBigEndian
00000000  4c 00 00 00 01 14 02 00  00 00 00 00 c0 00 00 00  |L...............|
00000010  00 00 00 46 9b 00 08 00  20 00 00 00 d0 e9 ee f2  |...F.... .......|
00000020  15 15 c9 01 d0 e9 ee f2  15 15 c9 01 d0 e9 ee f2  |................|
00000030  15 15 c9 01 00 00 00 00  00 00 00 00 01 00 00 00  |................|
00000040  00 00 00 00 00 00 00 00                           |........|
```

**If you are reading []byte or byte arrays, the order doesn't really matter. You get the original order of bytes.**

That was quite the detour, but now we know how ro read bytes in Go.

# Mild lnk Reverse Engineering
We are going to use a Windows Shortcut or `lnk` file for practice. Luckily, MSDN has an [example][msdn-lnk-example]. We are going to only need the file header or the first `72` (or `0x4C`) bytes. Here's a hexdump:

```
00000000  4C 00 00 00 01 14 02 00 00 00 00 00 C0 00 00 00  |L...........À...|
00000010  00 00 00 46 9B 00 08 00 20 00 00 00 D0 E9 EE F2  |...F.... ...Ðéîò|
00000020  15 15 C9 01 D0 E9 EE F2 15 15 C9 01 D0 E9 EE F2  |..É.Ðéîò..É.Ðéîò|
00000030  15 15 C9 01 00 00 00 00 00 00 00 00 01 00 00 00  |..É.............|
00000040  00 00 00 00 00 00 00 00 00 00 00 00              |............|
```

MSDN has the [MS-SHLLINK][msdn-lnk-format]. Open the revision 5.0 (latest at the time of writing) file to see the format. The example page also contains a break down of all fields.

There are three timestamps. Each one is eight bytes and is stored in little-endian order:

* `CreationTime` at offset `0x1C`: `D0 E9 EE F2 15 15 C9 01`
* `AccessTime` at offset `0x24`: `D0 E9 EE F2 15 15 C9 01`
* `WriteTime` at offset `0x2C`: `D0 E9 EE F2 15 15 C9 01`

# Filetime
According to the [FILETIME structure][msdn-filetime], it's "a 64-bit value representing the number of 100-nanosecond intervals since January 1, 1601 (UTC)." Oh boy!

We need to convert it to to Unix nano, which is the number of nanoseconds elapsed since January 1, 1970, 00:00:00 (UTC). To convert these, we can either do things by hand (multiply the Windows timestamp by 100 and then subtract the number of nanoseconds between epoch times) or just let someone else do the calculation for us. Fortunately, I found a type in Go in two places that point to one location:

* [syscall.Filetime][godoc-syscall-filetime]
* [golang.org/x/sys/windows.Filetime][godoc-windows-syscall-filetime]

``` go
type Filetime struct {
	LowDateTime  uint32
	HighDateTime uint32
}
```

To convert a Windows Filetime to Go's time.Time:

1. Read 8 bytes in LittleEndian from the file.
2. Create a `syscall.Filetime`.
	1. Assign the first 4 bytes to `LowDateTime` field and the other to `HighDateTime`.
3. Convert the resulting Filetime to nanoseconds with [Filetime.Nanoseconds()][godoc-windows-syscall-nanoseconds].
4. Convert the resulting value to time.Time.

Let's create a function:

``` go
// toTime converts an 8-byte Windows Filetime to time.Time.
func toTime(t [8]byte) time.Time {
	ft := &syscall.Filetime{
		LowDateTime:  binary.LittleEndian.Uint32(t[:4]),
		HighDateTime: binary.LittleEndian.Uint32(t[4:]),
	}
	return time.Unix(0, ft.Nanoseconds())
}
```

We are passing an 8-byte array (we could modify it to be a `[]byte` but that would add range checks, error handling, and panics). The byte array is most likely big-endian (because we read it directly from the reader), so we are reading each `uint32` in little-endian order. Then we populate `Filetime` and finally convert it to `time.Time`. Now we can do whatever we want with this.

Let's run this function on our timestamp (all three are the same in the MSDN example). Run `05-parse-timestamp.go`:

``` go
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"syscall"
	"time"
)

func main() {
	cr, _ := hex.DecodeString(strings.Replace("D0 E9 EE F2 15 15 C9 01", " ", "", -1))
	buf := bytes.NewReader(cr)
	var timestamp [8]byte
	err := binary.Read(buf, binary.LittleEndian, &timestamp)
	if err != nil {
		panic(err)
	}

	t := toTime(timestamp)
	fmt.Println(t)
	fmt.Println(t.UTC())
}

// toTime converts an 8-byte Windows Filetime to time.Time.
func toTime(t [8]byte) time.Time {
	ft := &syscall.Filetime{
		LowDateTime:  binary.LittleEndian.Uint32(t[:4]),
		HighDateTime: binary.LittleEndian.Uint32(t[4:]),
	}
	return time.Unix(0, ft.Nanoseconds())
}
```

Which is the same as the MSDN example:

```
2008-09-12 16:27:17.101 -0400 EDT
2008-09-12 20:27:17.101 +0000 UTC
```

<!-- Links -->
[msdn-lnk-example]: https://msdn.microsoft.com/en-us/library/dd871375.aspx
[msdn-lnk-format]: https://msdn.microsoft.com/en-us/library/dd871305.aspx
[godoc-binary-read]: https://golang.org/pkg/encoding/binary/#Read
[msdn-filetime]: https://msdn.microsoft.com/en-us/library/windows/desktop/ms724284(v=vs.85).aspx
[godoc-syscall-filetime]: https://golang.org/pkg/syscall/?GOOS=windows&GOARCH=amd64#Filetime
[godoc-windows-syscall-filetime]: https://godoc.org/golang.org/x/sys/windows#Filetime
[godoc-windows-syscall-nanoseconds]: https://godoc.org/golang.org/x/sys/windows#Filetime.Nanoseconds