---
title: "Gophercises - Lessons Learned"
date: 2018-10-06T00:22:58-04:00
draft: false
toc: true
comments: true
twitterImage: github-sc.jpg
categories:
- Go
- Not Security
- Lessons Learned
tags:
- Gophercises
---

I recently finished [Gophercises](https://gophercises.com), a great set of Go practice lessons by [Jon Calhoun](https://www.calhoun.io/). I think it took me around a month from start to finish with some stuff in the middle. Most were nice, some were tedious. For example, the last exercise was about [PDF generation](https://gophercises.com/exercises/pdf) and went to boring quickly.

After every lesson, I wrote down "Lessons Learned" in the README. This page collects most of them. All code is here:

* https://github.com/parsiya/Parsia-Code/tree/master/gophercises

<!--more-->

# Timers

* Read this: https://gobyexample.com/timers
* Block with `<-timerVar.C`
* Stop the timer with `stop := timerVar.Stop()`
    * If timer is stopped, `stop` will be `true`.
* **Stop doesn't unblock the channel.** If you stop the timer, the channel will remain blocked.
    * Here's code based on gobyexample that will dead-lock if executed.
        ``` go
        package main

        import "time"
        import "fmt"

        func main() {

            timer2 := time.NewTimer(10 * time.Second)
            stop2 := timer2.Stop()
            if stop2 {
                fmt.Println("Timer 2 stopped")
            }
            <-timer2.C
        }
        ```
    * Instead, use `timerVar.Reset(0)`. This will stop the timer and unblock the channel.

# rand.Shuffle

* https://golang.org/pkg/math/rand/#Shuffle
* Remember to seed a rand object.
    * `rnd := rand.New(rand.NewSource(time.Now().Unix()))`
* Needs a swap function of this type `func(i, j int)`.
    * Inside the swap function (does not need to be named `swap`), do the swaps.

``` go
func (e *Exam) Shuffle() {
	rnd := rand.New(rand.NewSource(time.Now().Unix()))
	rnd.Shuffle(len(e.problems), func(i, j int) {
		e.problems[i], e.problems[j] = e.problems[j], e.problems[i]
	})
}
```

# http.Handler

* Read this: https://medium.com/@matryer/the-http-handler-wrapper-technique-in-golang-updated-bc7fbcffa702
    * "The idea is that you take in an http.Handler and return a new one that does something else before and/or after calling the ServeHTTP method on the original."
* Then pass the custom handler to `http.ListenAndServe(":8080", customHandler)`

# JSON to Objects Mappings
Your best friend:

* https://mholt.github.io/json-to-go/
* Doublecheck where you need to have maps. Doesn't detect them all the time.

Maps to a `[]object` or array of objects:

``` json
[
    { 
        "key1": "value1",
        "key2": "value2"
    },
    { 
        "key1": "value3",
        "key2": "value4"
    }
]
```

Maps to a map of `[string]object`

``` json
{
	"object1": {
		"key1": "value1",
		"key2": "value2"
	},
	"object2": {
		"key1": "value3",
		"key2": "value4"
	}
}
```

# "html/template"

* https://golang.org/pkg/html/template/
* Same as Hugo's templates.

# "text/template"

* https://golang.org/pkg/text/template/
* Very similar to HTML templates but used for manipulating text.
* Use instead of a lot of `fmt.Sprintf`s.

# /x/net/html

* Read the package example: https://godoc.org/golang.org/x/net/html
* Token struct:
    ``` go
    type Token struct {
        Type     TokenType
        DataAtom atom.Atom
        Data     string
        Attr     []Attribute
    }
    ```
* `Type` can give us information about what kind of token it is. Important ones for this exercise are:
    * `StartTagToken`: `<a href>`
    * `EndTagToken`: `</a>`
    * `TextToken`: Text in between. Using text nodes will skip other elements inside the link.
* `Data` contains the data in the node.
    * Anchor tags: `a`.
    * Text nodes: The actual text of the node.
* Attribute is of type:
    ``` go
    type Attribute struct {
	    Namespace, Key, Val string
    }
    ```
* `Key` is the name of the attribute and `Value` is the value.
    * `<a href="example.net">`: `key` = `href` and `value` = `example.net`.

# strings.Builder
Strings are immutable, use this to append to strings for better efficiency.

* Example: https://golang.org/pkg/strings/#example_Builder

``` go
var sb strings.Builder  // Create the builder.
sb.WriteString("whatever")  // Write to it. We can use fmt.Sprintf as param too.
return sb.String()  // Get the final string.
```

We can also pass one as a pointer as `io.Writer`. For example, `json.NewEncoder(&sb)`.

# io.Reader for string
Get an `io.Reader` from a string.

``` go
reader: = strings.NewReader("Whatever")
```

# net.URL

* https://golang.org/pkg/net/url/
* There are tons of great methods.
* Convert a string to URL: `Parse(rawurl string) (*URL, error)`
* URL will give you tons of utilities:
``` go
type URL struct {
    Scheme     string
    Opaque     string    // encoded opaque data
    User       *Userinfo // username and password information
    Host       string    // host or host:port
    Path       string    // path (relative paths may omit leading slash)
    RawPath    string    // encoded path hint (see EscapedPath method)
    ForceQuery bool      // append a query ('?') even if RawQuery is empty
    RawQuery   string    // encoded query values, without '?'
    Fragment   string    // fragment for references, without '#'
}
```

* `IsAbs()` returns true if path is absolute.
* `Hostname()` returns host and port.
* Contents are case-sensitive.
* Get the complete URL with `URL.String()`.

# ioutil.Discard

* `var Discard io.Writer = devNull(0)`

# Break/Continue to Label

* Really helps when inside a select which is inside an infinite loop.
* Designate labels as usual.
* `break` or `continue` to label.

    ``` go
    Mainloop:
        for {
            select {
            case whatever:
                //
            default:
                // Do what you want
                break Mainloop
            }
        }
    ```

# Range on string returns Runes

* These runes must be converted to string before usage with `string(ch)`

# String vs. Rune

* `"a"` is a string, `'a'` is a rune.
* rune to string with `string('a')`.
* string to rune with `rune("a")`.
* string to int with `int("a")`.

# BoltDB

* https://github.com/boltdb/bolt
    * Repository's README is a good guide to get started.
* Key/Value store.
* Create buckets first.
* At the start of each transaction you need to get the buckets.
* In general, values do not transfer between transactions. If you want do, you need to `Copy` slice of results to another variable to use it outside.

## Using Time as Keys in BoltDB for Indexing
Read this:

* Source: https://zupzup.org/boltdb-example/
* Code: https://github.com/zupzup/boltdb-example

``` go
key := []byte(time.Now().Format(time.RFC3339))
```

And later we can search with `seek`.

# time.Add vs. time.Sub

* `time.Add` gets a `time.Duration` and returns `time.Time`:
    * `func (t Time) Add(d Duration) Time`
    * https://golang.org/pkg/time/#Time.Add
* `time.Sub` gets a `time.Time` and returns `time.Duration`:
    * `func (t Time) Sub(u Time) Duration`
    * https://golang.org/pkg/time/#Time.Sub

Obviously, both support negative values.

# Convert int Variable to time.Duration
You can multiple `time.Duration` by a constant (e.g. `time.Hours * 2`) but cannot multiply it by an `int` variable with value of 2 (e.g. `time.Hours * n`).

`n` needs to be converted to `in64` and then passed to `time.Duration(int64)`. For example, to go back `n` hours:

``` go
past := time.Now().Add(-time.Duration(int64(n)) * time.Hour)
```

# jmoiron/sqlx

Troubleshooting:

* Problem: `panic: sql: unknown driver "sqlite3" (forgotten import?)`
* Solution: `import _ "github.com/mattn/go-sqlite3"`
* Problem:
  ```
  # github.com/mattn/go-sqlite3
  exec: "gcc": executable file not found in %PATH%
  ```
* Solution: Install https://sourceforge.net/projects/mingw-w64/.

Good examples:

* https://jmoiron.github.io/sqlx/
* https://github.com/joncrlsn/go-examples/blob/master/sqlx-sqlite.go

Some troubleshooting:

* Problem: "missing destination name" error when using `Queryx` and `StructScan`.
* Solutions:
  * Struct fields must be exported.
  * Map the table columns to struct fields with `db:"table-column"`.

# Stringer package
Stringer package can generate `String()` for types. In this case, we can use it to make one for `Suit` and `Value` types.

* `go get golang.org/x/tools/cmd/stringer`
* go doc with example: https://godoc.org/golang.org/x/tools/cmd/stringer

1. Add the following on top of the file with the types (in this case `deck/card.go`).
    * `//go:generate stringer -type=Suit,Value``
2. Run `go generate` inside the `deck` directory.
3. It will create a file named `suit_string.go`.
4. Now we can call `Suit.String()` and it will return a string.

# filepath.Walk
[filepath.Walk](https://golang.org/pkg/path/filepath/#Walk) can be used to traverse all files in a path recursively.

``` go
func Walk(root string, walkFn WalkFunc) error
```

`root` is the starting path and `WalkFunc` is a function that is called after visiting each file:

``` go
func(path string, info os.FileInfo, err error) error
```

[os.FileInfo](https://golang.org/pkg/os/#FileInfo) has a bunch of methods:

``` go
// A FileInfo describes a file and is returned by Stat and Lstat.
type FileInfo interface {
	Name() string       // base name of the file
	Size() int64        // length in bytes for regular files; system-dependent for others
	Mode() FileMode     // file mode bits
	ModTime() time.Time // modification time
	IsDir() bool        // abbreviation for Mode().IsDir()
	Sys() interface{}   // underlying data source (can return nil)
}
```

So to list everything in a directory ([main0.go](main0.go)):

``` go
func main() {

	// Make a list of all files in sample.
	err := filepath.Walk("sample", walkWithMe0)
	if err != nil {
		log.Println(err)
	}
}

// walkWithMe0 returns info about files.
func walkWithMe0(path string, info os.FileInfo, err error) error {

	// Now we can do what we want with os.FileInfo.
	fmt.Printf("Visiting %v\n", info.Name())
	return nil
}
```

`walkWithMe` is good for listing things but bad for saving info. The easiest way to pass into out is using an anonymous (or inline) function.

``` go
func main() {

	// Make a list of all files in sample.
	err := filepath.Walk("sample", func(path string, info os.FileInfo, err error) error {

		// Now we can do what we want with os.FileInfo.
		fmt.Printf("Visiting %v\n", info.Name())
		return nil
	})
	if err != nil {
		log.Println(err)
	}
}
```

* Detect directories: [info.IsDir()](https://golang.org/pkg/os/#FileInfo).
* On Windows [*syscall.Win32FileAttributeData](https://golang.org/pkg/syscall/?GOOS=windows&GOARCH=amd64#Win32FileAttributeData).
* Get file extension: [info.path.Ext()](https://golang.org/pkg/path/filepath/#Ext) returns the extension which just does some text processing on path. **It returns the period (e.g. ".txt").**
* To match filenames: [info.path.Match](https://golang.org/pkg/path/filepath/#Match).

# Print Stacktrace

* [debug.Stack()](https://golang.org/pkg/runtime/debug/#Stack): Returns a `[]byte` (remember to convert to string before printing).
* [runtime.Stack(buf []byte, all bool) int](https://golang.org/pkg/runtime/#Stack): Pass a `[]byte` that gets filled.

# Custom http.ResponseWriter
See this:
* https://upgear.io/blog/golang-tip-wrapping-http-response-writer-for-middleware/

# Embed
Embed stuff in structs to use them.

``` go
type myRW struct {
    http.ResponseWriter
}
```

# Type Assertion

* https://tour.golang.org/methods/15

``` go
t, ok := i.(T)
if ok {
    // i.T is implemented and stored in T
}
```

# http.Error Only Support Plaintext
When doing `http.Error` the result will be sent as text and not `text/html`. 

Use `fmt.Fprintf(w, ...)` instead.

# Chroma
Already familiar because it's used in Hugo.

`quick.Highlight` sacrifices control but does things quickly:

``` go
quick.Highlight(os.Stdout, someSourceCode, "go", "html", "monokai")
```

For more control use `formatter.Format(w io.Writer, s *Style, it Iterator)`:

``` go
// Highlighter is a more hands-on version of QuickHighlighter and comes with
// lines highlight support.
func Highlighter(fileName, source, style string, lineno int) (string, error) {
	// If styleText does not match any style, it will return "swapoff."
	// So we check if we entered "swapoff" and if not, we will change it to
	// "solarized-dark."
	st := styles.Get(style)
	if st.Name == "swapoff" && style != "swapoff" {
		st = styles.Get("solarized-dark")
	}

	// While we already know we are looking at Go code, we are going to
	// Chroma's lexer.Analyze to get the lexer based on extension.
	// https://github.com/alecthomas/chroma#identifying-the-language
	lexer := lexers.Match(fileName)
	// lexer is nil if no match could be found.
	if lexer == nil {
		// So we use the Analyse function.
		lexer = lexers.Analyse(source)
	}
	// Default to Go, if neither process detected a lexer.
	if lexer == nil {
		lexer = lexers.Get("go")
	}

	// Create the range variable for highlighting line numbers.
	// It's of type [][2]int.
	hl := [][2]int{[2]int{lineno, lineno}}
	// We are only highlighting one line so both items in the [2]int array
	// are the same. If we wanted to highlight a range, we would have used
	// start and finish line numbers.

	// Create a customized html.Formatter.
	// We can also get rid of the 8 tab space now.
	formatter := html.New(html.Standalone(), html.WithLineNumbers(),
		html.HighlightLines(hl), html.TabWidth(4))

	// Get iterator.
	it, err := lexer.Tokenise(nil, source)
	if err != nil {
		return "", err
	}

	var b bytes.Buffer
	wri := bufio.NewWriter(&b)

	if err := formatter.Format(wri, st, it); err != nil {
		return "", err
	}

	return b.String(), nil
}
```

# json.NewDecoder json.NewEncoder
When decoding from or encoding to an `io.Reader/Writer` (e.g. file, HTTP response), we can do this:

``` go
var []obj MyStruct
// fill in []obj

// File to encode stuff to.
f, _ := os.Create("whatever.txt")
enc := json.NewEncoder(f)
if err := enc.Encode(obj); err != nil {
    // Handle error
}

// Now json is saved to file.
```

To decode, we can do something similar with an `io.Reader` (e.g. file).

``` go
var []obj2 MyStruct

f, _ := os.Open("whatever.txt")
dec := json.NewDecoder(f)
if err := enc.Decode(&obj2); err != nil {
    // Handle error
}

// Now json is populated from file.
```
# Twitter APIs

## Twitter Application-Only Auth-Flow
Docs: https://developer.twitter.com/en/docs/basics/authentication/overview/application-only

1. Create an application and a set of read-only consumer API keys. Twitter will ask you to write 300 words about your application and other crap.
2. Create the authorization token by combining the key and secret and then base64 encoding them. `base64(Key:Secret)`.
    * Use [request.SetBasicAuth(Key,Secret)](https://golang.org/pkg/net/http/?#Request.SetBasicAuth) in the `http` package.
3. Send the following POST request to https://api.twitter.com/oauth2/token to get the bearer token.
    ```
    POST /oauth2/token HTTP/1.1
    Host: api.twitter.com
    User-Agent: Whatever
    Authorization: Basic [token from step 2]
    Content-Type: application/x-www-form-urlencoded;charset=UTF-8
    Accept-Encoding: gzip

    grant_type=client_credentials
    ```
4. Response will have the bearer token if successful (and a 200 OK status)
   ``` json
   {"token_type":"bearer","access_token":"AAAAAAAAAAAAAAAAAAAAAAAAAA"}
   ```
5. Use the token in the header of every request `Authorization: Bearer AAAAAAAAAAAAAAAAAAAAAAAAAA`
6. ???
7. Profit

## Get Retweeters
GET request to https://api.twitter.com/1.1/statuses/retweets/tweetID.json?count=100.

* https://developer.twitter.com/en/docs/tweets/post-and-engage/api-reference/get-statuses-retweets-id

Results has these fields.

``` json
[
  {
    // ...
    "user": {
      // ...
      "id": 281679947,
      "id_str": "281679947",
      "is_translation_enabled": false,
      "is_translator": false,
      "lang": "en",
      "listed_count": 43,
      "location": "NYC",
      "name": "Christine Romo",
      // ...
      "screen_name": "romoabcnews",
    }
  }
]
```

We want to read `id_str` and `screen_name` so we unmarshal the JSON to `[]Retweeter` where:

``` go
// User represents a user.
type User struct {
	Id   string `json:"id_str"`
	Name string `json:"screen_name"`
}

// Retweeter represents a user who has retweeted the content.
type Retweeter struct {
	TwitterUser User `json:"user"`
}
```

# Chaining Reader and Writer Interfaces
This is pretty cool. You can see it inside `Encrypter` and `Decrypter`.

In short, you pass an `io.Reader` or `io.Writer` to another and chain them. Then you write to one (or read from one) and encryption/decryption works. We have already seen this in a previous lesson where we used `json.NewDecoder/NewEncoder` on files or buffers.

# io.TeeReader(r io.Reader, w io.Writer) io.Reader
"TeeReader returns a Reader that writes to w what it reads from r. All reads from r performed through it are matched with corresponding writes to w. There is no internal buffering ..."

* https://golang.org/pkg/io/#TeeReader

I did not use it in this lesson, but seems like a useful thing.

# Pass Arguments to Delve Debugger in VS Code
Pass the arguments inside `launch.json` like this.

``` json
"args": [
    "get",
    "test",
    "yolo",
    "key3",
],
```

# HTML Input type File
We can use something like this

``` html
<input type="file"
    id="upload" name="upload"
    accept="image/jpeg,image/png" />
```

This only shows files of type `jpeg` and `png`. We can also do `image/*` to show all images.

# Int to Enum
Assuming we have this enum:

``` go
type EnumType int

const (
	Zero Enum = iota
	One
	Two
	Three
)
```

We can convert an int to this type with `EnumType(2)`.

# http.Request.FormFile
Gets the first file in the param (usually POST body).

* https://golang.org/pkg/net/http/?#Request.FormFile
* `file, header, err := r.FormFile("upload")`
* `file` can be used like any other file (hint: implements `io.Reader`).
    * https://golang.org/pkg/mime/multipart/#File
* `header` has info about the file like name and size.
    * https://golang.org/pkg/mime/multipart/#FileHeader

Response.PostForm is a map of `url.Values` (`map[string][]string`).

# Access Struct Fields with the Reflect Package
Don't use `reflect` I guess. But this is fun. Seems like it will panic if unexported fields are accessed.

In this case, our struct only has string fields so we only check for empty string.

``` go
v := reflect.ValueOf(c)
for i := 0; i < v.NumField(); i++ {
    if v.Field(i).Interface() == "" {
        return fmt.Errorf("Corp not initialized. Set value of %s", v.Type().Field(i).Name)
    }
}
```

We can access the value of a field with `v.Field(i).Interface()` and its name with `v.Type().Field(i).Name`.

# Convert Float to String with Two Floating Points
Change `2` to get more floating points.

``` go
func FloatToString(f float64) string {
	return strconv.FormatFloat(f, 'f', 2, 64)
}
```
