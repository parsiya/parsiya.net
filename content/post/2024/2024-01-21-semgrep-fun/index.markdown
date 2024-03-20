---
title: "A Few Fun Semgrep Experiments"
date: 2024-01-21T02:32:24-08:00
draft: false
toc: true
comments: true
url: /blog/semgrep-fun/
twitterImage: 05.png
categories:
- semgrep
- Static Analysis
---

I want to use Semgrep as a light code intelligence tool with a few experiments.
I will write custom rules to extract info from code and then process the
results.

The type of these experiments is inspired by [Martin Jambon][mjambon-gh] who is
actually a core Semgrep developer. These are supposed to be self-contained but
short experiments. You can see his at https://github.com/mjambon/dev-random.

[mjambon-gh]: https://github.com/mjambon

<!--more-->

# Intro
If you know me, you know I never shut up about Semgrep, see
https://parsiya.net/categories/semgrep/.

I use Semgrep if I want something quick that works. For complex uses cases, you
need to create your own static analysis tools. Parsing is doable with
[tree-sitter][ts] (same thing Semgrep uses) and [tree-sitter queries][tsq].
For Go, I have also used the [ast][ast-url] package.

[ts]: https://tree-sitter.github.io/tree-sitter/
[tsq]: https://tree-sitter.github.io/tree-sitter/using-parsers#pattern-matching-with-queries
[ast-url]: https://pkg.go.dev/go/ast

# Requirements
This blog assumes you have this knowledge. Nothing fancy.

1. Some familiarity with Go.
2. Writing basic Semgrep rules.

# Setup
To interact with Semgrep, I have created a couple of wrapper packages in
[Go][semgrep-go] and [Rust][semgrep-rs]. The overall concept of post-processing
is straightforward:

1. Create custom rules that use metavariables to extract specific info from code.
2. Create a wrapper to run Semgrep and deserialize the JSON output.
3. ~~Draw the rest of the owl.~~ Process the output and apply the logic.

[semgrep-rs]: https://github.com/parsiya/semgrep-rs
[semgrep-go]: https://github.com/parsiya/semgrep_go

In this blog I will use [semgrep_go][semgrep-go]. You can follow along:

```
git clone --recurse-submodules https://github.com/parsiya/semgrep-fun
go run main.go 01 code/juice-shop
```

These are simple applications that just do the job. There's not a lot of error
handling.

# Gotchas
Hopefully you don't have to repeat my mistakes. These have taken a few hours of
my life.

## Complete Rule IDs
By default, Semgrep adds some extra text to rule IDs in the results. I call them
"complete rule IDs" and (I think) they're added to prevent rule ID collision.

For local rules, the complete text depends on the path in `--config`. E.g., if I
run Semgrep with `--config tmp/whatever.yaml` and the rule ID is `my-rule`, the
complete rule ID is `tmp.whatever.my-rule`.

Rules in the Semgrep registry follow a similar pattern. It's based on the path
that of the rule in the GitHub repo [semgrep/semgrep-rules][rules-gh]. E.g., the
complete rule ID for the C `double-free` rule is
`c.lang.security.double-free.double-free` because it's in
`semgrep-rules/c/lang/security/double-free.yaml`. Note the double `double-free`
(har har) in the end because both the file name and the rule ID are the same.

[rules-gh]: https://github.com/semgrep/semgrep-rules

Our options when processing the results are:

1. Use the complete rule ID. This is doable for registry rules because their ID
   is predictable, but not practical for local rules because we might have no
   control over their path.
2. Check if the rule ID in the results ends with the rule ID from our files with
   [strings.HasSuffix][suffix].
    1. Don't split by `.` and compare the last part. I've been bit by this when
       the rule ID had periods.
3. Run Semgrep with `--no-rewrite-rule-ids` to disable the complete rule ID
   generation. We will only the rule ID in the output, but this might lead to
   collisions.

[suffix]: https://pkg.go.dev/strings#HasSuffix

## Reading the JSON Output
There are two ways to read the JSON output.

1. Tell Semgrep to store the results in a file with the `--output` switch.
    1. This might be removed in the future according to the developers.
2. Read it from process output.
    1. The package uses this option.

## Output Structs
The structure of the output is defined in [semgrep/semgrep-interfaces][int-gh].
The source of truth is the atd file, but it's an OCaml thing and I don't know
how to parse it. I rely on the automatically generated JSON schema in
[semgrep_output_v1.jsonschema][schema].

I used [omissis/go-jsonschema][go-schema] (formerly `atombender/go-jsonschema`)
to generate the Go structs from the JSON schema. From time to time, the schema
might break backwards compatibility.

Don't upgrade your Semgrep version without checking if the format has changed.
Generate the structs and then do a simple compare to see if anything major has
changed.

### Generating Structs
I use these commands:

```
$ git clone https://github.com/semgrep/semgrep-interfaces && cd semgrep-interfaces
# optional: check out the tag for a specific Semgrep version
$ git checkout v1.52.0

# install go-jsonschema
$ go install github.com/omissis/go-jsonschema/cmd/gojsonschema@latest

# generate the output
# -p output: package name is output
# -o output.go: write the structs to output.go
$ gojsonschema -p output -o output.go --verbose semgrep-interfaces/semgrep_output_v1.jsonschema
```

What I tried and didn't work in Go:
https://parsiya.io/abandoned-research/semgrep-output-json/.

[int-gh]: https://github.com/semgrep/semgrep-interfaces
[schema]: https://github.com/semgrep/semgrep-interfaces/blob/main/semgrep_output_v1.jsonschema
[go-schema]: https://github.com/omissis/go-jsonschema

Similar article for Rust: https://parsiya.net/blog/2022-10-16-yaml-wrangling-with-rust/.

## Extracting Metavariables via the Message Field
In these examples, I have smuggled the value of metavariables from the message
field. It's convenient and with a bit of smart placement and text processing,
you can get structured data out of it.

You could also access the values of metavariables from the struct. They can be
accessed via `result.Extra.Metavars["$METAVARNAME"]`. There are two fields,
`AbstractContent` and `PropagatedValue`. Generally, you want the propagated
value (the equivalent of having `value($METAVARNAME)` in the message field).
For more information please see
https://semgrep.dev/docs/writing-rules/experiments/display-propagated-metavariable/.

# The Experiments
The `code` subdirectory contains the test data as git submodules. Be sure to
populate them with before running the examples. They are:

* [OWASP Juice Shop][juice-gh]
* [sirupsen/logrus][logrus]

[juice-gh]: https://github.com/juice-shop/juice-shop
[logrus]: https://github.com/sirupsen/logrus

## 00. Running Semgrep
The "official" way to run Semgrep is via the Semgrep command. So my package uses
a wrapper. You can also use the `osemgrep` binary directly or look into how the
Python wrapper does it.

I am going to run it on [OWASP Juice Shop][juice-gh] with the `p/default`
ruleset and then use it in some other examples.

The `semgrep_go` package allows us to use some common switches. The `Extra`
field is a `[]string` that allows us to pass the rest of the switches. Because
we want to store the output in a file, we will just pass `--output`. But we can
also have multiple parameters like
`[]string{"--no-rewrite-rule-ids", "--severity", "WARN"}`.

```go
// Setup Semgrep switches.
opts := run.Options{
    Output:    run.JSON,       // Output format is JSON.
    Paths:     []string{path}, // "code/juice-shop"
    Rules:     []string{"p/default"},
    Verbosity: run.Debug,
    Extra:     []string{"--output=output/juice-shop.json"},
}
```

Let's run Semgrep. We don't care about the output so we will use `Run` instead
of `RunJSON`. We will also ignore the output.

```go
log.Print("Running Semgrep, this might take a minute.")
// Run Semgrep and ignore the output.
_, err := opts.Run()
return err
```

Read `output/juice-shop.json` and parse it with `jq`. This example shows the
ruleID and path of every hit.

```
$ jq '.results[] | "ruleid: " + .check_id + " - path: " + .path' output/juice-shop.json
```

{{< imgcap title="See the complete rule IDs" src="00.png" >}}

## Exclude Rules
Objective: Remove results for specific rules.

Let's start with something easy. We've used a ruleset/rulepack, but we want to
ignore results from certain rules instead of modifying it directly to remove
those rules. We can do it in two ways:

1. Use multiple `--exclude-rule` switches.
2. Process the results and delete the hits from excluded rules.

Our example is running Semgrep with the `p/default` ruleset on
[OWASP Juice Shop][juice-gh] in `code/juice-shop`.

### 01. Passing Multiple exclude-rule Switches
The [semgrep-go][semgrep-go] package allows us to pass command line switches to
Semgrep. We could have used `jq` to process JSON on the command line, too, but I
rather use Go in a proper program especially if the list of excluded rules is
big or dynamic.

```go
// fun/01_exclude_switch.go

// In the real world we will get a long list from somewhere.
excludedRules := []string{
    "javascript.audit.detect-replaceall-sanitization.detect-replaceall-sanitization",
}
var extra []string
// Add all the excluded rules like a `--exclude-rule=[ID]` argument.
for _, r := range excludedRules {
    extra = append(extra, "--exclude-rule="+r)
}

log.Printf("Excluding results for: %s", excludedRules)
```

Add the extra switches in the `Extra` field.

```go
// Setup Semgrep switches.
opts := run.Options{
    Output:    run.JSON,       // Output format is JSON.
    Paths:     []string{path}, // "code/juice-shop"
    Rules:     []string{"p/default"},
    Verbosity: run.Debug,
    Extra:     extra, // Items in Extra will be added to the CLI as-is.
}
```

Run Semgrep and deserialize the output.

```go
log.Print("Running Semgrep, this might take a minute.")
// Run Semgrep and get the deserialized output.
out, err := opts.RunJSON()
if err != nil {
    return err
}
```

Loop through the hits/findings/matches in the deserialized output and check
ruleIDs against the exclusions.

```go
// Check if any of the ruleIDs match what we wanted to exclude.
for _, hit := range out.Results {
    if strings.Contains(hit.RuleID(), "detect-replaceall-sanitization") {
        return fmt.Errorf("Found a rule that should have been excluded.")
    }
}
```

The field name for ruleID in the output is actually `CheckId`. So I have a
`RuleID()` method. Finally, we use the package to create an ASCII table of all
ruleIDs and their number of hits.

If you've cloned the [semgrep-fun][semgrep-fun] repo, run
`go run main.go 01 code/juice-shop`.

[semgrep-fun]: https://github.com/parsiya/semgrep-fun

{{< imgcap title="Excluding rules with CLI switches" src="01.png" >}}

### 02. Removing Specific Results from the Output
The results might come from a pipeline where cannot modify the Semgrep command.
In this experiment, I will process the deserialized output and remove all hits
with the specific rule IDs.

Instead of running Semgrep again, I will use the output from section 00 in
`output/juice-shop.json`.

```go
// Read the data in "output/juice-shop.json".
data, err := os.ReadFile("output/juice-shop.json")
if err != nil {
    return err
}
// Deserialize the data.
out, err := output.Deserialize(data)
if err != nil {
    return err
}
```

`out` has our deserialized results.

```go
// Create a new slice to hold the modified results.
var modifiedResults []output.CliMatch

// Loop through the results.
for _, hit := range out.Results {
    // Check if the hit's ruleID matches any of the excluded rules.
    if slices.Contains(excludedRules, hit.RuleID()) {
        // If it does, skip it.
        continue
    }
    // If the ruleID is not excluded, add it to modifiedResults.
    modifiedResults = append(modifiedResults, hit)
}

// Replace the results with the modified results.
out.Results = modifiedResults
```

Note how we are replacing the results in the original object. We can serialize
the modified object back to JSON and pass it to the next step of the pipeline.

```go
js, err := out.Serialize(true)
if err != nil {
    return err
}
```

Run this command to see it in action:
`go run main.go 02 code/juice-shop`.

{{< imgcap title="Summary of results" src="02.png" >}}

## 03. Unit Test Coverage in Go
Objective: Which functions in a package have unit tests. 

### Go Unit Tests
TL;DR:

1. Assume function is `Func1` in file `func1.go`.
2. Test is function `TestFunc1` in file `func1_test.go` in the same package.

I usually use the `vscode-go` extension to
[generate test skeletons][vscode-go-test]. Works better than AI, tbh.

[vscode-go-test]: https://code.visualstudio.com/docs/languages/go#_test.

### Logic

1. Extract all function names with their package and file names.
    1. The package name can reduce false positives for identical names in
       different packages.
2. Go through the list of functions and filter the noise.
    1. (optional) Select functions that are not in files that end in `_test.go`.
    2. (optional) Select functions that are exported (start with a capital letter).
3. Check each function has a test. E.g., for `Func1` do:
    1. Does `TestFunc1` exist in the same package?
        1. If not, log there's no test.
    2. If so, is it in the `func1_test.go`?
        1. If not, log the test is in the wrong place.
    3. Log `Func1` has a test in the correct location.

### .semgrepignore
Semgrep ignores [certain test files and paths][semgrep-def] (among other
things). See everything in the [default .semgrepignore file][semgrep-ignore].
We want to scan the test files.

[semgrep-def]: https://semgrep.dev/docs/ignoring-files-folders-code/#understanding-semgrep-defaults
[semgrep-ignore]: https://github.com/semgrep/semgrep/blob/develop/cli/src/semgrep/templates/.semgrepignore

To make Semgrep scan test files we create an empty `.semgrepignore` file in the
current working directory before we run Semgrep and delete it after.

### The Custom Rule
This is a custom rule that collects:

1. Package name
2. Function name

We also need the file name but that's done in the post-processing part.

The rule will look like this. This is the experimental rule syntax. Here's a
{{< xref path="/post/2023/2023-10-28-semgrep-experimental-syntax/"
    text="tutorial" >}}.
I have also included the old rule syntax.

```yaml
rules:
  - id: blog-2023-11-go-function-extract
    match:
      all:
        - inside: |
            package $PKG
            ...
        - func $FUNC(...)
    # patterns:
    #   - pattern-inside: |
    #       package $PKG
    #       ...
    #   - pattern: func $FUNC(...)
    message: $PKG - $FUNC
    languages:
      - go 
    severity: WARNING
```

You can see the rule in action at:
https://semgrep.dev/playground/r/zdUKA4D/parsiya.blog-2023-11-go-function-extract

### Running Semgrep and Extracting the Info
Rule messages are in the form of `$PKG - $FUNC`. We will need three pieces of
information:

1. Package name: In message.
2. Function name: In message.
3. File path: In `.Path` or using the helper method `.FilePath()`.

Then it becomes a DSA problem and you can skip reading the rest of the section
if you want to.

First, we create a `FuncInfo` object for each function:

```go
// FuncInfo contains information about a function.
type FuncInfo struct {
	Package string
	Name    string
	Path    string
}
```

And create a map where the key is a package name and the members are the
functions in that package.

```go
// FuncList is a map where key is the package name and the value is FuncMap.
type FuncList map[string]FuncMap
```

Then we can easily populate these from the results:

```go
// Loop through the results.
for _, hit := range out.Results {
    // $PKG - $FUNC
    msg := strings.Split(hit.Message(), " - ")
    // msg[0]: $PKG
    // msg[1]: $FUNC

    // Note we're not doing a lot of error checking here.
    if len(msg) != 2 {
        log.Printf("Wrong message, got: %s", hit.Message())
        continue
    }
    // Store the function info in a FuncInfo struct.
    fn := FuncInfo{
        Package: msg[0],
        Name:    msg[1],
        Path:    hit.FilePath(),
    }
    if _, ok := funcList[fn.Package]; !ok {
        funcList[fn.Package] = make(FuncMap)
    }
    funcList[fn.Package][fn.Name] = fn
}
```

We could use this map to extract any info we want. We can also use another trick
here. In Go, the tests belong to the same package so we can just create a list
of functions in each package and then do a search in an array of strings.

```go
data := make([][]string, 0)

// Now, we have a map of all functions in code, we can go through the
// functions in each package and check if they have a test.
for _, funcs := range funcList {

    // It's easier to create a slice of all functions in a package for
    // searching.
    var funcNames []string
    for _, fn := range funcs {
        funcNames = append(funcNames, fn.Name)
    }

    // [next section with the checks]
}
```

Then we can go through each function and check if it has a test in the same
package by using `string.Contains`. We're also saving a few cycles by skipping
test functions (in files ending in `_tests.go`).

```go
for _, fn := range funcs {
    // Skip functions in `*_test.go` files.
    if strings.HasSuffix(fn.Path, "_test.go") {
        continue
    }

    // Check if the function has a test. AKA "Test"+fn.Name is in the
    // package.
    if slices.Contains(funcNames, "Test"+fn.Name) {
        continue
    }
    // Add the functions with missing tests to the data slice.
    data = append(data, []string{fn.Name, fn.Package, fn.Path})
}
```

Running it on `code/logrus` gives us this table. But you can pass the path to
any other Go code to the command line.

{{< imgcap title="List of functions in logrus" src="03.png" >}}

## Summary Reports
You run Semgrep and get a bunch of results. If you want to review the results,
you should use the `--sarif` switch and use a [SARIF][sarif] viewer. I usually
use the VS Code SARIF plugin. It allows me to look at the issue in the editor.

[sarif]:https://sarifweb.azurewebsites.net/

But we can also process the output and create reports with specific items. The
`semgrep_go` package supports creating two types of tables:

1. Count by rule ID
2. Count by file path

We're going to use the output of running `p/default` on [Juice Shop][juice-gh]
from before.

### 04. Text Summary Report
Let's create a simple ASCII report. We will create two tables. First one shows
us high impact rules and the second one, files with highest number of findings.
Generally, we want to have the rule IDs and files with the highest number of
findings at the top, this is done by passing `true` to the two functions below.
If we pass `false`, the tables will be sorted by rule ID or file path
alphabetically.

```go
// fun/04_text_report.go

// [Removed]
// The deserialized results are in `out`.

// Create the reports.
ruleIDTextReport := out.RuleIDTextReport(true)
filePathTextReport := out.FilePathTextReport(true)

// Print the reports.
log.Print("Rule ID report:")
log.Print(ruleIDTextReport)

log.Print("File Path Report:")
log.Print(filePathTextReport)
```

This time instead of passing the code base path, we will pass the output file
from section 00. The program will print two text tables.
`go run main.go 04 output/juice-shop.json`

{{< imgcap title="Summary report" src="04.png" >}}

### 05. HTML Summary Report
For the HTML summary report, I wanted to make something similar to the Semgrep
outline. We can create a template using the Go [html/template][go-html] package
and apply it to the output object. This is going to look ugly, but good enough
for an example.

[go-html]: https://pkg.go.dev/html/template

The code is similar to the previous section. We will deserialize the result and
create a report struct.

```go
// fun/05_html_report.go

// Report contains the information in the HTML report.
type Report struct {
	NumberOfFindings int
	ByRuleID         []output.HitMapRow
	ByFilePath       []output.HitMapRow
}

func HTMLReport(path string) error {
    // [Removed]
    // The deserialized results are in `out`.

    // Create the report object.
    rep := Report{
        NumberOfFindings: len(out.Results),
        ByRuleID:         out.RuleIDHitMap(true),
        ByFilePath:       out.FilePathHitMap(true),
    }
    // removed
}
```

Then we will pass to an HTML template which uses the built-in Go template engine.

```go
// embed the 05-report-html-tmpl.html in a string.
//
//go:embed 05-report-html-template.html
var tmpl string

func HTMLReport(path string) error {
    // removed

	// Apply the template.
	t, err := template.New("report").Parse(tmpl)
	if err != nil {
		return err
	}
	var data bytes.Buffer
	if err = t.Execute(&data, rep); err != nil {
		return err
	}
    // removed
}
```

We will write the resulting HTML report to `output/05-report.html`. You can also
see it in the cloned repo.

`go run main.go 05 output/juice-shop.json`

{{< imgcap title="Graphic design is my passion" src="05.png" >}}

## 06. Go Function Call Chain
This is a simple function call chain experiment.

Probably the most straightforward way of doing this would be with a rule like
this rule.

```yaml
rules:
- id: go-function-chain
  patterns:
    - pattern-inside: |
        package $PKG
        ...
    - pattern-inside: |
        func $CALLER(...) {...}
    - pattern-either:
        - pattern: $CALLEE(...)
        - pattern: $IMP.$CALLEE(...)
    - metavariable-regex:
        metavariable: $CALLEE
        regex: ^[^.]*$
    - focus-metavariable: $CALLEE
  message: $PKG - $CALLER - $CALLEE - $IMP
  languages:
    - go
  severity: WARNING
```

We're looking for two types of calls:

1. Local package functions: `$CALLEE(...)`
2. Imported functions: `$IMP.$CALLEE(...)`

Playground link: https://semgrep.dev/playground/r/oqUgbKy/parsiya.go-function-chain

I had to fix two issues with this pattern:

First, Imported functions like `strings.Contains` are captured twice, one as
`$CALLEE: strings.Contains` and the other as
`$IMP: strings, $CALLEE = Contains`. The `metavariable-regex` looks for the
literal dot in `$CALLEE` and drops the first match.

Second, we're only capturing the top-level package name instead of the complete
name. So if two different packages have the same top-level package and function
names, we have a collision.

We can track all imports in each file. The pattern will be `import $IMPORT` and
we will group the results by file path. Now, we can create the complete package
name for each file.

```yaml
rules:
- id: go-import-collection
  patterns:
    - pattern-inside: |
        package $PKG
        ...
    - pattern-either:
      - patterns:
          - pattern: import "$IMPORT"
          - pattern-not: import $ALIAS "$IMPORT"
      - pattern: import $ALIAS "$IMPORT"
  message: $PKG - $ALIAS - $IMPORT
  focus-metavariable: $IMPORT
  languages:
    - go
  severity: WARNING
```

Playground link: https://semgrep.dev/playground/r/2ZUzvdK/parsiya.go-import-collection
When processing the results from this rule, we have to filter out the text
`$ALIAS` in the message which happens when the package is not imported as an
alias. Alternatively, we could have two rules. One for each pattern.

The rest of the processing is kind of straightforward. 

The `go-import-collection` rule returns each package's alias (if it exists) and
its complete name. We create an `ImportMap` for each file. It's a
`map[string]string` where the key is the top-level package name (e.g., `bar` for
`github.com/foo/bar`) or its import alias (e.g., `bar` for
`import bar "github.com/foo/bar"`).

All of these go into a different map where the key is the file path and value is
the import map.

```go
// ImportMap is map of one file's imports.
//
// Key: Alias if it exists or the top-level package if not (e.g., "bar" for
// "github.com/foo/bar").
//
// Value: Complete package name.
type ImportMap map[string]string

// Imports is a map of file paths to their imports. Key is file path.
type Imports map[string]ImportMap
```

`go-function-chain` returns the function name, package name, and file path for
each function. This is enough to identify each function in code. The file path
helps prevent collisions when two packages have the same name in different
parent packages. E.g., `github.com/foo/bar` and `github.com/baz/bar`.

```go
// Function represents one function.
type Function struct {
	Package  string
	Name     string
	FilePath string
}
```

The final result is still undercooked and has two issues:

1. It only goes down one level. E.g., caller to callee.
2. Object methods are not recognized properly. E.g.,
   `runtime.FuncForPC(pcs[i]).Name()` has package name of
   `runtime.FuncForPC(pcs[i])` which is wrong.

But we have enough information to create a decent call chain.

### Bonus Go Package Shenanigans
Go packages are special. All files in the same package can be merged into one
big file without parsing issues. When dealing with Go packages, we can use this
to our advantage and treat each package as one big file. This helps with
intra-package analysis because we can simplify our rules.

**There's one issue**. When you merge everything under the hood before Semgrep
analysis, the results will have points to the merged file (e.g., line 15 of the
merged.go). We have to modify the results and translate them back to the
original files because the user did not see our pre-processing.

This has a simple solution. We have the code snippet with the result, we can
just search it in the original files. I did not expect it to be this simple. I
was creating a map of offsets to track which offset is from which file, but this
solution is just easier.

## 07. Misc Tips and Tricks
At this point I have been sporadically writing this blog for almost two months
so I just wanna finish it. Here are some other tips and tricks, you can read
more at https://parsiya.io/research/semgrep-tips/.

```bash
# Download a ruleset yaml file.
$ wget https://semgrep.dev/c/p/{ruleset-name} -O file.yaml
# Example
$ wget https://semgrep.dev/c/p/default -O default.yaml
```

Run all rules `--config r/all`.

Check if a specific file exists. E.g., `/path/to/badfile.ext`.

```yaml
rules:
- id: detect-file
  patterns:
    - pattern-regex: .*
  message: Semgrep found the file
  languages:
    - generic
  severity: WARNING
  paths:
    include:
      - /path/to/badfile*
    exclude:
      - /paths/to/exclude/*
```

# What Did We Learn Here Today?
We learned to process Semgrep output results. With handcrafted rules, we can
extract so much information from Semgrep results.