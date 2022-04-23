---
title: "A Hands-On Intro to Semgrep's Autofix"
date: 2021-10-25T20:00:47-07:00
draft: false
toc: true
comments: true
twitterImage: 11-go-httponly-1.png
categories:
- Automation
- Semgrep
---

Semgrep's experimental [autofix][semgrep-autofix] feature can automagically
modify vulnerable code. A few things can be fixed like this but it's worth
exploring. This post is an introduction to creating fixes for your Semgrep
rules.

I have included links to the playground for practicing. If you prefer
running the rules via the command-line please see the rules and code at
[https://github.com/parsiya/Parsia-Code/tree/master/semgrep-autofix][gh-code].

[semgrep-autofix]: https://semgrep.dev/docs/experiments/overview/#autofix
[gh-code]: https://github.com/parsiya/Parsia-Code/tree/master/semgrep-autofix

<!--more-->

Note: This is an experimental feature. The following is correct at the time of
writing (October 2021). If you are from the future, things will be different.

# Prerequisites
You don't have to be an appsec guru but this blog assumes you are somewhat
familiar with:

1. Semgrep and have done [https://semgrep.dev/learn][semgrep-learn].
2. Java and Go code.
3. Some application security topics like HttpOnly and XSS.

[semgrep-learn]: https://semgrep.dev/learn

## Testing Rules
An essential part of any experimentation like this is running rules against code
snippets. With Semgrep we have two options:

1. Semgrep playground
2. Semgrep CLI

### Semgrep Playground
The playground is at [https://semgrep.dev/editor][semgrep-playground] and I will
mostly use it to show my work. If you create an account, you can save your rules
and save them or, you can use it without one.

[semgrep-playground]: https://semgrep.dev/editor

### Semgrep CLI
If you don't like your rules to hit the cloud (and I usually want to keep my
rules and code secret), you can use the Semgrep CLI. Getting the CLI is as easy
as `python3 -m pip install semgrep` (I use it inside WSL). See more at
[https://semgrep.dev/docs/getting-started/][semgrep-getting-started].

[semgrep-getting-started]: https://semgrep.dev/docs/getting-started/

After writing a rule, verify it to catch any formatting/logic errors (`-c` can
also point to a directory of rules):

```
semgrep -c rule1.yaml --validate
```

Run a rule on a file or directory (add `--debug` for troubleshooting):

```
semgrep -c rule1.yaml example.java

semgrep -c my-rules-directory src-directory
```

Use the  `--autofix` switch to automagically modify files. `--dryrun` shows the
changes w/o modification. However, executing rules with `fix` sections without
`--autofix` does the same:

```
semgrep -c rule1.yaml example.java --autofix --dryrun
```

{{< imgcap title="No need to use dryrun" src="00-autofix-dryrun.png" >}}

# Autofix Variants
There are two ways to include it in rules:

* `fix`
* `regex-fix`

## Fix
Straightforward feature. Whatever has been caught by the rule will be replaced
by what you specify.

### Python - sys.exit
The example in the documentation is at
[https://semgrep.dev/s/R6g][python-exit-example] and replaces `exit` with
`sys.exit`. If I click the first `Apply fix` button, `exit(3)` is replaced with
`sys.exit(3)`.

[python-exit-example]: https://semgrep.dev/s/R6g

{{< imgcap title="First fix applied" src="01-sys-exit.png" >}}

Metavariables in `fix` are replaced by their values. This is very useful.

### Java - CBC Padding Oracle
`fix` shines when we are catching and replacing a string. Look at the
[java.lang.security.audit.cbc-padding-oracle][cbc-padding-rule] rule (I have
modified the rule to make it easier to read).

[cbc-padding-rule]: https://github.com/returntocorp/semgrep-rules/blob/develop/java/lang/security/audit/cbc-padding-oracle.yaml

```yaml
# java-cbc-padding-oracle/cbc-padding-oracle.yaml
rules:
  - id: cbc-padding-oracle
    severity: WARNING
    message: Match found
    languages:
      - java
    pattern: $CIPHER.getInstance("=~/.*\/CBC\/PKCS5Padding/")
    fix: $CIPHER.getInstance("AES/GCM/NoPadding")
```

It looks for anything that looks like `object.getInstance("string")` and the
string contains `CBC/PKCS5Padding`.

You can see Semgrep's [string matching][string-matching] in
`=~/.*\/CBC\/PKCS5Padding/`. It returns a match if the regex matches the
string parameter of the `getInstance` method. See it in action at
[https://semgrep.dev/s/parsiya:java-cbc-padding-oracle][playground-cbc-padding-oracle].

After running the rule you can see the fix in the right side and click on
`Apply fix` to modify the code (if you want to repeat, both the rule and the
test code support `ctrl+z`).

[string-matching]: https://semgrep.dev/docs/writing-rules/pattern-syntax/#string-matching
[playground-cbc-padding-oracle]: https://semgrep.dev/s/parsiya:java-cbc-padding-oracle

String matching is deprecated. Let's rewrite the rule with
[metavariable-regex][metavariable-regex].

```yaml
# java-cbc-padding-oracle/cbc-padding-oracle-metavariable-regex.yaml
rules:
  - id: cbc-padding-oracle-metavariable-regex
    message: Match found
    languages:
      - java
    severity: WARNING
    patterns:
      - pattern: $CIPHER.getInstance($INS)
      - metavariable-regex:
          metavariable: $INS
          regex: .*\/CBC\/PKCS5Padding
    fix: $CIPHER.getInstance("AES/GCM/NoPadding")
```

The string parameter is now a metavariable and we directly run the regex against
it. Try changing the regex to see what else you can match in
[https://semgrep.dev/s/parsiya:java-cbc-padding-oracle-metavariable-regex][playground-cbc-metavar].

[metavariable-regex]: https://semgrep.dev/docs/writing-rules/rule-syntax/#metavariable-regex
[playground-cbc-metavar]: https://semgrep.dev/s/parsiya:java-cbc-padding-oracle-metavariable-regex

It looks like the metavariable-regex version has more "computation." My very
"scientific" experiment of 50 runs shows they are not that different.

```
$ multitime -q -n 50 ./cbc-padding-oracle.sh
===> multitime results
1: -q ./cbc-padding-oracle.sh
            Mean        Std.Dev.    Min         Median      Max
real        0.781       0.006       0.773       0.780       0.806
user        0.501       0.041       0.406       0.500       0.609
sys         0.256       0.044       0.172       0.258       0.359

$ multitime -q -n 50 ./cbc-padding-oracle-metavariable-regex.sh
===> multitime results
1: -q ./cbc-padding-oracle-metavariable-regex.sh
            Mean        Std.Dev.    Min         Median      Max
real        0.788       0.007       0.778       0.786       0.813
user        0.516       0.047       0.406       0.516       0.609
sys         0.247       0.048       0.156       0.250       0.359
```

### Java - HttpOnly Cookies
We want our cookies to have the `HttpOnly` and `Secure` attributes. I am going
to explain the fix for `HttpOnly` and let you write the ones for `Secure`
(almost identical). Summarized rule from the [semgrep-rules][rule-url] repo:

[rule-url]: https://github.com/returntocorp/semgrep-rules/blob/develop/java/lang/security/audit/cookie-missing-httponly.yaml

```yaml
# java-httponly/httponly-practice.yaml
rules:
- id: cookie-missing-httponly
  message: Match found
  severity: WARNING
  languages: [java]
  patterns:
  - pattern-not-inside: $COOKIE.setValue(""); ...
  - pattern-either:
    - pattern: $COOKIE.setHttpOnly(false);
    - patterns:
      - pattern-not-inside: $COOKIE.setHttpOnly(...); ...
      - pattern: $RESPONSE.addCookie($COOKIE);
```

It matches if the code is calling:

1. `$COOKIE.setHttpOnly(false);` manually.
2. `$RESPONSE.addCookie($COOKIE);` without `$COOKIE.setHttpOnly(...)`.

The playground link is
[https://semgrep.dev/s/parsiya:java-httponly-practice][java-httponly-practice].
If you are running locally:

```
semgrep -c httponly-practice.yaml httponly.java
```

[java-httponly-practice]: https://semgrep.dev/s/parsiya:java-httponly-practice

The fix is different for each pattern. It should replace:

1. `$COOKIE.setHttpOnly(false);` with `$COOKIE.setHttpOnly(true);`.
2. `$RESPONSE.addCookie($COOKIE);` with `$COOKIE.setHttpOnly(true); $RESPONSE.addCookie($COOKIE);`.

We cannot create a fix that matches both cases. We can break the rule and create
separate fixes.

#### HttpOnly Pattern 1
The first pattern only checks `$COOKIE.setHttpOnly(false);` and we just need to
replace `false` with `true`. Playground link: 
[https://semgrep.dev/s/parsiya:java-httponly-practice-1][java-httponly-practice-1].

[java-httponly-practice-1]: https://semgrep.dev/s/parsiya:java-httponly-practice-1

```yaml
# java-httponly/httponly-practice-1.yaml
rules:
- id: cookie-missing-httponly-1
  message: Match found
  severity: WARNING
  languages: [java]
  patterns:
  - pattern-not-inside: $COOKIE.setValue(""); ...
  - pattern: $COOKIE.setHttpOnly(false);
  fix: $COOKIE.setHttpOnly(true);
```

{{< imgcap title="semgrep -c httponly-practice-1.yaml httponly.java" src="02-httponly-1.png" >}}

#### HttpOnly Pattern 2
The second pattern matches if we see `$RESPONSE.addCookie($COOKIE);` but no
`setHttpOnly`. The fix is `$COOKIE.setHttpOnly(true);` as a new line before the
match. Playground link is
[https://semgrep.dev/s/parsiya:java-httponly-practice-2][java-httponly-practice-2]
or use the CLI.

```
semgrep -c httponly-pracitce-2.yaml httponly.java
```

[java-httponly-practice-2]: https://semgrep.dev/s/parsiya:java-httponly-practice-2

```yaml
# java-httponly/httponly-practice-2.yaml
rules:
  - id: cookie-missing-httponly-2
    message: Match found
    severity: WARNING
    languages:
      - java
    patterns:
      - pattern-not-inside: $COOKIE.setValue(""); ...
      - pattern-not-inside: $COOKIE.setHttpOnly(...); ...
      - pattern: $RESPONSE.addCookie($COOKIE);
    fix: |
      $COOKIE.setHttpOnly(true);
      $RESPONSE.addCookie($COOKIE);
```

The fix works but it's not aligned properly.

{{< imgcap title="httponly-pracitce-2 fix" src="03-httponly-2.png" >}}

This is not an issue in Java but we can fix this with `fix-regex`.

## fix-regex
`fix` is great for simple replacements (e.g., `badFunc` to `goodFunc`). But
`fix-regex` has the power of regular expressions. See the docs at
[https://semgrep.dev/docs/experiments/overview/#autofix-with-regular-expression-replacement][fix-regex-doc].

[fix-regex-doc]: https://semgrep.dev/docs/experiments/overview/#autofix-with-regular-expression-replacement

It has three fields:

* `regex`: Runs a regex on **the text captured by the rule**.
* `replacement`: The replacement to the text captured by the rule.
* `count`: (optional) How many instances of `regex` are replaced with
  `replacement`.

**Note:** Currently (2021-10-25), `fix-regex` does not support metavariables
unlike `fix`. If have metavariables in the `replacement` section, they will be
treated as text. You can track this bug at
[https://github.com/returntocorp/semgrep/issues/3269][fix-regex-metavar-bug].

[fix-regex-metavar-bug]: https://github.com/returntocorp/semgrep/issues/3269

### Java - HttpOnly Cookies Revisited
Previously, we "fixed" HttpOnly but the alignment was not correct. I am going to
solve the same problem with `fix-regex`. The second pattern matched the 4th line
in the code below:

```java
  @RequestMapping(value = "/cookie1", method = "GET")
  public void setCookie(@RequestParam String value, HttpServletResponse response) {
      Cookie cookie = new Cookie("cookie", value);
      response.addCookie(cookie); // <--- This line was matched.
  }
```

Let's experiment with how the capture works (if you want to tag along [https://semgrep.dev/s/parsiya:java-httponly-fix-regex-practice][httponly-fix-regex-practice]).

[httponly-fix-regex-practice]: https://semgrep.dev/s/parsiya:java-httponly-fix-regex-practice

To see everything that was matched let's run this rule.

```yaml
# java-httponly/httponly-fix-regex-practice.yaml
rules:
  - id: cookie-missing-httponly-fix-regex-practice
    message: Match found
    severity: WARNING
    languages:
      - java
    patterns:
      - pattern-not-inside: $COOKIE.setValue(""); ...
      - pattern-not-inside: $COOKIE.setHttpOnly(...); ...
      - pattern: $RESPONSE.addCookie($COOKIE);
    fix-regex:
      regex: (.*)
      replacement: //\1
```

We are creating a capture group in `regex` and then using it in the `replacement`
section with `\1`.

{{< imgcap title="The result after running the above" src="04-httponly-fix-regex-1.png" >}}

So what happened here? To regex is greedy (the docs mention this). Two different
matches were captured. Both were prepended with `//` (we can fix this with
`(.*+)` but let's continue).

1. The line and its whitespace.
    1. `[8xSpace]response.addCookie(cookie);`
2. The "nothing" after the line above.
    1. At least that's what I think it is.

We can fix this with the `count` field. We only want to replace the first match
so we set it to `1`.

{{< imgcap title="Running the rule with count: 1" src="05-httponly-fix-regex-2.png" >}}

This is much better. But I have not fixed the alignment. We can capture the
whitespace with another capture group.

```yaml
    fix-regex:
      regex: (\s*)(.*)
      replacement: \1// \2
      count: 1
```

The first capture group is the whitespace and the second is the code.

{{< imgcap title="Alignment fixed" src="06-httponly-fix-regex-3.png" >}}

Now we need to add the new line with the correct whitespace (it's in `\1`) above
the captured line. `\2` is the original `addCookie` line. If `fix-regex`
supported metavariable replacement like `fix` the rule would look like:

```yaml
# java-httponly/httponly-fix-regex-practice-2.yaml
fix-regex:
  regex: (\s*)(.*)
  replacement: |
    \1$COOKIE.setHttpOnly(true);
    \1\2
  count: 1
```

This is not implemented, yet. See 
[https://semgrep.dev/s/parsiya:java-httponly-fix-regex-practice-2][ideal].

[ideal]: https://semgrep.dev/s/parsiya:java-httponly-fix-regex-practice-2

{{< imgcap title="Metavariable in replacement" src="07-httponly-fix-regex-4.png" >}}

We must capture `cookie` from `response.addCookie(cookie);` (the match) and
add `.setHttpOnly(true)`.

The new regex is `(\s*)(.*addCookie\((.*)\).*)`:

1. `(\s*)`: The first capture group is still whitespace. 
2. `(.*addCookie\((.*)\).*)`: The second is `response.addCookie(cookie);`
   without the whitespace. We will print it as-is in the 2nd line of the fix.
3. `.*addCookie\((.*)\)`: This is inside the second group and is trying to
   capture whatever comes after `addCookie(` and before `)`.

We have everything we need to create the fix:

```yaml
# java-httponly/httponly-fix-regex-practice-final.yaml
rules:
  - id: cookie-missing-httponly-fix-regex-practice-final
    message: Match found
    severity: WARNING
    languages:
      - java
    patterns:
      - pattern-not-inside: $COOKIE.setValue(""); ...
      - pattern-not-inside: $COOKIE.setHttpOnly(...); ...
      - pattern: $RESPONSE.addCookie($COOKIE);
    fix-regex:
      regex: (\s*)(.*addCookie\((.*)\).*)
      replacement: |
        \1\3.setHttpOnly(true);
        \1\2
      count: 1
```

{{< imgcap title="Correct fix with fix-regex" src="08-httponly-fix-regex-final.png" >}}

Playground link
[https://semgrep.dev/s/parsiya:java-httponly-fix-regex-practice-final][httponly-final].

[httponly-final]: https://semgrep.dev/s/parsiya:java-httponly-fix-regex-practice-final

### Go - text/template
In Go you can use `text/template` and `html/template`. The latter does some
output encoding and is safer for web use. It's possible to use `text/template`
correctly or in a non-web use case, but it's not usually the case.

At first glance you would think we can use `fix` and replace `text/template`
with `html/template`. To test this theory, add a `fix` section to the Semgrep's
[import-text-template][text-template] rule at
[https://semgrep.dev/s/parsiya:go-import-text-template-fix][go-text-fix].

[go-text-fix]: https://semgrep.dev/s/parsiya:go-import-text-template-fix
[text-template]: https://github.com/returntocorp/semgrep-rules/blob/develop/go/lang/security/audit/xss/import-text-template.yaml

The first reaction is to add a fix section like this:

```yaml
# go-import-text-template/import-text-template-fix.yaml
rules:
- id: import-text-template-fix
  message: Match found.
  severity: WARNING
  pattern: |
    import "text/template"
  languages:
    - go
  fix: import "html/template"
```

When we ask Semgrep to match `import "text/template"` it matches everything from
the `import` keyword until the end of `"text/template"`. This usually includes
other imports and our fix will replace other imports.

{{< imgcap title="The matched string in the rule above" src="09-import-text-fix.png" >}}

`fix-regex` "fixes" this (har har). The `regex` only looks for `text/template`
in the matched text and replaces it with `html/template` without overwriting
anything else. `count` is optional here because there's only one match. It's a
good habit to include it anyways.

```yaml
# go-import-text-template/import-text-template-fix-regex.yaml
rules:
- id: import-text-template-fix-regex
  message: Match found.
  severity: WARNING
  pattern: |
    import "text/template"
  languages:
    - go
  fix-regex:
    regex: text/template
    replacement: html/template
    count: 1
```

See the magic at
[https://semgrep.dev/s/parsiya:import-text-template-fix-regex][go-text-fix-regex].

[go-text-fix-regex]: https://semgrep.dev/s/parsiya:import-text-template-fix-regex

{{< imgcap title="text/template replaced with html/template" src="10-import-text-fix-regex.png" >}}

### Go - HttpOnly Cookies
Similar to the Java version, we can check if a cookie in Go has the `HttpOnly`
attribute. The original rule from the repo is at
[https://semgrep.dev/s/parsiya:go-httponly-original][go-httponly].

[go-httponly]: https://semgrep.dev/s/parsiya:go-httponly-original

```yaml
# go-httponly/go-httponly-original.yaml
rules:
  - id: cookie-missing-httponly
    patterns:
      - pattern-not-inside: |
          http.Cookie{
            ...,
            HttpOnly: true,
            ...,
          }
      - pattern: |
          http.Cookie{
            ...,
          }
    message: Match found
    fix-regex:
      regex: (HttpOnly\s*:\s+)false
      replacement: \1true
    severity: WARNING
    languages:
      - go
```

The rule checks if you have `http.Cookie` without `HttpOnly: true`. However, the
fix section only kicks in if the code has `HttpOnly: false`. If Go, the default
value for both `Secure` and `HttpOnly` is false so the absence of this attribute
is still a vulnerability

We can take a brute force approach and always add `HttpOnly: true`. This will
create a compiler error if the property already exists. So, I am gonna create a
new rule to only catch if there is no mention of `HttpOnly`.

```yaml
# go-httponly/go-httponly-1.yaml
rules:
  - id: cookie-missing-httponly-1
    severity: WARNING
    languages:
      - go
    patterns:
      - pattern-not-inside: |
          http.Cookie{
            ...,
            HttpOnly: ...,
            ...,
          }
      - pattern: |
          http.Cookie{
            ...,
          }
    message: Match found
    fix-regex:
      regex: (?s)(\s+)(.*)
      replacement: |
        \1\2
        \1    HttpOnly: true,
      count: 1
```

Playground link
[https://semgrep.dev/s/parsiya:go-cookie-missing-httponly-1][go-httponly-1].

[go-httponly-1]: https://semgrep.dev/s/parsiya:go-cookie-missing-httponly-1

{{< imgcap title="Fix with the new rule" src="11-go-httponly-1.png" >}}

As an exercise try and figure out how the fix works. It assumes code is
formatted by `gofmt` (see the space before `HttpOnly`). Rob Pike will come and
flip your work desk if you don't run it anyways.

### Adding Comments
This has gone long enough, these blogs take up a lot of time. Especially, with
playground links and local files for each exercise. I am just gonna do another
one and finish.

We want to add a comment before the vuln location. Things like remediation
messages or annotations are good candidates. I am gonna use the previous example
(Go), but most programming languages that do not rely on whitespace and use `//`
should be similar.

```yaml
# go-comment/go-comment
rules:
  - id: cookie-missing-httponly-comment
    severity: WARNING
    languages:
      - go
    patterns:
      - pattern-not-inside: |
          http.Cookie{
            ...,
            HttpOnly: ...,
            ...,
          }
      - pattern: |
          http.Cookie{
            ...,
          }
    message: Match found
    fix-regex:
      regex: (?s)(\s+)(.*)
      replacement: |
        \1// Match found by cookie-missing-httponly-comment.
        \1// HttpOnly must be set to true here.
        \1\2
      count: 1
```

Playground link [https://semgrep.dev/s/parsiya:go-comment][go-comment].

[go-comment]: https://semgrep.dev/s/parsiya:go-comment

{{< imgcap title="Comment added to the code" src="12-go-comment.png" >}}

# What Did We Learn Here Today?
We learned how to use Semgrep's `fix` and `fix-regex` with several "real world"
examples. Go through the [semgrep-rules] repo on GitHub and see if you can add
fixes for new rules or optimize/correct existing ones.

[semgrep-rules-gh]: https://github.com/returntocorp/semgrep-rules/