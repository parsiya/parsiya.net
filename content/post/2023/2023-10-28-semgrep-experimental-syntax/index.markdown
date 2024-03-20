---
title: "Semgrep's Experimental Rule Syntax"
date: 2023-10-28T12:43:08-07:00
draft: false
toc: true
comments: true
# twitterImage: .png
categories:
- semgrep
- Static Analysis
aliases:
- "/blog/2023-10-28-semgreps-new-rule-syntax/"
---

Semgrep has an experimental and (IMO) more readable rule syntax. I am converting
my own reference into a tutorial.

<!--more-->

**Disclaimer:** Semgrep (binary, playground, cloud, etc.) supports the experimental
syntax, but it's not released. If you're from the future and things have
changed, let me know somehow. E.g., make an issue in the blog's source at
[parsiya/parsiya.net][source] or create a pull request.

[source]: https://github.com/parsiya/parsiya.net

# TL;DR
Use these tables:

| Old | Experimental |
|---|---|
| patterns (top-level) | match and all |
| patterns (other) | all |
| pattern | [can be removed] |
| pattern-not | - not |
| pattern-either | any |
| pattern-inside | inside |
| pattern-not-inside | inside under not |

These items go inside a `where` clause:

| Old | Experimental |
|---|---|
| metavariable-pattern | metavariable and pattern |
| metavariable-regex | metavariable and regex |
| metavariable-comparison | metavariable and comparison |
| metavariable-analysis | metavariable and analyzer |
| focus-metavariable | focus |

Taint mode changes

| Old | Experimental |
|---|---|
| mode:taint | removed |
| match (taint mode) | taint |
| pattern-sources | sources |
| pattern-sinks | sinks |
| pattern-propagators | propagators |
| pattern-sanitizers | sanitizers |

# Official References
I've only been able to find two references so far:

* [Trying out the new Semgrep syntax][new-syntax-video] video.
* The [rule syntax JSON schema][rule-schema].

[new-syntax-video]: https://www.youtube.com/watch?v=dZUPjFvknnI
[rule-schema]: https://github.com/returntocorp/semgrep-interfaces/blob/main/rule_schema_v1.yaml

# Example 1
Modified version of the first example in the [Advanced Rule Tutorials][adv], 
[practice playground link][df-old].

[adv]: https://semgrep.dev/learn/advanced/1
[df-old]: https://semgrep.dev/playground/r/AbU2BL/parsiya.blog-2023-10-use-decimalfield-for-money-old

```yaml
rules:
- id: blog-2023-10-use-decimalfield-for-money-old
  patterns:
  # I know this `patterns` can be replaced by one `pattern`
  # but it's modified for the tutorial.
  - patterns:
    - pattern: $F = django.db.models.FloatField(...)
    - pattern: $F = django.db.models.FloatField(...)
  - pattern-inside: |
      class $M(...):
        ...
  - metavariable-regex:
      metavariable: '$F'
      regex: '.*(price|fee|salary).*'
  message: _removed_
  languages: [python]
  severity: ERROR
```

## Top-Level pattern(s) -> match and all
The top-level `pattern` or `patterns` becomes `match`. It's almost always
followed by `all` or `any`.

```yaml
rules:
- id: use-decimalfield-for-money-new-syntax
  # top-level patterns replaced by match and all.
  match:
      # the rest of the patterns
      # # I know this `patterns` can be replaced by one `pattern`
      # # but it's modified for the tutorial.
      # - patterns:
      #   - pattern: $F = django.db.models.FloatField(...)
      #   - pattern: $F = django.db.models.FloatField(...)
      # - pattern-inside: |
      #     class $M(...):
      #       ...
      # - metavariable-regex:
      #     metavariable: '$F'
      #     regex: '.*(price|fee|salary).*'
  message: _removed_
  languages: [python]
  severity: ERROR
```

## Other patterns -> all
Other `patterns` keys that are a subset of the top-level one are replaced by
`all`. Our example has a redundant `patterns` with two identical children to
show how it will be modified.

Note that if we had a `pattern-either` here we would use `any`.

```yaml
rules:
- id: use-decimalfield-for-money-new-syntax
  # top-level patterns replaced by match and all.
  match:
    all:
        # rest of the patterns
        - pattern: $F = django.db.models.FloatField(...)
        - pattern: $F = django.db.models.FloatField(...)
      # - pattern-inside: |
      #     class $M(...):
      #       ...
      # - metavariable-regex:
      #     metavariable: '$F'
      #     regex: '.*(price|fee|salary).*'
  message: _removed_
  languages: [python]
  severity: ERROR
```

## pattern can be removed
The `pattern` keyword can be omitted. Replace `pattern: [something]` with just
`- [something]`.

```yaml
- pattern: [something]  ---> - [something]

- pattern: |            ---> - |
    [something]                   [something]
    [more lines]                  [more lines]
```

More changes:

```yaml
rules:
- id: use-decimalfield-for-money-new-syntax
  # top-level patterns replaced by match and all.
  match:
    all:
      # the rest of the patterns
      # I know this `patterns` can be replaced by one `pattern`
      # but it's modified for the tutorial.
      - $F = django.db.models.FloatField(...)
      - |
        $F = django.db.models.FloatField(...)
      # - pattern-inside: |
      #     class $M(...):
      #       ...
      # - metavariable-regex:
      #     metavariable: '$F'
      #     regex: '.*(price|fee|salary).*'
  message: _removed_
  languages: [python]
  severity: ERROR
```

There's one catch, if your pattern contains `:` it might mess with the yaml
format. Either use a bar to send it to the next line or enclose it in `"`,
[explanation at 1:26 in the reference video][126].

[126]: https://youtu.be/dZUPjFvknnI?t=86

## pattern-not -> - not
We don't have it in our current example, but it's similar to `pattern`.

```yaml
- pattern-not: [something]  ---> - not: [something]

- pattern-not: |            ---> - not: |
    [something]                       [something]
    [more lines]                      [more lines]
```

## pattern-inside -> inside
Easy, peasy.

```yaml
rules:
- id: use-decimalfield-for-money-new-syntax
  # top-level patterns replaced by match and all.
  match:
    all:
      # the rest of the patterns
      # I know this `patterns` can be replaced by one `pattern`
      # but it's modified for the tutorial.
      - $F = django.db.models.FloatField(...)
      - |
        $F = django.db.models.FloatField(...)
      # pattern-inside
      - inside: |
          class $M(...):
            ...
      # - metavariable-regex:
      #     metavariable: '$F'
      #     regex: '.*(price|fee|salary).*'
  message: _removed_
  languages: [python]
  severity: ERROR
```

## where
Acts as a container for some elements that add conditions to metavariables. We
will use `metavariable-regex` as an example:

1. Add a `where` clause in the same level as `all`
2. `metavariable-regex` is also replaced with `metavariable` and `regex`.

```yaml
rules:
- id: use-decimalfield-for-money-new-syntax
  # top-level patterns replaced by match and all.
  match:
    all:
      # I know this `patterns` can be replaced by one `pattern`
      # but it's modified for the tutorial.
      - $F = django.db.models.FloatField(...)
      - |
        $F = django.db.models.FloatField(...)
      # pattern-inside
      - inside: |
          class $M(...):
            ...
    where:
      # metavariable-regex
      - metavariable: $F
        regex: '.*(price|fee|salary).*'
  message: _removed_
  languages: [python]
  severity: ERROR
```

See the final rule in [the playground][df-new].

[df-new]: https://semgrep.dev/playground/r/ReUly9/parsiya.blog-2023-10-use-decimalfield-for-money-new

Other elements that appear under `where` have also been modified:

* `metavariable-pattern`
* `metavariable-analysis`
* `metavariable-comparison`
* `focus-metavariable`

We can use them like this:

```yaml
rules:
- id: sample-rule
  match:
    all:
      # removed
    where:
      # metavariable-regex
      - metavariable: $F
        regex: '.*(price|fee|salary).*'
      # metavariable-analysis
      - metavariable: $F
        analyzer: redos
      # focus-metavariable becomes `focus`
      - focus: $F
  message: _removed_
  languages: [python]
  severity: ERROR
```

`metavariable-pattern` is tricky because it can contain multiple patterns, but
it's similar to the patterns we've seen before.

```yaml
    where:
      # metavariable-pattern
      - metavariable: $F
        pattern: "some pattern"
      # if it had multiple patterns
      - metavariable: $F
        all:
          - "pattern1"
          - "pattern2"
```

# Example 2
This one is a
{{< xref path="/post/2022/2022-03-31-semgrep-hotspots/" text="C++ Hotspot rule" >}}
that tracks when arrays are passed to functions. The complete rule is on
[GitHub][array-rule] and has a [handy triage guide][array-triage].

[array-rule]: https://github.com/parsiya/semgrep-hotspots/blob/main/cpp/arrays-passed-to-functions.yaml
[array-triage]: https://github.com/parsiya/semgrep-hotspots/blob/main/cpp/arrays-passed-to-functions.md

I will be using a partial version of the rule, [playground link][partial].

[partial]: https://semgrep.dev/playground/r/zdUZON/parsiya.blog-2023-10-arrays-passed-to-functions-partial

```yaml
rules:
- id: arrays-passed-to-functions-partial
  patterns:
    # a lot of ways to create an array
    - pattern-either:
      - pattern-inside: |
          $TYPE $BUF[$SIZE] = $EXPR;
          ...
      - pattern-inside: |
          $TYPE $BUF[$SIZE];
          ...
    # we don't want to flag these usages again
    - pattern-not-inside: free($BUF);
    - pattern-not-inside: delete($BUF);
    # exclude uppercase variables, these are usually constants
    - metavariable-regex:
        metavariable: $BUF
        regex: (?![A-Z0-9_]+\b)
    # flag if it's passed to a function
    - pattern: $FUNC(..., $BUF, ...);
  message: _removed_
  languages:
    - cpp
  severity: WARNING
```

## pattern-not-inside -> inside under not
The only new item here is `pattern-not-inside`.

```yaml
rules:
- id: arrays-passed-to-functions-partial
  match:
    # removed everything else
    - pattern-not-inside: free($BUF);
    - pattern-not-inside: delete($BUF);
```

First, we create a `not` and then add an `inside` under it. Also note how the
`inside` is indented unlike `- not: [pattern]` (from `pattern-not`).

```yaml
rules:
- id: arrays-passed-to-functions-partial
  match:
    # removed everything else
    - not:
        inside: free($BUF);
    - not:
        inside: delete($BUF);
```

I thought I could merge the two `not`s. You cannot. It's a map and if you add
two `inside`, you will get an error that keys must be unique.

## pattern-either -> any
`any` will act as OR.

```yaml
- pattern-either:
  - pattern-inside: |
      $TYPE $BUF[$SIZE] = $EXPR;
      ...
  - pattern-inside: |
      $TYPE $BUF[$SIZE];
      ...
```

becomes:

```yaml
- any:
  - inside: |
      $TYPE $BUF[$SIZE] = $EXPR;
      ...
  - inside: |
      $TYPE $BUF[$SIZE];
      ...
```

## Final Results
The rest is routine:

1. Top-level `patterns` -> `match`.
2. `pattern-either` -> `any`.
3. `pattern-not-inside` -> `not` and `inside`.
4. `metavariable-regex` -> `metavariable` and `regex`.
5. `pattern` (the word) is just removed.


```yaml
rules:
- id: arrays-passed-to-functions-partial
  match:
    # a lot of ways to create an array
    - any:
      - inside: |
          $TYPE $BUF[$SIZE] = $EXPR;
          ...
      - inside: |
          $TYPE $BUF[$SIZE];
          ...
    # we don't want to flag these usages again
    - pattern-not-inside: free($BUF);
    - pattern-not-inside: delete($BUF);
    # exclude uppercase variables, these are usually constants
    - metavariable-regex:
        metavariable: $BUF
        regex: (?![A-Z0-9_]+\b)
    # flag if it's passed to a function
    - pattern: $FUNC(..., $BUF, ...);
  message: _removed_
  languages:
    - cpp
  severity: WARNING
```

## Implied Constant Propagation
The original rule and the one we created do not have the same matches.
The original rule has three matches, [playground link][org1].

{{< imgcap title="old rule" src="01.jpg" >}}

[org1]: https://semgrep.dev/playground/r/OrUb1j/parsiya.blog-2023-10-arrays-passed-to-functions-partial-original

The modified rule only returns one match, [playground link][new1].

[new1]: https://semgrep.dev/playground/r/eqUOB0/parsiya.blog-2023-10-arrays-passed-to-functions-partial-new-syntax

{{< imgcap title="new rule" src="02.jpg" >}}

The reason is that [constant propagation][const] is on by default in the experimental
syntax (at least for now). Credit: [Cooper Pierce][cooper-gh], Semgrep.

[const]: https://semgrep.dev/docs/writing-rules/data-flow/constant-propagation/
[cooper-gh]: https://github.com/kopecs

We can get the same result by adding an [options][opt] key and get the same
matches, [playground link][mod1].

```yaml
rules:
  - id: blah-blah
    options:
      constant_propagation: false
    match:
      all:
      # the rest of the rule
```

[opt]: https://semgrep.dev/docs/writing-rules/rule-syntax/#options
[mod1]: https://semgrep.dev/playground/r/v8URl1/parsiya.blog-2023-10-arrays-passed-to-functions-partial-new-syntax-const-prop

# Example 3
In the last example we will look at a complex `metavariable-pattern` rule from
Semgrep examples, [playground link for practice][pattern-old].

[pattern-old]: https://semgrep.dev/playground/r/5rUzZ7/parsiya.blog-2023-10-open-redirect-old

```yaml
rules:
- id: blog-2023-10-open-redirect-old
  languages:
    - python
  message: Match found
  severity: WARNING
  patterns:
    - pattern-inside: |
        def $FUNC(...):
          ...
          return django.http.HttpResponseRedirect(..., $DATA, ...)
    - metavariable-pattern:
        metavariable: $DATA
        patterns:
          # patterns

```

Converting the outside patterns is easy.

```yaml
rules:
  - id: blog-2023-10-open-redirect-new
    languages:
      - python
    message: Match found
    match:
      all:
        - inside: |
            def $FUNC(...):
              ...
              return django.http.HttpResponseRedirect(..., $DATA, ...)
      where:
        - metavariable: $DATA
          patterns:
            # patterns
```

Now we do the same process for the inner patterns and replace `patterns` with
`all` (we don't need a `match`). Things can get complicated quickly. We have
three nested `where` clauses. One for the top `metavariable-pattern`, another
for the 2nd one, and the last one is for `metavariable-regex`.

The result is in [this playground link][pattern-new].

```yaml
rules:
- id: blog-2023-10-open-redirect-new
  languages:
    - python
  message: Match found
  severity: WARNING
  match:
    all:
      - inside: |
          def $FUNC(...):
            ...
            return django.http.HttpResponseRedirect(..., $DATA, ...)
    where:
      - metavariable: $DATA
        all:
          - any:
              - $REQUEST
              - $STR.format(..., $REQUEST, ...)
              - $STR % $REQUEST
              - $STR + $REQUEST
              - f"...{$REQUEST}..."
        where:
          - metavariable: $REQUEST
            all:
              - any:
                  - request.$W
                  - request.$W.get(...)
                  - request.$W(...)
                  - request.$W[...]
            where:
              - metavariable: $W
                regex: (?!get_full_path)
```

[pattern-new]: https://semgrep.dev/playground/r/GdUR1Y/parsiya.blog-2023-10-open-redirect-new

# What Did We Learn Here Today?
We learned to convert rules from the old Semgrep syntax to the experimental one. IMO, the
experimental syntax is more readable. There are some inconsistencies like the constant
propagation section (and probably more), but not a big issue.
