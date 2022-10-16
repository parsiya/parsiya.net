---
title: "YAML Wrangling with Rust"
date: 2022-10-16T11:43:58-07:00
draft: false
toc: true
comments: true
twitterImage: owl.jpg
categories:
- not security
- rust
- semgrep
---

I will talk about how I parsed Semgrep rules in YAML with Rust, how I created
Rust structs from JSON schemas for Semgrep rules, and finally, what
didn't work. This blog post has different sections with code so you can follow
and experiment.

<!--more-->

The code is at: https://github.com/parsiya/yaml-wrangling-with-rust. 

**Choose Your Adventure:** 

* I am just interested in the Rust structs and sample code to parse Semgrep rules:
    * https://github.com/parsiya/yaml-wrangling-with-rust/tree/main/08-rustacean-matchmaking/src
* I just want to parse YAML without creating format-specific structs:
    * See [Generic Rust Structs]({{< relref "#generic-rust-structs" >}} "Generic Rust Structs").
* I want to learn as you did.
    * Continue reading.

# Setup
I have created several cargo crates for this blog. If you want to see sample
code or want to follow along, clone the repositories and start editing. I did
most of this in a Debian 11 running inside WSL2. Although, it should work on
pretty much every system that supports Rust.

**Ingredients:**

1. A recent version of Rust. I used `1.64.0` in a Debian 11 distro under WSL2.
2. Your editor of choice. I am not a real hacker. I use VS Code with the
   [rust-analyzer][ra-link] extension.
3. Optional: git to clone the repository.

[ra-link]: https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer

**Getting Started:**

1. Clone https://github.com/parsiya/yaml-wrangling-with-rust.
2. `cd yaml-wrangling-with-rust`
3. `wget https://raw.githubusercontent.com/returntocorp/semgrep-interfaces/ee75cb212500f2a57ef5938013a4955a84bb9ab1/rule_schema.yaml`

# How Did I Get Here?
I wanted to learn Rust. I read [the book][the-rust-book] and
[took some notes][fearless-gh]. I got bored. Now that I am
[unemployed and a burden on society][ea-quit-tweet], I have more time.

I saw this [private Semgrep server][server-gh] a couple of weeks ago and being a
[Semgrep junkie]({{< relref "/categories/semgrep/" >}} "Semgrep junkie") I
want to implement a similar server to learn Rust.

[the-rust-book]: https://doc.rust-lang.org/book/
[fearless-gh]: https://github.com/parsiya/fearless-concurrency
[ea-quit-tweet]: https://twitter.com/CryptoGangsta/status/1545540067019538432
[server-gh]: https://github.com/wahyuhadi/semgrep-server-rules

Almost all Semgrep rules are in YAML[^1]. Most files only contain one rule (good
practice). A file with one rule looks like:

```yaml
rules:
- id: rule-1
  ...
```


[^1]: It has experimental jsonnet support, but I have not used it.

Files can have several rules; that's how rulesets are implemented:

```yaml
rules:
- id: rule-1
  ...
- id: rule-2
  ...
```

To have a rule server, I need to interact with these files:

1. Extract rules from files with multiple rules.
2. Bundle rules together in one file to serve rulesets.

# Parsing YAML Files with Rust
The de facto YAML library in Rust is [serde-yaml][serde-yaml-gh]. Following the
[examples][serde-yaml-docs], I quickly found out I must create proper Rust
structs to correctly deserialize Semgrep rules.

[serde-yaml-gh]: https://github.com/dtolnay/serde-yaml
[serde-yaml-docs]: https://docs.rs/serde_yaml/latest/serde_yaml/

```rust
fn main() {
    let contents = fs::read_to_string("../multiple-rules.yaml")
        .expect("Should have been able to read the file");

    // let my_yaml: <???> = serde_yaml::from_str::<???>(&contents).unwrap();
}
```

Every example used a small struct to serialize to YAML and then deserialize back
to an object!

{{< imgcap title="Accurate view of serde_yaml tutorials!" src="owl.jpg" >}}

## Partial Deserialization
We can haz partial deserialization. Create a few high-level structs and only
capture a few items. Every Semgrep rule must have `id` and `languages`. A sample
rule file will look like this:

```yaml
rules:
- id: rule-1
  languages:
    - c
    - cpp
  # the rest of the rule
- id: rule-2
  languages:
    - rust
  # ... 
```

First, I created the struct that holds the complete rule file. The `rules` tag
contains an array of rules or `Vec<Rule>` (I haven't created that struct, yet).

Above the struct definition are `derive` macros that generate implementations
for the struct traits:

* `Debug`: To print the contents of the struct with `{:#?}`.
* `Serialize/Deserialize`: For serialization/deserialization of these structs.
  See more at [https://serde.rs/derive.html][serde-derive-docs].

[serde-derive-docs]: https://serde.rs/derive.html

```rust
// 01-first-try/src/main.rs
#[derive(Debug, Serialize, Deserialize)]
struct RuleFile {
    rules: Vec<Rule>,
}
```

What should a `Rule` look like? I am only looking for two fields:

```rust
#[derive(Debug, Serialize, Deserialize)]
struct Rule {
    id: String,
    languages: Vec<String>,
}
```

Let's deserialize the test file (it has three of my
[C++ Semgrep Hot Spot Rules][semgrep-hotspots]).

[semgrep-hotspots]: https://github.com/parsiya/semgrep-hotspots

```rust
// 01-first-try/src/main.rs
fn main() {
    // read the file.
    let contents = fs::read_to_string("../multiple-rules.yaml")
        .expect("Should have been able to read the file");

    // don't unwrap like this in the real world! Errors will result in panic!
    let rule_file: RuleFile = serde_yaml::from_str::<RuleFile>(&contents).unwrap();

    println!("{:#?}", rule_file);
}
```

The rules are deserialized correctly but I only have access to the defined
fields.

```yaml
:~/yaml-wrangling-with-rust/01-first-try$ cargo run
...
RuleFile {
    rules: [
        Rule {
            id: "snprintf-insecure-use",
            languages: [
                "cpp",
                "c",
            ],
        },
        Rule {
            id: "potentially-uninitialized-pointer",
            languages: [
                "cpp",
                "c",
            ],
        },
        Rule {
            id: "memcpy-insecure-use",
            languages: [
                "cpp",
                "c",
            ],
        },
    ],
}
```

Let's modify the code and add a dummy required field. Switch to the
`02-missing-required-field` directory:

```rust
// 02-missing-required-field/src/main.rs
#[derive(Debug, Serialize, Deserialize)]
struct Rule {
    id: String,
    languages: Vec<String>,
    // added field
    dummy: String,
}
```

The program panics because the input file doesn't have the `dummy` tag.

```
:~/yaml-wrangling-with-rust/02-missing-required-field$ cargo run
...
thread 'main' panicked at 'called `Result::unwrap()` on an `Err` value:
    Error("rules[0]: missing field `dummy`", line: 2, column: 3)', src/main.rs:7:75
```

We can make fields optional by using the [Option][option-docs] keyword. This
tells the program there might be a string in that field or nothing.

```rust
// 02-missing-required-field/src/main.rs
#[derive(Debug, Serialize, Deserialize)]
struct Rule {
    id: String,
    languages: Vec<String>,
    // added field
    dummy: Option<String>,
}
```

[option-docs]: https://doc.rust-lang.org/std/option/

## Experiments in Creating Rust Structs from JSONSchema
Creating everything by hand is a pain.
[Manual Work is a Bug]({{< relref
    "/post/2018/2018-10-03-manual-work-bug/index.markdown" >}}
    "Manual Work is a Bug")[^manual].
Luckily, Semgrep rules have a JSON Schema in the
[semgrep-interfaces][semgrep-interfaces-gh] repository. I am referencing the line
numbers from this version:

* [https://github.com/returntocorp/semgrep-interfaces/blob/a36652b1e2b9d089918a88575d00e8c7bdd5afd9/rule_schema.yaml][rule-schema-gh]

[^manual]: I shill this article at every opportunity.

[semgrep-interfaces-gh]: https://github.com/returntocorp/semgrep-interfaces
[rule-schema-gh]: https://github.com/returntocorp/semgrep-interfaces/blob/a36652b1e2b9d089918a88575d00e8c7bdd5afd9/rule_schema.yaml

A [JSON Schema][json-schema.org] is a way to design and validate JSON
documents[^2]. Earlier I mentioned that every Semgrep rule must have the `id`
and `languages` fields. This requirement is on [line 160][schema-l160]. Each
rule must also have `one of` those three combinations of pattern fields.

[json-schema.org]: https://json-schema.org/
[schema-l160]: https://github.com/returntocorp/semgrep-interfaces/blob/a36652b1e2b9d089918a88575d00e8c7bdd5afd9/rule_schema.yaml#L160
[^2]: But we're dealing with YAML! Yes, but converting between YAML, JSON, and TOML is a 1:1 process and a solved problem. Our JSON Schema is even in YAML.

```yaml
# rule_schema.yaml - line 160
  rules:
    type: array
    items:
      type: object
      required:
        - id
        - languages
      oneOf:
        - required:
            - pattern
        - required:
            - patterns
        - required:
            - pattern-sources
            - pattern-sinks
```

I found a few solutions to automatically create Rust structs from a JSON Schema.
None were successful. But they might be useful for others or future me.

**Note about the rule_schema.yaml file.** The
[semgrep-interfaces][semgrep-interfaces-gh] repository does not have a license.
I did not know if I could copy it. If you have skipped the `Getting Started`
section and want to follow the exercises, go and copy the file.

## OxideComputer/typify
The [typify][typify-gh] crate says  
[The documentation][typify-docs] didn't show how to generate code. I used the
[example-build/build.rs][typify-test] file.

[typify-gh]: https://github.com/oxidecomputer/typify
[typify-docs]: https://docs.rs/typify/0.0.10/typify/
[typify-test]: https://github.com/oxidecomputer/typify/blob/ab2d3e18f624ce4a55278c0846ebb5f936134023/example-build/build.rs

```rust
// 03-typify-generation/src/main.rs
use schemars::schema::Schema;
use typify::{TypeSpace, TypeSpaceSettings};

fn main() {

    // read the JSON schema in YAML format.
    let content = std::fs::read_to_string("../rule_schema.yaml").unwrap();

    // create the schema (this is useful if you want to validate).
    let schema = serde_yaml::from_str::<schemars::schema::RootSchema>(&content).unwrap();

    // I have no idea what's happening here.
    let mut type_space = TypeSpace::new(TypeSpaceSettings::default().with_struct_builder(true));
    // panic happens here!
    type_space.add_ref_types(schema.definitions).unwrap();
    
    // removed
}
```

Well, we got a panic!

```
thread 'main' panicked at 'not yet implemented',
    /home/parsia/.cargo/registry/src/github.com-1ecc6299db9ec823/typify-impl-0.0.10/src/convert.rs:31:36
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```

Adding all the definitions from the schema causes the program to panic. Let's
leave debugging for another day (you're welcome to figure it out).

## Marwes/schemafy_lib
I found this library in [json-schema.org/Code generation][code-gen]. The
[schemafy_lib docs][schemafy_lib-docs] has a straightforward code generation
example.

[code-gen]: https://json-schema.org/implementations.html#code-generation
[schemafy_lib-docs]: https://docs.rs/schemafy_lib/latest/schemafy_lib/#usage

```rust
// 04-schemafy-generation/src/main.rs
fn main() {
    let content = std::fs::read_to_string("../rule_schema.yaml").unwrap();
    let schema = serde_yaml::from_str(&content).unwrap();

    use schemafy_lib::Expander;
    let mut expander = Expander::new(
        Some("Schema"),
        "::schemafy_core::",
        &schema,
    );

    let code = expander.expand(&schema);
    println!("{}", code.to_string());
}
```

No panic but we only get two empty structs. Oh, well!

```rust
#[derive (Clone , PartialEq , Debug , Default , Deserialize , Serialize)]
pub struct SchemaItemRules { } 

#[derive (Clone , PartialEq , Debug , Default , Deserialize , Serialize)]
pub struct Schema { 
    #[serde (skip_serializing_if = "Option::is_none")]
    pub rules : Option<Vec<SchemaItemRules>>
}
```

## Other Code Generation Methods
There are a few more suggestions on the code generation page. I tried:

* [quicktype.io][quicktype-io] didn't work.
* [jtd-codegen][jtd-codegen-gh] is for `JSON Type Definitions` and not schemas.
* Generated Java/TypeScript classes (I didn't check them for validity) with
  [tryjsonschematypes.appspot.com][try]. Conversion to Rust structs didn't work.

[quicktype-io]: https://app.quicktype.io/#l=schema
[jtd-codegen-gh]: https://github.com/jsontypedef/json-typedef-codegen
[try]: https://tryjsonschematypes.appspot.com/#java

## Using serde_yaml Value
We can also use [serde_yaml::Value][value-docs] to parse YAML files without
deserializing them into detailed structs. This is very useful if you just want
to modify YAML files. For example, just splitting the Semgrep rules in a file.

[value-docs]: https://docs.rs/serde_yaml/latest/serde_yaml/enum.Value.html

It took me a bit to figure it out. `Value` is a container that holds different
YAML objects. Note, I am reading a rule file, again, and not the schema.

```rust
// 05-value/src/main.rs - section 1
fn main() {
    let content = std::fs::read_to_string("../multiple-rules.yaml").unwrap();

    // ----- start of section 1
    use serde_yaml::Value;
    // read the file and store it in a `Value`.
    let rule_file = serde_yaml::from_str::<Value>(&content).unwrap();

    println!("{:#?}", rule_file);
    // ----- end of section 1
}
```

This gives us good info.

```json
Mapping {
    "rules": Sequence [
        Mapping {
            "id": String("snprintf-insecure-use"),
            "message": String("Potentially vulnerable snprintf usage."),
            "languages": Sequence [
                String("cpp"),
                String("c"),
            ],
            "severity": String("WARNING"),
            "metadata": Mapping {
                "category": String("hotspot"),
                "references": Sequence [
                    String("https://dustri.org/b/playing-with-weggli.html"),
                ],
            },
            // some items removed
        },
        Mapping {
            "id": String("potentially-uninitialized-pointer"),
            // removed
        },
        Mapping {
            "id": String("memcpy-insecure-use"),
            // removed
        },
    ],
}
```

Some YAML to Rust patterns:

1. Object => [Mapping][mapping-docs].
2. Array => [Sequence][sequence-docs].
3. string => Rust String.

[mapping-docs]: https://docs.rs/serde_yaml/latest/serde_yaml/struct.Mapping.html
[sequence-docs]: https://docs.rs/serde_yaml/latest/serde_yaml/type.Sequence.html

I can also convert it back to a YAML string. Comment the `section 1` code
and uncomment `section 2`. 

```rust
// 05-value/src/main.rs - section 2
fn main() {
    let content = std::fs::read_to_string("../multiple-rules.yaml").unwrap();

    // ----- start of section 2
    use serde_yaml::Value;
    let rule_file = serde_yaml::from_str::<Value>(&content).unwrap();
    // convert it back to a YAML string.
    let back_to_yaml = serde_yaml::to_string::<Value>(&rule_file).unwrap();
    println!("{}", back_to_yaml);
    // ----- end of section 2
}
```

And I got the same file back.

{{< imgcap title="The rule file converted back to a YAML string" src="01-back-to-yaml.png" >}}

Time to extract info from the YAML files. `rule_file` is a `Mapping` and has a
field named `rules`. `rules` is a `Sequence` and has one or more items. Each
item is a single rule in another `Mapping` and has a string `id`.

Comment section 2 and uncomment section 3, then run `cargo run`.

```rust
// 05-value/src/main.rs - section 3
fn main() {
    let content = std::fs::read_to_string("../multiple-rules.yaml").unwrap();

    // ----- start of section 3
    use serde_yaml::{Mapping};
    // get the file as a mapping.
    let rule_file_mapping: Mapping = serde_yaml::from_str::<Mapping>(&content).unwrap();
    // we know "rules" is a Sequence so we get it.
    let rules = rule_file_mapping.get("rules").unwrap().as_sequence().unwrap();
    // go through the rules.
    for rule in rules {
        // we know the "id" of each rule is a String.
        println!("{}", rule.get("id").unwrap().as_str().unwrap());
    }
    // ----- end of section 3
}
```

I am doing a lot of `unwraps` which are not safe!

```
:~/yaml-wrangling-with-rust/05-value$ cargo run
   
snprintf-insecure-use
potentially-uninitialized-pointer
memcpy-insecure-use
```

This method is great if you only want to extract specific parts of the file and
treat the rest like a blob.

## Generic Rust Structs
Now, I can create some generic Rust structs for splitting the files. The rule
file is an object with one field named `rules`. `rules` is an array of rules
(type `Mapping`).

```rust
// This allows us to split the rules without caring about their contents.
#[derive(Debug, Serialize, Deserialize)]
struct GenericRuleFile {
    rules: Vec<serde_yaml::Mapping>,
}
```

Open `cargo.toml` to see how I've added serde's `derive` feature.

```toml
# removed
[dependencies]
serde = {version = "1.0", features = ["derive"]}
serde_yaml = "0.9"
```

Now, I can use the struct to split files with multiples rules. For each rule, I
am creating a new `GenericRuleFile` to create a separate rule file.

```rust
// 06-generic-structs/src/main.rs
fn main() {
    let content = std::fs::read_to_string("../multiple-rules.yaml").unwrap();
    // deserialize
    let generic_rule_file: GenericRuleFile = serde_yaml::from_str(&content).unwrap();

    // go through each rule. Each one is a Mapping.
    for single_rule in generic_rule_file.rules {
        
        // create a new GenericRuleFile object with only one rule.
        let mut new_rules: Vec<serde_yaml::Mapping> = Vec::new();
        new_rules.push(single_rule);
        let new_generic_rule = GenericRuleFile{
            rules: new_rules,
        };

        // convert it to yaml.
        let single_rule_yaml: String = serde_yaml::to_string(&new_generic_rule).unwrap();
        // print it.
        println!("{}", single_rule_yaml);
    }
}
```

{{< imgcap title="Separated rules" src="02-split-rules.png" >}}

## Artisanal Handcrafted Rust Structs!
But that didn't cut it, I wanted more control. To get started, I pasted some
rules into [jsonformatter.org/yaml-to-rust][yaml-to-rust]. Surprisingly, it
wasn't that hard.

[yaml-to-rust]: https://jsonformatter.org/yaml-to-rust

Some general tips (more in the examples):

1. Find the definition of an item by searching the schema for `tagname:`. It
   should have the `type:` tag on the next line. E.g., `pattern-either:`.
2. `type: object` => struct.
3. `properties:` => struct fields.
4. `array` => `Vec`.
5. `required:` => Use `T` instead of `Option<T>` (or don't, we're not here to validate).
6. `$ref: something` => `points to another struct`.
7. Don't define Rust enums unless you have YAML enums (they start with `!`).

Note I am not trying to validate rules here. I care about some required fields,
but I think it's just easier to use the schema for validation before
deserialization.

### RuleFile
Let's learn through some examples. The top object is defined at the bottom of
the file starting from line 430. Searching for `rules:` I can find the start of
the document object.

```yaml
# rule_schema.yaml - line 430
type: object
properties:
  rules:
    type: array
```

This is the complete file or `RuleFile`. It has an array of `Rule`s in the tag
`rules:`.

```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct RuleFile {
    rules: Vec<Rule>,
}
```

### Rule
`Rule` is more complicated. Find it fields under the `properties:` tag for
`rules:` (line 436):

```yaml
# rule_schema.yaml - line 436
properties:
  rules:
    type: array
    items:
      type: object
      properties: # <--- HERE
        id:
          $ref: "#/$defs/id"
        version:
          title: Version of rule
          type: string
        message:
          title: Description to attach to findings
          type: string
        # removed
```

The `id` field which is of type `id`. Line 427 has the definition:

```yaml
# rule_schema.yaml - line 427
  id:
    title: Rule ID to attach to findings
    type: string
```

There's no need to create a struct for `id` because `String` is a Rust primitive
type and it has no other members. `version` and `message` are strings, too. I
can create the first three fields:

```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct Rule {
    // Rule ID to attach to findings
    id: String,
    // Version of rule
    version: Option<String>,
    // Description to attach to findings
    message: Option<String>,
}
```

Note how `version` and `message` are `Options`. These are not required tags and
might not be present in every rule.

Although `mode` is an enum, we cannot define it as an enum here. If so, serde
will look for a YAML enum (they start with `!`).

```yaml
# rule_schema.yaml - line 445
mode:
  default: search
  enum:
    - search
    - taint
    - join
    - extract
```

I defined it as a normal string.

```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct Rule {
    // removed

    mode: Option<String>,
}
```

`languages` is another required field and an array of strings.

```yaml
# rule_schema.yaml - line 452
languages:
  title: Languages this pattern should run on
  type: array
  items:
  type: string
```

It becomes a `Vec<String>`:

```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct Rule {
    // removed

    // Languages this pattern should run on
    languages: Vec<String>,
}
```

`paths` is another struct:

```yaml
# rule_schema.yaml - line 458
paths:
  title: Path globs this pattern should run on
  type: object
  properties:
    include:
      $ref: "#/$defs/path-array"
    exclude:
      $ref: "#/$defs/path-array"
  additionalProperties: false
```

The struct has two fields `include` and `exclude`. Both are of type
`path-array`. Search for `path-array:` in the schema (don't forget the colon) to
find the definition:

```yaml
# rule_schema.yaml - line 423
path-array:
  type: array
  items:
    type: string
```

It's just a `Vec<String>`:

```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct Paths {
    include: Option<Vec<String>>,
    exclude: Option<Vec<String>>,
}
```

Adding the `paths` field to `Rule`:

```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct Rule {
    // removed

    // Path globs this pattern should run on
    paths: Option<Paths>,
}
```

`severity` is another text enum.

```yaml
# rule_schema.yaml - line 467
severity:
  title: Severity to report alongside this finding
  enum:
    - ERROR
    - WARNING
    - INFO
    - INVENTORY
    - EXPERIMENT
```

Another ordinary string:

```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct Rule {
    // removed

    // Severity to report alongside this finding
    severity: Option<String>,
}
```

### fix-regex
Skipping a few fields to use `fix-regex` (line 487) as a good example:

```yaml
# rule_schema.yaml - line 487
fix-regex:
  type: object
  title: Replacement regex to fix matched code.
  properties:
    count:
      title: Replace up to this many regex matches
      type: integer
    regex:
      title: Regular expression to find in matched code
      type: string
    replacement:
      title: Code to replace the regular expression match with. Can use capture groups.
      type: string
  required:
    - regex
    - replacement
  additionalProperties: false
```

I created a struct with three fields (two are required).

```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct FixRegex {
    // Replace up to this many regex matches
    count: Option<i32>,
    // Regular expression to find in matched code
    regex: String,
    // Code to replace the regular expression match with. Can use capture groups.
    replacement: String,
}
```

We have another problem. The field is named `fix-regex` but it's an illegal
field name in Rust. Use the serde [rename field attribute][serde-rename] to
assign the `fix-regex` YAML tag to the `fix_regex` struct field (I think the
`alias` attribute also works).

[serde-rename]: https://serde.rs/field-attrs.html#rename

```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct Rule {
    // removed

    // Replacement regex to fix matched code.
    #[serde(rename = "fix-regex")]
    fix_regex: Option<FixRegex>,
}
```

`metadata` and `object` are freeform and can contain everything. I kept them as
`serde_yaml::Mapping`

```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct Rule {
    // removed

    // Arbitrary structured data for your own reference
    metadata: Option<serde_yaml::Mapping>,

    // Options object to enable/disable certain matching features in semgrep-core
    options: Option<serde_yaml::Mapping>,
}
```

### pattern-either-content
Let's use on a more complicated object. On line 24 there is
`pattern-either-content`:

```yaml
# rule_schema.yaml - line 24
pattern-either-content:
  type: array
  title: "Return finding where any of the nested conditions are true"
  items:
    anyOf:
      - $ref: "#/$defs/patterns"
      - $ref: "#/$defs/pattern-either"
      - $ref: "#/$defs/pattern-inside"
      - $ref: "#/$defs/pattern"
      - $ref: "#/$defs/pattern-regex"
```

It's an array of objects. To get a better understanding, study this example from
[the Semgrep documentation][pattern-either-docs]:

[pattern-either-docs]: https://semgrep.dev/docs/writing-rules/rule-syntax/#pattern-either

```yaml
rules:
  - id: insecure-crypto-usage
    pattern-either:
      - pattern: hashlib.sha1(...)
      - pattern: hashlib.md5(...)
      # pattern-regex: ...
      # pattern-inside: ...
    message: Found insecure crypto usage
    languages:
      - python
    severity: ERROR
```

Searching for `patterns:` takes us to line 357:

```yaml
# rule_schema.yaml - line 357
patterns:
  type: object
  properties:
    patterns:
      title: Return finding where all of the nested conditions are true
      $ref: "#/$defs/patterns-content"
```

The field `patterns` will point to the `PatternsContent` struct. Don't worry
about defining it right now.


```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct PatternEitherContent {

    patterns: Option<Vec<PatternsContent>>,
}
```

Next is `pattern-either` which points to itself:

```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct PatternEitherContent {

    patterns: Option<Vec<PatternsContent>>,

    #[serde(rename = "pattern-either")]
    pattern_either: Option<Vec<PatternEitherContent>>,
}
```

The next field is `pattern-inside` defined on line 387:

```yaml
# rule_schema.yaml - line 387
pattern-inside:
  type: object
  properties:
    pattern-inside:
      title: Return findings only from within snippets Semgrep pattern matches
      type: string
  required:
    - pattern-inside
  additionalProperties: false
```

It's just a String.

```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct PatternEitherContent {

    patterns: Option<Vec<PatternsContent>>,

    #[serde(rename = "pattern-either")]
    pattern_either: Option<Vec<PatternEitherContent>>,

    #[serde(rename = "pattern-inside")]
    pattern_inside: Option<String>,
}
```

And finally, `pattern-regex:` on line 339:

```yaml
# rule_schema.yaml - line 339
pattern-regex:
  type: object
  properties:
    pattern-regex:
      title: Return finding where regular expression matches
      type: string
  required:
    - pattern-regex
  additionalProperties: false
```

It's another string.

```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct PatternEitherContent {

    patterns: Option<Vec<PatternsContent>>,

    #[serde(rename = "pattern-either")]
    pattern_either: Option<Vec<PatternEitherContent>>,

    #[serde(rename = "pattern-inside")]
    pattern_inside: Option<String>,

    #[serde(rename = "pattern-regex")]
    pattern_regex: Option<String>,
}
```

### focus-metavariable
While defining `PatternsContent` I got stuck on the `focus-metavariable:` field
for a bit. See line 375:

```yaml
# rule_schema.yaml - line 375
focus-metavariable:
  type: object
  properties:
    focus-metavariable:
      title: Focus on what a given metavariable is matching
      items:
        OneOf: # <--- HERE
          - string
          - array
  required:
    - focus-metavariable
  additionalProperties: false
```

This field can either have a string OR an array of strings. Both of these
examples are valid:

```yaml
focus-metavariable: $ITEM

focus-metavariable:
  - $ITEM1
  - $ITEM2
```

To convert this field, I could write a custom deserializer in `function` and
then use the [deserialize_with][des-with] serde field attribute.

```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct PatternEitherContent {
    #[serde(rename = "focus-metavariable", deserialize_with ="function")]
    focus_metavariable: Option<Vec<String>>,
}
```

You can see a couple of deserializer examples at
[https://github.com/serde-rs/serde/issues/1907][serde-1907-gh].

[serde-1907-gh]: https://github.com/serde-rs/serde/issues/1907

But I decided to use the [serde_with][serde_with] crate which defines
`OneOrMany`.

1. Add `#[serde_as]` before the struct.
2. Add `#[serde_as(as = "Option<OneOrMany<_>>")]` before the field.

[des-with]: https://serde.rs/field-attrs.html#deserialize_with
[serde_with]: https://docs.rs/serde_with/

```rust
#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct PatternEitherContent {
    #[serde_as(as = "Option<OneOrMany<_>>")]
    #[serde(rename = "focus-metavariable")]
    focus_metavariable: Option<Vec<String>>,
}
```

This code automatically convert the single string into a vector.

### Empty Fields
When converting a rule to YAML, the fields with `None` values will appear in the
output with the value of `null`. We have two ways to fix it:

1. Add `#[serde(skip_serializing_if = "Option::is_none")]` to each field.
2. Add `#[skip_serializing_none]` from `serde_as` to each struct which is
   easier.

### Comments
Unfortunately, `serde` doesn't keep or parse YAML comments. Rule comments are
lost after deserialization.

## The Final Structs
The final structs are in `07-artisanal-structs/src/semgrep_rules.rs`. I used
them to read `multiple-rules.yaml`, create a `RuleFile`, and then convert
everything back to YAML.

{{< imgcap title="Running 07-artisanal-structs" src="03-split-2.png" >}}

### Testing the Structs
I wrote a utility to test my shiny new structs. The utility accepts two commands
and both of them have a second parameter. It should be a path to the root of
your rules directory. In my examples, I used the `semgrep-rules` repository.

1. `test-rules`: Reads all rules in the path recursively and tries to parse them.
2. `index-rules`: Reads all rules in the path and creates an index of them by rule ID.

#### test-rules
Initially, I only looked for files with `.yaml` and `.yml` extensions. There are
some YAML test files in the repo that are not rules. Their extensions are
`.test.yml`, `.test.yaml` and `.test.fixed.yaml`. We cannot process them.
 
After excluding those, only errors are from `stats` files. These are not rules
but we cannot detect them by extension.

Use the `test-rules` command and set the path to semgrep-rules as the second
parameter to see this output:

```
:~/yaml-wrangling-with-rust/08-rustacean-matchmaking$ cargo run -- test-rules ../../semgrep-rules/
    Finished dev [unoptimized + debuginfo] target(s) in 0.42s
     Running `target/debug/rustacean-matchmaking ../../semgrep-rules/`
[!] File: ../../semgrep-rules/stats/cwe_to_metacategory.yml
        Error: missing field `rules`
[!] File: ../../semgrep-rules/stats/metacategory_to_support_tier.yml
        Error: missing field `rules`
[!] File: ../../semgrep-rules/stats/web_frameworks.yml
        Error: missing field `rules`
```

#### index-rules
This code parses rules and stores them in a HashMap for later use (e.g., to
create and serve rulesets). Pass the command `index-rules` to create a rule
index and print the number of the rules. You can uncomment the last line to
also print the rule IDs.

```rust
// 08-rustacean-matchmaking/src/main.rs
// store all rules in a HashMap where the key is rule ID and the value is the rule.
pub fn create_rule_index(registry_path: &str) {
    
    utils::check_registry_path(registry_path);
    // store all rule file paths
    let rule_file_paths = utils::find_rules(registry_path.to_string());
    
    let mut rule_index: HashMap<String, semgrep_rules::Rule> = HashMap::new();

    for rule_file in rule_file_paths {
        
        // read the rule file and deserialize it.
        let contents = utils::read_file_to_string(&rule_file);
        let deserialized_result = serde_yaml::from_str::<semgrep_rules::RuleFile>(&contents);

        // check for errors.
        let deserialized = match deserialized_result {
            Ok(rf) => rf,
            Err(e) => {
                // log the error and move to the next file.
                println!("[!] File: {}\n\tError: {}", rule_file, e.to_string());
                continue;
            },
        };

        // iterate through the rules in the rule file and extract all the rules.
        for individual_rule in deserialized.rules {
            // get the id and own it.
            rule_index.insert(individual_rule.id.to_owned(), individual_rule);
        }
    }
    println!("Number of rules in the index: {}", rule_index.keys().len());
    // print the keys.
    // println!("{:#?}", rule_index.keys());
}
```

Run it with `cargo run -- index-rules /path/to/semgrep-rules/`.

```
:~/yaml-wrangling-with-rust/08-rustacean-matchmaking$ cargo run -- index-rules ../../semgrep-rules/
   Compiling rustacean-matchmaking v0.1.0 (/yaml-wrangling-with-rust/08-rustacean-matchmaking)
    Finished dev [unoptimized + debuginfo] target(s) in 10.91s
     Running `target/debug/rustacean-matchmaking index-rules ../../semgrep-rules/`
[!] File: ../../semgrep-rules/stats/cwe_to_metacategory.yml
        Error: missing field `rules`
[!] File: ../../semgrep-rules/stats/metacategory_to_support_tier.yml
        Error: missing field `rules`
[!] File: ../../semgrep-rules/stats/web_frameworks.yml
        Error: missing field `rules`
Number of rules in the index: 1710
```

# What Did We Learn Here Today?
A lot! This is an essential building block for my private Semgrep rules server.

1. Multiple ways to parse YAML files with Rust.
2. Manually create Rust structs from a JSON Schema.
3. Two ways to do the same automatically (neither worked).
4. A building block for creating a private Semgrep rules server in Rust.
5. Learning Rustacean Matchmaking! har har!
