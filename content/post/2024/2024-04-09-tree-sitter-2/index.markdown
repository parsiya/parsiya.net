---
title: "Knee Deep in tree-sitter CST"
date: 2024-04-09T12:35:35-08:00
draft: false
toc: true
comments: true
url: /blog/knee-deep-tree-sitter-2/
twitterImage: 04.png
categories:
- Static Analysis
- tree-sitter
---

We will continue the tree-sitter adventure and tackle the problems we couldn't
solve with just tree-sitter queries. We can get results with a combination of
queries and the Concrete Syntax Tree (CST).

In the
{{< xref path="/post/2024/2024-03-19-tree-sitter-queries/" text="previous post">}}
, I focused on just using queries. While they're useful for finding specific nodes, they're not enough.

Code is at https://github.com/parsiya/knee-deep-tree-sitter. Don't forget to
populate the submodule, we need it for the last part.

<!--more-->

# Discovering Indirect Parent/Children Connections
We had problems figuring out the first `function_declaration` parent of a
function call. With the CST, we can repeatedly call `.parent()` on nodes and
check the type with `.kind()`.

* `parent()` returns an `Option<Node>`.
    * If we reach a node without a parent, we've reached the top of the code.
* `kind()` returns a string.

This function does the trick.

```rs
/// Find the first parent of type `kind`. If the input's type is the `kind`
/// parameter, we will not return it. We're only interested in parents.
pub(crate) fn parent_of_kind<'a>(n: &'a Node, kind: &str) -> Option<Node<'a>> {
    // These work, too.
    // let mut current_node = n.to_owned();
    // let mut current_node = n.clone();
    let mut current_node = *n;

    while current_node.parent() != None {
        // Already checked if the parent is not None so we can just unwrap.
        current_node = current_node.parent().unwrap();
        // Check the kind.
        if current_node.kind() == kind {
            return Some(current_node);
        }
    }
    // return None;
    None
}
```

# Function Call Chains
One of our problems with queries was not being to skip nodes. I guessed that we
can start from function calls and go up. We're going to exactly do that.

1. Capture `call_expression` nodes with queries.
2. Go up the tree until the first parent that is a `function_declaration`.

The query is simple.

```ts
(call_expression) @callee
```

`child_by_field_name("name")` returns the field "name" as an `Option<Node>`.

```rs
// Assuming node is a tree_sitter::Node.
// Get the "name" field of a node.
if let Some(caller) = node.child_by_field_name("name") {
    // Do something if the node has such a field.
} else {
    // The node doesn't have this field.
}
```

After finding the parent, we can grab the function's information in the
`function` field of the `call_expression`. The tree for `Child2()` is:

```
call_expression             // Child2()
  function: identifier      // Child2
  arguments: argument_list  // ()
```

Running it against the following code:

```go
package main

func Parent() {
	child()
}

func Parent2() {
	child2()
}

func child() {}

func child2() {}
```

The result is correct. Run `cargo run -- 03`.

{{< imgcap title="cargo run -- 03" src="01.png" >}}

## Methods and Imports
This doesn't count methods and imported functions like the following code:

```go
package main

import "fmt"

func main() {
	object.Method()
	fmt.Println("something")
    Child2()
}
```

`fmt.Println("something")` becomes:

```
call_expression                 // fmt.Println("something")
  function: selector_expression // fmt.Println
    operand: identifier         // fmt
    field: field_identifier     // Println
  arguments: argument_list      // ("something")
    interpreted_string_literal  // "something"
```

The good news is that our current query to find the parent works. But the type
of the `function` field is not an `identifier` anymore. We see a
`selector_expression`. The name of the import is in `operand` and the function
name is in the `field`.

I have simplified our code by just unwrapping those options. I am relying on the
tree-sitter grammar catching malformed code during parsing, which, IMO, is a
sane assumption.

```rs
// (call_expression) always has a "function" field so we can
// simplify our code and just unwrap.
let callee = current_node.child_by_field_name("function").unwrap();
match callee.kind() {
    "identifier" => {
        child_function.name = node_text(callee, src);
    }
    // Same with named fields of (selector_expression).
    "selector_expression" => {
        child_function.package =
            node_text(callee.child_by_field_name("operand").unwrap(), src);

        child_function.name =
            node_text(callee.child_by_field_name("field").unwrap(), src);
    }
    _ => {
        println!(
            "The 'function' field of node is of the unexpected kind, got: {}",
            callee.kind()
        );
        continue;
    }
};
```

Counter argument: If we want to trust the tree, why are we using Rust in the
first place? :p

`object.Method()` in the tree is similar and our code already captures it:

```
call_expression                 // object.Method()
  function: selector_expression // object.Method
    operand: identifier         // object
    field: field_identifier     // Method
```

`operand` is the name of the object and `field` is the method.
Run `cargo run -- 04`.

{{< imgcap title="cargo run -- 04" src="02.png" >}}

# Traversing the Tree with TreeCursor
[TreeCursor][treecursor] is another way to traverse the tree. Given any node, it
allows us to efficiently go through the tree. We can walk through the input node
and all of its children. Unfortunately, the docs only have a little bit of info
about it at [Walking Trees with Tree Cursors][treecursor-walk].

[treecursor-walk]: https://tree-sitter.github.io/tree-sitter/using-parsers#walking-trees-with-tree-cursors
[treecursor]: https://docs.rs/tree-sitter/latest/tree_sitter/struct.TreeCursor.html

Let's try to walk the entire tree and spit out the nodes. I don't want this to
turn into leetcode bullshit thing so use whatever you prefer.

1. Go down the tree until you reach a leaf (node without a child).
2. Go to its next sibling and continue going down.
3. If there are no more siblings, go back to the parent and go to a parent's sibling.
4. If we've reached the root, we're done.

```rs
'outer: loop {
    // 0. Add the current node to the map.
    node_map.insert(c.node(), node_text(c.node(), src));

    // 1. Go to its child and continue.
    if c.goto_first_child() {
        continue 'outer;
    }

    // 2. We've reached a leaf (node without a child). We will go to a sibling.
    if c.goto_next_sibling() {
        continue 'outer;
    }

    // 3. If there are no more siblings, we need to go back up.
    'inner: loop {
        // 4. Check if we've reached the root node. If so, we're done.
        if !c.goto_parent() {
            break 'outer;
        }
        // 5. Go to the previous node's sibling.
        if c.goto_next_sibling() {
            // And break out of the inner loop.
            break 'inner;
        }
    }
}
```

I have created a map where the key is the node and the value is the text of the
node (because the tree-sitter tree only stores the offset and not the text).
Unfortunately, embedding/augmenting a struct in Rust is not as easy as it's in
Go specially since we need to recreate all the child/parent relationships if we
decide to redo the tree.

Then we go through the query result to see if the text from the map is the same
as the one we had and it is. Run `cargo run -- 05`.

{{< imgcap title="cargo run -- 05" src="03.png" >}}

# Types
So, back to our good old friend, types. Our issue with types was recursion. The
type of a `slice_type` (e.g., `[]int`) could be another type. We couldn't
extract them with queries.

Here, I created a function that parses a subset of possible types. It's a
monstrosity that looks like this.

```rs
/// Represents a Go type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GoType {
    SimpleType(SimpleType), // Lone (type_identifier)
    Slice(Slice),
    Pointer(Pointer),
    Array(Array),
    Map(Map),
    Channel(Channel),
    Qualified(Qualified),
}
```

We're gonna ignore `parameter_list` and only focus on functions that return a
single value here. A `parameter_list` is just a list of variable name and types.

Then I created a function to parse the type. It would call itself when it
reached a node that was another type.

Some parts are simple. If you see a `type_identifier`, it's a string that
contains a type without any gimmicks.

```rs
match n_kind {
    "type_identifier" => Ok(GoType::SimpleType(SimpleType {
        internal_type: n_text,
    })),
}
```

Things are bit more complicated, but still straightforward for other types like
`slice`. From the previous blog, we know `slice_type` has a field named
`element` that contains the type of the slice so we parse it with a recursive
call and return it as a `Slice` struct.

`map_or_else` is an interesting combinator. The first argument is executed if
there's an error. If not, the second part is. Because I am returning from the
function, it will return an error if I cannot parse the type. If parsing is
successful, we will re turn a `slice_type`.

```rs
match n_kind {
    // It's a slice. The `element` field has the type.
    "slice_type" => {
        // Get the element field.
        if let Some(element) = n.child_by_field_name("element") {
            parse_go_type(element, src).map_or_else(
                |e| {
                    TypeError::wrap_string(format!(
                        "Couldn't parse the type of {}, text: {}, err: {}",
                        n_kind, n_text, e.msg
                    ))
                },
                // Return a slice with the parsed type.
                |s_type| {
                    Ok(GoType::Slice(Slice {
                        internal_type: Box::new(s_type),
                    }))
                },
            )
        } else {
            // Return an error if the element field doesn't exist.
            TypeError::wrap_string(format!(
                "Got a {} without an element field, text: {}",
                n_kind, n_text,
            ))
        }
    }
}
```

`map_type` is similar. For `map[key]value`, we have two fields: `key` and
`value`.

```rs
match n_kind {
    // It's a map.
    "map_type" => {
        // Assuming parsing was correct and map_type has two children, key
        // and value.
        let k = n.child_by_field_name("key").unwrap();
        let v = n.child_by_field_name("value").unwrap();

        parse_go_type(k, src).map_or_else(
            |e| {
                TypeError::wrap_string(format!(
                    "Couldn't parse the key type of {}, text: {}, err: {}",
                    n_kind, n_text, e.msg
                ))
            },
            // If key type was parsed correctly, parse the value type.
            |key_type| {
                parse_go_type(v, src).map_or_else(
                    |e| {
                        TypeError::wrap_string(format!(
                            "Couldn't parse the value type of {}, text: {}, err: {}",
                            n_kind, n_text, e.msg
                        ))
                    },
                    // Both key and value types were parsed correctly. Return a Map.
                    |value_type| {
                        Ok(GoType::Map(Map {
                            key: Box::new(key_type),
                            value: Box::new(value_type),
                        }))
                    },
                )
            },
        )
    }
}
```

This allows us to parse something like this `[]map[string][]int`, a slice of
maps where the key is a string and the value is a slice of ints. The result is:

```json
{
  "Slice": {
    "internal_type": {
      "Map": {
        "key": {
          "SimpleType": {
            "internal_type": "string"
          }
        },
        "value": {
          "Slice": {
            "internal_type": {
              "SimpleType": {
                "internal_type": "int"
}}}}}}}}
```

This code allows to parse a good chunk of types which I feel is good enough for
a tutorial/proof-of-concept. Run `cargo run -- 06` to see the parsed return
values of a few functions (`source5.go`):

{{< imgcap title="cargo run -- 06" src="04.png" >}}

# Automatic Structs with type_sitter
I've reached a point where manual structs do not cut it anymore. I had a similar
issue when converting Semgrep JSONSchemas to Rust structs. See
{{< xref path="/post/2022/2022-10-16-yaml-wrangling-rust/"
  text="YAML Wrangling with Rust">}}.

I found a very interesting project [Jakobeha/type-sitter][type-sitter]. We can
point it to the `node-types.json` file to generate Rust structs.

The latest version of `type-sitter` requires `tree-sitter` 0.22, but the latest
version of `tree-sitter-go` needs 0.21, so I created the `type_sitter_example`
directory in the repository for this example. 

```
cargo install type-sitter
git submodule add https://github.com/tree-sitter/tree-sitter-go
type-sitter-cli tree-sitter-go/src/node-types.json -o src/type_sitter_example/type_sitter_go --use-yak-sitter
head src/type_sitter_example/type_sitter_go/go.rs

cargo add type-sitter-lib --features yak-sitter
cargo add yak-sitter
```

[type-sitter]: https://github.com/Jakobeha/type-sitter

The generated code is similar to what we did:

```rs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum SimpleType<'tree> {
    ArrayType(ArrayType<'tree>),
    ChannelType(ChannelType<'tree>),
    FunctionType(FunctionType<'tree>),
    GenericType(GenericType<'tree>),
    InterfaceType(InterfaceType<'tree>),
    MapType(MapType<'tree>),
    NegatedType(NegatedType<'tree>),
    PointerType(PointerType<'tree>),
    QualifiedType(QualifiedType<'tree>),
    SliceType(SliceType<'tree>),
    StructType(StructType<'tree>),
    TypeIdentifier(TypeIdentifier<'tree>),
}
```

Let's see if it works. We will create a `mod.rs` in
`src/type_sitter_example/type_sitter_go` with `pub mod go`.

The library mentioned we can optionally [yak-sitter][yak]. It's what I was
trying to do in the previous section. I wanted to wrap the nodes in the
tree-sitter tree and add the text. In fact, one of the extra info is the
original source code instead of just the byte offsets.

[yak]: https://github.com/Jakobeha/type-sitter/blob/main/yak-sitter/README.md

I was not able to get it to work without yak-sitter (e.g., the version of
structs that work with `tree-sitter` nodes). I managed to create a working
example based on a test at
https://github.com/Jakobeha/type-sitter/blob/main/type-sitter-lib/tests/use_node_types.rs#L11.

We can do something like this:

```rs
// Now we can go through the nodes and filter function return values.
let func_returns = yak_root
    .children(&mut yak_root.walk())
    // Go through all the children and unwrap them.
    .filter_map(|child| child.unwrap().regular())
    // Filter (function_declaration) statements.
    .filter_map(|n| n.function_declaration())
    // Get the "result" field for each (function_declaration)
    .filter_map(|n| n.result().flatten())
    // The result could be a (parameter_list) or (simple_type).
    // We're gonna ignore parameter_list here and only select simple types.
    .filter_map(|n| n.simple_type())
    // Convert to text.
    .map(|n| n.text())
    // Collect in a vector.
    .collect::<Vec<_>>();
```

We go through the nodes and filter the ones that are `function_declaration`. Then
go through the `result` field and finally get the `simple_types` (note, we're
gonna miss when the result is a `parameter_list`).

You can run the example with

```
cd src/type_sitter_example
cargo run --
```

{{< imgcap title="type_sitter example" src="05.png" >}}

# What Did We Learn Here Today?
We poked the tree-sitter tree, traversed it to solve some of our problems from
the previous blog that we could solve with queries. Now we can:

1. Find parents of functions.
2. Traverse the tree-sitter tree in an efficient manner with TreeCursor.
3. Extract Go types from code.
4. Use structs generated by `type_sitter`.