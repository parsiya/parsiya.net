---
title: "Using Mozilla Rhino to Run JavaScript in Java"
date: 2019-12-22T20:13:09-08:00
draft: false
toc: false
comments: true
twitterImage: 01-beautified.png
categories:
- Burp
- Burp extension
tags:
- Java
- Rhino
---

This post discusses what I learned about executing JavaScript modules in Java
with Mozilla Rhino. By the end of this post, you will know:

1. What Rhino is.
2. How to use Rhino in your Java application (e.g., a Burp extension).
3. Some tips and tricks when dealing with Rhino.
4. Alternative options.

Code is at:

* https://github.com/parsiya/Parsia-Code/tree/master/java-rhino

<!--more-->

# What's Mozilla Rhino?
[Mozilla Rhino][rhino-link] is an open-source implementation of JavaScript in
Java. In other words, we can run JavaScript on the JVM.

# Beautifying JavaScript with Rhino
As part of a different project, I wanted to beautify JavaScript in Burp. The
extension is in Java and I could not find anything that does it in native Java.
The closest thing I could find was a `java-prettify` from Google at
https://gerrit.googlesource.com/java-prettify/.

There is a Burp extension named [BurpSuiteJSBeautifier][jsbeautifier-github]
that beautifies JavaScript. This extension along with most utilities use an
open-source library named [js-beautify][js-beautify-github]. I did not try the
extension to see if it still works (the last update was more than 6 years ago)
but when I modified it in my example application, I got an error.

If your extension is in Python, `js-beautify` has
[Python bindings][js-beautify-python] that can be used in your extension.

For the remainder of the blog, I will work on an example that reads minified
JavaScript from a file, beautifies it, and stores it in another file.

## Adding Rhino to The Java Application
Let's start with a skeleton project. This is not a Burp extension but we can use
the instructions from [Developing and Debugging Java Burp Extensions with VisualStudio Code]
({{< relref "/post/2019-12-02-java-burp-1/index.markdown" >}} "Developing and Debugging Java Burp Extensions with VisualStudio Code").

Our `build.gradle` is a bit different this time because we are making a
standalone application. See the comments to figure out what was changed. The
most important part is adding Rhino as a dependency with: `compile
'org.mozilla:rhino:1.7.11'`.

```
// Apply the application plugin (runs the 'java' plugin implicitly).
apply plugin: 'application'

// Use Maven (because Burp Extender is on Maven)
repositories {
     mavenCentral()
}

dependencies {
    // Add the Burp Extender interface
    compile 'org.mozilla:rhino:1.7.11'
    compile 'commons-io:commons-io:2.6'
}

sourceSets {
    main {
        java {
            // Set the source directory to "src"
            srcDir 'src'
            exclude 'resources/'
        }
    }
    main {
        resources {
            // Set the resource directory to "src/resources"
            srcDir 'src/resources'
        }
    }
}

// Put the final jar file in a different location
libsDirName = '../release'

// This is needed if we want to run the jar with "gradlew run"
// mainClassName = 'beautify.Beautify'

// Create a task for bundling all dependencies into a jar file.
task bigJar(type: Jar) {
    // Make an executable jar that can be executed with "java -jar"
    manifest {
        attributes(
                'Main-Class': 'beautify.Beautify'
        )
    }
    // Bundle all dependencies together in one jar file.
    baseName = project.name + '-all'
    from { configurations.compile.collect { it.isDirectory() ? it : zipTree(it) } }
    with jar
}
```

## beautify.js
There are different versions of the beautifier. We can use it as Node or Python
package and there is a [web version][js-beautify-web] in a stand-alone
JavaScript file. This is the version used by the `BurpSuiteJSBeautifier`
extension and we will use it. Get it from
https://cdnjs.cloudflare.com/ajax/libs/js-beautify/1.10.2/beautify.js and add it
to the `resources` directory.

## Reading Resource Files
`src\Beautify\beautify.java` will be our main class. Inside, we
create a couple of helper utils. For example, to load a file from the jar's
resource, we use this:

```java
public static String getResourceFile(Class cls, String name) throws IOException {
    InputStream in = cls.getResourceAsStream(name);
    String content = IOUtils.toString(in, "UTF-8");
    in.close();
    return content;
}
```

If you are already using the [Apache Commons IO][commons-io-github]
library then this function is not an overhead. The following utility function does
the same but without the extra dependency.

```java
public static String getResourceFile(String name) throws IOException {
    InputStream in = BurpExtender.class.getResourceAsStream(name); 
    BufferedReader reader = new BufferedReader(new InputStreamReader(in));
    
    StringBuffer buf = new StringBuffer();
    String tmpStr = "";

    while((tmpStr = reader.readLine()) != null) {
        buf.append(tmpStr);
    }
    in.close();
    return buf.toString();
}
```

## Beautify Function
The other utility function is `beautify`. It uses `beautify.js` to beautify the
JavaScript code in the input. We will follow the Mozilla embedding
tutorial at
https://developer.mozilla.org/en-US/docs/Mozilla/Projects/Rhino/Embedding_tutorial.

We create a context and enter it.

```java
public static String beautify(String uglyJS) throws IOException {
    // Enter a context.
    Context cx = Context.enter();
```

We can set the optimization level. The optimization levels are explained at
https://developer.mozilla.org/en-US/docs/Mozilla/Projects/Rhino/Optimization. I
am not sure if we will need it here.

```java
// Set optimization.
// cx.setOptimizationLevel(-1);
```

Create standard objects.

```java
// Initialize standard objects.
Scriptable scope = cx.initSafeStandardObjects();
```

Moving forward, we can add scripts to the scope with
[cx.evaluateString][evaluatestring-docs].

Follow the BurpSuiteJSBeautifier extension source code at

* https://github.com/irsdl/BurpSuiteJSBeautifier/blob/master/jsbeautifier/src/burp/JSBeautifier/JSBeautifierFunctions.java#L321
* or this solution on [Stack Overflow][beautify-stackoverflow].

Tl;DR, we need to add a `global` variable to our scope because the `js_beautify`
function is added to the global variable. See the last few lines of `beautify.js` in the
following snippet:

```javascript
var js_beautify = legacy_beautify_js;
/* Footer */
if (typeof define === "function" && define.amd) {
    // Add support for AMD ( https://github.com/amdjs/amdjs-api/wiki/AMD#defineamd-property- )
    define([], function() {
        return { js_beautify: js_beautify };
    });
} else if (typeof exports !== "undefined") {
    // Add support for CommonJS. Just put this file somewhere on your require.paths
    // and you will be able to `var js_beautify = require("beautify").js_beautify`.
    exports.js_beautify = js_beautify;
} else if (typeof window !== "undefined") {
    // If we're running a web page and don't have either of the above, add our one global
    window.js_beautify = js_beautify;
} else if (typeof global !== "undefined") {
    // If we don't even have window, try global.
    global.js_beautify = js_beautify; // <----- HERE
}
```

Now we need to read `beautify.js` with `getResourceFile` and add it to the
scope.

```java
// Read the jsbeautify.js file.
String jsbeautifyFile = getResourceFile(Beautify.class, "/beautify.js");

cx.evaluateString(scope, "var global = {}; "+jsbeautifyFile, "global", 0, null);
```

If you do not include the initial forward-slash before the file name, you will
waste a few hours as I did.

Next is what wasted a few more hours of my life. In both the extension and the
Stack Overflow solution, the function is retrieved from the scope directly like
this:

```java
// Solution: https://stackoverflow.com/a/16338524 -- doesn't work
Object fjsBeautify = scope.get("js_beautify", scope);
```

**This does not work here.** I am not sure why. It might be a JavaScript version
issue. Even calling it with `global.js_beautify` does not work either.

Instead, what I did was add a new script to scope.

```java
// Add our own export.
cx.evaluateString(scope, "var js_beautify = global.js_beautify;", "export", 0, null);
```

Now we can get this new function with:

```java
// Get the function.
Object fjsBeautify = scope.get("js_beautify", scope);

```

We can follow the rest of the tutorial to call the function. The input to the
function is the `uglyJS` string:

```java
// Check to see if we got the correct function?
if (!(fjsBeautify instanceof Function)) {
    System.out.println("js_beautify is undefined or not a function.");
    // System.out.println(fjsBeautify.toString());
    
} else {
    Object functionArgs[] = { uglyJS };
    // Object functionArgs[] = { "var x='1234';var y='4444';var z='3123123';" };
    Function f = (Function)fjsBeautify;
    Object result = f.call(cx, scope, scope, functionArgs);
    Context.exit();
    return Context.toString(result);
}
// We should throw an exception here in production code.
Context.exit();
return null;
```

The next utility function takes two file paths, reads the first one, beautifies
it and stores it in the second path.

```java
public static void beautifyFile(String inFilePath, String outFilePath) throws IOException {
    // Read the file.
    File inFile = new File(inFilePath);
    String fileContent = FileUtils.readFileToString(inFile, "UTF-8");

    File outFile = new File(outFilePath);
    try {
        String beautified = beautify(fileContent);
        FileUtils.writeStringToFile(outFile, beautified, "UTF-8");
    } catch (Exception e) {
        // TODO: handle exception
        StringWriter sw = new StringWriter();
        e.printStackTrace(new PrintWriter(sw));
        System.out.println(sw.toString());
    }
}
```

Time to tie everything together. As an example, we want to beautify the
`cookiebanner.min.js` at:

* https://raw.githubusercontent.com/dobarkod/cookie-banner/master/dist/cookiebanner.min.js

```java
    public static void main(String[] args) {

        try {
            beautifyFile("cookiebanner.min.js", "cookie-beautified.js");
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("Done");
    }
```

Build the project. The jar will be created in the `release` directory. Download
the `cookiebanner.min.js` file and store it in the same directory. Next, we can
run the jar file `java -jar test-jsbeautify-all.jar`.

After a few seconds, the `cookie-beautified.js` is created.

{{< imgcap title="Beautified JavaScript" src="01-beautified.png" >}}

To speed up things a little bit, we can modify `beautify.js` to call
`evaluateString` once.

```js
var global = {};

// Beautify.js

var js_beautify = global.js_beautify;
```

## Re-using the scope
If we want to beautify a bunch of JavaScript files, we can reuse this scope
instead of creating this every time. This is what the BurpSuiteJSBeautifier
extension does.

# Precompiling to Bytecode
It's also possible to compile the string into a class file and then execute it.
To make a class file, we can either do it programmatically with
[Context.compileString][compilestring-doc]. The result is a [Script][script-doc]
that can be executed with `exec`. This is not useful here because we are not
executing the script.

## Creating Class Files from JavaScript Files
We can create a class file from a JavaScript file using the Rhino jar.

1. Download the Rhino jar file to a path.
    1. For example, `rhino-1.7.11.jar` from https://github.com/mozilla/rhino/releases/tag/Rhino1_7_11_Release.
2. Run the following command.
    1. `java -cp rhino-1.7.11.jar org.mozilla.javascript.tools.jsc.Main beautify.js`
3. Load the resulting class file and use objects/functions/etc.

See the options at:

* https://developer.mozilla.org/en-US/docs/Mozilla/Projects/Rhino/JavaScript_Compiler

## js_beautify Options
The `js_beautify` function has a second optional parameter. This is a JSON
string with options. See an example at:

* https://github.com/beautify-web/js-beautify#nodejs-javascript-1

# Alternatives
Instead of using Rhino, it's possible to call `js-beautify` via the command
line. This method requires the https://www.npmjs.com/package/js-beautify to be
installed globally.

Then we can call `js-beautify -f inputfile -o output-file`.

Another option is to create an executable using https://github.com/zeit/pkg and
calling it similarly. This means we do not need to install the package. The
executable on Windows is around 40 MBs.

These two might be better your usecase. However, that means you have to create
the dependencies yourself and or ship them your app.

# What Did We Learn Here Today?

1. How to add Rhino to your project.
2. How to read resources inside jar files.
3. How to run a JavaScript function in Rhino.
4. Troubleshooting tips and tricks.


<!-- Links -->
[rhino-link]: https://developer.mozilla.org/en-US/docs/Mozilla/Projects/Rhino
[rhino-github]: https://developer.mozilla.org/en-US/docs/Mozilla/Projects/Rhino
[jsbeautifier-github]: https://github.com/irsdl/BurpSuiteJSBeautifier
[js-beautify-github]: https://github.com/beautify-web/js-beautify
[js-beautify-python]: https://github.com/beautify-web/js-beautify#python
[js-beautify-web]: https://github.com/beautify-web/js-beautify#web-library
[commons-io-github]: https://github.com/apache/commons-io
[beautify-stackoverflow]: https://stackoverflow.com/a/16338524
[evaluatestring-docs]: http://mozilla.github.io/rhino/javadoc/org/mozilla/javascript/Context.html#evaluateString-org.mozilla.javascript.Scriptable-java.lang.String-java.lang.String-int-java.lang.Object-
[compilestring-doc]: http://mozilla.github.io/rhino/javadoc/org/mozilla/javascript/Context.html#compileString-java.lang.String-java.lang.String-int-java.lang.Object-
[script-doc]: http://mozilla.github.io/rhino/javadoc/org/mozilla/javascript/Script.html