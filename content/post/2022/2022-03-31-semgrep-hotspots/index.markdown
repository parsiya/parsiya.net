---
title: "Code Review Hot Spots with Semgrep"
date: 2022-04-07T12:51:57-07:00
draft: false
toc: true
comments: true
twitterImage: 07-encode-decode.png
aliases:
- /blog/2022-04-07-introducing-code-review-hotspots-with-semgrep/
- /blog/semgrep-hotspot/
- /blog/2022-04-07-code-review-hotspots-with-semgrep/
categories:
- semgrep
- automation
---

I will discuss the (not novel) concept of code review hot spots. Hot spots are
parts of the code that might contain vulnerabilities. They are not suitable for
automatic reporting, so security engineers should review them manually. I will
define what I call a hot spot; I'll find some examples with Semgrep; and finally,
I'll show how I collect these rules.

<!--more-->

# What is a Hot Spot?
In this context, hot spots are parts of code that *might* contain security
vulnerabilities. You are not "always" looking for a specific problem, but rather
bad practices, common mistakes, insecure configurations, and in short, places
where bad things usually happen.

It's impossible to review every line of code in a modern software project. So we
search for a mental or written list of keywords like `SSLv3`, `MD5`, `memcpy`,
or `encrypt/decrypt`. We are not sure we'll find anything, but these are good
places to start looking for bugs.

# Types of Static Analysis Rules
You (as a security engineer) should have two separate groups of security-focused
static analysis rules:

1. `security`: For developers.
2. `hotspots`: For security engineers.

## Security Rules
`security` rules detect specific vulnerabilities (e.g., `log4j`). Ideally, they
should be lightweight and return zero false positives. I should enable the
developers to deploy my rules in their workflow (e.g., CI/CD pipeline or editor)
with confidence and have faith that I will not waste their time. If not, they
will stop trusting me and throw away (or circumvent) the application security
apparatus. I would do the same.

## Hot Spot Rules
`hotspots` are for me. I want to find error-prone parts of the code. I can
usually discard false positives with a quick review. These rules should be very
noisy, but don't spend too much time reducing the noise.

# Review of Existing Literature
I am not proposing a novel idea. I have learned from others.

## Everyone has a Hot Spot List
Every security engineer has a personal (mental or written) list of keywords
accumulated over time.
[.NET Interesting Keywords to Find Deserialization Issues][net-keywords] by
[irsdl][irsdl-twitter] is a good example. You can find similar lists with a
quick search. Collecting these are fun.

[irsdl-twitter]: https://twitter.com/irsdl
[net-keywords]: https://gist.github.com/irsdl/9315521bab79fe972859874b5f2185af

## Hardcoded Secret Detectors
Hardcoded secrets are hot spots. There are a gazillion products and regular
expressions to find API keys, passwords, and encryption keys. The results
usually have high false positives and require manual review.

## The Audit Category in Semgrep Rules
The [Semgrep rules][semgrep-rules-audit] repository stores calls them `audit`
rules and stores them under `security/audit`. You can run them all with the
[p/security-audit][security-audit-policy] policy.

[security-audit-policy]: https://semgrep.dev/p/security-audit
[semgrep-rules-audit]: https://github.com/returntocorp/semgrep-rules#rule-namespacing

{{< blockquote >}}
If a security rule is discouraging the use of a bad pattern (such as formatted
SQL strings), we recommend appending audit to your namespace. This distinguishes
it from a security rule that is specifically aiming to detect a vulnerability.
{{< /blockquote >}}

### Audit Shouldn't be Under Security in the Semgrep Rules Repository
**Semgrep bashing ahead.**

{{< blockquote author="- r2c folks (OK! They actually didn't say this)" >}}
Et tu, Parsia?
{{< /blockquote >}}

TL;DR: Running rules under `security` will also run the noisier `audit`.
`security` and `audit` should be separate categories in my opinion. You can
avoid this issue by using policies but it's still a problem with local rules.

Semgrep can use local rules with `--config /path/to/rules/`. It will run every
rule in the path and any subdirectories. So,
`--config semgrep-rules/python/lang/security` will also run the rules in
`python/lang/security/audit`

We can directly use the registry without downloading the rules.
`--config r/python.lang.security` will run all the rules in the registry under
`/python/lang/security` including `audit`.

This behavior is not ideal. `audit` rules are noisy by design. I have organized
our internal Semgrep rules differently. E.g., we have `python.lang.security` and
`python.lang.hotspots`. I can pass the rules in `security` to developers and
keep the noisy `hotspots` for ourselves.

## Microsoft Application Inspector
[Microsoft Application Inspector][appinspector-gh] is a "what's in the code"
tool. It has built-in features like `cryptography` or `authentication`. Each
rule belongs to a feature and contains a list of keywords/regular expressions.
If a rule has a hit, the final report will include that feature. For example, if
the code has `md5` the application has the `cryptography`.

I played with Application Inspector and [DevSkim][devskim-gh] (an IDE linter
that uses the same rule format) for a few weeks but decided they were not for
me. Application Inspector is designed to present features (e.g., this app has
`authentication`), but I was interested in navigating and reviewing the results.

[appinspector-gh]: https://github.com/microsoft/ApplicationInspector
[devskim-gh]: https://github.com/microsoft/DevSkim

## weggli by Felix - "Playing with Weggli" by Jonathan & Jordy
A few days ago, I was looking at some C++ rules in [weggli][weggli-gh]. `weggli`
is a C/C++ static analysis tool by [Felix Wilhelm][felix-twitter] from Google
Project Zero. weglli and Semgrep use the same parser
([Tree-Sitter][tree-sitter]) and have similar rule patterns. The readme has a
list of examples and I ported some to Semgrep.

I also found [Playing with Weggli][playing-weggli] by Julien Voisin and
[Jordy (Oblivion)][oblivion-site]. They ran some custom weggli rules on the
Linux codebase. The blog gave me ideas for Semgrep rules (see the `sizeof(*ptr)`
rule discussed later).

Thanks, Felix, Jonathan, and Jordy!

[felix-twitter]: https://twitter.com/_fel1x
[playing-weggli]: https://dustri.org/b/playing-with-weggli.html
[oblivion-site]: https://pwning.systems/about/
[weggli-gh]: https://github.com/googleprojectzero/weggli
[tree-sitter]: https://tree-sitter.github.io/tree-sitter/

# Different Types of Hot Spots
I have created a simple category for hot spots. I will define each one and
discuss examples.

1. **Insecure Configurations**: A (usually 3rd party) component with a vulnerable configuration.
2. **Dangerous Functions**: Using these functions is usually a security problem.
3. **Dangerous Patterns**: Safe methods and constructs that are used insecurely.
4. **Interesting Keywords**: Specific terms in variable/class/method names and comments.

## 1. Insecure Configurations
**The framework, library, or infrastructure's configuration is insecure.** We
can usually find insecure configurations by the existence (or omission) of
certain reserved keywords. These configurations can be in the code or config
files (d'oh).

### TLSv1 Support in Go
Look for [VersionTLS10][tlsv1-gh] and `VersionSSL30`[^sslv3] in Go code to see
support for TLSv1.0 or SSLv3. Use this simple Semgrep rule
(https://semgrep.dev/s/parsiya:blog-2022-03-go-tlsv1) to find these hot spots and
even automagically
{{< xref path="/post/2021/2021-10-24-semgrep-autofix" text="fix them" >}}.

[^sslv3]: Deprecated in Go 1.14.

[tlsv1-gh]: https://github.com/golang/go/blob/01c83be7932e7f51333c813460752f09f78ec2c4/src/crypto/tls/common.go#L29

{{< imgcap title="Detecting TLSv1 support with Semgrep" src="01-tlsv1.png" >}}

There's a similar rule in the Semgrep registry: 
https://semgrep.dev/r?q=go-stdlib.disallow-old-tls-versions.

### Skipping Certificate Verification in Go
We can disable TLS certificate[^1] checks in Go with
[InsecureSkipVerify][insecureskip]. It's bad, but not necessarily a problem. We
might be dealing with internal endpoints without valid certificates[^2].

[^1]: OK! x509 certs. Don't @ me!
[^2]: Or for a variety of other reasons.

If `InsecureSkipVerify` is true, we can use the optional
[VerifyPeerCertificate][verifypeercert] callback to do our own checks. The last
stand is [VerifyConnection][verifyconnection] which is executed for all
connections and can terminate the TLS handshake.

[insecureskip]: https://github.com/golang/go/blob/01c83be7932e7f51333c813460752f09f78ec2c4/src/crypto/tls/common.go#L641
[verifypeercert]: https://github.com/golang/go/blob/01c83be7932e7f51333c813460752f09f78ec2c4/src/crypto/tls/common.go#L590
[verifyconnection]: https://github.com/golang/go/blob/01c83be7932e7f51333c813460752f09f78ec2c4/src/crypto/tls/common.go#L603

Another simple Semgrep rule to find all three keywords:
https://semgrep.dev/s/parsiya:blog-2022-03-go-cert-check.

{{< imgcap title="Go certificate bypass check" src="02-go-cert.png" >}}

The rule in the Semgrep registry at
https://semgrep.dev/r?q=go-stdlib.bypass-tls-verification takes advantage of the
Sem(antic) in Semgrep and looks for things like
`tls.Config{..., InsecureSkipVerify: true, ...}`.

### External Entity Injection in Java
Java is notorious for [External Entity Injection (XXE) problems][xxe-java]. Most
XML parsing libraries do not have secure defaults. We use hardcoded strings and
language constants to look for them. For example, `DocumentBuilderFactory`.

The existing Semgrep rules do a decent job of eliminating false positives, but
it's impossible to find everything. A hot spot rule has an easier time and can
flag all of them for manual review. I used the
[OWASP XML External Entity Prevention Cheat Sheet][xxe-java] to compose a list
(warning: lots of noise): https://semgrep.dev/s/parsiya:blog-2022-03-java-xxe.

{{< imgcap title="Java XXE Hail Mary" src="05-java-xxe-hail-mary.png" >}}

[xxe-java]: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#java

### Security Issues in Dockerfiles
dockerfiles are essentially configuration files. Containers are versatile. We
can shoot ourselves in the foot (lookout C++! a new contender is here). Our
hot spot rules can look for things like
[is it running as root?][docker-root-registry] or
[source is not pinned][docker-src-not-pinned].

[docker-root-registry]: https://semgrep.dev/r?q=docker+last-user-is-root
[docker-src-not-pinned]: https://semgrep.dev/r?q=dockerfile-source-not-pinned

**Almost all cloud, k8s, and similar configuration issues fall into this category.**
Find how a configuration can be insecure, add their respective keywords to your
rules and run them on everything.

## 2. Dangerous Functions
**Every programming language, framework, and library has dangerous functions.**
However, their existence is not necessarily a vulnerability. You could say that
we should not use these dangerous functions and I agree, but removing them is
not always practical, especially in legacy code.

### MD5
`MD5` is a cryptographically broken hash function (emphasis on
"cryptographically"). That said, we cannot report every instance. There are
cases where using `MD5` is completely fine. I have seen some safe examples in
the real world:

1. A custom content management system (e.g., a blog) used MD5 to create an
   identifier for images. If you can edit the blog post and add a different
   image with the same hash, you can do bad things and overwrite the previous
   one. This is useless because you can just delete the original image with your
   access.
2. Generating a database index from a 20 digit numerical user ID. The ID has to
   be a valid number. As far as I know, it's impossible to generate an MD5
   collision with two numbers (ready to be proven wrong).

Flagging `MD5` is the knee-jerk reaction. Maybe you will create a ticket and ask
the developers to change it to SHA-256 "to be sure." Keep in mind that your
reputation will take a hit by asking developers to spend cycles without a
plausible vulnerability.

The "insecure randoms" like `java.lang.Math.random` are similar. They are OK to
use in a non-cryptographic context. A ticket about the "tip of the day" module
not using a CSPRNG (Cryptographically Secure PseudoRandom Number Generator)
is silly.

### sizeof(*ptr) in C
Using `sizeof(pointer)` instead of the actual object type is a common mistake in
C/C++. In this example we are using `memcpy(dst, src, sizeof(char*))` which
results in a classic buffer overflow. `sizeof(char*)` is usually 4 (x86) or 8
(x64) bytes while the `sizeof(char)` is 1.

```cpp
#include <stdio.h>
#include <string.h>

int main() {

  char dst[20];
  char* src = "hello hello";

  // seg fault - sizeof(char*) == 8
  memcpy(dst, src, strlen(src)*sizeof(char*));

  // sizeof(char): 1 - sizeof(char*): 8 - sizeof(source): 8
  // printf("sizeof(char): %lu - sizeof(char*): %lu - sizeof(src): %lu\n",
  //    sizeof(char), sizeof(char*), sizeof(src));
}
```

Interestingly, with`memcpy(dst, src, sizeof(src))` we get a warning:

```
warning: 'memcpy' call operates on objects of type 'char' while the size is
based on a different type 'char *'
[-Wsizeof-pointer-memaccess]
  memcpy(dst, src, sizeof(src));
```

I created a rule to find all `sizeof($TYPE*)` in the code with `pattern-regex`.
This will also search comments. We can reduce the false positives with
`pattern-not-regex`. Try extending
https://semgrep.dev/s/parsiya:blog-2022-03-sizeof-ptr.

{{< imgcap title="sizeof(pointer) Semgrep rule" src="03-sizeof.png" >}}

### text/template in Go
Go's standard library offers two template packages.
[html/template][html-template] does some output encoding while
[text/template][text-template] does none. Using `text/template` in a web
application might lead to XSS. We should review find and review `text/template`
imports.

The Semgrep registry has an [audit rule][text-template-rule] for this problem.
I am recycling my similar rule from the
{{< xref path="/post/2021/2021-10-24-semgrep-autofix" 
    text="autofix blog" anchor="go---texttemplate" >}}:
https://semgrep.dev/s/parsiya:go-import-text-template-fix.

[text-template]: https://pkg.go.dev/text/template
[html-template]: https://pkg.go.dev/html/template
[text-template-rule]: https://semgrep.dev/r?q=text-template

### Unsafe in Go
My attempt at an unoriginal programming language joke:

> Under the standard library of every secure programming language are a bunch of
> unsafes.

Go and Rust are considered secure programming languages, but both allow us to
use `unsafe` via [Go's unsafe package][go-unsafe] and
[Rust's unsafe keyword][rust-unsafe].

[go-unsafe]: https://pkg.go.dev/unsafe
[rust-unsafe]: https://doc.rust-lang.org/std/keyword.unsafe.html

Should we flag all unsafes? Depends on the industry. I don't. Game devs love to
use clever hacks. Finding these instances are easy. Look for `import "unsafe"`
in Go and `unsafe` in Rust. A sample rule for Go (Semgrep doesn't support Rust,
but Rust is already secure :p):
https://semgrep.dev/s/parsiya:blog-2022-03-go-unsafe.

{{< imgcap title="Finding unsafe imports in Go" src="06-go-unsafe.png" >}}

## 3. Dangerous Patterns
**Dangerous patterns often lead to security vulnerabilities.** Think of them as
"insecure usage of usually safe methods."

### Formatted SQL Strings in Java
The Semgrep registry has [a rule][sql-string-rule] that looks intimidating but
is just trying to find concatenated strings executed as SQL queries.

[sql-string-rule]: https://semgrep.dev/playground?registry=java.lang.security.audit.formatted-sql-string.formatted-sql-string

{{< imgcap title="SQL query caught by this rule" src="04-sql-string.png" >}}

If you have time, flag and review every SQL query. `exec` (and similar) commands
are also good choices. We want to review them and check if an attacker can
influence their input and get command injection.

### Return Value of openssl_decrypt in PHP
I encountered this problem recently. The [openssl_decrypt][openssl_decrypt-php]
is a safe function in PHP returns the decrypted string on success, but `false`
on failure. We might have a vulnerability if we don't check this edge case. The
[openssl-decrypt-validate][openssl_decrypt-semgrep] Semgrep rule flags these
cases for review:

[openssl_decrypt-php]: https://www.php.net/manual/en/function.openssl-decrypt.php
[openssl_decrypt-semgrep]: https://semgrep.dev/playground?registry=php.lang.security.audit.openssl-decrypt-validate.openssl-decrypt-validate

### Hardcoded Secrets
Let's say you are storing the AES keys in the source code or in a config file.
This is a dangerous pattern. AES is secure and not a dangerous function but you
have weakened it because everyone with access to the code is now able to break
your encryption.

Using a static salt in your password hashing scheme is the same. You have
weakened your (hopefully) secure algorithm.

## 4. Interesting Keywords
**Look for specific variable/method/class names, and comments**. These are not
language keywords but rather contextual concepts (wut?!).

Have you ever searched for `password` in a codebase to discover how passwords
are handled? They are probably stored in variables named `password`, `passwrd`,
or another variation. What about searching for `TODO` or `security` in the code
comments?

### Function with Encode and Decode in Their Names
[weggli][weggli-gh] has an example to find functions with `decode` in their
names. I want to review any function that has `encode` and `decode` in its name.
`encrypt/decrypt` is another good choice. These functions probably increase our
attack surface because we are dealing with two different formats. Parser bugs
are fun!

The Semgrep rule at
https://semgrep.dev/s/parsiya:blog-2022-03-encode-decode-function-name was easy
to create (man, I love Semgrep). We capture all functions in a metavariable
`$FUNC(...)`, then use `metavariable-regex` to filter them.

{{< imgcap title="Find functions with encode/decode in their name" src="07-encode-decode.png" >}}

### Bug and Feature Tracking Codes
Bugs are usually mentioned in code comments. For example, if I fix the ticket
`BUG-1234` I add a comment to that location in the code with some other
information. The same for new features or merge/pull requests. Search for these
patterns in code to find features, fixed bugs, existing bugs, **workarounds**
(`// BUG-234: hacky way of bypassing a security guardrail!`), and other
interesting things.

During my lucky
{{< xref path="/post/2021/2021-12-20-vscode-wsl-rce"
  text="RCE in the WSL Remote extension" >}}
I found a reference to a CVE in the [VS Code server code][cve-in-code].

The page for [CVE-2021-1416][cve-2020-1416] doesn't have much information. The
code tells a much better story. VS Code server would loads code from
`node_modules` in specific paths on Windows. If an attacker could put their own
Node modules in those paths, they could achieve RCE. Why is
`Azure Storage Explorer` even running this code?!

[cve-2020-1416]: https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-1416
[cve-in-code]: https://github.com/microsoft/vscode/blob/48b6c6a5ffca58a3fd7dc281419c42f8f9abc35a/src/vs/server/node/remoteExtensionHostAgentServer.ts#L677

{{< imgcap title="CVE-2020-1416 in code" src="09-cve.png" >}}

We can search for items like `CVE*`, `BUG-[number]`, and `CL[number]` (CL stands
for `Change List` in perforce which is the equivalent of a git commit).

# How Do I Collect These?
I have already explained where my examples have come from. Let's make a list:

1. Static analysis rules
2. Coding standards
3. Documentation
4. Other bugs
5. Experience

## 1. Static Analysis Rules
Go through static analysis rules for different languages and tools. I went
through Semgrep's `audit` rules and weggli examples. Check out
[GitHub Security Lab's CodeQL queries][codeql-gh-sec-lab] for more. While it's
impossible to replicate some of CodeQL rules in Semgrep, extract keywords for
manual review.

Why Semgrep and not CodeQL then? The short answer is
{{< xref path="/post/2021/2021-06-12-semgrep-scalpel"
  text="CodeQL is nice but doesn't work for me" >}}.

[codeql-gh-sec-lab]: https://github.com/github/securitylab/tree/main/CodeQL_Queries

You can even use patterns from other languages and adapt them to your target. We
just saw XXE in Java, but it also happens in other languages. Search for
`xml + other-language` and see what you can find.

The keywords in [Microsoft Application Inspector][appinspector-gh] and
[DevSkim][devskim-gh] rules are useful.

## 2. Coding Standards
Programming languages and development teams usually have their own coding
standards. Some functions and libraries are banned; some patterns are actively
discouraged. Add these to your list.

You can find legacy code, one-time exceptions ("hey can I use memcpy here
once?"), and items missed in code reviews.

## 3. Documentation
Reading and writing documentation is a great way to learn.

Sometimes the **programming language** has warnings in `in large, friendly letters`.

{{< imgcap title="Don't Panic! credit: nclm, CC0, via Wikimedia Commons" src="08-dont-panic.png" >}}

A good example (thanks to my friend [Tim Michaud][tim-twitter]) is PHP's
[unserialize][php-unserialize]. The documentation mentions:

> **Warning**: Do not pass untrusted user input to **unserialize()** regardless
> of the options value of `allowed_classes`.

[tim-twitter]: https://twitter.com/TimGMichaud
[php-unserialize]: https://www.php.net/manual/en/function.unserialize.php

At some point, developers stop trying to play Whac-A-Mole with bugs and say
something similar. Others don't give in and try to block patterns (e.g.,
[Jackson serialization gadgets][jackson-gadgets]). Personally, I think it's a
losing battle:

[jackson-gadgets]: https://cowtowncoder.medium.com/on-jackson-cves-dont-panic-here-is-what-you-need-to-know-54cd0d6e8062#da96

{{< blockquote link="https://parsiya.net/blog/2022-02-07-security-nightmares-of-game-package-managers/" >}}
An intentionally insecure system is insecure. If you install a game in an
insecure path there's not much we can do.
{{< /blockquote >}}

Every **cloud provider, library, framework, and operating system** has official
and unofficial security guides. Read them and add items to your list.

[**OWASP security checklists and cheat sheets**][owasp-cheatsheet-series] are
also good resources. The Java XXE rule above was compiled from the OWASP XXE
cheat sheet.

[owasp-cheatsheet-series]: https://cheatsheetseries.owasp.org/

**Talk to the developers and understand their threat model**. They know the code
better than you. Some of my best bugs have come from these conversations. "what
keeps you up at night?", "what data is most important?", and "What do wish was
more secure?" are good questions.

## 4. Other Bugs
**Study bugs**. Very few public bugs are accompanied by source code, but
**opensource pull/merge requests** are great. Identify the vulnerable patterns
and create rules. Don't spend a lot of time trying to weed out false positives.
Our objective is to find hot spots. Sometimes just flagging a specific function
is more than enough.

Read internal security bugs written by other engineers. Review bugs disclosed to
your organization by external security researchers. Grab the code/configuration
and try to perform root cause analysis. Find out which part was vulnerable. This
has two uses:

1. You will find new patterns and learn more.
2. You can hunt for variants. Run the pattern against the rest of your codebase.

**Ticket Numbers and annotations** are also good places to start. As we
discussed above, look for ticket numbers `BUG-1234`, annotations
(`CVE-2021-1234`), and other items in the code.

## 5. Experience
Not much to discuss here, but over the years you start seeing things in code. If
your gut feeling tells you something is wrong then add it to your list.
Periodically prune it.

The list doesn't have to be sophisticated. Things like `encode/decode`,
`authentication/authN`, `authorization/authZ`, `encrypt/decrypt`, or `hash/hmac`
are great choices. We already saw the
[.NET Interesting Keywords to Find Deserialization Issues][net-keywords] list.
Look for these lists.

# What Did We Learn Here Today?
I introduced the concept of `hot spots in source code`. These are locations that
might contain vulnerabilities but should be reviewed manually. The results are
noisy, so hot spot rules are not suitable for CI/CD pipelines and automatic
alerts.

The main audience for hot spots is security engineers. We have to rely on static
analysis tools to review millions of lines of code. Our approach here is not
scientific, but holistic. We rely on our gut feelings and manual analysis. This
is usually not something a machine can do (I am sure Semmle folks disagree).

I went through existing instances of this concept and tried to create a
lightweight classification. We discussed examples and Semgrep rules for each
category. The last section explained how I collect ideas and samples to find
more hot spots.

If you have any feedback, you know where to find me. I am here every week.
