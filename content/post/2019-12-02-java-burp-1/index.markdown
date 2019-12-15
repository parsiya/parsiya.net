---
title: "Developing and Debugging Java Burp Extensions with Visual Studio Code"
date: 2019-12-02T19:32:09-08:00
draft: false
toc: true
comments: true
twitterImage: 03-intellicode.png
categories:
- Burp
- Burp extension
tags:
- Java
---

A few days ago, I released the [Bug Diaries](https://github.com/parsiya/bug-diaries)
Burp extension. It's a Burp extension that aims to mimic Burp issues for the
community (free) version. For reasons, I decided to rewrite it in Java. This is
the first part of my series on what I learned switching to Java.

This part discusses how my environment is set up for development with
[Visual Studio Code](https://code.visualstudio.com/). Things like
auto-completion, Gradle builds and most importantly debugging.

Clone the repository to skip some of the steps in the blog. I still recommend
doing them yourself if you are not familiar with Gradle and Burp development,
clone the following repository:

* https://github.com/parsiya/burp-sample-extension-java

<!--more-->

# Bug Diaries in Python
The original extension was in Python. To that day, all of my Burp extensions had
been in Python. I documented what I learned:

* [Swing in Python Burp Extensions - Part 1]({{< relref
  "/post/2019-11-04-gui-python-burp-extension-1/index.markdown" >}} "Swing in
  Python Burp Extensions - Part 1")
* [Swing in Python Burp Extensions - Part 2 - NetBeans and TableModels]({{<
  relref "/post/2019-11-11-gui-python-burp-extension-2/index.markdown" >}}
  "Swing in Python Burp Extensions - Part 2 - NetBeans and TableModels")
* [Swing in Python Burp Extensions - Part 3 - Tips and Tricks]({{< relref
  "/post/2019-11-26-gui-burp-extension-3/index.markdown" >}} "Swing in Python
  Burp Extensions - Part 3 - Tips and Tricks") 

I had a lot of problems enabling the right-click functionality on Burp's
[IMesageEditors][imsgeditor-doc].Long story short, I decided to rewrite the
extension in Java instead.

This is how my development VM is arranged.

# Install Visual Studio Code

1. Install [VS Code][vscode-url].
2. Install the [Java Extension Pack][java-extension-pack].

There is also a VS Code installer for Java developers at
https://aka.ms/vscode-java-installer-win. I did not use it.

# Install OpenJDK
I use OpenJDK because of the shitty licensing requirements of Oracle.

1. Download OpenJDK 11 (see below why). I used the installer from
   [AdoptOpenJDK.net](https://adoptopenjdk.net).
    * Red Hat has binaries at
      https://developers.redhat.com/products/openjdk/download. You will need a
      free developer account.
2. If you are extracting the OpenJDK manually, modify the environment variables:
    * Set `JAVA_HOME` to `C:\Program Files\path\to\jdk\`. (Do not include the
      `bin` directory).
        * For my JDK it was `C:\Program Files\AdoptOpenJDK\jdk-11.0.5.10-hotspot`.
    * Add the `bin` directory for the JDK installation to `PATH`.

Now `java -version` should return something like (remember to open a new command
line after setting the `PATH`):

```
openjdk version "11.0.5" 2019-10-15
OpenJDK Runtime Environment AdoptOpenJDK (build 11.0.5+10)
OpenJDK 64-Bit Server VM AdoptOpenJDK (build 11.0.5+10, mixed mode
```

**Note**: If you install the JDK 13 or newer, you cannot use the Burp's exe file
to load your extension. As of December 2019, The Burp's `exe` file, uses a
bundled JRE which is built with JDK 11 (version 55.0). If you try to load an
extension that is built with a later Java version, you will get this error:

```
java.lang.UnsupportedClassVersionError: burp/BurpExtender has been compiled by
a more recent version of the Java Runtime (class file version 57.0), this
version of the Java Runtime only recognizes class file versions up to 55.0
```

Solution:

1. Use an earlier version to build your extension. Recommended.
2. Run the Burp's jar file directly using your installed Java.
    * I actually don't know if this works. If you try and it works, please let
      me know. 

# Gradle
[Gradle][gradle-website] does not have an installer either.

1. Download the latest release from https://gradle.org/releases/.
2. Extract it to `C:\Program Files` (the instructions say `C:\` but I prefer
   program files).
    * In my VM it ended up at `C:\Program Files\gradle-6.0.1`.
3. Add the `bin` directory to `PATH`.
    * `C:\Program Files\gradle-6.0.1\bin`

Now `gradle -version` should return something like:

```
gradle -version

------------------------------------------------------------
Gradle 6.0.1
------------------------------------------------------------

Build time:   2019-11-18 20:25:01 UTC
Revision:     fad121066a68c4701acd362daf4287a7c309a0f5

Kotlin:       1.3.50
Groovy:       2.5.8
Ant:          Apache Ant(TM) version 1.10.7 compiled on September 1 2019
JVM:          11.0.5 (AdoptOpenJDK 11.0.5+10)
OS:           Windows 10 10.0 amd64
```

# Setting up Gradle
Create a directory for extension development. In the root of this directory run
the following command:

* `gradle init --type basic`
* Press `Enter` twice to select the default.
* If you are creating an extension with a specific name, customize the project
      name here. You can later change it in `settings.gradle`.

This will create a bunch of directories and files.

## build.gradle
Open `build.gradle` and paste the following.

{{< codecaption title="build.gradle" lang="yaml" >}}
// Apply the Java plugin
apply plugin: 'java'

// Use Maven (because Burp Extender is on Maven)
repositories {
     mavenCentral()
}

dependencies {
    // Add the Burp Extender interface
    compile 'net.portswigger.burp.extender:burp-extender-api:2.1'
}

sourceSets {
    main {
        java {
            // Set the source directory to "src"
            srcDir 'src'
        }
    }
}

// Create a task for bundling all dependencies into a jar file.
task bigJar(type: Jar) {
    baseName = project.name + '-all'
    from { configurations.compile.collect { it.isDirectory() ? it : zipTree(it) } }
    with jar
}
{{< /codecaption >}}

Read the comments inside the file to see what each section does. The most
important section is adding the [Burp Extender interface Maven repository][burp-maven].
This gives us build support and the equally important code completion with
IntelliCode (iT's Ai BaSeD!!1!).

Any extra dependencies are added similar to the Burp extender interface. For
example, [Google's Gson version 2.8.6][gson-maven-link] can be added like
this:

```
dependencies {
    // Add the Burp Extender interface
    compile 'net.portswigger.burp.extender:burp-extender-api:2.1'
    compile 'com.google.code.gson:gson:2.8.6'
}
```

## Gradle Wrapper
The Gradle Wrapper is a way to get reliable builds regardless of the local
Gradle version. Note you need Gradle to install the Wrapper.

If you just want to initiate the Wrapper, you need to have Gradle. Run
`gradle wrapper` in the extension directory. To build the project with the
Wrapper, replace `gradle` in your commands with `gradlew` (*nix) or
`gradlew.bat` (Windows). For example, `gradlew.bat build`.

# Creating a Skeleton Extension

1. Create the `src\burp` directory. This directory will contain the `burp`
   package.
    * All packages will be under `src`.
2. In `src\burp` create a file named `BurpExtender.java`.
    * This file will be the extension's entry point.
    {{< imgcap title="Extension directory at this step" src="01-burpextender.png" >}}
3. Edit `BurpExtender.java` and add this code.

{{< codecaption title="BurpExtender.java" lang="java" >}}
package burp;

public class BurpExtender implements IBurpExtender
{
    //
    // implement IBurpExtender
    //
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        // set our extension name
        callbacks.setExtensionName("Burp Sample Extension Java");
    }
}
{{< /codecaption >}}

Note: If your extension only has one package (or a few files), you can put all
your files inside `src` directly.

# Setting up VS Code Tasks
To make our life easier, we are going to assign the `bigJar` Gradle task to the
default build task in VS Code. This is important if your extension uses non-Burp
dependencies (like `gson` above). In this case you need to publish this
jar file.

1. Press `Ctrl+Shift+P` or `F1` to open the VS Code command palette.
2. Type `task` and select `Configure Default Build Task`.
3. Select `Create tasks.json file from template`.
4. Select `Others`.
    1. VS Code will create the `.vscode\tasks.json` file.
5. Open `.vscode\tasks.json` and paste the following in it:

{{< codecaption title="tasks.json" lang="json" >}}
{
    // See https://go.microsoft.com/fwlink/?LinkId=733558
    // for the documentation about the tasks.json format
    "version": "2.0.0",
    "tasks": [
        {
            "label": "gradle",
            "type": "shell",
            "command": "gradle bigjar",
            // "command": "gradlew.bat bigjar", // Wrapper on Windows
            // "command": "gradlew bigjar",     // Wrapper on *nix
            "group": {
                "kind": "build",
                "isDefault": true
            }
        }
    ]
}
{{< /codecaption >}}

Now we can build our project with:

1. Pressing `Ctrl+Shift+B`. **Recommended**, it's faster and looks 1337.
2. `Terminal (menu) > Run Task (sub menu) > gradle`.
3. Opening the command palette, typing `tasks` then selecting `Run Build Task`.

Run it once to download the Burp Extender interface and build the library. The
output jar will be in `build\libs\burp-sample-extension-java-all.jar`.

# Setting Up IntelliCode
Our build works but You might have noticed that VS Code does not recognize
imported interfaces from the `burp` package.

{{< imgcap title="VS Code errors" src="02-vscode-error.png" >}}

Every time, a new dependency is added (or we get the same error again), we need
to clean the Java language server.

1. Open the VS Code command palette with `Ctrl+Shift+P` or `F1`.
2. Type `java clean` and select `Java Clean the Java language server workspace`.
3. Restart VS Code when asked.
4. Now we have IntelliCode support.

{{< imgcap title="IntelliCode support" src="03-intellicode.png" >}}

**Note:** This is the solution to most `vscode-java` extension problems.

# Burp Setup
Let's add some code to the extension to show how I test the extension after
each build.

Modify `BurpExtender.java`. See how IntelliCode is making our life easier.

{{< imgcap title="IntelliCode in action, woot!" src="04-intellicode2.gif" >}}

{{< codecaption title="BurpExtender.java" lang="java" >}}
package burp;

public class BurpExtender implements IBurpExtender
{
    //
    // implement IBurpExtender
    //
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        // set our extension name
        callbacks.setExtensionName("Burp Sample Extension Java");
        String fileName = callbacks.getExtensionFilename();
        callbacks.printOutput(fileName);
    }
}
{{< /codecaption >}}

This code prints the extension file name to the console. Build the extension
with `Ctrl+Shift+B`.

{{< imgcap title="Extension built" src="05-build.png" >}}

The jar file will appear in `build\libs`.

{{< imgcap title="Built jar" src="06-built-jar.png" >}}

Visual setup:

1. Start Burp in a second monitor.
2. Detach the `Extender` window via `Window (menu) > Detach Extender`.
3. Press `Windows+Left Arrow` to send it to the corner of the screen.
4. Windows will show a list of other processes and ask me to select the other
   window in that screen.
5. Choose Burp so the Extender and Burp appear side by side in the second
   screen.
6. Grab the border between these two windows to adjust their sizes.

My extension development cycle is:

1. Edit code in monitor 1 in VS Code.
2. Press `Ctrl+Shift+B` to build.
3. `Ctrl+Left-Click` on the checkbox in front of the extension in Extender to
   reload it (this is in monitor 2).
4. Use the extension in Burp (monitor 2).

{{< imgcap title="Extension loaded" src="07-run.png" >}}

# Debugging the Extension with VS Code
This is the most important part of this post. I will discuss how I debug
extensions in VS Code. Looking around, I could only find a few references:

* Debugging Burp Extensions by Eric Gruber at https://blog.netspi.com/debugging-burp-extensions/
  shows how to use IntelliJ to debug Burp. It gave me the idea of using jdwp.
* Derek ([@StackCrash][stackcrash-twitter]) in his blog at
  https://www.itsecguy.com/my-first-burp-suite-extension/ mentions that adding
  `burp.StartBurp` to the Run section of the project's properties does the trick.
    * This is consistent with what Dafydd Stuttard says in a
      [Burp support ticket][support-ticket]. "add the Burp JAR file to the
      project as a library, and start Burp by calling its main method in
      burp.StartBurp.main()"

The VS Code Java extension pack comes with a Java debugger. To use it we need to
run Burp with this command-line option:

* `-agentlib:jdwp=transport=dt_socket,address=localhost:8000,server=y,suspend=n`

This will run the debug server at `localhost:8000`. Note that most examples on
the internet run the server with just the port so the server will listen on
`0.0.0.0` which is obviously not good (unless you want to debug from a remote
machine).

Next, we have to run Burp's jar file with the following parameter. Burp's jar
file is at this path in a default installation:

* `C:\Program Files\BurpSuiteCommunity\burpsuite_community.jar`

The complete command:

```
java -agentlib:jdwp=transport=dt_socket,address=localhost:8000,server=y,suspend=n
    -jar "C:\Program Files\BurpSuiteCommunity\burpsuite_community.jar"
```

* **Hint**: Use this as a shortcut so you can always debug Burp in your
  development VM.
* You may get an error about our JDK not being tested with Burp. Ignore it.

## Using Burp's Bundled JRE
You might have seen the `BurpSuiteCommunity.vmoptions` file inside the Burp's
directory. We can add run-time parameters to it. We can enable debugging by
adding the following line to the file:

```
-agentlib:jdwp=transport=dt_socket,address=localhost:8000,server=y,suspend=n
```

Now we can run the `exe` and debug our extensions. I have included a sample 
`.vmoptions` file in the git repository.

Next we have to launch the Java debugger in VS Code and connect to the debug
port. Put a breakpoint on the `callbacks.printOutput(fileName);` line. Then
select `Debug (menu) > Start Debugging` or press `F5`.

This will create the `.vscode\launch.json` file and open it. Paste this code
into it and save:

{{< codecaption title="launch.json" lang="json" >}}
{
    "version": "0.2.0",
    "configurations": [
        {
            "type": "java",
            "name": "BurpExtension",
            "request": "attach",
            "hostName": "localhost",
            "port": 8000 // Change this if you had set a different debug port.
        }
    ]
}
{{< /codecaption >}}

The file is very simple. The only important options are the `hostName` and
`port` which should point to the debug port specified above (`localhost:8000`).

Start debugging again. Windows Firewall dialog might pop-up. If it does and you
are not debugging a remote machine, press cancel. If the debugger times out
while the firewall dialog is active, debug again (`F5`).

After the debugger is attached, reload the extension with `Ctrl+Right-Click`
on the checkbox and see the debugger break.

{{< imgcap title="Achievement unlocked: Debugging in VS Code" src="08-debugging.png" >}}

Pretty nifty and super useful.

# Storing the Extension's Jar in a Different Path
If you look inside the `build` directory, you will see a lot of class files. We
do not want these in our source control. It's wise to add the `build` directory
to the `.gitignore` file. But this means our final jar file is also ignored and
we want our final jar file in the repository so people can just grab it and use
it.

We can change the location of the extension's jar file by modifying the
`libsDirName` property in `build.gradle`.

```
libsDirName = "../@jar"
```

This config copy the final jar file to
`@jar\burp-sample-extension-java-all.jar`.

# What Did We Learn Here Today?

1. Create a simple Burp extension in Java.
2. Setup Gradle and build the extension.
3. Enable Java IntelliCode in VS Code.
4. Debug Java Burp extensions in VS Code.
5. Change the location of the final jar file.

<!-- Links -->
[imsgeditor-doc]: https://portswigger.net/burp/extender/api/burp/IMessageEditor.html
[vscode-url]: https://code.visualstudio.com/
[java-extension-pack]: https://marketplace.visualstudio.com/items?itemName=vscjava.vscode-java-pack
[gradle-website]: https://gradle.org
[burp-maven]: https://mvnrepository.com/artifact/net.portswigger.burp.extender/burp-extender-api/2.1
[stackcrash-twitter]: https://twitter.com/StackCrash
[support-ticket]: https://support.portswigger.net/customer/portal/questions/16709362-debug-java-project
[gson-maven-link]: https://mvnrepository.com/artifact/com.google.code.gson/gson/2.8.6
