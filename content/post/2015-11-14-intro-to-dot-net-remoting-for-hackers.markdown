---
categories:
- .NET Remoting
- dnSpy
- Reverse Engineering
comments: true
date: 2015-11-14T16:22:36Z
title: Intro to .NET Remoting for Hackers
---

This is a simple tutorial about [.NET Remoting][net-remoting-1]. I am going to re-create a very simple RCE and local privilege escalation that I encountered in my projects and use it to explain .NET Remoting and simple debugging in `dnSpy`.

In this post we will:

1. Do a brief introduction to .NET Remoting
1. Develop a simple .NET Remoting client and a vulnerable server in Visual Studio
2. Observe .NET Remoting traffic
3. See .NET Remoting in action by doing some basic debugging with dnSpy
4. Re-create the vulnerable application
5. Use dnSpy to patch and create modified .NET modules to exploit our sample vulnerable server

If you know of any applications that use .NET Remoting please let me know. I want to look at them.

[net-remoting-1]: https://msdn.microsoft.com/en-us/library/kwdt6w2k%28v=vs.71%29.aspx
<!--more-->

### Table of Contents:

* [0. Ingredients and Setup](#ch0)
* [1. Brief Intro to .NET Remoting](#ch1)
* [2. Developing a .NET Remoting Application](#ch2)
* [3. .NET Remoting Messages](#ch3)
* [4. Debugging with dnSpy](#ch4)
* [5. Re-creating the Vulnerability](#ch5)
* [6. Modifying IL Instructions with dnSpy and Patching Binaries](#ch6)
* [7. Remediation](#ch7)

### <a name="ch0"></a> 0. Ingredients and Setup

* Windows 7 Virtual Machine
* Visual Studio Community 2015: [https://www.visualstudio.com/en-us/products/visual-studio-community-vs.aspx][vs2015]. We only need the C# components which are part of the default installation
* RawCap to capture local traffic
* Wireshark to analyze captured traffic
* [dnSpy (1.4.0.0)][dnspy1.4] to decompile and debug C# code

### <a name="ch1"></a> 1. Brief Intro to .NET Remoting
In simple words, .NET Remoting is a means to achieve InterProcess Communication (IPC). One application (let's call it server) exposes some remotable objects. Other applications (we will call them clients) create an instance of those objects and treat them like local objects. But these local objects will be executed on the server. Usually these remotable objects are in a shared library (e.g. DLL). Both client and server will have a copy of this DLL. .NET Remoting can use TCP, HTTP or named pipes to transfer the remotable objects.

The concept of .NET Remoting is very similar to [Java Remote Method Invocation (Java RMI)][javarmi]. In Java RMI we will see serialized Java objects being passed around and in .NET Remoting we will see .NET objects.

Don't worry if you do not understand parts of it because this was a very short intro. We will see how .NET Remoting works later.

**Note**: .NET Remoting is deprecated and you should not be using it. But who am I kidding? We are all using old technology all the time so we might as well get used to it.

### <a name="ch2"></a> 2. Developing a .NET Remoting Application
I am going to create two version of my simple .NET Remoting applications. Both are very simple. The first application will act as tutorial about how to create a .NET Remoting client/server application and the second aims to re-create a vulnerable server that I encountered in one of my projects.

I am going to be using [Visual Studio Community 2015][vs2015] which is free. We will have three different projects in one solution:

* Remoting Library: A DLL which contains the remotable objects.
* Server
* Client

If you want to play along, Visual Studio solutions are at [https://bitbucket.org/parsiya/net-remoting/src/](https://bitbucket.org/parsiya/net-remoting/src/.). With compiled executables being in the `Executables` directory (keep in mind that these are executables from a stranger on the internet so treat them accordingly).

First the DLL. Create a solution and a new project. Choose `Class Library` as type of the project. According to [this MSDN article][remotableobjects], in order for an object to be remotable it should either be `Serializable` or inherit [`MarshalByRefObject`][marshalbyref] class. I am taking the `MarshalByRefObject` route. For more information please refer to [Making Objects Remotable][makingobjectsremotable].

Here's how the Remoting Library (the DLL) looks like:

{{< codecaption lang="csharp" title="RemotingLibrary.cs" >}}
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RemotingSample
{
  public class RemoteMath : MarshalByRefObject
  {
    public int Add(int a, int b)    // add
    {
      Console.WriteLine("Add({0},{1}) called", a, b);
      return a + b;
    }

    public int Sub(int a, int b)    // subtract
    {
      Console.WriteLine("Sub({0},{1}) called", a, b);
      return a - b;
    }
  }
}
{{< /codecaption >}}

Note that the class `RemoteMath` is derived from `MarshalByRefObject` to make it remotable. We don't need to do anything else with regards to .NET Remoting in this DLL. Each function will print some text when it is called so we can see where the function actually runs.

Create a new project named `Server` and use the following code. The comments should explain what is happening:

{{< codecaption lang="csharp" title="Server.cs" >}}
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.Remoting;
using System.Runtime.Remoting.Channels;
using System.Runtime.Remoting.Channels.Tcp;

namespace RemotingSample
{
  class Server
  {
    static void Main(string[] args)
    {
      // create a TCP channel and bind it to port 8888
      TcpChannel remotingChannel = new TcpChannel(8888);

      // register the channel, the second parameter is ensureSecurity
      // I have set it to false to disable encryption and signing
      // for more information see section Remarks in https://msdn.microsoft.com/en-us/library/ms223155(v=vs.90).aspx
      ChannelServices.RegisterChannel(remotingChannel, false);

      // create a new servicetype of type RemoteMath named "rMath" and of type SingleCall
      // SingleCall: a new object will be created for each call
      // as opposed to WellKnownObjectMode.Singleton where there is one object for all calls (and clients)
      WellKnownServiceTypeEntry remoteObject = new WellKnownServiceTypeEntry(typeof(RemoteMath), "rMath", WellKnownObjectMode.SingleCall);

      // register the remoteObject servicetype
      RemotingConfiguration.RegisterWellKnownServiceType(remoteObject);

      Console.WriteLine("Registered service");
      Console.WriteLine("Press any key to exit");
      Console.ReadLine();
    }
  }
}
{{< /codecaption >}}

We need to add two references to the project using `Project (menu) > Add References`:

1. `System.Runtime.Remoting` assembly
2. Remoting Library project

Server will expose the `RemoteMath` class and wait until a key is pressed. Client can call the functions in `RemoteMath` until the server is terminated.

Client code also needs the same two references. Client calls `Add` and `Sub` and prints the results.

{{< codecaption lang="csharp" title="Client.cs" >}}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.Remoting;
using System.Runtime.Remoting.Channels;
using System.Runtime.Remoting.Channels.Tcp;

namespace RemotingSample
{
  class Client
  {
    static void Main(string[] args)
    {
      // create and register the TCP channel
      // please note that I have set the security of the channel to false
      TcpChannel clientRemotingChannel = new TcpChannel();
      ChannelServices.RegisterChannel(clientRemotingChannel, false);

      // create an object of type RemothMath
      // we have to do a cast because Activator.GetObject returns an object (doh)
      // type is RemoteMath and server address is what we created in Server.cs (port:8888 and rMath)

      // Server.cs code:
      // TcpChannel remotingChannel = new TcpChannel(8888);
      // ChannelServices.RegisterChannel(remotingChannel, false);
      // WellKnownServiceTypeEntry remoteObject = new WellKnownServiceTypeEntry(typeof(RemoteMath), "rMath", WellKnownObjectMode.SingleCall);

      RemoteMath remoteMathObject = (RemoteMath)Activator.GetObject(typeof(RemoteMath), "tcp://localhost:8888/rMath");

      // now we can call Add and Sub functions
      Console.WriteLine("Result of Add(1, 2): {0}", remoteMathObject.Add(1, 2));
      Console.WriteLine("Result of Sub(10, 3): {0}", remoteMathObject.Sub(10, 3));

      Console.WriteLine("Press any key to exit");
      Console.ReadLine();
    }
  }
}
{{< /codecaption >}}

Now we can build the solution. If you look at the resulting executables we will that both client and server have a copy of `RemotingLibrary.dll`.

{% imgcap /images/2015/remoting1/01.png Both Client and Server have the same DLL %}

{{< figure src="/images/2015/remoting1/01.png" title="Both Client and Server have the same DLL" >}}

{{< imgcap caption="Both Client and Server have the same DLL" src="/images/2015/remoting1/01.png" >}}

Now start `RawCap` and capture local traffic.

### <a name="ch3"></a> 3. .NET Remoting Messages

When you initially run the server, it will ask to be added to Windows Firewall's exceptions. You can safely deny that as both client and server are local. This is a major vulnerability in many .NET Remoting applications that work locally (like our example). If we do a `netstat` we can see that server is bound to `0.0.0.0` and is listening on all interfaces. Meaning anyone can connect to the server and execute exposed functions on our computer. We will read more about this later.

{% imgcap /images/2015/remoting1/02.png Server listening on all interfaces %}

Now run both server and client and look at the results.

We can see client calling both functions and printing the result.

{% imgcap /images/2015/remoting1/03.png Client execution %}

We can clearly see that the functions were executed in server's application context because server is printing the verbose messages from `RemotingLibrary.dll`.

{% imgcap /images/2015/remoting1/04.png Server execution %}

If we look at the traffic in Wireshark and filter all traffic to/from port `8888`:

{% imgcap /images/2015/remoting1/05.png .NET Remoting traffic in Wireshark %}

You can read about the format and structure of .NET Remoting packets in the following documents:

* [[MS-NRTP].NET Core Protocol - PDF][msnrtp] or just search for `[MS-NRTP]`.
* [[MS-NRBF] .NET Remoting: Binary Format Data Structure - PDF][msnrbf] or just search for `[MS-NRBF]`.

After the TCP handshake we see the first packet from client to server. According to section `2.2.3.3 Message Frame Structure` of `[MS-NRTP]` every message should start with `ProtocolId` which is 4 bytes and should be `0x54454E2E` or `.NET`.

    2e 4e 45 54 01 00 00 00 00 00 8d 00 00 00 04 00  .NET............
    01 01 1a 00 00 00 74 63 70 3a 2f 2f 6c 6f 63 61  ......tcp://loca
    6c 68 6f 73 74 3a 38 38 38 38 2f 72 4d 61 74 68  lhost:8888/rMath
    06 00 01 01 18 00 00 00 61 70 70 6c 69 63 61 74  ........applicat
    69 6f 6e 2f 6f 63 74 65 74 2d 73 74 72 65 61 6d  ion/octet-stream
    00 00                                            ..

    .NET tcp://localhost:8888/rMath application/octet-stream

    ProtocolId: 0x54454E2E or .NET
    Major version: 0x00
    Minor Version: 0x00
    OperationType: 0x0000 or Request

This is setting up the .NET Remoting channel and specifying the exposed class that it wants to access `rMath`. Next is the second part of the first message.

    00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00  ................
    00 15 12 00 00 00 12 03 41 64 64 12 61 52 65 6d  ........Add.aRem
    6f 74 69 6e 67 53 61 6d 70 6c 65 2e 52 65 6d 6f  otingSample.Remo
    74 65 4d 61 74 68 2c 20 52 65 6d 6f 74 69 6e 67  teMath, Remoting
    4c 69 62 72 61 72 79 2c 20 56 65 72 73 69 6f 6e  Library, Version
    3d 31 2e 30 2e 30 2e 30 2c 20 43 75 6c 74 75 72  =1.0.0.0, Cultur
    65 3d 6e 65 75 74 72 61 6c 2c 20 50 75 62 6c 69  e=neutral, Publi
    63 4b 65 79 54 6f 6b 65 6e 3d 6e 75 6c 6c 02 00  cKeyToken=null..
    00 00 08 01 00 00 00 08 02 00 00 00 0b           .............

    Add RemotingSample.RemoteMath, RemotingLibrary, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null

This is the `Add(1,2)` call. We can see the following in this message:

    RemotingLibrary: DLL containing the exposed class
    RemotingSample.Remotemath: The exposed class
    Add: The function that is called

And if you look closely you can see the `Add` parameters in the last line in little endian (Int32 or 4 bytes).

    01 00 00 00: int a
    02 00 00 00: int b

I don't want to talk about the message structure, just identifying the method, parameters, class and DLL when we see such a packet is enough.

For a very good explanation of all fields using examples please refer to section `4.1 Two-Way Method Invocation Using TCP-Binary` of `[MS-NRTP]`.

Think of the reply as an ACK and like any other .NET Remoting message it starts with `.NET`. According to `[MS-NRTP] Section 2.1.1.1.2 Receiving Reply` "If the OperationType of the message is Request(0), an implementation MUST wait for the Two-Way Reply message in the same connection."

    2e 4e 45 54 01 00 02 00 00 00 1c 00 00 00 00 00 .NET............

    ProtocolId: 0x54454E2E or .NET
    Major version: 0x00
    Minor Version: 0x00
    OperationType: 0x0002 or Response

Then the actual result is sent from server to client.

    00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00  ................
    00 16 11 08 00 00 08 03 00 00 00 0b              ............

We can see the return value (which is again an Int32 and 4 bytes) at the end of the packet prefixed by the same `0x08` byte that we saw before (remember the parameters?), and is `03 00 00 00`.

Messages for `Sub` are very similar. I am not going to talk about them because, ahem `they are left as an exercise for the reader`.

### <a name="ch4"></a> 4. Debugging with dnSpy

In this section, I assume you know basic debugging (e.g. breakpoints, step into/over/out) so I will not go into details. I will mostly just talk about (some of) dnSpy's features.

Run `Server.exe` and then run dnSpy (for x86 application use `dnSpy-x86.exe`). Drag and drop `Client.exe` into it and navigate to `Main`. Notice that dnSpy automatically loads referenced DLLs including `RemotingLibrary.dll`. The decompiled code in dnSpy is the same as our original code but without the comments.

{% imgcap /images/2015/remoting1/06.png Opening Client.exe in dnSpy %}

Now we can run the client in dnSpy. Click on the green button named `Start` and it will open a dialog to start an executable in dnSpy. In version 1.4 it is pre-populated with `Client.exe` that we just dragged and dropped into dnSpy. As you can see, what can also specify arguments and also order the debugger to break on certain events. Let's keep the original selection and run `Client.exe`. dnSpy will break on `Main`.

{% imgcap /images/2015/remoting1/07.png Start options %}

Now we can debug normally using shortcut keys or small button to the right of the `Continue` button (formerly `Start`).

To set a breakpoint, you can either select a line and press `F2`, click on the space left of the line number or right click on the line and select it from the context menu. In this case we put a breakpoint on line `16` or the first `Console.WriteLine`.

{% imgcap /images/2015/remoting1/08.png Breakpoint %}

#### 4.1 Finding Nemo
In this case, we can clearly see the `Add` function and where it is called. But let's assume that we only saw the traffic and opened the binary in dnSpy and didn't know where it is called. Our binary contains tons and tons of imaginary functions that may or may not call `Add`. How do we find `Add`?

From the traffic we know that the function name is `Add` and it is in class `RemotingSample.Remotemath` and resides in `RemotingLibrary.dll`. Using these clues we can easily find the `Add` function in dnSpy.

{% imgcap /images/2015/remoting1/09.png Finding Add %}

Our first instinct would be to put a breakpoint on `Add` and let the client `Continue`. But **this breakpoint will never trigger**. Because in .NET Remoting an instance of the function is created on the client and then executed on the server. If you don't believe me, try it. But how do we find who uses this function?

#### 4.2 Analyze This
Now we can use the `Analyze` feature of dnSpy. Right click on the `Add` function in `RemotingLibrary.dll` and select `Analyze`. Now a very handy new pane (window? seriously what are these called?) named `Analyzer` pops up. We can see the function and two items `Uses` and `Used By`. `Uses` shows us the other functions (in loaded binaries in dnSpy) that are used by `Add` and `Used By` shows other functions that use `Add`.

{% imgcap /images/2015/remoting1/10.png Analyze this %}

That is a very nifty feature, neh? As you can see we can go down the wormhole and follow the chain. In this case we see that the `Main` function calls `Add`. If we double click on `Main` we will go back to the original entry point.

#### 4.3 .NET Remoting in Action
Now we can `Step Into` the line that calls `Add` in the client. If you have not changed the default settings, you should land in `mscorlib.dll` or more exactly in `CommonLanguageRuntimeLibrary.System.Runtime.Remoting.Proxies.RealProxy.PrivateInvoke()`. dnSpy's default settings, will skip all the other code (like attribute get/set etc). You can change this in `View (menu) > Options (menu item) > Debugger (tab) > DebuggerBrowsable` and `Call string-conversion`.

{% imgcap /images/2015/remoting1/11.png Landed in RealProxy %}

In order to see local variables and their values press `Alt+4` to open the `Locals` window. This was changed in version 1.3 and up and is a huge UX upgrade.

{% imgcap /images/2015/remoting1/12.png Meeting the Locals %}

This where we always end up after following .NET Remoting calls; where the message is being sent and we can see its contents. In version 1.3 of dnSpy, any breakpoints set here would not be triggered but now we can do it (what a time to be alive). So you can set a breakpoint on line 404 (if you can find it *he he he*) `RemotingProxy remotingProxy = null;` just right before `if (1 == type)` and look at messages.

`Type == 1` so the first `if` will be true. Let's look at it (with some comments):

{{< codecaption lang="csharp" title="" >}}

if (1 == type)
{
  Message expr_14 = new Message();
  
  // msgData is one of the function parameters (along with type) and contains the message info
  // we can see that it is used to populate expr_14 which looks like a temp Message
  expr_14.InitFields(msgData);
  
  // expr_14 is copied to message
  message = expr_14;			// put a breakpoint here
  
  num = expr_14.GetCallType();
}

{{< /codecaption >}}

Let's put a breakpoint on line `409 num = message = expr_14;` and continue. When we reach this line, we can step over it until we reach line `410` and then see the contents of the variable named `message`. Why didn't we put a breakpoint on the next line? Because if it won't trigger with default settings (remember those debugger settings at the start of this section?). Press `Alt+4` to look at `message`.

{% imgcap /images/2015/remoting1/13.png Contents of variable message %}

We can see the message and a lot of information about it. Scroll down to line `474 RealProxy.HandleReturnMessage(message, message2);` and set a breakpoint on line `475` and `Continue`. We can see that the text in the function is printed on the server and we land in the new breakpoint and can see the return value in `message2`.

{% imgcap /images/2015/remoting1/14.png Return value %}

If we `Step Out` we will land back in `Main`. Try doing the same for the `Sub` function call.

Now we know the places to see the outgoing .NET Remoting message and return values. In a real world project we could do this to look at the messages instead of Wireshark or developing our own .NET Remoting proxy.

### <a name="ch5"></a> 5. Re-creating the Vulnerability

**Note:** Please run this application in a Virtual Machine disconnected from the internet. This application will make your machine vulnerable to unauthenticated RCE. Make sure that Windows firewall is not disabled and do not allow `Server.exe` through it. I believe the chance of someone getting compromised is very very slim because no one reads these posts anyway, but it never hurts to be careful.

One application that I looked at, let's call it `Remoting Expanded` had two components. A server which was run as `SYSTEM` on startup via a Windows service and a client application which was executed by an standard user. Client used .NET Remoting to execute functions in server to perform actions that were not available to standard users. I basically went through the same steps to look at and debug the .NET Remoting calls. I was looking at the decompiled code of the DLL containing the remotable objects and discovered that there are a lot of exposed functions which are not used by the client application. One of them was `StartProcess` (that's not its real name) and executed an executable as SYSTEM.

To re-create we are going to change our code and add a new function to the `RemotingLibrary` DLL. Client and server are not modified but be sure to rebuild the solution to get the new DLL in build directories of client and server projects. I created a new project and called it `RemotingLibraryExpanded`.

{{< codecaption lang="csharp" title="RemotingLibraryExpanded.cs" >}}

namespace RemotingLibraryExpanded
{
  public class RemoteMathExpanded : MarshalByRefObject
  {
    public int Add(int a, int b)    // add
    {
      Console.WriteLine("Add({0},{1}) called", a, b);
      return a + b;
    }

    public int Sub(int a, int b)    // subtract
    {
      Console.WriteLine("Sub({0},{1}) called", a, b);
      return a - b;
    }

    // super secret process start method
    public void StartProcess(string processPath)
    {
      Console.WriteLine("Starting process {0}", processPath);
      Process.Start(processPath);
    }
  }
}

{{< /codecaption >}}

Now we can rebuild the solution. Client and server will run as before now we want to exploit this new method to do local privilege escalation (running the executable of our choice as SYSTEM). At this point we can either write code (which we already did) or modify the client application using dnSpy (and some other tools). I modified the application in my project because it was much easier than writing code from scratch because there were a lot of stuff happening before the client started making calls to server.

### <a name="ch6"></a> 6. Modifying IL Instructions with dnSpy and Patching Binaries
The easiest thing to do is to modify one of the function calls to call `StartProcess` and run an executable (e.g. `C:\Windows\System32\calc.exe`). Open the client in dnSpy and right click on the line that calls `Add` (line 16 in dnSpy). Choose `Edit IL Instructions`.

{% imgcap /images/2015/remoting1/15.png IL instructions %}

What is IL? CIL (Common Intermediate Language) or IL is (almost) the .NET equivalent of Java bytecode. Let's look at what we got and see if we can decipher it (read the comments please):

{{< codecaption lang="csharp" title="IL code for line 16" >}}

// pop remoteMathObject from stack and put it in local variable 1
12	0028	stloc.1

// push the string to stack
13	0029	ldstr	"Result of Add(1, 2): {0}"

// push local variable 1 to stack. In this case, remoteMathObject is pushed to stack
// this is done because we are going to call remoteMathObject.Add
14	002E	ldloc.1

// push the value 0x1 to the stack
// IL has ldc.i4.1 to ldc.i4.8 and also a separate ldc.i4 <Int32> to push Ints to the stack
15	002F	ldc.i4.1

// push the value 0x2 to the stack
16	0030	ldc.i4.2

// call Add
17	0031	callvirt	instance int32 [RemotingLibrary]RemotingSample.RemoteMath::Add(int32, int32)

// box converts a value type to an object reference.
// I assume it means that we are converting the result of add to Int32
18	0036	box	[mscorlib]System.Int32

// call console.writeline (parameters are the format string that was pushed to stack and return value of add)
19	003B	call	void [mscorlib]System.Console::WriteLine(string, object)

{{< /codecaption >}}

Now we have a general idea of what's happening here. We need to change `Add` to `StartProcess`. Click on `Add` and a small context menu pops up.

{% imgcap /images/2015/remoting1/16.png Method context menu %}

Select `Method` and a new page pops up that allows you to modify it to any method in all loaded assemblies. We can see the new fancy `StartProcess` function. So we select that. There's also a handy search feature.

{% imgcap /images/2015/remoting1/17.png Pick a method %}

The method call is changed but `Add` had two Int32 parameters while `StartProcess` has only one string parameter. Without more modifications, two Int32s are pushed to the stack before the new method is being called. If we press OK on the IL code window we will see this monstrosity.

{% imgcap /images/2015/remoting1/18.png You ruined everything!!1! %}

But that's fine, we can edit the IL instructions and fix it. But how do we know what to do? At this point we can just learn IL coding but based on the instructions that we have seen, we should have a general idea of what to do. We also need to remove the `Console.WriteLine` because `StartProcess` has no return value (well `void()` but you know what I mean) and we should be calling `remoteMathObject.StartProcess("c:\\windows\\system32\\calc.exe");` individually.

The following IL code does the trick:

{{< codecaption lang="csharp" title="Fixed IL instructions" >}}

12	0028	stloc.1
13	0029	ldloc.1
14	002A	ldstr	"c:\\windows\\system32\\calc.exe"
15	002F	callvirt	instance void [RemotingLibraryExpanded]RemotingLibraryExpanded.RemoteMathExpanded::StartProcess(string)
16	0034	nop

{{< /codecaption >}}

{% imgcap /images/2015/remoting1/19.png You fixed it!!1! %}

There is another way to do this. Download [LINQPad 5.0][linqpad-dl]. The standard version is free and is more than enough for our purpose. Copy paste all of the code in the client class into it. Now just like in Visual Studio we need to add references and import namespaces.

1. Change the `Language` drop-down list to `C# Program`.
1. Right click and select `References and Properties`.
2. In the `References` tab click `Add` and search for `System.Runtime.Remoting.dll`.
3. Click `Browse` and select `RemotingLibraryExpanded.dll`.
4. Select the `Additional Namespace Imports` tab.
5. Click `Pick from assemblies`.
6. Select `RemotingLibraryExpanded.dll` and add its namespace.
7. Select `System.Runtime.Remoting.dll` and add `System.Runtime.Remoting.Channels` and `System.Runtime.Remoting.Channels.Tcp`.

{% imgcap /images/2015/remoting1/20.png References in LINQPad %}

{% imgcap /images/2015/remoting1/21.png Namespaces in LINQPad %}

Now all of the errors in LINQPad should be gone and we can modify the code. Modify the first `Console.WriteLine` to `StartProcess("c:\\windows\system32\calc.exe")` and press `Execute`. The application may or may not execute properly. It will probably fail because we already have a TCP channel registered but we don't care about that. Click on the `IL` button at the bottom to see the generated IL code which is the same as what we wrote in dnSpy.

{% imgcap /images/2015/remoting1/22.png IL code in LINQPad %}

Now we can save the modified module (in this case a new version of the client executable) using dnSpy. Use `File (menu) > Save Module` to save the new executable (let's call it `Client1.exe`). Run `Client1.exe` and Pew.

{% imgcap /images/2015/remoting1/23.png Pew Pew %}

*How can this be used in local privilege escalation?*  
In the original project, server was running as SYSTEM, which means any standard user could run any binary or command and effectively give themselves admin.

*How does this lead to Remote Code Execution (RCE)?*  
As we saw at the start of this post, server is listening on `0.0.0.0` or all interfaces. This means any attacker can connect to the server and execute arbitrary commands. Windows Firewall will not help if you had added an exception for server when it was initially started.

### <a name="ch7"></a> 7. Remediation
Remediation is an important part of my day job. I am not an `infosec thoughtleader` but I think breaking is worth nothing if we don't want to/cannot talk to and work with the developers to fix things. So I am going to add remediation sections to my posts where appropriate and do my small part in helping. As with any other part of these posts, if you think there is a better way of doing things please let me know.

{% imgcap /images/2015/remoting1/24.jpg [insert reference to Starship Troopers and killing bugs and call yourself a geek] %}

It should be noted that channel properties and registration could also be done in executables' config files. Please refer to [Format for .NET Remoting Configuration Files][channelconfig] for more information.

I also have to reiterate that **this is deprecated technology** and it should not be used for new applications. But if you are stuck with legacy code and want to fix it, please read on.

Start here for MSDN articles on this topic: [Security in Remoting][security-in-remoting].

#### 7.1 RCE
In this scenario we should only be listening on `localhost`. We have to modify the server. If we look at [TcpChannel properties][tcpchannel-properties] we can see there is a `bindTo` property. We can add it to a dictionary and use it in the constructor as follows:

{{< codecaption lang="csharp" title="Binding the server to localhost" >}}

using System.Collections;

IDictionary tcpChannelProperties = new Hashtable();
tcpChannelProperties["port"] = 8888;
tcpChannelProperties["bindTo"] = "127.0.0.1";

TcpChannel remotingChannel = new TcpChannel(tcpChannelProperties, null, null);

// Or in the config file:

<channels>
  <channel ref="tcp" port="8888" bindTo="127.0.0.1" />
</channels>

{{< /codecaption >}}

And now we can see the server listening only on localhost.

{% imgcap /images/2015/remoting1/25.png Server listening on localhost %}

We can also [authenticate the client](https://msdn.microsoft.com/en-us/library/bb187429%28v=vs.85%29.aspx).

#### 7.2 Channel Encryption and Authentication
We can also encrypt the channel. Channels have a `Secure` property that will encrypt the channel if set to `true`. However, **both client and server channels should be set to secure**. We can simply add it to `tcpChannelProperties` in both client and server and set it to `true`:

{{< codecaption lang="csharp" title="Securing the server channel" >}}

using System.Collections;

IDictionary tcpChannelProperties = new Hashtable();
properttcpChannelPropertiesies["port"] = 8888;
tcpChannelProperties["bindTo"] = "127.0.0.1";
tcpChannelProperties["secure"] = true

TcpChannel remotingChannel = new TcpChannel(tcpChannelProperties, null, null);

// Or in the config file:

<channels>
	<channel ref="tcp" port="8888" bindTo="127.0.0.1" secure="true" />
</channels>

{{< /codecaption >}}

Let's only set the server channel to secure and see what happens:

{% imgcap /images/2015/remoting1/26.png Insecure client channel and secure server channel %}

The client establishes the TCP connection and starts sending message in plaintext, but server never responds.

If we modify the client code similar to the server:

{{< codecaption lang="csharp" title="Securing the client channel" >}}

using System.Collections;

IDictionary tcpChannelProperties = new Hashtable();
tcpChannelProperties["secure"] = true;

// Or in the config file:
<channels>
	<channel ref="tcp" secure="true" />
</channels>

{{< /codecaption >}}

Now the channel is encrypted.

{% imgcap /images/2015/remoting1/27.png Encrypted TCP channel %}

The [Encryption and Message Integrity][encryption-and-message-integrity] MSDN article talks about encryption. The `See Also` links at the bottom of the page go to authentication articles. For example [Authentication with the TCP Channel](https://msdn.microsoft.com/en-us/library/59hafwyt%28v=vs.85%29.aspx).

-----

Hopefully this was useful. This will pave the way for another blog post where I talk about an older vulnerability that we will investigate using dnSpy and .NET Remoting. If you have any comments/feedback/corrections/complaints, please let me know; you know where to find me.

<!-- links -->

[net-remoting-1]: https://msdn.microsoft.com/en-us/library/kwdt6w2k%28v=vs.71%29.aspx
[vs2015]: https://www.visualstudio.com/en-us/products/visual-studio-community-vs.aspx
[dnspy1.4]: https://github.com/0xd4d/dnSpy/releases/tag/v1.4.0.0
[javarmi]: http://www.oracle.com/technetwork/java/javase/tech/index-jsp-138781.html
[marshalbyref]: https://msdn.microsoft.com/en-us/library/system.marshalbyrefobject%28v=vs.110%29.aspx
[remotableobjects]: https://msdn.microsoft.com/en-us/library/vstudio/h8f0y3fc%28v=vs.100%29.aspx
[msnrtp]: http://download.microsoft.com/download/9/5/E/95EF66AF-9026-4BB0-A41D-A4F81802D92C/%5BMS-NRTP%5D.pdf
[msnrbf]: http://download.microsoft.com/download/9/5/E/95EF66AF-9026-4BB0-A41D-A4F81802D92C/%5BMS-NRBF%5D.pdf
[linqpad-dl]: https://www.linqpad.net/Download.aspx
[tcpchannel-properties]: https://msdn.microsoft.com/library/bb397830%28v=vs.100%29.aspx
[channelconfig]: https://msdn.microsoft.com/en-us/library/ms973907.aspx
[security-in-remoting]: https://msdn.microsoft.com/en-us/library/9hwst9th%28v=vs.85%29.aspx
[encryption-and-message-integrity]: https://msdn.microsoft.com/en-us/library/k62k71x0%28v=vs.85%29.aspx
[makingobjectsremotable]: https://msdn.microsoft.com/library/wcf3swha%28v=vs.100%29.aspx
