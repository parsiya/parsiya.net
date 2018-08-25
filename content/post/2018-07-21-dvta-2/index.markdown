---
title: "DVTA - Part 2 - Cert Pinning and Login Button"
date: 2018-07-21T01:38:50-04:00
draft: false
toc: true
comments: true
twitterImage: 09.png
categories:
- Reverse Engineering
- DVTA
tags:
- dnSpy
---

After setting up the Damn Vulnerable Thick Client Application, we are now ready to hack it.

In this section, we will bypass the certificate pinning, enable the login button, learn how to modify the code in dnSpy through writing C# code and get a quick intro to Common Intermediate Language (CIL).

You can see previous parts here:

* [Damn Vulnerable Thick Client Application - Part 1 - Setup]({{< relref "post/2018-07-15-dvta-1/index.markdown" >}} "DVTA - Part 1 - Setup")

<!--more-->

# Disabled Login Button
Let's start with the `Release` binary. First we need to go back and "fix" the FTP address like previous part. Now we can start the application and we can see the login button is disabled.

Maybe it's enabled when you enter the username and password like some applications/websites. No, it seems it's disabled by default. Register button is working.

It's time for dnSpy again. Make a copy of the modified binary and drop it into dnSpy.

We want to enable the login button. Our best guess is to navigate to `DVTA > Login`. One of the methods is the `btnLogin_Click`. By now you have figured out the login button is probably named `btnlogin` but let's assume we do not know that. We need to hunt down button name button in the method.

{{< imgcap title="Login button method and name in dnSpy" src="img/01.png" >}}

Right-click on the method and select `Analyze`, I cannot emphasize how useful this functionality is. We can list where this method is used and what it uses.

{{< imgcap title="Tracing btnLogin_Click" src="img/02.png" >}}

Clicking on `Login.InitializeComponent` brings us to a page where we can see login button's properties. This line shows where the method is assigned to the button object.

{{< imgcap title="Setting btnlogin properties" src="img/03.png" >}}

A few lines before, we can see the line that disabled the button. We can use dnSpy to enable it. At work, I would have enabled it and moved on but we are here to learn. I think there's more to the button than just this workaround. We must detect where the button is enabled to bypass that control.

Right click `btnLogin` and select `Analyze`, then open `Read By` to see `Login.button1_Click`.

{{< imgcap title="Hunting btnlogin" src="img/04.png" >}}

It's enabled in `button1_Click`. It's not hard to guess that `button1` is the `Fetch Login Token` button on the login page (this another one of protections added in this fork). Look at the decompiled code:

{{< codecaption title="button1_Click" lang="csharp" >}}
// Token: 0x0600001C RID: 28 RVA: 0x00002FBC File Offset: 0x000011BC
private void button1_Click(object sender, EventArgs e)
{
    this.checforDebuggers();
    ServicePointManager.ServerCertificateValidationCallback =
        new RemoteCertificateValidationCallback(Login.PinPublicKey);
    WebResponse timeResp = WebRequest.Create("https://time.is/Singapore").GetResponse();
    this.label1.Text = Convert.ToString(timeResp.ContentLength);
    if (timeResp.ContentLength < 143L)
    {
        this.isLoginAllowed = true;
        this.btnlogin.Enabled = true;
    }
    timeResp.Close();
}
{{< /codecaption >}}

The code is readable without needing to know C#.

First we call `checforDebuggers()` which looks like is checking for debuggers. Click to see its code:

{{< codecaption title="checkforDebuggers()" lang="csharp" >}}
private void checforDebuggers()
{
    if (Debugger.IsAttached)
    {
        Environment.Exit(1);
    }
}
{{< /codecaption >}}

Looks like a simple anti-debug measure. Later we will see if we can trigger it by running the application through dnSpy.

# Certificate Pinning Bypass
Our next hurdle is certificate pinning. A simple description of certificate pinning is "looking for a specific certificate instead of any valid one." In other words, you look for a specific property in the certificate and not just its validity. This property could anything in the certificate like issuer or public key.

I had never seen this C# methods before, but based on the name we can find out it's a callback to validate the certificate. The callback is trying to pin the public key of the certificate for `https://time.is`. This is the place where we encounter an error when we press the `Fetch Login Token` button.

{{< codecaption title="Error after pressing the \"Fetch Login Token\" button" lang="csharp" >}}
************** Exception Text **************
System.Net.WebException: The underlying connection was closed:
 Could not establish trust relationship for the SSL/TLS secure channel.
 ---> System.Security.Authentication.AuthenticationException:
 The remote certificate is invalid according to the validation procedure.
...
{{< /codecaption >}}

In dnSpy Click on `login.PinPublicKey` to go to the callback method.

{{< codecaption title="login.PinPublicKey method" lang="csharp" >}}
// Token: 0x0600001D RID: 29 RVA: 0x00002113 File Offset: 0x00000313
public static bool PinPublicKey(object sender, X509Certificate certificate,
    X509Chain chain, SslPolicyErrors sslPolicyErrors)
{
    return certificate !=
        null && certificate.GetPublicKeyString().Equals(Login.PUB_KEY);
}
{{< /codecaption >}}

This code is doing public key pinning. Meaning after the application retrieves the certificate from `time.is`, it checks the public key against the hardcoded one in `login.PUB_KEY`. We can disable this check in different ways. To name a few:

1. Enable the login button manually where we saw before.
2. Modify `Login.PinPublicKey` to always return `true`.
3. Modify the value of `login.PUB_KEY` to the public key of current certificate for `https://time.is`.

I am going with method two to demonstrate patching with dnSpy.

## Patching login.PinPublicKey
You should know how to edit the method by now. Edit the method and change the return value to `true`.

{{< imgcap title="Patched login.PinPublicKey" src="img/05.png" >}}

Now we can use the button. Notice how the label changed to a number. But the login button is still not active so there must be a different check.

{{< imgcap title="Certificate Pinning bypassed" src="img/06.png" >}}

# Enabling the Login Button
The login button is still disabled. We need to figure how to enable it.

## Bypassing Response Length check
Let's look at the code again.

{{< codecaption title="Response length check" lang="csharp" >}}
...
WebResponse timeResp = WebRequest.Create("https://time.is/Singapore").GetResponse();
this.label1.Text = Convert.ToString(timeResp.ContentLength);
if (timeResp.ContentLength < 143L)
{
    this.isLoginAllowed = true;
    this.btnlogin.Enabled = true;
}
...
{{< /codecaption >}}

After login, `label` is replaced with response length. This length is checked against `143` in the `if`. In my case, response length was `30500` bytes did not satisfy the condition. We have acquired enough knowledge to easily reverse this check.

{{< imgcap title="Response length check" src="img/07.png" >}}

But this is too easy, let's learn a bit of IL instead.

## What is IL?
IL or CIL stands for Common Intermediate Language. If you are familiar with Java, it's the equivalent of Java bytecode. Both .NET and Java application code is converted to an intermediate language (CIL and bytecode). When it's executed, they are converted to native instructions these instructions of the target machine (based on OS and Architecture). This is the secret to their portability and why we can decompile the intermediate code back to almost the same source code.

CIL is a stack based assembly language. Meaning values are pushed to the stack before functions are called. It's much easier to read (and learn) than traditional assembly languages (e.g. x86 with its variable length instructions).

## Patching IL with dnSpy
Right-click on the `if (timeResp.ContentLength < 143L)` line and select `Edit IL Instructions...`. A new page pops up with five instructions highlighted. These instructions implement that `if`.

{{< imgcap title="IL instructions for the condition" src="img/08.png" >}}

{{< codecaption title="IL instructions for if" lang="nasm" >}}
003D	ldloc.0
003E	callvirt	instance int64
            [System]System.Net.WebResponse::get_ContentLength()
0043	ldc.i4	    0x8F
0048	conv.i8
0049	bge.s	    28 (005E) ldloc.0 
{{< /codecaption >}}

We can search for each instruction to see what it does. I used this as reference: https://en.wikipedia.org/wiki/List_of_CIL_instructions.

* `ldloc.0`: push 0 to stack.
* `callvirt`: call `get_ContentLength` (the getter for `ContentLength`).
* `ldc.i4 0x8F`: push `0x8F == 143` to stack as int32.
* `conv.i8`: convert top item on stack (`143`) to int64 and store it on stack again.
* `bge.s`: pop value1 and value2 from stack, branch if value1>value2. In this case branch if `143` is more than `ContentLength`.

If you have seen traditional Assembly patching, you already know we just need/want to modify `bge.s` to `ble.s`. Similar to patching a `JNE` (Jump Not Equal) to `JE` (Jump Equal).

See more info about `bge.s` on MSDN:

* https://msdn.microsoft.com/en-us/library/system.reflection.emit.opcodes.bge_s(v=vs.110).aspx#Anchor_1

Click on `bge.s` and see how dnSpy helps us with providing a list of IL instructions.

{{< imgcap title="dnSpy's list of IL instructions" src="img/09.png" >}}

Select `ble.s` and close the IL window. See decompiled C# code is now modified.

{{< imgcap title="Modified C# code after IL patching" src="img/10.png" >}}

Save the patched executable and try again. Login button is now enabled. Now we can login normally.

{{< imgcap title="Login button enabled" src="img/11.png" >}}

# Conclusion
In this part we learned how to use the very very useful `Analyze` feature of dnSpy. We did a bit of normal patching and finally learned a bit of IL assembly. In next part we will start with network traffic and do a bit of proxying.

While waiting, you can my other blog posts on thick client proxying at:

* https://parsiya.net/categories/thick-client-proxying/