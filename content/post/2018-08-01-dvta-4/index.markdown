---
title: "DVTA - Part 4 - Traffic Tampering with dnSpy"
date: 2018-08-02T19:41:54-04:00
draft: false
toc: true
comments: true
twitterImage: 16.png
categories:
- Reverse Engineering
- DVTA
tags:
- dnSpy
---

After doing network recon in part three, it's time to do some traffic manipulation. We will learn how to capture and modify network traffic using dnSpy. This is much easier than trying to intercept and modify traffic after it's transmitted.

Previous parts are at:

* [DVTA - Part 1 - Setup]({{< relref "post/2018-07-15-dvta-1/index.markdown" >}} "DVTA - Part 1 - Setup")
* [DVTA - Part 2 - Cert Pinning and Login Button]({{< relref "post/2018-07-21-dvta-2/index.markdown" >}} "DVTA - Part 2 - Cert Pinning and Login Button")
* [DVTA - Part 3 - Network Recon]({{< relref "post/2018-07-30-dvta-3/index.markdown" >}} "DVTA - Part 3 - Network Recon")

<!--more-->

# General Traffic Manipulation Intro
Previously we used Wireshark to capture network traffic. Passive sniffing is usually easy but only useful to a degree. If the application was using TLS, we would have seen garbage after the TLS handshake [^1]. In these cases, Man-in-the-Middling (MitM-ing) the traffic with a proxy tool (e.g. Burp) is usually the way to go. But that introduces new challenges.

1. Redirecting the traffic to the proxy.
2. Masquerading as the server (e.g. make client accept our proxy's certificate instead of server).
3. Modifying packets.

I will need a lot of pages to talk about these and document what I have learned through the years. This is not the place for it.

Depending on the interception method, you can bypass some of these challenges. For example, by hooking application's function calls that send the data, you can omit the first two (traffic redirection and server emulation). This is exactly what we are going to do to manipulate traffic in two ways:

1. Debugging with dnSpy - this part.
2. Hooking with WinAppDbg - next part.

# Debugging with dnSpy
My first interaction with dnSpy was when version 1 was released. I used it to modify the outgoing traffic and make myself admin. It was one of my first thick client tests and I was so proud of myself. We are going to do the same here. We will debug the application with dnSpy and then view/modify the outgoing data. We need to:

1. Identify the function/code where data is assembled before transmission.
2. Set a breakpoint.
3. Debug the application with dnSpy.
4. Use the application.
5. Modify the traffic when the breakpoint is triggered.
6. ???
7. Profit.

Putting a breakpoint where the traffic is being transmitted is also viable in some use-cases. But in this case with the direct connection to MSSQL server, we want to manipulate queries.

## Login
We will start with the login request. We already know where it happens but let's pretend we do not[^2]. Drag and drop `dvta.exe` into dnSpy. Then click on `Start`. Note the dialog box allows you to enter command line parameters and set initial breakpoints. None is needed in our case so we will just press `Ok`.

{{< imgcap title="Starting the application with dnSpy" src="01.png" >}}

The anti-debug does not get triggered. We could have easily removed it anyway. Fetch the login token and try to login with dummy credentials. After it fails, do not close the `Invalid Login` button.

In dnSpy click on the pause button (tooltip says `Break All`).

{{< imgcap title="\"Break All\" button" src="02.png" >}}

We break in `System.Windows.Forms.dll > MessageBox`.

{{< imgcap title="MessageBox break" src="03.png" >}}

This is a system DLL and not part of the application. Time for another useful dnSpy feature. Use `Debug (menu) > Windows > Call Stack` or `Ctrl+Alt+C`.

{{< imgcap title="Viewing call Stack" src="04.png" >}}

Call stack allows us to see how we got here.

{{< imgcap title="Call stack displayed in dnSpy" src="05.png" >}}

`Login.btnLogin_Click` is in the call chain. We can double-click on it to get to the code.

{{< imgcap title="btnLogin_Click" src="06.png" >}}

Username and password are passed to `db.checkLogin`. Click on it:

{{< codecaption title="db.checkLogin" lang="csharp" >}}
// Token: 0x06000003 RID: 3 RVA: 0x00002204 File Offset: 0x00000404
public SqlDataReader checkLogin(string clientusername, string clientpassword)
{
    string text = string.Concat(new string[]
    {
        "SELECT * FROM users where username='",
        clientusername,
        "' and password='",
        clientpassword,
        "'"
    });
    Console.WriteLine(text);
    return new SqlCommand(text, this.conn).ExecuteReader();
}
{{< /codecaption >}}

Query is created in a way that is vulnerable to SQL injection (but we were expecting that in a damn vulnerable application). Put a breakpoint here to see the query in action.

Right-click on the `string text =` line and select `Add Breakpoint` or click on the grey edge to the left of the line number (where the red circle is in the following image):

{{< imgcap title="Breakpoint set" src="07.png" >}}

Click on `Continue` and try to login again. The breakpoint will get triggered. Close the call stack window and you should see a new window named `Locals`. This window is used to view and modify the value of variables in scope.

{{< imgcap title="Breakpoint triggered" src="08.png" >}}

Like any other debugger, we can `Step Into`, `Step Over`, and the rest of the usual control. You can navigate with the shortcut keys or the buttons to the right of `Start/Continue`. Press `F10` or `Step Over` to get to the next decompiled instruction which is `Console.WriteLine(text);`.

{{< imgcap title="text cannot be modified" src="09.png" >}}

We have a problem inside dnSpy. We cannot modify the value of `text`. The [cs0103](https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/compiler-messages/cs0103) error means variable does not exist (e.g. not in scope). I am not sure why this is happening but we can modify the value in a different place. Set a breakpoint on `return new SqlCommand ...` and click `Continue`.

{{< imgcap title="Breakpoint at return triggered" src="10.png" >}}

### Bypassing Login
This time, we want to jump inside the function call. Click `Step Into`.

{{< imgcap title="Inside SqlCommand constructor" src="11.png" >}}

Here we can modify the value of the query. Double-click on the value in the `Locals` window and type the following (don't forget the double quotes because we are modifying a string):

* `"SELECT * FROM users where username='admin'"`

Then press `Enter` and notice the modified value is highlighted:

{{< imgcap title="SQL query modified" src="12.png" >}}

Press `Continue` and let this query run. We are logged in as admin.

{{< imgcap title="Logged in as admin" src="13.png" >}}

Note that we can change this query to anything we want (e.g. `INSERT` or `DELETE`).

## Register
Messing with the register function is similar. Run the application with dnSpy and attempt to register any user. Do not close the message box and stop dnSpy with `Break All` like we saw before.

{{< imgcap title="dnSpy after Break All" src="14.png" >}}

Next, use the call stack to discover where it was called.

{{< imgcap title="btnReg_Click" src="15.png" >}}

Click on `RegisterUser` in line 64 `if (dbaccessClass.RegisterUser(username, password, email))` to see the query being created. Set a breakpoint on line 93 `cmd.ExecuteNonQuery();` and press `Continue`.

{{< imgcap title="RegisterUser" src="16.png" >}}

### Registering Admins
New users cannot be admin. The admin account is hardcoded. We can bypass this restriction and register a new admin.

Try to register again. When the breakpoint is reached, expand the `cmd` object in the `Locals` window to see the `CommandText`:

{{< imgcap title="Register user SQL statement" src="17.png" >}}

The statement looks like this:

* `"insert into users values('user2','pass2','user2@example.com','0')"`

We already know the last value is `isAdmin`. We can modify this to create a new admin.

{{< imgcap title="Modified register payload" src="18.png" >}}

Press `Continue` and login as admin with `user2:pass2`.

{{< imgcap title="New admin user in the database" src="19.png" >}}

**Note**: We could have done this in different ways. Another way (because in the real world you are not usually creating queries client-side and contacting the DB directly), was to put a breakpoint where the SQL statement is created and flip the value of `isadmin` to `1`.

## Grabbing the Database Credentials
Database credentials are hardcoded in the application. It's very easy to see them using dnSpy.

We already know where the SQL queries are created. Go back to the `cmd.ExecuteNonQuery()` line from last section. Run the application again and try to register a user. We want the breakpoint to be reached.

After the breakpoint is triggered, open the `Locals` window and expand `this`. We can see a variable called `decryptedDBPassword` with value `p@ssw0rd`. This means the password was stored in some encrypted format. In future sections we will return to figure out how it's encrypted.

{{< imgcap title="DB password" src="20.png" >}}

To see the complete connection string, expand `conn` and scroll down to `_connectionString`:

{{< imgcap title="Connection string" src="21.png" >}}

# Conclusion
In this part, we learned how to debug with dnSpy. We used our new power to manipulate the outgoing traffic, made ourselves admin, and managed to discover the database credentials.

In next part, we will use WinAppDbg to hook function calls and intercept/modify traffic. To get started see my WinAppDbg posts:

* https://parsiya.net/categories/winappdbg/

<!-- Footnote -->
[^1]: Same with any other sort of encryption, but those are rare these days.
[^2]: By now you should know this pattern. I use it to show new ways of doing things. If it gets boring, feel free to skip but I hope you will read and learn something new.
