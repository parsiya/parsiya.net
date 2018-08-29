---
title: "DVTA - Part 5 - Client-side Storage and DLL Hijacking"
date: 2018-08-25T13:49:10-04:00
draft: false
toc: false
comments: true
twitterImage: img/15.png
categories:
- Reverse Engineering
- DVTA
tags:
- dnSpy
---

Thick clients store ample information on the device. In this part, we are going to investigate DVTA to see what, how, and where it stores data. We are also going to do some basic DLL hijacking. Our tools are procmon, PowerSploit, and dnSpy.

Previous parts are at:

* [DVTA - Part 1 - Setup]({{< relref "/post/2018-07-15-dvta-1/index.markdown" >}} "DVTA - Part 1 - Setup")
* [DVTA - Part 2 - Cert Pinning and Login Button]({{< relref "/post/2018-07-21-dvta-2/index.markdown" >}} "DVTA - Part 2 - Cert Pinning and Login Button")
* [DVTA - Part 3 - Network Recon]({{< relref "/post/2018-07-30-dvta-3/index.markdown" >}} "DVTA - Part 3 - Network Recon")
* [DVTA - Part 4 - Traffic Tampering with dnSpy]({{< relref "/post/2018-08-01-dvta-4/index.markdown" >}} "DVTA - Part 4 - Traffic Tampering with dnSpy")

<!--more-->

# Grabbing Database Credentials via Static Analysis
In [Part 4]({{< relref "post/2018-08-01-dvta-4/index.markdown#grabbing-the-database-credentials" >}} "Part 4 - Grabbing the Database Credentials") we discovered the MSSQL credentials through dynamic analysis with dnSpy. The credentials are `admin:p@ssw0rd`. This time we are going to see where they are stored and how.

Open up dnSpy and load the application. Search for the `RegisterUser` method (if the search is not successful manually drag and drop `DBAccess.dll`). Right-click on the `RegisterUser` method and select `Analyze`. Note we are not in the main application anymore but inside `DBAccess.dll`. Under `Used By` we can see `btnReg_Click`.

{{< imgcap title="Tracing RegisterUser" src="img/01.png" >}}

Inside `btnReg_Click` the connection is being created:

{{< imgcap title="Inside btnReg_Click" src="img/02.png" >}}

Double-clicking on `openConnection` takes us to the method that establishes the connection.

{{< imgcap title="openConnection method" src="img/03.png" >}}

The application is reading some information from `ConfigurationManager.AppSettings`. This information comes from the `AppSettings` tag in the configuration file. If the application is named `myFancyApp.exe` then the configuration file is usually named `myFancyApp.exe.config`. 

I have written about configuration files before in context of proxying. More background material here:

* [Thick Client Proxying - Part 7 - Proxying .NET Applications via Config File]({{< relref "post/2017-10-07-thick-client-proxying-7-proxying-dotNet-applications.markdown" >}} "Thick Client Proxying - Part 7 - Proxying .NET Applications via Config File").

Open the configuration file `dvta-master\DVTA\DVTA\bin\Release\DVTA.exe.config` and look inside. It's an XML file with an `appSettings` section:

``` xml
<appSettings>
    <add key="DBSERVER" value="127.0.0.1\SQLEXPRESS" />
    <add key="DBNAME" value="DVTA" />
    <add key="DBUSERNAME" value="sa" />
    <add key="DBPASSWORD" value="CTsvjZ0jQghXYWbSRcPxpQ==" />
    <add key="AESKEY" value="J8gLXc454o5tW2HEF7HahcXPufj9v8k8" />
    <add key="IV" value="fq20T0gMnXa6g0l4" />
    <add key="ClientSettingsProvider.ServiceUri" value="" />
</appSettings>
```

As you can guess, `DBPASSWORD` is base64 encoded and encrypted. We can decrypt it with this program on Go playground: https://play.golang.org/p/7Vjw2Asr4Lo.

``` go
package main

import (
	"fmt"
	"crypto/aes"
	"encoding/base64"
	"crypto/cipher"
)

func main() {
	dbPassword, err := base64.StdEncoding.DecodeString("CTsvjZ0jQghXYWbSRcPxpQ==")
	if err != nil {
		panic(err)
	}
	aesKey := []byte("J8gLXc454o5tW2HEF7HahcXPufj9v8k8")
	iv := []byte("fq20T0gMnXa6g0l4")


	cb, err := aes.NewCipher(aesKey)
	if err != nil {
		panic(err)
	}
	mode := cipher.NewCBCDecrypter(cb, iv)
	
	dec := make([]byte, len(dbPassword))
	mode.CryptBlocks(dec, dbPassword)
	
	fmt.Printf("% x\n", dec)
	fmt.Printf("%s", dec)
}
```

Result is (note the [PKCS#7](https://tools.ietf.org/html/rfc5652#section-6.3) padding):

```
70 40 73 73 77 30 72 64 08 08 08 08 08 08 08 08
p@ssw0rd
```

If we did not know the algorithm, we had to investigate in dnSpy. Click on `decryptPassword`:

``` csharp
public string decryptPassword()
{
    string s = ConfigurationManager.AppSettings["DBPASSWORD"].ToString();
    string key = ConfigurationManager.AppSettings["AESKEY"].ToString();
    string IV = ConfigurationManager.AppSettings["IV"].ToString();
    byte[] encryptedBytes = Convert.FromBase64String(s);
    AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
    aes.BlockSize = 128;
    aes.KeySize = 256;
    aes.Key = Encoding.ASCII.GetBytes(key);
    aes.IV = Encoding.ASCII.GetBytes(IV);
    aes.Padding = PaddingMode.PKCS7;
    aes.Mode = CipherMode.CBC;
    byte[] decryptedbytes = aes.CreateDecryptor(aes.Key, aes.IV).TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
    this.decryptedDBPassword = Encoding.ASCII.GetString(decryptedbytes);
    Console.WriteLine(this.decryptedDBPassword);
    return this.decryptedDBPassword;
}
```

Which is similar to what we did. Note it's also printed to console.

# Local File Access
What else is there? Applications usually store information in local files and the registry. We can use procmon to view their filesystem activity. Start procmon and then the application. In procmon, only keep the `Process Name is dvta.exe` filter and remove our previous ones. Then use the menu buttons to only `Show File System Activity`. It's beside the `Network Activity` button that we used before.

{{< imgcap title="Enabling Network Activity" src="img/04.png" >}}

procmon displays files accessed by the application:

{{< imgcap title="Reading the config file" src="img/05.png" >}}

To reduce clutter, you can add filters and exclude paths.

Play with the application and sign-in with a few different users, Unfortunately it seems like the application does not store any information in local files. However, do not close procmon because we are going to do some DLL hijacking.

# DLL Hijacking
There are a lot of articles that explain it much better than me so I am going to do a short description and then link to resources. DLL hijacking happens when the application is looking for a DLL not via an absolute path. This means Windows will search for the DLL is specific paths starting with the root directory of the application. If it's not found in one, it will move on to the other. If attackers have write access to one of those paths (that is higher on the search hierarchy than where the actual DLL is), they can put a malicious DLL there and effectively take control of the application.

Some links from Microsoft:

* Search order for desktop applications: https://docs.microsoft.com/en-us/windows/desktop/dlls/dynamic-link-library-search-order#search-order-for-desktop-applications
* Dynamic link library security: https://docs.microsoft.com/en-us/windows/desktop/dlls/dynamic-link-library-security

You can find so many more with a search.

## Step 1: Identifying DLLs
First, we need to figure out which DLLs are vulnerable to hijacking. I am going to show two ways.

### Procmon
To discover DLL hijacking entry points, we can use procmon. Add these filters:

* `Process Name contains DVTA`
* `Result is NAME NOT FOUND`
* (optional) `Path ends with dll`

{{< imgcap title="Procmon filters for DLL hijacking" src="img/06.png" >}}

A lot of results pop up:

{{< imgcap title="NAME NOT FOUND results" src="img/07.png" >}}

The application is looking for these DLLs in the current directory (or other paths) and cannot find them. This means, Windows will search for these DLLs on the machine according to the search order.

### Find-ProcessDLLHijack from PowerSploit
[PowerSploit](https://github.com/PowerShellMafia/PowerSploit) also has utilities for identifying (and performing) DLL hijacking.

To install PowerSploit:

1. Clone the repository (or download it as a zip file) at https://github.com/PowerShellMafia/PowerSploit.
2. Copy the directory to `C:\Users\IEUser\Documents\WindowsPowerShell\Modules` where `IEUser` is the current user.
3. Open a PowerShell prompt as admin.
4. Run `Set-ExecutionPolicy bypass`. This will disable all the warnings. You are running in a VM right?
5. Open a new PowerShell prompt and run `Import-Module PowerSploit`.
6. ???
7. Profit.

Run the application and execute the following PowerShell command (we have auto-complete):

* `Find-ProcessDLLHijack DVTA-v3 | Format-List`

I have patched the utility three times, so my executable is named `DVTA-v3`. Replace it with your process name.

{{< imgcap title="Hijackable DLLs according to PowerSploit" src="img/08.png" >}}

## Step 2: Checking Write Permissions
Without write access to somewhere high enough in the search path to replace the DLL, we cannot do anything. In our sample setup, this is not a problem because we most likely have admin on the machine. In the real world, be sure to check ACLs for write access.

There are also other paths, `Find-PathDLLHijack` can identify them.

{{< imgcap title="Paths with Write Access" src="img/09.png" >}}

## Step 3: Deploying the Malicious DLL
Now we need to write it to the path identified in the previous section with `Write-HijackDll`. I chose `VERSION.dll`.

We can deploy with PowerSploit using `Write-HijackDll`. It creates a bat file, runs the command in it and deletes itself. We can specify the bat file path with `-BatPath` and the command with `-Command`:

* `Write-HijackDll -BatPath b.bat -Command "copy NUL testfile.txt"`

{{< imgcap title="Deploying the DLL with Wire-HijackDll" src="img/13.png" >}}

We run the application and nothing happens. Why? Let's investigate with procmon.

Disable the `NAME NOT FOUND` filter and add a new filter `Path contains version.dll`.

{{< imgcap title="Path contains version.dll filter" src="img/11.png" >}}

Which shows us that `version.dll` was found in `System32`. Our malicious DLL was not high enough on the DLL search order hierarchy.

{{< imgcap title="version.dll found in System32" src="img/12.png" >}}

We need to deploy the DLL to the application directory. I also learned another lesson, either store the bat file in the same directory as the DLL or provide the full path when running `Write-HijackDll`. This time I also changed the payload to pop `calc.exe`.

{{< imgcap title="Running Write-HijackDll again" src="img/14.png" >}}

And run the application again.

{{< imgcap title="Calc executed" src="img/15.png" >}}

# Registry Hives
Registry hives are also popular places for storing information. Procmon allows us to monitor registry activity too. Run procmon and keep the `Process Name contains dvta` filter. Disable all other filters from before. Enable registry activity with the `Show Registry Activity` button. It is to the left of the file activity one.

{{< imgcap title="Show registry activity button" src="img/16.png" >}}

Run the application and see the registry keys that are accessed.

{{< imgcap title="Registry activity in procmon" src="img/17.png" >}}

But this is too much, we only want to see what registry keys are created or modified. Add a new filter `Operation is RegSetValue` (you can also add `RegCreateKey`). Login to the application and see the important events roll in.

{{< imgcap title="Registry keys modified by the app" src="img/18.png" >}}

The application writes password and other information to the registry at `HKCU\dvta`. These keys are also not erased when the user exits.

{{< imgcap title="DVTA registry keys" src="img/19.png" >}}

# Conclusion
That was it for part five. We learned how to look at client-side storage, trace registry activity, and did a bit of DLL hijacking. At this point I think I am done with this app. I might have missed some parts.

I hope this helped. Thanks for reading this and if you have any questions/feedback, you know where to find me.