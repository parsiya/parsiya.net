---
categories:
- Burp
- Thick Client Proxying
comments: true
date: 2016-05-15T16:55:24-04:00
draft: false
tags:
- Burp
- FileHippo
- dnSpy
- AWS
- Tutorial
title: "Thick Client Proxying - Part 5: FileHippo App Manager or the Bloated Hippo"
toc: true
---
I have talked a lot about this and that but have done nothing in action. Now I will talk about proxying actual applications. I will start with something easy, the [FileHippo App Manager][filehippo-dl1]. This app was chosen because it can be proxied with Burp, it does not use TLS and it has its own proxy settings (also works with Internet Explorer proxy settings). The requests are pretty simple to understand. I like the FileHippo website because it archives old versions of software. For example I loved the non-bloated Yahoo! Messenger 8.0 when I used it (it's pretty popular in some places) and used FileHippo to download the old versions.

FileHippo App Manager turned out to be more interesting than I thought and this post turned into some .NET reverse engineering using dnSpy. Here's what I talk about in this post:

* The app contains the AWS SDK and a fortunately invalid set of AWS Access/Secret keys. Both the SDK and the keys are in dead code.
* Requests have an `AccessToken` header which is generated client-side. We will discuss how it is generated.
* The application has a "hidden" DEBUG mode which unfortunately does nothing special. We will discover how to enable it.

[filehippo-dl1]: http://filehippo.com/download_app_manager/
<!--more-->

Note: I attempted to contact both [Well Known Media][wkmedia-link] (parent company of FileHippo) and [FileHippo][filehippo-link] via their security addresses. `security@filehippo.com` and `security@wkmedia.com` do not exist. I contacted them via their only email on the Well Known Media website which is `adsales@wkemdia.com` and got no response. I tried to check the validity of the keys using the most non-intrusive way possible as discussed below and fortunately they were not valid so I went ahead and shared the adventure.

# 1. Ingredients

* Windows 7 VM
* [FileHippo App Manager 2.0 beta 4][filehippo-dl1]
* Burp free
* [JSON Decoder plugin from Burp's App Store][jsondecoder-dl]
* [dnSpy][dnspy-dl]

# 2. Proxying

## 2.1 Proxy settings
Install and run the application. Click on the `Settings` gear icon to the left and then select the `Connection` tab to see the proxy settings.

{{< imgcap title="Application's proxy settings" src="/images/2016/thickclient-5-filehippo/01.PNG" >}}

As you can see, the application supports its own proxy settings and also can use IE proxy settings via the `Auto-detect proxy settings for this network`. It does not really matter which method is chosen, we can use both of these to point the application to Burp. Point it to Burp's proxy listener (default is `127.0.0.1:8080`), run Burp and then press `Test`.

We can see two requests in Burp. First request is to get `update.filehippo.com` which is redirected with a `302 Found` response to http://filehippo.com/default.asp.

{{< codecaption title="GET update.filehippo.com and the 302 response" lang="html" >}}
Request:
GET / HTTP/1.1
Host: update.filehippo.com
Connection: close

Response:
HTTP/1.1 302 Found
Location: http://filehippo.com/default.aspx
...
Content-Length: 150
Connection: Close

<html><head><title>Object moved</title></head><body>
<h2>Object moved to <a href="http://filehippo.com/default.aspx">here</a>.</h2>
</body></html>
{{< /codecaption >}}

The application automatically attempts to grab the `default.aspx` page and if successful will pass the proxy test.

If we look at the traffic captured between the application and Burp we can see http proxying in action.

{{< imgcap title="HTTP proxying in action" src="/images/2016/thickclient-5-filehippo/02.PNG" >}}

[As we already know]({{< ref "2015-10-19-proxying-hipchat-part-3-ssl-added-and-removed-here.markdown#2-1-get-downloads-hipchat-com-blog-info-html" >}} "HTTP requests through a proxy"), there is no `CONNECT` because the proxy can see the `Host` header and forward the requests to the correct destination.

## 2.2 App Manager Scanning

Close the application and restart it again (there is one request that we want to see).

First request is a weird one. It is asking the server for the current date and time via a GET request to http://appmanager.filehippo.com/api/v1/DateTime.

{{< codecaption title="Get DateTime" lang="json" >}}
GET /api/v1/DateTime HTTP/1.1
User-Agent: download_manager
ClientId: 4dfe2b82-501c-4324-83ce-6d49a96cdf61
AppManagerVersion: 2.0.0.392
AccessToken: 2N0+YwVnSXph9L0ZuS8zOmnSvvKHq10QYMtuM0GdUVmLp067RfBBpw==
RequestTime: 2016-05-17T04:47:25.3968037Z
Host: appmanager.filehippo.com
Connection: close

Response body:
{"DateTime":"2016-05-17T04:47:57.0719162Z","Status":0,"Message":null}
{{< /codecaption >}}

Note the `AccessToken` which is a 40 byte blob in base64. For this request we can remove the `AccessToken` and it works. Why would the app get the date and time from the server?

Then the app requests http://appmanager.filehippo.com/api/v1/ProgramDefinitions which is a list of all applications that are supported by the App Manager. This request also contains the `AccessToken` header which contains a base64 encoded 40 byte blob. It seems like this access token is also time sensitive because if you send the request to Repeater and then send it after 10 minutes the response is `401 Unauthorized` while this did not happen in the `DateTime` request. At this point we do not know where this access token comes from because it is not in any of the responses (up until now we have only done the proxy test). There is also a 32 byte GUID named `ClientId`. Based on the previous request and the `ClientId` header, you can probably guess how the `AccessToken` is generated.

{{< codecaption title="Retrieving program definitions" lang="json" >}}
Request:
GET /api/v1/ProgramDefinitions HTTP/1.1
User-Agent: download_manager
ClientId: ...
AppManagerVersion: 2.0.0.392
AccessToken: ...
RequestTime: 2016-05-15T21:56:10.2127122Z
Host: appmanager.filehippo.com
Connection: close

Response body:
{
    "Status": 0,
    "Message": null,
    "Definitions": [
        {
            "DetectionXML": "<fp>\r\n    <fn>abiword.exe</fn>\r\n    <pfloc>abisuite2\\abiword\\bin</pfloc>\r\n</fp>\r\n<fp>\r\n    <fn>abiword.exe</fn>\r\n    <pfloc>abiword\\bin</pfloc>\r\n</fp>\r\n<reg>\r\n    <k hive=\"hklm\" key=\"software\\abisuite\\abiword\\v2\">\r\n        <v name=\"Version\"/>\r\n    </k>\r\n</reg>\r\n<reg>\r\n    <k hive=\"hklm\" key=\"software\\abiword\\v2\">\r\n        <v name=\"Version\"/>\r\n    </k>\r\n</reg>",
            "ProgramId": 135
        },
        {
            "DetectionXML": "<fp>\r\n    <fn>ACDSee*.exe</fn>\r\n    <pfloc>ACD Systems\\ACDSee\\*</pfloc>\r\n</fp>\r\n<fp>\r\n    <fn>ACDSee*.exe</fn>\r\n    <pfloc>ACD Systems\\ACDSee\\17.0</pfloc>\r\n</fp>\r\n<fp>\r\n    <fn>ACDSee*.exe</fn>\r\n    <pfloc>ACD Systems\\ACDSee\\18.0</pfloc>\r\n</fp>",
            "ProgramId": 83
        },
        ...
{{< /codecaption >}}

Next is a `POST` request to http://appmanager.filehippo.com/api/v1/ScanResults with a JSON payload in the body. The payload contains information about installed programs. The access token is also different.

{{< codecaption title="POST ScanResults" lang="json" >}}
parts of request's body:
{
    "Programs": [
        {
            "Registry": [],
            "Id": 298,
            "Files": [
                {
                    "VerPv": "2.0.0.392",
                    "VerPvr": "2.0.0.392",
                    "Len": 10566352,
                    "VerFv": "2.0.0.392",
                    "VerFvr": "2.0.0.392",
                    "File": "C:\\Program Files (x86)\\FileHippo.com\\FileHippo.AppManager.exe",
                    "Md5": "6798339CF7C87F5F567A8F050614D6B8"
                }
            ]
        },
        {
            "Registry": [],
            "Id": 12,
            "Files": [
                {
                    "VerPv": "46.0.1",
                    "VerPvr": "46.0.1.0",
                    "Len": 392136,
                    "VerFv": "46.0.1",
                    "VerFvr": "46.0.1.5966",
                    "File": "C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe",
                    "Md5": "7DF8845A1CF92C227E81DBBC6F6434DF"
                }
            ]
        }
        ...
}
{{< /codecaption >}}

The response contains links to the applications that have updates. For example in this case, `Firefox 47 Beta 2.0` is available.

{{< codecaption title="Response to ScanResults" lang="json" >}}
{
    "HasUpdate": true,
    "Size": 4203840,
    "InstalledDatePublished": "2015-10-19T08:04:36",
    "Title": "Notepad++ 6.9.1",
    "ProgramID": 186,
    "ApplicationManagerIconData": "base64 encoded application icon",
    "DatePublished": "2016-03-29T12:27:13",
    "IconURL": null,
    "InstalledVersion": "6.8.5.0.0",
    "LatestVersion": "6.9.1.0.0",
    "InstallationPath": "C:\\Program Files (x86)\\Notepad++",
    "FileID": 67045,
    "IsBeta": false,
    "DownloadUrl": "http://filehippo.com/download/file/2c2add5142b29932a40731e489a786c97d3ca3b1a2a9627b395eb6878d0c12df"
}
...
{{< /codecaption >}}

Notice that the download link is over HTTP, in fact `FileHippo.com` is served over HTTP.

Next request is where the app _exfiltrates_ (hyperbole of course) data from our machine. Not super secret stuff but information about installed applications and the operating system. The previous request only contained applications supported by the App Manager but this one contains a lot more. It's a `POST` request to http://appmanager.filehippo.com/api/v1/InstallerPrograms with another JSON payload.

The `ClientId` is the same between requests but the `AccessToken` is different each time and we still do not know where it comes from.

{{< codecaption title="InstallerPrograms" lang="json" >}}
{
    "Programs": [
        {
            "Publisher": "FileHippo.com",
            "Name": "FileHippo App Manager",
            "Is64Bit": false,
            "Version": null,
            "HiveLocalMachine": true,
            "HiveCurrentUser": false,
            "Key": "FileHippo.com"
        },
        {
            "Publisher": "Google Inc.",
            "Name": "Google Chrome",
            "Is64Bit": false,
            "Version": "50.0.2661.102",
            "HiveLocalMachine": true,
            "HiveCurrentUser": false,
            "Key": "Google Chrome"
        },
        {
            "Publisher": "Ma\u00ebl H\u00f6rz",
            "Name": "HxD Hex Editor version 1.7.7.0",
            "Is64Bit": false,
            "Version": "1.7.7.0",
            "HiveLocalMachine": true,
            "HiveCurrentUser": false,
            "Key": "HxD Hex Editor_is1"
        },
        ...
{{< /codecaption >}}

Notice the *exfiltrated* data. It includes if the application is installed for all users (has entries in the `LocalMachine` registry hive) vs. installed for current user (has entries in the `CurrentUser` registry hive), the version, publisher and if it is a 64-bit application.

The response to this message makes no sense (dots are added to the code block for better visibility).

``` json
Response to InstallerPrograms
{"Status":1,"Message":"The IP address \"10.0.1.34\"
    is a reserved IP address (private, multicast, etc.)"}
```

The request does not contain any IP addresses. Is this the internal IP address of the metrics server? Why is this a response?

{{< imgcap title="Scan Result" src="/images/2016/thickclient-5-filehippo/03-ScanResult.PNG" >}}

## 2.3 Updating Applications via the FileHippo App Manager
Updating is pretty simple. I am going to update `Notepad++`.

First the application sends a `GET` request over HTTP to download the new version. This link came from the `DownloadUrl` element in the `ScanResults` response that we saw above. The response is a `302 Moved Permanently` to a different download URL: http://dl1.filehippo.com/668e1f2d71fd4e9290c5396cb22af8c0/npp.6.9.1.Installer.exe?ttl=1463371091&token=045580ac50574f9e72be3a8db8337740.

Then the installer is downloaded over HTTP and executed. We will later see how.

{{< imgcap title="All requests in Burp HTTP History" src="/images/2016/thickclient-5-filehippo/04-AllRequests.PNG" >}}

## 2.4 Calling Home
From time to time the app `Calls Home` and send the current Operating System version.

``` json
POST /api/v1/CallHome HTTP/1.1
User-Agent: download_manager
ClientId: ...
AppManagerVersion: 2.0.0.392
AccessToken: ...
RequestTime: 2016-05-15T22:08:59.6814622Z
Content-Type: application/json; charset=utf-8
Host: appmanager.filehippo.com
Content-Length: 66
Expect: 100-continue
Connection: close

{"OperatingSystem":"Microsoft Windows NT 6.1.7601 Service Pack 1"}
```

And the response is similar to the `InstallerPrograms` request:

``` json
Response to CallHome
{"Status":1,"Message":"The IP address \"10.0.1.34\"
    is a reserved IP address (private, multicast, etc.)"}
```

Another `CallHome` response had a different internal IP in response `10.0.0.73`. Is the application leaking internal IPs in responses?

## 2.5 Self-Update
Every once in a while the application checks if a new version of itself is published. The request and the response are both pretty simple.

``` json
GET /api/v1/AppUpdateCheck HTTP/1.1
User-Agent: download_manager
ClientId: ...
AppManagerVersion: 2.0.0.392
AccessToken: ...
RequestTime: 2016-05-18T04:44:05.3721068Z
Host: appmanager.filehippo.com
Connection: close

Response body:
{"Url":null,"UpdateAvailable":false,"Status":0,"Message":null}
```

## 2.6 Done with Proxying

At this point we are pretty much done with the proxying, however we still have some questions such as:

* How is the `AccessToken` header generated?
* How does the installer get executed?

# 3. Application Analysis via dnSpy
It's a .NET application, so we can use our favorite tool for investigating managed code which is dnSpy. The application does not have a lot of functionality. But the executable is around 10 MBs which is interestingn.

``` asm
PS C:\Program Files (x86)\FileHippo.com> ls

    Directory: C:\Program Files (x86)\FileHippo.com

Mode                LastWriteTime     Length Name
----                -------------     ------ ----
-a---          9/2/2015   7:00 AM   10566352 FileHippo.AppManager.exe
-a---         5/11/2016   9:51 PM     177577 Uninstall.exe
-a---         2/17/2015  12:47 PM     211456 updater.exe
```

## 3.1 The Bloated Hippo
Let's open the application in dnSpy.

{{< imgcap title="Amazon SDK for .NET" src="/images/2016/thickclient-5-filehippo/05-DecompiledAppManager.PNG" >}}

The application contains the [Amazon SDK for .NET][amazon-sdk-dot-net].

There are also other third party libraries:

* Newtonsoft Json
* Bouncy Castle? The application does not use any kind of encryption whatsoever (not even HTTPs).
* log4net
* Exceptionless

## 3.2 Searching through the Code
There is a lot of dead code in the application. dnSpy supports searching through the assemblies but the application has so much dead code that the results will have a lot of noise. In order to discover interesting things, we need to only decompile and search in the application modules. They all conveniently start with `FileHippo`.

{{< imgcap title="FileHippo components" src="/images/2016/thickclient-5-filehippo/06-FileHippoComponents.PNG" >}}

Select the application and then `File > Export to Project` to create a Visual Studio project using the decompiled code. But this contains all of the 3rd party libraries. The directory that we need is `\decompiled-project\FileHippo.AppManager\FileHippo` which contains two directories:

* AppManager
* Shared

Everything else can be safely ignored and now we can `grep` through the code with less noise.

## 3.3 The AccessToken Header
We saw the `AccessToken` header and we did not see it coming from the server. Now we can look at decompiled code and find out how it is created. Let's search for `AccessToken` in the decompiled code.

{{< codecaption title="grep -ir \"accesstoken\"" lang="asm" >}}
$ grep -ir "accesstoken"
AppManager/Core/Authentication/AuthenticationProvider.cs:   public bool Authenticate(string accessToken, string clientId, string requestTime)
AppManager/Core/Authentication/AuthenticationProvider.cs:   string text = this.Encrypter.DecryptString(accessToken);
AppManager/Core/Authentication/AuthenticationProvider.cs:   public string GenerateAccessToken(string clientId, DateTime requestTime)
AppManager/Core/Authentication/IAuthenticationProvider.cs:  bool Authenticate(string accessToken, string clientId, string requestTime);
AppManager/Core/Authentication/IAuthenticationProvider.cs:  string GenerateAccessToken(string clientId, DateTime requestTime);
AppManager/Core/WebClient/v1/Client.cs:                     string value = this._authenticationProvider.GenerateAccessToken(this.ClientId, requestTime);
AppManager/Core/WebClient/v1/Client.cs:                     headers.Add("AccessToken", value);_
{{< /codecaption >}}

Look at line four. There is a function named `GenerateAccessToken` in `FileHippo.AppManager.Core.Authentication.AuthenticationProvider`. We can see the function code here:

{{< codecaption title="GenerateAccessToken(string clientId, DateTime requestTime)" lang="csharp" >}}
// FileHippo.AppManager.Core.Authentication.AuthenticationProvider
// Token: 0x0600DE83 RID: 56963 RVA: 0x002073FC File Offset: 0x002055FC
public string GenerateAccessToken(string clientId, DateTime requestTime)
{
	this.Encrypter.Key = Encoding.UTF8.GetBytes(this.GetEncryptionKey());
	int count = this.Encrypter.BlockSize / 8;
	this.Encrypter.IV = Encoding.UTF8.GetBytes(requestTime.ToString("T", CultureInfo.InvariantCulture)).Take(count).ToArray<byte>();
	return this.Encrypter.EncryptString(clientId);
}
{{< /codecaption >}}

It looks like that the application encrypts the `clientId` uses the current time. Using the current time in the token was the reason for the access tokens being invalidated after a while.

### 3.3.1 The Encryption Scheme
Put a breakpoint on the return line of `GenerateAccessToken` function and run the application from inside dnSpy. Remember to close the previous instance of the application which may be in the Windows tray.

{{< imgcap title="Encrypter information" src="/images/2016/thickclient-5-filehippo/07-EncrypterInformation.PNG" >}}

We see `3DES`, a 0x18 byte (24 byte or 192 bit) key and an 8 byte IV.

{{< imgcap title="IV" src="/images/2016/thickclient-5-filehippo/08-IV.PNG" >}}

IV is `30 31 3A 31 35 3A 30 32` which is `01:15:32` in hex (quick hint: `0x3n` is ASCII-Hex for number `n`). This looks like time and the answer is right in front of our eyes in the previous screenshot. Look at the `requestTime`. Line number 7 generates the IV.

And we can see the key too which is `00020206040A060E08120A160C1A0E1E10221226142A162E` in hex.

{{< imgcap title="Key" src="/images/2016/thickclient-5-filehippo/09-Key.PNG" >}}

The key is different from the IV, because it is the result of a function call. Later during static analysis we will see how the key is generated. For now, we want to see if it is hardcoded or no. Stop the application and run it again and look at the value of the key. It has not changed.

Now let's `step into` the function.

``` csharp
// Token: 0x0600DD04 RID: 56580 RVA: 0x00202858 File Offset: 0x00200A58
public string EncryptString(string text)
{
  return Convert.ToBase64String(this.Encrypt(Encoding.UTF8.GetBytes(text))); <-- we are here
}
```

Which counts for the base64 encoding. Another step and we land in:

``` csharp
// Token: 0x0600DD02 RID: 56578 RVA: 0x002027E8 File Offset: 0x002009E8
public byte[] Encrypt(byte[] data)
{
  return this.Encrypt(data, data.Length); <-- we are here
}
```

And finally.

{{< codecaption title="Encrypt" lang="csharp" >}}
// Token: 0x0600DD03 RID: 56579 RVA: 0x002027F4 File Offset: 0x002009F4
public byte[] Encrypt(byte[] data, int length)
{
  MemoryStream memoryStream = new MemoryStream(); <-- we are here
  CryptoStream cryptoStream = new CryptoStream(memoryStream, this._algorithm.CreateEncryptor(this._algorithm.Key, this._algorithm.IV), CryptoStreamMode.Write);
  cryptoStream.Write(data, 0, length);
  cryptoStream.FlushFinalBlock();
  byte[] result = memoryStream.ToArray();
  cryptoStream.Close();
  memoryStream.Close();
  return result;
}_
{{< /codecaption >}}

So `AccessToken` is `ClientId` encrypted using `3DES` with IV being the current time `hour:minute:second` and a hardcoded key.

### 3.3.2 Key Generation
Let's go back and look at how the encryption key is generated. Just clicking the `GetEncryptionKey` function in dnSpy shows us the decompiled code:

{{< codecaption title="GetEncryptionKey" lang="csharp" >}}
// Token: 0x0600DE84 RID: 56964 RVA: 0x00207474 File Offset: 0x00205674
private string GetEncryptionKey()
{
  StringBuilder stringBuilder = new StringBuilder();
  for (int i = 0; i < 24; i++)
  {
    stringBuilder.Append(char.ConvertFromUtf32((i % 2 == 0) ? i : (i * 2)));
  }
  return stringBuilder.ToString();
}
{{< /codecaption >}}

This looks pretty easy to reverse and is the same as the following Python code.

{{< codecaption title="Encryption Key" lang="Python" >}}
key = ""
for i in xrange(0,24):
  if (i % 2 == 0):
    key += "%0.2X" % i
  else:
    key += "%0.2X" % (i*2)
print key
{{< /codecaption >}}

Which returns the same key: `00020206040A060E08120A160C1A0E1E10221226142A162E`.

## 3.4 The Abandoned S3 Keys
As I mentioned before, the application has the Amazon SDK. I usually grep for certain keywords in decompiled code. Keywords such as `username`, `password`, `encryption`, `decryption` and `secret`.

So what happened when I searched for `secret` in application code?

{{< codecaption title="grep -it \"secret\"" lang="asm" >}}
$ grep -ir "secret"
.../AmazonS3ContentPublishingService.cs: protected virtual string GetSecretKey()
.../AmazonS3ContentPublishingService.cs: return this.AmazonS3SecretKey;
.../AmazonS3ContentPublishingService.cs: using (AmazonS3 amazonS = AWSClientFactory.CreateAmazonS3Client(this.GetAccessKey(), this.GetSecretKey()))
.../AmazonS3ContentPublishingService.cs: private readonly string AmazonS3SecretKey = "B6nB5T9d1CHGL4YrU5zCuySf65Js7fsi2cNhQh1B";
{{< /codecaption >}}

`AmazonS3SecretKey` in the last line. Oh wow. Looking at the decompiled code for `AmazonS3ContentPublishingService.cs` we can see:

``` csharp
// Token: 0x04003423 RID: 13347
private readonly string AmazonS3AccessKey = "AKIAJYWNSWLQDSSXG3FA";

// Token: 0x04003425 RID: 13349
private readonly string AmazonS3BucketName = "cache.filehippo.com";

// Token: 0x04003424 RID: 13348
private readonly string AmazonS3SecretKey = "B6nB5T9d1CHGL4YrU5zCuySf65Js7fsi2cNhQh1B";
```

A little bit further up we have:

``` csharp
// Token: 0x0600E4D3 RID: 58579 RVA: 0x00211474 File Offset: 0x0020F674
protected virtual string GetBucketURL()
{
  return "http://cache.filehippo.com";
}
```

But what is at http://cache.filehippo.com?

{{< imgcap title="http://cache.filehippo.com" src="/images/2016/thickclient-5-filehippo/11-cache.filehippo.com.PNG" >}}

Assuming these keys are valid, they can be used to modify the website and possibly put backdoored versions of the File Hippo App Manager application.

### 3.4.1 Checking the Validity of the Key Pair without Going to Jail
I wanted to find a non-intrusive way of checking the validity of these keys. So I asked one of my colleagues about it.

We can use the AWS CLI application to get the bucket policy like [this][aws-cli-bucket-policy]:
`aws s3api get-bucket-policy --bucket my-bucket`.

Fortunately (for both me and FileHippo.com) the result was `AccessDenied`. Meaning that the keys are not valid for that bucket.

However they may be valid for other buckets (or have access to other AWS services). We can get the list of buckets that are associated with a key pair like [this][aws-cli-list-bucket]: `aws s3api list-buckets --query 'Buckets[].Name'`.

Again this resulted in an `AccessDenied` message.

## 3.5 The Update Process
We have already seen part of the update process. The download is pulled over HTTP and then executed. There's not much to look at that part. But many times applications/services running binaries (or starting processes) are the main vector to a sweet RCE or local privilege escalation. For example if you can make the service (typically run as SYSTEM) execute your binary you can make yourself admin already. We probably will not find anything here but it is good practice to go ahead and look at the update process especially because we have the decompiled code.

First we need to find a way to discover where the installer is executed. We have the decompiled code, so we can grep for keywords. Grep for `execute` returns this.

``` asm
$ grep -ir "execute"
AppManager/Core/UpdateProgram.cs:  public void ExecuteInstaller(string installerFilePath, Guid requester)
AppManager/Core/UpdateProgram.cs:  public void ExecuteInstallerAsync(string installerFilePath, Guid requester)
AppManager/Core/UpdateProgram.cs:  this.ExecuteInstaller(installerFilePath, requester);
AppManager/ProgramItemControl.Designer.cs:  this.updateProgram.ExecuteInstallerAsync(this._downloadFilePath, Guid.NewGuid());
AppManager/ProgramItemControl.Designer.cs:  this.updateProgram.ExecuteInstallerAsync(e.AdditionalData, Guid.NewGuid());
```

`ExecuteInstaller` executes the update like this.

{{< imgcap title="ExecuteInstaller code" src="/images/2016/thickclient-5-filehippo/12-ExecueInstallerCode.PNG" >}}

By analyzing (right click `Analyze`) the `ExecuteInstaller` function we will see where it is called.

{{< imgcap title="ExecuteInstaller analysis" src="/images/2016/thickclient-5-filehippo/13-ExecuteInstallerAnalysis.PNG" >}}

To see if this is actually the case, we can go back inside `ExecuteInstaller` and set a breakpoint at the start of the function and then run the application via dnSpy.

When we land in the function after the breakpoint is hit, we can see how we got here by using `Debug (menu) > Call Stack` and the culprit for running thee installer is the following line:

{{< codecaption title="Running the installer" lang="csharp" >}}
Process process = Process.Start(installerFilePath);
{{< /codecaption >}}

So next time you are looking at a .NET application to determine how it executes external binaries one of the things we search for is `Process.Start`.

## 3.6 Debug and Background Modes
While looking at the application I saw references to a `Debug Mode`. After I grepped for `debug` I saw the following lines (among other things):

{{< codecaption title="grep -ir \"debug\"" lang="csharp" >}}
AppManager/MainForm.cs:                         if (text2.ToLower() == "/debug")
AppManager/MainForm.cs:                                 ApplicationManager.DebugMode = true;
AppManager/MainForm.cs:                 this.SetDebugLabelVisibility();
AppManager/MainForm.cs:                         ApplicationManager.DebugMode = !ApplicationManager.DebugMode;
AppManager/MainForm.cs:                         this.SetDebugLabelVisibility();
AppManager/MainForm.cs:         private void SetDebugLabelVisibility()
AppManager/MainForm.Designer.cs:                        this.debugModeLabel.Text = "Application is in DEBUG mode";
{{< /codecaption >}}

The application has a debug mode when run with the `/debug` switch. If we go to `FileHippo.AppManager.MainForm` and look at the `MainForm_Load` function we will the first line in the grep results above.

{{< codecaption title="MainForm_Load" lang="csharp" >}}
private void MainForm_Load(object sender, EventArgs e)
{
  ...
  bool flag = false;
  string[] commandLineArgs = Environment.GetCommandLineArgs();
  string[] array2 = commandLineArgs;
  for (int i = 0; i < array2.Length; i++)
  {
    string text = array2[i];
    string text2 = text;
    if (text2.ToLower() == "/debug")
    {
      ApplicationManager.DebugMode = true;
    }
    else if (text2.ToLower() == "/background")
    {
      flag = true;
    }
  }
  if (flag)
  {
    this.MinimizeToTray();
  }
  this.SetDebugLabelVisibility();
}
{{< /codecaption >}}

`/background` switch just minimizes the app to Windows tray and does nothing interesting. While `/debug` sets `ApplicationManager.DebugMode` to true and runs `this.SetDebugLabelVisibility();`.

### 3.6.1 Activating the Debug Mode
In order to see how the debug mode is activated we need to follow the `ApplicationManager.DebugMode` and see where it is set to `True`. Again we can use the excellent `Analyze` feature to see what accesses `ApplicationManager.DebugMode`. First we go for the `set` method to see if anything other than the command line switch activates the debug mode.

{{< imgcap title="Where debug mode is set" src="/images/2016/thickclient-5-filehippo/14-SetDebugModeAnalysis.PNG" >}}

Interesting, apart from where we already where (`MainForm_Load`), there is another place that sets the debug mode which is [ProcessCmdKey][processcmdkey-link].

{{< codecaption title="ProcessCmdKey" lang="csharp" >}}
protected override bool ProcessCmdKey(ref Message msg, Keys keyData)
{
  if (keyData == (Keys)196676)
  {
    ApplicationManager.DebugMode = !ApplicationManager.DebugMode;
    this.SetDebugLabelVisibility();
  }
  return base.ProcessCmdKey(ref msg, keyData);
}
{{< /codecaption >}}

`ProcessCmdKey` processes pressed keys. The keys pressed are in `keyData`. Check line 3, the keys pressed are compared to the equivalent of keys with integer value of `196676`. By clicking the `(Keys)` we can see the enum in `System.Windows.Forms.dll > Keys`. However, this value is not present in that file which means it's a key combination.

#### 3.6.1.1 Using LINQPad to Decipher 196676
In order to discover the keys for `196676` we will use our old friend [LINQPad][linqpad-dl] that we used in [Intro to .NET Remoting for Hackers]({{< ref "2015-11-14-intro-to-dot-net-remoting-for-hackers.markdown#6-modifying-il-instructions-with-dnspy-and-patching-binaries" >}} "Intro to .NET Remoting for Hackers").

1. Change the `Language` drop-down list to `C# Statement`.
2. Right click and select `References and Properties` or press `F4`.
3. In the `References` tab click `Add` and search for `System.Windows.Forms.dll`.
4. Press `Add` and then `Ok`. Now it should be added.
5. Again press `Ok` to close this window.
6. Type the following code and press the green arrow button and voila.

{{< codecaption title="Code entered in LINQPad" lang="csharp" >}}
Keys nem = (Keys)196676;

Console.WriteLine(nem.ToString());
{{< /codecaption >}}

{{< imgcap title="System.Windows.Forms added as reference" src="/images/2016/thickclient-5-filehippo/15-SystemWindowsFormsAdded.PNG" >}}

{{< imgcap title="Debug shortcut is Ctrl+Shift+D" src="/images/2016/thickclient-5-filehippo/16-DebugShortcutDiscovered.PNG" >}}

Run the application and press `Ctrl+Shift+D` to see the anticlimactic debug mode in action. See the bottom right label `Application is in DEBUG mode`.

{{< imgcap title="Debug mode in action" src="/images/2016/thickclient-5-filehippo/17-DebugModeinAction.gif" >}}

### 3.6.2 What does the Debug Mode do?
Go back to `MainForm_Load` and do `Analyze` on `ApplicationManager.DebugMode` but this time look at the `get` method. This time we want to see where this is accessed which means the places where the application checks if debug mode is active. Most likely application behavior changes after checking the `DebugMode`.

{{< imgcap title="Get debug mode functions" src="/images/2016/thickclient-5-filehippo/18-GetDebugMode.PNG" >}}

We've already seen some of them such as `ProcessCmdKey`. I decided to pursue a few of the others.

#### 3.6.2.1 Scanner Debug Mode
First function is `FileHippo.AppManager.Core.UpdateChecker.CreateScanResultsRequest(...)` in which we see the following:

``` csharp
Scanner scanner = new Scanner();
scanner.ApplicationVersion = this.ApplicationVersion;
scanner.CustomFolders = settings.CustomerFoldersRaw;
scanner.DebugMode = ApplicationManager.DebugMode; <-- scanner set to Debugmode
```
Again if we go after `scanner.DebugMode` with `Analyze` with its `get` method, we can see the scanner debug mode in `			FileHippo.AppManager.Core.LegacyComponents.Scanner.DoScan(...)`:

{{< codecaption title="Scanner debug mode" lang="csharp" >}}
this.mCustomFolders.Add(text2);
try
{
  this.mCustomFolders.AddRange(Directory.GetDirectories(text2, "*.*", SearchOption.AllDirectories));
  goto IL_19F;
}
catch (UnauthorizedAccessException ex)
{
  if (this.DebugMode)
  {
    Interaction.MsgBox(ex.Message, MsgBoxStyle.OkOnly, null);
  }
  goto IL_19F;
}
catch (DirectoryNotFoundException ex2)
{
  if (this.DebugMode)
  {
    Interaction.MsgBox(ex2.Message, MsgBoxStyle.OkOnly, null);
  }
  goto IL_19F;
}
{{< /codecaption >}}

It seems like if the scanner cannot access a directory in debug mode, the application displays a message box. Nothing special.

#### 3.6.2.2 (Obsolete) Debug Program Definitions
Next one is `FileHippo.AppManager.Core.UpdateChecker.DownloadProgramDefinitions()`. This one is also interesting. It is never called. If you do `Analyze > Used By`, the list is empty. If you set a breakpoint in the function and run the app in debug mode, the breakpoint is never triggered. It looks like that it should change the program definition URL if the app is in debug mode and the function is called:

{{< codecaption title="DownloadProgramDefinitions()" lang="csharp" >}}
private string DownloadProgramDefinitions()
{
  string result;
  using (WebClient webClient = new WebClient())
  {
    string address = ApplicationManager.DebugMode ? ApplicationManager.ProgramDefinitionURL_Debug : ApplicationManager.ProgramDefinitionURL;
    this.ConfigureWebClient(webClient);
    byte[] bytes = webClient.DownloadData(address);
    string @string = Encoding.ASCII.GetString(bytes);
    result = @string;
  }
  return result;
}
{{< /codecaption >}}

Check line 6, if `DebugMode` is active, the program definition URL is modified. Those two values are set like this:

``` csharp
public static string ProgramDefinitionURL
{
  // Token: 0x0600DD73 RID: 56691 RVA: 0x00204A28 File Offset: 0x00202C28
  get
  {
    return string.Format("{0}/update/programs", ApplicationManager.RootURL);
  }
}

// Token: 0x17002562 RID: 9570
public static string ProgramDefinitionURL_Debug
{
  // Token: 0x0600DD74 RID: 56692 RVA: 0x00204A3C File Offset: 0x00202C3C
  get
  {
    return string.Format("{0}/update/all_programs", ApplicationManager.RootURL);
  }
}
```

However, none of them are called in the application. As we have seen in Burp the program definition URL is `/api/v1/ProgramDefinition`.

You can continue to see what the rest of the stuff do. But none of them are interesting or give us any secrets. Most just display message boxes if errors occur. One also enabled the debug label.

# 4. Conclusion
It took me a while to find a suitable app. I like FileHippo and decided to use this application for analysis by accident. It turned out to be much more interesting that I had anticipated (I wanted to just use it for proxying). dnSpy allowed me to dig deeper and discover some interesting things. Hopefully this can help readers in analyzing managed code.

The AWS keys were another surprise. Fortunately the keys are invalid. I tried contacting World Known Media (owns FileHippo) and FileHippo both to report it but I got no answer. The keys are invalid to the best of my knowledge and have been accessible for a couple of years at least.

Thanks for reading and as usual if you have any questions/complaints/suggestions, you know where to find me.

<!-- links -->
[filehippo-dl1]: http://filehippo.com/download_app_manager/
[jsondecoder-dl]: https://portswigger.net/bappstore/ShowBappDetails.aspx?uuid=ceed5b1568ba4b92abecce0dff1e1f2c
[dnspy-dl]: https://github.com/0xd4d/dnSpy/releases
[amazon-sdk-dot-net]: https://aws.amazon.com/sdk-for-net/
[john-roberts-linkedin]: https://www.linkedin.com/in/johnoroberts
[aws-cli-list-bucket]: https://docs.aws.amazon.com/cli/latest/reference/s3api/list-buckets.html
[aws-cli-bucket-policy]: https://docs.aws.amazon.com/cli/latest/reference/s3api/get-bucket-policy.html
[linqpad-dl]: https://www.linqpad.net/Download.aspx
[processcmdkey-link]: https://msdn.microsoft.com/en-us/library/system.windows.forms.form.processcmdkey(v=vs.110).aspx
[wkmedia-link]: http://www.wkmedia.com/
[filehippo-link]: http://filehippo.com/
