---
categories:
- Hipchat
- Proxying
- Netmon
- Network Traffic
comments: true
date: 2015-10-08T23:05:24Z
title: 'Proxying Hipchat Part 1: Where did the Traffic Go?'
---

This is a slightly different version of a series of blog post that I wrote on our internal blog about proxying. I see that proxying traffic is a time consuming step in testing thick client applications so I thought I would share what I know. I tackled Hipchat. Why Hipchat? Because it uses a known protocol (XMPP) and I thought it's an interesting application.

I used Hipchat Windows client version 2. At the time of writing version 4 is in beta. In this part we will see how we can identify endpoints from traffic captures even when they are behind a load balancer/shared hosting etc. In next parts we will start proxying.

<!--more-->

### 0. Setup and Tools
I will be using the following tools in this part:

1. Microsoft Network Monitor (Netmon). You can also use Wireshark.
2. Powershell/Command Prompt/etc: I am using Windows but I am sure you can find the equivalent commands if you are fancy ;)
3. Procmon

You can deploy your own Hipchat server by [downloading a VM][hipchatova]. You will need a license (or an evaluation version) or you can buy a 10 license server for [10 bucks](https://www.atlassian.com/purchase/product/com.atlassian.hipchat.server).

Note: In these posts, the Hipchat server is named `hipchatserver.com` and its IP is `10.10.10.10` (these are just examples). Some of the screenshots are edited to hide the actual IPs and replace them with samples. My machine's sample IP address for the network interface that hosts the Hipchat server is `10.10.10.9`.

### 1. Traffic Attribution
Run Netmon and Procmon as admin and run HipChat. We already know how to do [traffic attribution]({% post_url 2015-08-01-network-traffic-attribution-on-windows >}} "Network Traffic Attribution on Windows"). I was not logged into any chatrooms, so Hipchat is not loading any extra content (e.g. images linked in rooms).

In Netmon we also see the following endpoints:

1. 10.10.10.10
2. 54.231.81.2
3. 54.231.96.96
4. 54.231.47.194
5. 54.225.209.74

{% imgpopup /images/2015/hipchat1/01-Traffic-in-Netmon.png 80% Traffic in Netmon >}}

Traffic in Netmon, click to view full-size image.

You will notice that I have a slightly different layout in Netmon now. I have removed time related columns. Right click any column name and select `Choose Columns`. There are also different layouts like `HTTP Troubleshoot`.

{{< imgcap src="" caption="" /images/2015/hipchat1/02-Endpoints-in-Netmon.png Endpoints in Netmon >}}


In Procmon we can see five endpoints:

1. hipchatserver.com:5222
1. s3-website-us-east-1.amazonaws.com:http
1. s3-1.amazonaws.com:https
1. ec2-54-531-47-194.compute-1.amazonaws.com:https
1. ec2-54-225-209-74.compute-1.amazonaws.com:https

{{< imgcap src="" caption="" /images/2015/hipchat1/03-Endpoints-in-Procmon.png Endpoints in Procmon >}}

Procmon filters are:

* ProcessName is Hipchat.exe
* Operation is TCP Connect

### 2. Where does the traffic go?
Now we need to find out more about these endpoints (e.g. their actual address/URL etc). Based on their temporal sequence in Procmon and Netmon we have some insights.

#### 2.1 – 10.10.10.10 – hipchatserver.com
This is easy. It’s the Hipchat server at `hipchatserver.com`.

    PS C:\> nslookup 10.10.10.10
    Server:  zzzz.com
    Address:  10.10.10.2

    Name:    hipchatserver.com
    Address:  10.10.10.10

    PS C:\> ping -a 10.10.10.10
    Pinging hipchatserver.com [10.10.10.10] with 32 bytes of data:
    ...

#### 2.2 – 54.231.81.2 – s3-website-us-east-1.amazonaws.com
This is where things start to become interesting. Let’s re-use our old tricks.

    PS C:\> nslookup 54.231.81.2
    Server:  zzzz.com
    Address:  10.10.10.2

    Name:    s3-website-us-east-1.amazonaws.com
    Address:  54.231.81.2

    PS C:\> ping -a 54.231.81.2
    Pinging s3-website-us-east-1.amazonaws.com [54.231.81.2] with 32 bytes of data:
    ...

It seems like the second endpoint is hosted on an AWS S3 bucket. S3 buckets are mainly storage containers but they can also host static websites like this website. But we won't find anything if we go to that address. `s3-website-us-east-1.amazonaws.com` is the east coast AWS data center which is located in Northern Virginia. You will get a different endpoint based on where you are located.

Let's look at the conversation in Netmon. This is similar to `Follow TCP/UDP Stream` in Wireshark but unfortunately not as good.

{{< imgcap src="" caption="" /images/2015/hipchat1/04-bloginfo-fetch.png Fetching blog_info.html >}}

We are in luck, we can see a `GET` request over HTTP. Let’s look at it’s payload:

    GET /blog_info.html HTTP/1.1
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
    User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/538.1 (KHTML, like Gecko) HipChat/2.2.1388 Safari/538.1
    Connection: Keep-Alive
    Accept-Encoding: gzip, deflate
    Accept-Language: en-US,*
    Host: downloads.hipchat.com

Note the User-Agent. Hipchat is fetching [http://downloads.hipchat.com/blog_info.html](http://downloads.hipchat.com/blog_info.html). This is the `Latest News` at the bottom of the Hipchat client. Notice that it is being loaded over HTTP and surprisingly it is not available over TLS (try accessing [https://downloads.hipchat.com/blog_info.html](https://downloads.hipchat.com/blog_info.html)) does not work. In fact you cannot access [https://downloads.hipchat.com](https://downloads.hipchat.com/).

{{< imgcap src="" caption="" /images/2015/hipchat1/05-Latest-news-in-hipchat.png "Latest News" fetched over HTTP ;) >}}

##### 2.2.1 But what if this request was over TLS?
Then we would have seen the TLS handshake and then encrypted data. Even by looking at the Common Name (CN) field in server’s certificate in 2nd part of the TLS handshake (`Server Hello`) we wouldn't have been able to discover the endpoint.
Traffic in Netmon, click to view full-size image.
We are going to have to look at DNS requests. We know the endpoint’s IP address so we will try to find the DNS request that had this IP in its answer. The endpoint’s IP address is `54.231.81.2` which is `36E75102` in Hex. In Netmon, select `All Traffic` (In Netmon DNS traffic is not included in process traffic) and enter the following filter:

	  DNS && ContainsBin(FrameData, HEX, "36E75102")

This filter searches for the IP address in DNS traffic. It will find the DNS query that returned this IP address.

{{< imgcap src="" caption="" /images/2015/hipchat1/06-Downloads.png downloads.hipchat.com >}}

As we can see, it is `downloads.hipchat.com`.

IP to Hex conversion can be done online, by hand or using Python:

{% codeblock lang:python IP to Hex >}}
PS C:\> python
>>> import socket
>>> from binascii import hexlify
>>> print hexlify ( socket.inet_aton("54.231.81.2") )
36e75102
{% endcodeblock >}}

#### 2.3 – 54.231.96.96 – s3-1.amazonaws.com

Same trick. `54.231.96.96` in Hex is `36E76060` so filter is:

	  DNS && ContainsBin(FrameData, HEX, "36E76060")

which points to `s3.amazonaws.com`. As we will see in part two, this is the request to load the emoticon shown with latest news, in this case it is the `success kid` image macro.

    - Dns: QueryId = 0xC28D, QUERY (Standard query), Response - Success, 53, 0 ... 
        QueryIdentifier: 49805 (0xC28D)
      + Flags:  Response, Opcode - QUERY (Standard query), RD, RA, Rcode - Success
        QuestionCount: 1 (0x1)
        AnswerCount: 3 (0x3)
        NameServerCount: 0 (0x0)
        AdditionalCount: 0 (0x0)
      - QRecord: s3.amazonaws.com of type Host Addr on class Internet  PS C:\> python
         QuestionName: s3.amazonaws.com
         QuestionType: A, IPv4 address, 1(0x1)
         QuestionClass: Internet, 1(0x1)
      - ARecord: s3.amazonaws.com of type CNAME on class Internet: s3.a-geo.amazonaws.com
         ResourceName: s3.amazonaws.com
         ResourceType: CNAME, Canonical name for an alias, 5(0x5)
         ResourceClass: Internet, 1(0x1)
         TimeToLive: 2554 (0x9FA)
         ResourceDataLength: 11 (0xB)
         CName: s3.a-geo.amazonaws.com
      - ARecord: s3.a-geo.amazonaws.com of type CNAME on class Internet: s3-1.amazonaws.com
         ResourceName: s3.a-geo.amazonaws.com
         ResourceType: CNAME, Canonical name for an alias, 5(0x5)
         ResourceClass: Internet, 1(0x1)
         TimeToLive: 1555 (0x613)
         ResourceDataLength: 7 (0x7)
         CName: s3-1.amazonaws.com
      - ARecord: s3-1.amazonaws.com of type Host Addr on class Internet: 54.231.96.96
         ResourceName: s3-1.amazonaws.com
         ResourceType: A, IPv4 address, 1(0x1)
         ResourceClass: Internet, 1(0x1)
         TimeToLive: 4 (0x4)
         ResourceDataLength: 4 (0x4)
         IPAddress: 54.231.96.96

#### 2.4 – 54.243.47.194 – ec2-54-243-47-194.compute-1.amazonaws.com
This is easy, we can just go to [http://ec2-54-243-47-194.compute-1.amazonaws.com](http://ec2-54-243-47-194.compute-1.amazonaws.com) and observe that it is [http://www.hipchat.com](http://www.hipchat.com). Interesting thing, if you go to [http://www.hipchat.com](http://www.hipchat.com) in your browser, it will redirect to the HTTPs version of the website. Going to the Amazon EC2 address is the only way to access hipchat.com over HTTP.

We can also use this filter in Netmon:

	  DNS && ContainsBin(FrameData, HEX, "36F32FC2")

Which results in:
    
    - Dns: QueryId = 0x1D07, QUERY (Standard query), Response - Success, 54.243.47.194 
        QueryIdentifier: 7431 (0x1D07)
      + Flags:  Response, Opcode - QUERY (Standard query), RD, RA, Rcode - Success
        QuestionCount: 1 (0x1)
        AnswerCount: 1 (0x1)
        NameServerCount: 0 (0x0)
        AdditionalCount: 0 (0x0)
      - QRecord: www.hipchat.com of type Host Addr on class Internet
         QuestionName: www.hipchat.com
         QuestionType: A, IPv4 address, 1(0x1)
         QuestionClass: Internet, 1(0x1)
      - ARecord: www.hipchat.com of type Host Addr on class Internet: 54.243.47.194
         ResourceName: www.hipchat.com
         ResourceType: A, IPv4 address, 1(0x1)
         ResourceClass: Internet, 1(0x1)
         TimeToLive: 60 (0x3C)
         ResourceDataLength: 4 (0x4)
         IPAddress: 54.243.47.194

#### 2.5 – 54.225.209.74 – ec2-54-225-209-74.compute-1.amazonaws.com
This is the same as above with one small difference. Using this filter:

    DNS && ContainsBin(FrameData, HEX, "36E1D14A")

We can see that is points to hipchat.com (last IP was `www.hipchat.com`).

    - Dns: QueryId = 0x280E, QUERY (Standard query), Response - Success, 54.225.209.74 
        QueryIdentifier: 10254 (0x280E)
      + Flags:  Response, Opcode - QUERY (Standard query), RD, RA, Rcode - Success
        QuestionCount: 1 (0x1)
        AnswerCount: 1 (0x1)
        NameServerCount: 0 (0x0)
        AdditionalCount: 0 (0x0)
      - QRecord: hipchat.com of type Host Addr on class Internet
         QuestionName: hipchat.com
         QuestionType: A, IPv4 address, 1(0x1)
         QuestionClass: Internet, 1(0x1)
      - ARecord: hipchat.com of type Host Addr on class Internet: 54.225.209.74
         ResourceName: hipchat.com
         ResourceType: A, IPv4 address, 1(0x1)
         ResourceClass: Internet, 1(0x1)
         TimeToLive: 59 (0x3B)
         ResourceDataLength: 4 (0x4)
         IPAddress: 54.225.209.74


So the application is communicating with both `www.hipchat.com` and `hipchat.com`. Probably because of a redirect as we can see later.

That's enough for now. In part two we will talk about proxying.


<!-- links -->
[hipchatova]: https://www.hipchat.com/server/get-it

