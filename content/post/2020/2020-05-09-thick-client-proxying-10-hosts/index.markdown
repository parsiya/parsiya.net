---
title: "Thick Client Proxying - Part 10 - The hosts File"
date: 2020-05-09T13:01:59-07:00
draft: false
toc: true
comments: true
twitterImage: 04-example-in-burp.png
categories:
- Thick client proxying
- Burp
aliases:
- "/blog/2020-05-09-thick-client-proxing-part-10-the-hosts-file/"
---

Welcome to the 10th installment of
[Thick Client Proxying]({{< relref "categories/thick-client-proxying" >}} "Thick Client Proxying").
A series running since 2016. Woot! Today I will talk about traffic redirection
using the `hosts` file.

<!--more-->

# This Is Not Really New
Yeah! I realized I have talked about it in [19 different posts][hosts-query] but
never explicitly wrote about it. I just assumed readers would know this.

If you are already familiar with these concepts please directly go to the
[How Do We Proxy With This?](#how-do-we-proxy-with-this) section.

[hosts-query]: https://www.google.com/search?q=%22hosts%22+site%3Ahttps%3A%2F%2Fparsiya.net%2Fblog%2F

# The hosts File
The `hosts` file is located at `C:\Windows\System32\Drivers\etc\hosts`. Each
line in the file looks like this:

* `IP-Address domain`.
* `127.0.0.1 google.com`

Any change in this file results in a change in the Windows DNS cache. Note that
you need admin access to edit this file.

On nix-based operating systems (e.g., GNU/Linux[^interject] and Apple stuff) the
`hosts` file has the same format and functionality. BUT there is no local DNS
cache on Linux (not sure about Apple operating systems). The OS checks this file
before making a DNS request. You could say this file IS the DNS cache. See the
[hosts manual page][hosts-manual] for more information.

[^interject]: Interjection avoided.
[hosts-manual]: http://man7.org/linux/man-pages/man5/hosts.5.html

For the rest of the blog I am going to talk about Windows but the same principle
applies to others.

# Windows DNS Cache
The complete name for this entity is `local DNS resolver cache` but I will just
call it the Windows DNS cache. When the OS wants to resolve a domain, it will
first look in this cache to see if it's already been resolved. If the entry has
expired or an entry for that domain does not exist the OS will do a lookup.

## Windows DNS Cache in Action
Start your favorite Windows VM (also works on your host) and start doing things.

### Note for Hyper-V Users
For some reason, Hyper-V Windows VMs do not update their local DNS cache. It
remains empty. I do not know the reason but the solution is to manually
configure a DNS server in the VM.

1. `Control Panel > Network and Internet > Network Connections` in the VM.
2. Right click on the `Ethernet Adapter` and select `Properties`.
3. Select `Internet Protocol Version 4 (TCP/IPv4)` and click the `Properties`
   button.
4. Select the `Use the following DNS server addresses` radio button.
5. Enter `8.8.8.8` (or your preferred DNS server like `1.1.1.1`).

{{< imgcap title="Hyper-V guest with manual DNS server" src="01-manual-dns-server.png" >}}

### Useful Commands

* View the Windows DNS cache: `ipconfig /displaydns` or `Get-DnsClientCache`.
* Clear the cache: `ipconfig /flushdns` or `Clear-DnsClientCache`
    * In my Hyper-V guest `ipconfig /flushdns` asks for elevation but
      `Clear-DnsClientCache` works in a non-elevated PowerShell prompt.
    * In my host both work without elevation.

### View the DNS Cache
No we can see the DNS cache in our VM.

1. Clear the DNS cache.
2. `ping example.net` or `nslookup example.net`
3. View the DNS cache.

{{< imgcap title="DNS cache after resolving example.net" src="02-dns-cache-view.png" >}}

## The Relation Between the hosts File and the DNS Cache
Each line in the hosts file becomes an entry in the DNS cache. Do some
experiments:

1. Open the `hosts` file in an elevated editor (e.g., notepad as admin).
2. Add the following entry:
    1. `127.0.0.1 example.net`.
3. Save the file.
4. Clear the DNS cache.
    1. This removes the extra entries that have been cached.
5. View the DNS cache.

{{< imgcap title="example.net entry from the hosts file" src="03-example-local-cache.png" >}}

# How is This Useful?
I have two proxy usecases for the Windows DNS cache.

1. We can use it to discover endpoints. Read
   [Thick Client Proxying - Part 9 - The Windows DNS Cache]
   ({{< relref "/post/2019/2019-04-27-thick-client-proxying-9-local-dns-cache/index.markdown#anchor" >}}
   "Thick Client Proxying - Part 9 - The Windows DNS Cache").
2. We can redirect domains to our proxy.

## How Do We Proxy With This?
If your application is using HTTP but is not [proxy-aware]
({{< relref "/post/2016/2016-07-24-thickclient-proxying-6-how-proxies-work.markdown" >}}
"Proxy-Aware Clients") then you can redirect its endpoints to your
proxy listener.

PortSwigger has a great page on invisible proxying. Be sure to read it:

* https://portswigger.net/burp/documentation/desktop/tools/proxy/options/invisible

### Generic Steps

1. Identify the endpoints. E.g., `example.net:443`.
2. Ping the endpoint to get its IP address. Do this before the next step.
   1. `93.184.216.34`.
3. Redirect them to Burp (e.g., `localhost`) using the hosts file.
    1. We already did it with `127.0.0.1 example.net`.
4. Start a Burp proxy listener on `localhost:443`. The hosts file does not
   change the destination port so the Burp listener should be on the same port.
5. Enable `invisible proxying` for the Burp listener above.
    1. `Proxy > Option > Select the listener > Edit > Request Handling > Check 'Support invisible ...`.
6. Add the endpoint's IP address and domain to `Project Options > Connections > Hostname Resolution`.
    1. This tells Burp use that IP address directly instead of looking up the domain.
7. Profit.

Now we can open our browser and go to `http://example.net`.

{{< imgcap title="example.net proxied in Burp" src="04-example-in-burp.png" >}}

## What If We Are Not Using HTTP?
If your application is not using HTTP then Burp's invisible proxying does not
work. It relies on the `Host` header in the request to identify the endpoint.

There are some cases where the application uses a text-based protocol that can
be proxied with Burp.

### No Host Header with One Endpoint
If there is only one endpoint, then we can use the `Request Handling` tab of the
proxy listener (where invisible proxying was). It has a redirection setting. You
can redirect everything that comes to a specific listener to a specific host and
port. Checking `Force use of TLS` just automatically populates the port field
with `443`.

{{< imgcap title="Request Handling tab" src="05-request-handling.png" >}}

If we have multiple endpoints but each use a different port then our work is
still easy. We create one listener for each port and use the same technique.

### No Host Header with Multiple Endpoints on The Same Port
Then tough luck. I mean, yeah. This is commonly the case where the thickclient
talks to several endpoints over TLS on port 443. The problem is that we have no
way of telling Burp to differentiate between traffic going to `example.net` and
`ea.com` without the `Host` header.

In these cases I usually just proxied one endpoint at a time to see the traffic.
The Burp documentation for invisible proxying (linked above) has a section named
`Redirecting outbound requests` (the page does not have anchors so I cannot
directly link to the section). It says:

1. Create a network interface for each endpoint.
2. Redirect one endpoint to one interface.
3. Create a separate listener on each interface for each endpoint.
    1. Now each listener only gets one endpoint's traffic.
4. Use the `Request Handling` tab above to redirect it to the endpoint.

It's a pain to accomplish as you can imagine. This works if you have a couple of
endpoints.

# Troubleshooting
It's not always easy like our `example.net` example. In fact, it's never easy
like this. This section discusses the issues I have usually seen.

## I See the Burp Interface Instead of example.net
After browsing to `http://example.net` the Burp's web interface shows up or it
does not connect.

* Have you added the domain in `Hostname Resolution`?
    * Burp is asking the OS to resolve domains for it so it's using the hosts
      file. This means the traffic leaving Burp is redirected back to
      `localhost:443` which is the proxy listener.

## Proxy Server is Refusing Connection Error Message

* Have you set the Firefox or Windows proxy settings to some another value?
* Is your Burp listener listening on port `443` (or whatever port the
  application is trying to connect to)?

## The Connection times out after a Long Time

* Have you enabled "invisible proxying"?

## TLS Certificate Issues

* Have you added Burp to the operating system's certificate store?
    * Is the app using a separate certificate store (bundled JVM keystore)?
* Is there certificate pinning?
* Is the app looking for a specific Common Name in the generated certificate?

# Limitations
This method has a few limitations:

1. Doesn't work if your application contacts the endpoint by IP (happens in
   internal applications) or does its own DNS lookup (very rare as in I have
   never seen one).
2. Does not scale. If there are multiple endpoints we have to make one interface
   per endpoint.

# What Did We Learn Here Today?

* We can proxy using the `hosts` file.
* Be sure to somehow tell Burp (or your proxy) where to send the requests.
* Having multiple endpoints on one port (which is common) is an open problem.
