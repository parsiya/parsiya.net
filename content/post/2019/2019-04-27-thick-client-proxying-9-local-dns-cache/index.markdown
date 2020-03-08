---
title: "Thick Client Proxying - Part 9 - The Windows DNS Cache"
date: 2019-04-28T13:35:00-07:00
draft: false
toc: true
comments: true
twitterImage: 05.png
categories:
- Thick client proxying
tags:
- powershell
---

This post explains a trick that I have been using for a few years to discover
application endpoints on Windows quickly.

It's a simple trick:

1. Clear the DNS cache.
2. Take a snapshot of the cache.
3. Run the application and use different functionalities.
4. Take another snapshot of the cache.
5. Compare these two snapshots.
6. ???
7. Discover (most) endpoints.

Code is at:

* [https://github.com/parsiya/Parsia-Code/tree/master/dns-cache](https://github.com/parsiya/Parsia-Code/tree/master/dns-cache)

<!--more-->

# Discovering Endpoints
Discovering application endpoints is one of the starting steps in thick client
proxying. I have written about it so many times that I will just make a list
here. Off the top of my head I can think of:

1. Netmon or Microsoft Message Analyzer
   * These tools isolate traffic by pid.
2. Procmon (Process Monitor)
   * Filter by process name and then `TCP/UDP Connect/Send/Receive`.
3. Procexp (Process Explorer)
   * The TCP/IP tab.
4. TCP Catcher or 3rd party other tools.

# The DNS Cache
You can interact with the DNS cache in different ways. Most common ways are:

* [ipconfig][ipconfig-docs]
  * View : `ipconfig /displaydns`
  * Clear: `ipconfig /flushdns`
* PowerShell
  * View : [Get-DnsClientCache][get-dns]
  * Clear: [Clear-DnsClientCache][clear-dns]

# Creating a PasteOps Prototype
We will use PowerShell because the output of commands are objects. We can format
the output at-will.

## PasteOps v1.0
The first iteration of our commands is completely manual. We copy/paste the
following command into the PowerShell console (or ISE during development):

1. `Clear-DnsClientCache`
2. Start Google Chrome or `ping google.com`
   * I will explaint the reason for this step below.
3. `$dns1 = Get-DnsClientCache`
4. Navigate to https://example.net.
5. `$dns2 = Get-DnsClientCache`
6. `Compare-Object -ReferenceObject $dns2 -DifferenceObject $dns1`

{{< imgcap title="Results of PasteOps" src="01.png" >}}

We have successfully discovered that the thick client (browser) has contacted
`example.net`.

### The Ping Step
In a real scenario, we want to clear the cache just right before starting the
application. In our PasteOps, `$dns1` might be empty if we call it just
right after clearing the cache and that will return an error when doing the
compare.

{{< imgcap title="Error when comparing with a null result" src="02.png" >}}

## What does Get-DnsClientCache Return?
Looking at the [Get-DnsClientCache][get-dns] documentation, we can see it
returns [MSFT_DnsClientCache][MSFT_DnsClientCache]:

```
class MSFT_DNSClientCache : CIM_ManagedElement
{
  string InstanceId;
  string Caption;
  string Description;
  string ElementName;
  string Entry;
  string Name;
  uint16 Type;
  uint32 TimeToLive;
  uint16 DataLength;
  uint8  Section;
  string Data;
  uint32 Status;
};
```

As we will see later, not all fields are populated for every record.

### Output Format
Table output in PowerShell is usually truncated but we can format the output
as objects unlike Bash[^1].

[Using Format Commands to Change Output View][using-format-commands] is a good
introduction to different output formats.

We can use `Format-Table` to get the output in a table and see truncated
results (it's fixable):

* `Get-DnsClientCache | Format-Table`

{{< imgcap title="Truncated results" src="03.png" >}}

We probably don't need to see all the fields, let's modify our command:

* `Get-DnsClientCache | Format-Table -Property Entry,RecordName,Data`

{{< imgcap title="RecordName does not exist" src="04.png" >}}

Wait, what? `RecordName` column is in the original output but does not exist
here. You might have also observed that you could use tab-complete for
the other two field names (e.g., `-Pro [tab] Ent [tab]` to get
`-Property Entry`) but not `RecordName`.

We have to use field names based on the return value which is
`MSFT_DNSClientCache`.

* `Get-DnsClientCache | Format-Table -Property Entry,Name,Type,Data`

{{< imgcap title="Columns based on object fields" src="05.png" >}}

Some field values like `Type` are different from the original command
output. Objects have some default printing formats. See the following link for
a similar command:

* http://www.viapowershell.com/2016/06/hidden-formatting.html

## Compare-Object Output
We have enough to write a PowerShell script to do the job. We can get the
output of both commands and then remove the duplicates with
[Compare-Object][compare-object].

The output of `Compare-Object` is a `PSCustomObject` that wraps the original
object with a slide indicator.

``` powershell
$ Compare-Object -ReferenceObject $dns2 -DifferenceObject $dns1

InputObject                                                        SideIndicator
-----------                                                        -------------
MSFT_DNSClientCache (Entry = "example.net", Name = "example.net")  <=
```

The `-PassThru` switch will spit out the unwrapped objects.

``` powershell
$ Compare-Object -ReferenceObject $dns2 -DifferenceObject $dns1 -PassThru

Entry           RecordName      Record Status    Section TimeTo Data   Data
                                Type                     Live   Length
-----           ----------      ------ ------    ------- ------ ------ ----
example.net     example.net     A      Success   Answer   77102      4 93.184.216.34
```

## PasteOps v2.0
Wrapped objects are not useful here. Let's add `-PassThru` to our PasteOps.

{{< codecaption title="PasteOps v2.0" lang="powershell" >}}
Clear-DnsClientCache
# Obviously replace this if you are looking to trace example.net
ping example.net
$dns1 = Get-DnsClientCache
# Run the application.
$dns2 = Get-DnsClientCache
Compare-Object -ReferenceObject $dns2 -DifferenceObject $dns1 -PassThru
{{< /codecaption >}}

We can directly work on objects and format the output in different ways or
export them with something like [Export-Csv][export-csv] for later use.

* https://github.com/parsiya/Parsia-Code/blob/master/dns-cache/pasteops-v2.ps1

# PowerShell Script
The next step after PasteOps is combining all these commands into a PowerShell
script.

{{< codecaption title="Endpoint-Discovery v1.0" lang="powershell" >}}
Write-Output "Clearing the DNS cache"
Clear-DnsClientCache
Write-Output "Pinging example.net to populate the DNS cache"
Invoke-Expression "ping example.net" | Out-Null
Write-Output "Creating a snapshot of the DNS cache"
$dns_before = Get-DnsClientCache
Read-Host "Start the application and interact with it. Press Enter when done"
Write-Output "Creating a snapshot of the DNS cache"
$dns_after = Get-DnsClientCache
Compare-Object -ReferenceObject $dns2 -DifferenceObject $dns1 -PassThru
{{< /codecaption >}}

* https://github.com/parsiya/Parsia-Code/blob/master/dns-cache/endpoint-discovery.ps1

If we run the script and open up Google Chrome when prompted, we can see:

{{< imgcap title="Endpoints used by Google Chrome" src="06.png" >}}

We can pass the command output (which is a list of objects) to pipes and
manipulate it:

{{< imgcap title="Manipulating command output" src="07.png" >}}

# Limitations
Any connection method that does not end up in the DNS cache is not discoverable
by this method. This usually happens when the application:

* Does its own DNS lookup.
* Contacts the endpoint by IP.

Full automation might be an issue. It's definitely feasible to integrate the
script into an automation framework and harvest the endpoints. It will miss
endpoints unless you know that your framework can call all application
functionality.

# What Did We Learn Here Today?

1. We can use the Windows DNS cache to do endpoint discovery.
2. A simple PowerShell script allows us to collect this endpoints and spits out
   objects that can be manipulated however you want.

<!-- Footnotes -->
[^1]: Bash bashing.

<!-- Links -->
[ipconfig-docs]: https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/ipconfig
[get-dns]: https://docs.microsoft.com/en-us/powershell/module/dnsclient/get-dnsclientcache
[clear-dns]: https://docs.microsoft.com/en-us/powershell/module/dnsclient/clear-dnsclientcache
[MSFT_DnsClientCache]: https://msdn.microsoft.com/en-us/library/hh872334(v=vs.85).aspx
[using-format-commands]: https://docs.microsoft.com/en-us/powershell/scripting/samples/using-format-commands-to-change-output-view
[compare-object]: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/compare-object
[manual-work-bug]: https://queue.acm.org/detail.cfm?id=3197520
[export-csv]: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-csv