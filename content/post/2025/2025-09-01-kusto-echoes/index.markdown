---
title: "Kusto Detective Agency: Echoes of Deception - 0-8 Solves"
date: 2025-09-01T20:00:00-07:00
draft: false
toc: true
twitterImage: 
url: /blog/2025-kda-echoes
categories:
- Kusto
---

Kusto is kinda important at my current employer and one of my work besties does
SecOps. So, I've decided to learn more Kusto. Solves for the first eight tasks
for Kusto Detective Agency challenge Echoes of Deception.

<!-- More -->

It turns out Kusto is not just a better looking SQL, it does a lot more. E.g.,
it can make a graph and find paths (yes, as I've just searched, T-SQL can also
do this). It makes me wonder if we can do some esoteric data flow static
analysis by converting the AST into rows of data and finding paths from sources
to sinks (or am I reinventing CodeQL, again, lol [^1]).

[^1]: My last CodeQL reinvention was creating a database from code for static
    analysis which is essentially what a [CodeQL Extractor][codeql-extactor] is.

[codeql-extactor]: https://docs.github.com/en/code-security/codeql-cli/using-the-advanced-functionality-of-the-codeql-cli/extractor-options

There are a series of challenges named [Kusto Detective Agency][kda] which are
basically "find this flag in a bunch of logs with KQL." A few months ago, I was
enthusiastic and started season 3 `Call of the Cyber Duty` in real time with
almost zero Kusto background and did the first three before I realized, this is
much harder than I imagined.

[kda]: https://detective.kusto.io/

I started from season 1 to learn and do the challenges. Here are the first eight
(or nine if you count onboarding) solves.

# Typical Workflow
Each challenge has a bunch of "training" material associated with it. These are
Kusto functionalities and tricks that can be used to solve the challenge. I
didn't notice them in my season 3 run.

Then I look at the tables. We can get the table columns and types with a query
like this:

```
TableName
| getschema
| project ColumnName, DataType
```

And it will give us something like this:

```
Timestamp	System.DateTime
callsign	System.String
lat	        System.Double
lon	        System.Double
```

Then I check the first 10 rows to see what the data looks like:

```
TableName
| take 10
```

Then I try to figure out how to solve the challenge using the training material.

## Using AI
AI (LLMs in this context) was kinda both good and bad here. It was great for
syntax issues, AKA "I want to filter A and B, write a Kusto query for me", but
not great for the actual solves. I usually added all the data, table schemas and
other insights from training to a markdown file and asked different models in
GitHub Copilot Chat to solve. It actually worked for the first 2-3 challenges,
but not after.

I had the best results with Claude 4 and GPT-5. Both have a tendency to ya[^2]
and over complicate things even with extensive instructions. It was a fun
experience to yank them often and try to herd AI into the correct solve path.

[^2]: Even more than me and I am called Yapsia in certain circles.

# 0: Onboarding
We need to find which detective has earned the most bounties.

```
DetectiveCases
| take 2
```

We have five columns:

```
Timestamp
EventType
DetectiveId
CaseId
Properties
```

See different types of `EventType`

```
DetectiveCases
| distinct EventType

CaseUnsolved
CaseAssigned
CaseSolved
CaseOpened
```

If `CaseOpened`, `Properties` will have the bounty: `{"Bounty":3146}`.

We can extract bounties:

```
let bounties = DetectiveCases
| where EventType == "CaseOpened"
| extend Bounty = tolong(Properties.Bounty)
| project CaseId, Bounty;
```

I wrote a query that added up all detective bounties using `CaseSolved` events.
It was the wrong answer. I should have checked if the detective was assigned the
case in a `CaseAssigned` event AND if they had a `CaseSolved` event for the same
case ID. Apparently, you can solve a case  get no bounty if you were not
assigned the case.

We can extract assignments like this:

```
let assignments = DetectiveCases
| where EventType == "CaseAssigned"
| project CaseId, AssignedDetectiveId = DetectiveId;
```

Sum for the IDs that are the same for assigned and solved.

```
let bounties = DetectiveCases
| where EventType == "CaseOpened"
| extend Bounty = tolong(Properties.Bounty)
| project CaseId, Bounty;
let assignments = DetectiveCases
| where EventType == "CaseAssigned"
| project CaseId, AssignedDetectiveId = DetectiveId;
DetectiveCases
| where EventType == "CaseSolved"
| project CaseId, SolvedDetectiveId = DetectiveId
| join kind=inner assignments on CaseId
| where SolvedDetectiveId == AssignedDetectiveId
| join kind=inner bounties on CaseId
| summarize total = sum(Bounty) by SolvedDetectiveId
| sort by total desc
```

And the top three are:

```
kvc61f0b891ee26195970a	874,699
kvc12a22e9e9e65c1694f1	838,852
kvc29d392ca965f09646f8	812,028
```

Our answer is `kvc61f0b891ee26195970a`.

# Case 1: To bill or not to bill?
`What is the total bills amount due in April?`

Old SQL query to calculate bills:

```sql
SELECT SUM(Consumed * Cost) AS TotalCost
FROM Costs
JOIN Consumption ON Costs.MeterType = Consumption.MeterType
```

The `Costs` table has only two rows:

Cost columns:

```
| MeterType   | Unit  | Cost     |
| ----------- | ----- | -------- |
| Water       | Liter | 0.001562 |
| Electricity | kwH   | 0.3016   |
```

The `Consumption` table has four columns:

* `Timestamp`
* `HouseholdId`
* `MeterType`
* `Consumed`

So:

1. Timestamp should be in April.
2. Ignore HouseholdId because we want the total.
3. Each bill is Consumed * Cost based on MeterType.

We only have April data so we don't need to check the Timestamp, but I did it
anyways. [getmonth][getmonth] (also called `monthofyear`) is a fun function and
`getmonth(Timestamp) == 4` checks if the timestamp's month is April.

[getmonth]: https://learn.microsoft.com/en-us/kusto/query/monthofyear-function

```
Consumption
| where getmonth(Timestamp) == 4
| summarize total_consumed = sum(Consumed) by MeterType
| join kind=inner (Costs) on MeterType
| extend bill = total_consumed * Cost
| summarize total = sum(bill)
```

This works, but doesn't have the correct answer `35,637,875.19770707`.

Checking for duplicates:

```
Consumption
| where getmonth(Timestamp) == 4
| summarize Count = count() by Timestamp, HouseholdId, MeterType, Consumed
| where Count > 1
| take 10
```

There are a lot of 2 counts. So we try to get distinct

```
Consumption
| where getmonth(Timestamp) == 4
| distinct Timestamp, HouseholdId, MeterType, Consumed
| summarize total_consumed = sum(Consumed) by MeterType
| join kind=inner (Costs) on MeterType
| extend bill = total_consumed * Cost
| summarize total = sum(bill)
```

Looks like there might be multiple reports per household per day. Some of them
are negative which is curious. At first both me and AI thought a negative is
either correction or a house selling solar energy back, but it turns out
duplicates and negatives are invalid and we need to filter these out.

```
Consumption
| where getmonth(Timestamp) == 4
| where Consumed > 0
| distinct Timestamp, HouseholdId, MeterType, Consumed
| summarize total_consumed = sum(Consumed) by MeterType
| join kind=inner (Costs) on MeterType
| extend bill = total_consumed * Cost
| summarize total = sum(bill)
```

And the answer is `35420883.072401375`.

# Case 2: Catch the Phishermen!
`What phone number is used for placing the phishing calls?`

The import for this case took 70 seconds there must be lots of data.

One table `PhoneCalls`:

* `Timestamp`
* `EventType`: `Connect`, `Disconnect`
* `CallConnectionId`: guid
* `Properties`: JSON

If EventType is `Disconnect`, then `Properties` says who disconnected the call.

```json
{"DisconnectedBy":"Origin"}
{"DisconnectedBy":"Destination"}
```

For Connect we get something like this:

```json
{"Origin":"06635832122","Destination":"06370200090","IsHidden":false}
{"Origin":"06360086060","Destination":"06549896514","IsHidden":true}
```

Let's extract everything:

```
PhoneCalls
| where EventType == "Connect"
| extend Props = parse_json(Properties)
| extend Origin = tostring(Props.Origin)
| extend Destination = tostring(Props.Destination)
| extend IsHidden = tobool(Props.IsHidden)
| project-away Props
```

We can assume phishing callers hide their number. That gives us 1901071 calls.

```
PhoneCalls
| where EventType == "Connect"
| extend Props = parse_json(Properties)
| extend Origin = tostring(Props.Origin)
| extend Destination = tostring(Props.Destination)
| extend IsHidden = tobool(Props.IsHidden)
| project-away Props
| where IsHidden == true
| count
```

We need to summarize the count by `Origin` to see which numbers make lots of
calls.

```
PhoneCalls
| where EventType == "Connect"
| extend Props = parse_json(Properties)
| extend Origin = tostring(Props.Origin)
| extend Destination = tostring(Props.Destination)
| extend IsHidden = tobool(Props.IsHidden)
| project-away Props
| where IsHidden == true
| summarize TotalCalls = count() by Origin
| order by TotalCalls desc
```

There's no number that stands out.

```
| Phone       | TotalCalls |
| ----------- | ---------- |
| 06749360920 | 257        |
| 06836757512 | 248        |
| 06784884765 | 248        |
| 06422797186 | 164        |
| 06632227502 | 162        |
| 06226870181 | 158        |
| 06890115685 | 158        |
| 06371507378 | 158        |
// ...
```

Then we add average call duration (I asked Claude to write this):

```
PhoneCalls
| where EventType == "Connect"
| extend Props = parse_json(Properties)
| extend Origin = tostring(Props.Origin)
| extend Destination = tostring(Props.Destination)
| extend IsHidden = tobool(Props.IsHidden)
| project-away Props
| where IsHidden == true
| join kind=inner (
    PhoneCalls
    | where EventType == "Disconnect"
) on CallConnectionId
| extend CallDuration = datetime_diff('second', Timestamp1, Timestamp)
| summarize 
    TotalCalls = count(),
    AvgDuration = avg(CallDuration),
    UniqueDestinations = dcount(Destination)
    by Origin
| order by UniqueDestinations desc, AvgDuration asc, TotalCalls desc
```

And the result is interesting.

```
| PhoneNum    | UniqueDestinations | AvgDuration | TotalCalls |
| ----------- | ------------------ | ----------- | ---------- |
| 06749360920 | 257                | 297.96      | 256        |
| 06784884765 | 248                | **145.78**  | 248        |
| 06836757512 | 248                | 296.06      | 248        |
| 06422797186 | 164                | 305.83      | 163        |
| 06632227502 | 162                | 301.44      | 162        |
```
    
The 2nd number's average call duration (145) is half of the others. That is our
phisher: `06784884765`.

# Case 3: Return stolen cars!
`Where are the stolen cars being kept?`

We have two tables:

```
StolenCars
| take 10

// One column - VIN
```

And

```
CarsTraffic
| take 10

// Timestamp
// VIN
// Ave
// Street
```

We should to check where the stolen cars appear frequently, but we need to
add unique VINs because otherwise it will capture the same car going home.

```
let stolen = StolenCars;
CarsTraffic
| where VIN in (stolen) // Remember kusto-mice? No need to join only one column.
| summarize Appearances = count(), UniqueVINs = dcount(VIN) by Ave, Street
| order by Appearances
```

Top three:

```
| Ave | Street | Appearances | UniqueVINs |
| --- | ------ | ----------- | ---------- |
| 223 | 86     | 223         | 12         |
| 122 | 248    | 122         | 10         |
| 223 | 98     | 223         | 9          |
```

Top address has 12 unique VINs. But that is not the answer. Looks like we need
to find all 20 stolen cars going to the address (the task assumes only one
entity with one chop shop is stealing cars).

Maybe they are changing VINs. So first we find the last location of every stolen
VIN.

```
let stolen = StolenCars;
let last_locations = CarsTraffic
| where VIN in (stolen)
| summarize LastTimestamp = max(Timestamp) by VIN
| join kind=inner (CarsTraffic) on VIN
| where Timestamp == LastTimestamp
| project VIN, LastTimestamp, Ave, Street;
```

Then we need to see which new VINs appear in the same location within a short
time, let's say 5 minutes.

```
let stolen = StolenCars;
let last_locations = CarsTraffic
| where VIN in (stolen)
| summarize LastTimestamp = max(Timestamp) by VIN
| join kind=inner (CarsTraffic) on VIN
| where Timestamp == LastTimestamp
| project VIN, LastTimestamp, Ave, Street;
CarsTraffic
| join kind=inner (last_locations) on Ave, Street
| where Timestamp > LastTimestamp and Timestamp <= LastTimestamp + 5m
| where VIN !in (stolen)  // Find NEW VINs that appear at same location
| summarize NewVINs = make_set(VIN), NewVINCount = dcount(VIN) by Ave, Street
| order by NewVINCount desc
```

We get two answers

```
| Ave | Street | NewVINs   | NewVINCount |
| --- | ------ | --------- | ----------- |
| 223 | 86     | [removed] | 227         |
| 122 | 251    | [removed] | 118         |
```

We've already tried the first one, it might be second one. That is also wrong.

We modify the query a bit. We check whether the VIN has changed within 10
minutes and create a list of possible new VINs. Then check where they appear
last and look which one is closest to the number of stolen cars (20).

```
let stolen = StolenCars;
let last_locations = CarsTraffic
| where VIN in (stolen)
| summarize LastTimestamp = max(Timestamp) by VIN
| join kind=inner (CarsTraffic) on VIN
| where Timestamp == LastTimestamp
| project VIN, LastTimestamp, Ave, Street;
let new_vins = CarsTraffic
| join kind=inner (last_locations) on Ave, Street
| where Timestamp > LastTimestamp and Timestamp <= LastTimestamp + 10m
| where VIN !in (stolen)
| distinct VIN;
CarsTraffic
| where VIN in (new_vins)
| summarize arg_max(Timestamp, *) by VIN
| summarize UniqueVINs = dcount(VIN), TotalAppearances = count() by Ave, Street
| order by UniqueVINs desc
```

This is the result. The answer is the third one with 21 unique VINs `156 81`

```
| Ave | Street | UniqueVINs | TotalAppearances |
| --- | ------ | ---------- | ---------------- |
| 223 | 86     | 59         | 59               |
| 122 | 251    | 49         | 49               |
| 156 | 81     | 21         | 21 <---          |
| 183 | 94     | 2          | 2                |
```

# Case 4: Triple trouble!
`Who is behind all this?`

Two new tables. `IpInfo` and `NetworkMetrics`.

```
IpInfo
| take 10

// IpCidr
// Info - Name of the owner
```

And

```
NetworkMetrics

// Timestamp
// ClientIP
// TargetIP
// BytesSent
// BytesReceived
// NewConnections
```

Where do we even start? I checked the hints for the first (and last) time.
Summary of hints:

```
Hint 1: Uncover the Hidden Trail

Delve deeper into the telemetry data and consider the possibility of a longer
preparation period that preceded the breach.

Hint2: Exposing the Leaker

Analyze the patterns, spikes, or anomalies that indicate a massive influx of data.
(Keyword here is "anomaly").

Hint 3: Unmasking the Cunning Intruders

observe the changes in usage patterns across the entire attacker network.
```

First we want to see which IP addresses received/sent a lot of data and it turns
out we can find the IP address that had the secret data (probably?).

```
NetworkMetrics
| summarize TotalBytesSent = sum(BytesSent) by Day = bin(Timestamp, 1d), TargetIP
| top 20 by TotalBytesSent
```

17 of the top 20 IP addresses in the result are `178.248.55.249` so that is msot
likely the victim system, and it belongs to DigiTown. Note the fun
[ipv4_is_in_range][ipv4_inrange] function which LLMs didn't know until I
mentioned it.

[ipv4_inrange]: https://learn.microsoft.com/en-us/kusto/query/ipv4-is-in-range-function

```
IpInfo
| where ipv4_is_in_range("178.248.55.249", IpCidr)
| project IpCidr, Info

// 178.248.55.0/24	DIGITOWN
```

We know we need to detect anomalies. So let's look at the times with the
suspicious transfers. The training mentioned creating a graph and using
[series_decompose_anomalies][ano] which I'd never seen before.

[ano]: https://learn.microsoft.com/en-us/kusto/query/series-decompose-anomalies-function

I did some experiments to see how it works. 1 day appear to be a good compromise
and will tell us which day was anomalous.

```
NetworkMetrics
| make-series BytesSent=sum(BytesSent) on Timestamp step 1d
| extend anomalies = series_decompose_anomalies(BytesSent)
```

The result is one row with three columns. Each column is an array. Columns are:

* `BytesSent`
* `Timestamp`
* `anomalies`: Vector liks `[0,0,... ,1,0]` with only one `1`.

So I need to `extend` this to get the data out and then look for the only point
with the `1`.

```
NetworkMetrics
| make-series BytesSent=sum(BytesSent) on Timestamp step 1d
| extend anomalies = series_decompose_anomalies(BytesSent)
| mv-expand
    BytesSent to typeof(long),
    Timestamp to typeof(datetime),
    anomalies to typeof(double)
| where anomalies > 0
```

And this gives us

```
255,535,868,619	6/29/2023, 12:00:00 AM	1
```

So we've found the date where the bad things happened. We need to see which
IP addresses sent the most data on that day?

I learned another trick from Liesel Hughes. Their tech blog is gone but the
[archive link][liesel] remains.

[liesel]: https://web.archive.org/web/20231206104114/https://www.lieselhughes.com/posts/tech/kusto-detective-agency/season2case4/

They expanded the `IPCidr` table and resolved all IP addresses into a new
table with this trick. I remember I got stuck in this exact same phase in task
four of season 3. This is very similar to that task.

```
.set-or-replace IpInfoEx <|
    NetworkMetrics
    | distinct ClientIP 
    | evaluate ipv4_lookup(IpInfo, ClientIP, IpCidr)
```

This creates a new table for each unique IP in the dataset that we can use.

```
| ClientIP        | IpCidr           | Info                      |
| --------------- | ---------------- | ------------------------- |
| 146.19.241.91   | 146.19.241.0/24  | ALTANET-AS                |
| 161.199.246.241 | 161.199.246.0/24 | COEOSOLUTIONS             |
| 98.173.151.101  | 98.173.144.0/21  | ASN-CXA-ALL-CCI-22773-RDC |
```

It turns out that I was using the [series_decompose_anomalies][ano] wrong and it
has three results: `anomaly`, `score`, and `baseline`.

Using the trick from Liesel, we can change our query to look up the owners of
`IpCidrs` from the new `IpInfoEx` table.

```
NetworkMetrics
| lookup IpInfoEx on ClientIP
| make-series BytesSent=sum(BytesSent) on Timestamp step 1d by Info
| extend (Anomaly, Score, Baseline) = series_decompose_anomalies(BytesSent)
| mv-expand
    Anomaly to typeof(double),
    Score to typeof(double),
    // We can ignore Baseline
    BytesSent to typeof(long)
| where Anomaly != 0 // Not sure what negative anomaly scores mean.
| project Info, Score
| sort by Score desc
```

And the first result is `KUANDA.ORG` which is our answer.

# Case 5: Blast into the past
`What is the link to secret interview?`

Apparently there's a secret interview. The 900th episode of Scott Hanselman's
podcast that was unpublished and is in these logs.

New table `StorageArchiveLogs`

```
// Timestamp
// Event
```

`EventText` has three types:

```
Read blob transaction: 
'https://agjmmlhdu.blob.core.windows.net/eqjotm/qdlyqqhgik.mp2' read access
(1 reads) were detected on the origin

Delete blob transaction:
'https://qxjkisxw.blob.core.windows.net/ypfsrg/xvyvhtihrm.mpe' backup is
completely removed

Create blob transaction:
'https://oxdnbbgqup.blob.core.windows.net/svlkp/yragrkd.mpg' backup is created on
https://2023storagebackup.blob.core.windows.net/oxdnbbgqup/svlkp/yragrkd.mpg
```

The training section teaches how to extract different types of `EventText`. So
we can parse everything.

```
StorageArchiveLogs
| parse EventText with TransactionType " blob transaction: '" BlobURI "'" *
| parse EventText with * "(" Reads:long "reads)" *
| parse EventText with * "backup is created on " BackupURI
| extend Host = tostring(parse_url(BlobURI).Host)
| project-away EventText
```

The training also teaches us `count/sum if` functions to summarize different
transaction types. AI didn't know so I had to explain them and ask it to rewrite
the query with those.

```
StorageArchiveLogs
| parse EventText with TransactionType " blob transaction: '" BlobURI "'" *
| parse EventText with * "(" Reads:long "reads)" *
| parse EventText with * "backup is created on " BackupURI
| extend Host = tostring(parse_url(BlobURI).Host)
| project-away EventText
| summarize Deletes=countif(TransactionType == 'Delete'), 
		Reads=sumif(Reads, TransactionType == 'Read') by Host
```

I used anomaly detection as a crutch, but turns out this was much easier. We
know the interview was published and then deleted. We want a blob that was
created, backed up, and deleted.

```
StorageArchiveLogs
| parse EventText with TransactionType " blob transaction: '" BlobURI "'" *
| parse EventText with * "backup is created on " BackupURI
| extend FileName = tostring(parse_url(BlobURI).Path)
| summarize 
    Creates = countif(TransactionType == 'Create'),
    Deletes = countif(TransactionType == 'Delete'),
    BackupURIs = make_set_if(BackupURI, isnotempty(BackupURI))
    by BlobURI, FileName
| where Creates > 0 and Deletes > 0  // created and deleted
| where array_length(BackupURIs) > 0 // has backup
| project BlobURI, FileName, SecretInterviewLinks = BackupURIs
```

This query returned over 17000 rows. But we know it was published and then
quickly deleted so the time between creation and deletion must be small.
I modified the query to track the time between creation and deletion.

```
StorageArchiveLogs
| parse EventText with TransactionType " blob transaction: '" BlobURI "'" *
| parse EventText with * "backup is created on " BackupURI
| extend FileName = tostring(parse_url(BlobURI).Path)
| summarize 
    CreateTime = minif(Timestamp, TransactionType == 'Create'),
    DeleteTime = maxif(Timestamp, TransactionType == 'Delete'),
    Creates = countif(TransactionType == 'Create'),
    Deletes = countif(TransactionType == 'Delete'),
    BackupURIs = make_set_if(BackupURI, isnotempty(BackupURI))
    by BlobURI, FileName
| where Creates > 0 and Deletes > 0  // created and deleted
| where array_length(BackupURIs) > 0 // has backup
| extend LifetimeMinutes = datetime_diff('minute', DeleteTime, CreateTime)
| where LifetimeMinutes > 0          // valid timespan
| project BlobURI, FileName, BackupURIs, CreateTime, DeleteTime, LifetimeMinutes
| order by LifetimeMinutes asc
```

The top entry in this result set was deleted only after six minutes.

```
"BlobURI": https://okeexeghsqwmda.blob.core.windows.net/vyskl/jqfovf.mp4,
"FileName": /vyskl/jqfovf.mp4,
"BackupURIs": [
  "https://2023storagebackup.blob.core.windows.net/okeexeghsqwmda/vyskl/jqfovf.mp4"
],
"CreateTime": 2023-07-12T14:12:00.000Z,
"DeleteTime": 2023-07-12T14:18:00.000Z,
"LifetimeMinutes": 6
```

The answer is the back up at:
`https://2023storagebackup.blob.core.windows.net/okeexeghsqwmda/vyskl/jqfovf.mp4`.

# Case 6: Hack this rack!
`Who is the leader of Kuanda.org?`

```
NationalGalleryArt
| take 10

| ColumnName     | Notes                   |
| -------------- | ----------------------- |
| ObjectId       | Unique ID of the object |
| Title          |                         |
| BeginYear      |                         |
| EndYear        |                         |
| Medium         |                         |
| Inscription    |                         |
| Attribution    |                         |
| AssistiveText  | Could be empty          |
| ProvenanceText | Could be empty          |
| Creditline     |                         |
| Classification | See below               |
| ImageUrl       | URL. Could be empty     |
```


`Classification` can be:

```
Index of American Design
Photograph
Print
Volume
Portfolio
Drawing
Painting
Sculpture
Time-Based Media Art
Technical Material
Decorative Art
```

And apparently this is the code:

```
12204/497 62295/24 50883/678 47108/107 193867/3,
45534/141 hidden 100922/183 143461/1 1181/505 46187/380.
41526/155 66447/199 30241/114, 33745/154 12145/387 46437/398 177191/131:
293/64 41629/1506 210038/432, 41612/803 216839/1.

404/258 rules 40/186 1472/222 122894/2 46081/105:
41594/650 32579/439 44625/141 184121/19 33254/348 357/273 32589/821,
46171/687 punctuations 62420/10 50509/48 1447/128,
176565/82'56721/591 561/225 insensitive, 30744/129 76197/32.

1319/42 41599/216 68/457 136016/146, 42420/126'46198/389 42429/158 40091/108 41667/252,
1515/555 177593/223 176924/73 45889/65 159836/96 35080/384 32578/199.
1607/167 124996/9 71/56, 1303/187 45640/1114 72328/247 75802/11,
1168/146 163380/12 57541/116 206122/738 365/267 46026/211 46127/19.

119295/425 45062/128 12198/133 163917/238 45092/8 54183/4 42453/82:
561/433 9/387 37004/287 1493/118 41676/38 163917/238 3159/118 63264/687
1/905 1493/109 43723/252, 136355/1 1159/134 40062/172 32588/604,
158574/1 45411/8 10/892 127587/175 - 633/9 72328/247 1514/615 42940/138.

164958/84 221014/479 151526/7 111124/138, 41668/206 34109/46 1514/555,
147789/2 3228/152 993/323 166477/167 178042/167, 50753/91'207786/8 12/372.
1108/158'42423/150 12/309 66154/9 213566/11 44981/158 1197/300
40184/149 92994/63-71071/179 75093/7 211718/18 74211/5 46144/399.
```

I assumed this is text and each item points to something in the collection that
resolves to a letter. Is the first item the object ID? Maybe?

If it's one of the fields, then the field needs to be long. Because some of
these second numbers are large like 497. The only fields long enough are
`Inscription` and `ProvenanceText`.

Or maybe we concatenate all the fields except `ObjectId` and the 2nd number is
the index (this was overthinking).

It looks like only `ProvenanceText` is long enough to be the second field. But
these do not appear to be single letters because we have things like
`1108/158'42423/150` so each one is a word. In the training section for this
case, we also calculated the word count with regex like below. We're
definitely looking for words.

```
Recipe
| extend words = extract_all(@"(\w+)", Text)
| extend WordCount = array_length(words)
```

I extracted the numbers using regex in VS Code and wrote this query:

```
let code = datatable (ObjectId: int, WordIndex: int) [
  12204,497, 62295,24 // removed
];
code
| join kind=inner (
    NationalGalleryArt
    | extend ObjectId = toint(ObjectId)
    | extend words = extract_all(@"(\w+)", ProvenanceText)
    | project ObjectId, words
) on ObjectId
| extend extractedWord = iff(WordIndex <= array_length(words), words[WordIndex-1], "")
| project extractedWord
```

It extracted a bunch of words for me, but the sequence was not preserved. So I
asked AI for solutions and then added a sequence to the table like this.

```
let code = datatable (ObjectId: int, WordIndex: int) [
  12204,497, 62295,24 // removed
]
| serialize
| extend Sequence = row_number();
code
| join kind=inner (
    NationalGalleryArt
    | extend ObjectId = toint(ObjectId)
    | extend words = extract_all(@"(\w+)", ProvenanceText)
    | project ObjectId, words
) on ObjectId
| extend extractedWord = iff(WordIndex <= array_length(words), words[WordIndex-1], "")
| order by Sequence asc // preserving the sequence
| project extractedWord
```

But it was not correct. I had assumed the index is from zero
`words[WordIndex-1]`. Classic dev vs. data world off-by-one clash, we have to
index from 1,

```
let code = datatable (ObjectId: int, WordIndex: int) [
  12204,497, 62295,24 // removed
]
| serialize
| extend Sequence = row_number();
code
| join kind=inner (
    NationalGalleryArt
    | extend ObjectId = toint(ObjectId)
    | extend words = extract_all(@"(\w+)", ProvenanceText)
    | project ObjectId, words
) on ObjectId
                                                               // 1-index
| extend extractedWord = iff(WordIndex <= array_length(words), words[WordIndex], "")
| order by Sequence asc
| project extractedWord
```

And this is the result (after adding punctuation from the original code)

```
in catalogue of titles Grand,
three hidden words Demand your Hand
when found all, they form A line:
A clear timeline, simply Fine

words rules are simple to Review:
at least three Letters have in view,
all punctuations Mark the End,
they're case insensitive, my friend

to find all words, you'll need some skill,
seeking the popular will guide you still
below The King, the first word mounts,
the Second shares with Third their counts

reveal the last word with Wise thought:
take first two letters from word most sought
into marked dozen, and change just one,
and with those two – the word is done

so search the titles, high and low,
and when you find it, you'll know
you've picked the Image that revealed
the pass-code to the World concealed
```

Which is a riddle.

First I thought the riddle means this. Spoiler alert: some assumptions are
wrong.

1. Search the `Title` field.
2. We need three words.
3. Each word is at least three letters.
4. Words are case-insensitive.
5. First word is the 2nd most common? (below "The King")
6. The second and third word have the same word count.
7. Take first two letters from the most common word. Put them in a 12 letter
   word and change one letter to get the third word.

We can get the word count:

```
let wordCounts = NationalGalleryArt
| extend words = extract_all(@"(\w+)", Title)
| mv-expand word = words
| where isnotempty(word) and strlen(word) >= 3  // at least 3 letters
| extend word = tolower(tostring(word))  // case insensitive
| summarize Count = count() by word
| order by Count desc, word asc;
```

And the first five words are:

```
| Word     | Count  |
| -------- | ------ |
| the      | 25,417 |
| and      | 11,157 |
| untitled | 7,587  |
| with     | 7,541  |
| for      | 3,228  |
```

So `and` is the first word? Doesn't look like it. "below The King" doesn't mean
the second most frequent word. After an hour of thinking, I realized it means
the word after the word `king` in the frequency ranking. So we add the rank to
the table.

Originally I had this based on Claude suggestions:

```
let wordCounts = ...
...
| serialize
| extend Rank = row_number();
```

Then I did a bit of searching and realized I can do it easier with
[row_rank_min(Count)][row-rank-min].

[row-rank-min]: https://learn.microsoft.com/en-us/kusto/query/row-rank-min-function

```kql
let wordCounts = NationalGalleryArt
| extend words = extract_all(@"(\w+)", Title)
| mv-expand word = words
| where isnotempty(word) and strlen(word) >= 3  // at least 3 letters
| extend word = tolower(tostring(word))  // case insensitive
| summarize Count = count() by word
| order by Count desc, word asc
| extend Rank = row_rank_min(Count);
let kingRank = toscalar(wordCounts | where word == "king" | project Rank);
wordCounts
| where Rank == kingRank + 1
| project word, Count, Rank
```

And the answer is `day`.

The second and third words have the same ranking which is hard to find. I wanted
to create something that checks all words with same rank. But then I realized
this assumptions was also wrong and the riddle means the second word has the
same rank as the word "Third."

```kql
// Find the rank of "third" and all words with the same rank
let thirdRank = toscalar(wordCounts | where word == "third" | project Rank);
wordCounts
| where Rank == thirdRank
| project word, Count, Rank
```

This returned five results.

```
daphnis
fruit
macchina
third
year
```

But our first word was `day` and the hints means they all refer to time.

```
when found all, they form A line:
A clear timeline, simply Fine
```

The second word is `year`.

My prediction about the last word was also wrong. I searched for 12
letter words and found nothing. I am not "Wise" lmao.

```
reveal the last word with Wise thought:
take first two letters from word most sought
into marked dozen, and change just one,
and with those two – the word is done
```

This means we take the first two letters from the word with rank 1 (`the`) and do
something with rank 12 (`man`). Let's get them.

```
| Word | Count  | Rank |
| ---- | ------ | ---- |
| the  | 25,417 | 1    |
| man  | 2,217  | 12   |
```

`th` + `man` == `than`? No that has nothing to do with time.

Let's read it again. Get `th` and then add to `man` and change one letter. So
the letters are `thman` and one must be modified and it must be related to time
because our other words where `day` and `year`.

And the answer is `month` according to Claude :)

This means we need to find the title that has all these three words.

```
NationalGalleryArt
| where Title has_all ("day", "month", "year")

ID: 222,050	
// removed
https://api.nga.gov/iiif/64c9eb07-5e01-40fe-8fd0-886cfb4a70c7/full/!900,900/0/default.jpg
```

Oh, shit, I can read this because it's in Farsi, lol. I thought the text had
clues, but no.

But apparently, this is about the website from last task. Go to `KUANDA.ORG` and
click `join the club`. Needs passcode and login hint. We add this URI as login
hint.

We still need the passcode, but now the Octopus has some letters: `kotspusot`.

Which is an anagram of `stopkusto`. Both me and AI were useless here. I was
looking for a one-word anagram for 30 minutes..

Inside we see a letter signed by `Krypto` and that is our answer.

# Case 7: Mission 'Connect'
`In which city did the suspect land?`

Two new tables `Flights`.

```
Flights
| getschema
| project ColumnName, DataType

| ColumnName  | DataType        |
| ----------- | --------------- |
| Timestamp   | System.DateTime |
| callsign    | System.String   |
| lat         | System.Double   |
| lon         | System.Double   |
| velocity    | System.Double   |
| heading     | System.Double   |
| vertrate    | System.Double   |
| onground    | System.SByte    |
| geoaltitude | System.Double   |
```

And `Airports`

```
Airports
| getschema
| project ColumnName, DataType

| ColumnName   | DataType      |
| ------------ | ------------- |
| Id           | System.String |
| Ident        | System.String |
| Type         | System.String |
| Name         | System.String |
| lat          | System.Double |
| lon          | System.Double |
| elevation_ft | System.Int64  |
| iso_country  | System.String |
| iso_region   | System.String |
| municipality | System.String |
| gps_code     | System.String |
| local_code   | System.String |
```

Training talks about geo hashing values and using the S2 geo-hash algorithm.

Problem:

1. Kryto was in Doha airport.
2. Between August 11, 2023, between 03:30 AM and 05:30 AM (UTC).
3. Left with a jet and then switched planes mid-air.

My assumptions (I wasn't wrong this time):

1. Find flights that left Doha airport between 03:30 AM and 05:30 AM.
2. Find which flights came close to those flights and he might have jumped to them.
    1. What is a good s2 precision point here? What is the distance for a wingsuit plane-to-plane jump?
3. Assuming he has done only one jump. Let's find where all those flights landed.

The airport is Doha is `Hamad International Airport`.

```
Airports
| where municipality contains "doha"

"Id": 44686,
"Ident": OTHH,
// removed
```

So I wrote a function that find all planes on the ground in an airport from a
certain timestamp until n hours later.

```
let flightsFromAirport = (AirportIdent:string, StartTime:datetime, HoursToAdd:int) {
    let EndTime = datetime_add('hour', HoursToAdd, StartTime);
    Airports
    | where Ident == AirportIdent
    | extend key=geo_point_to_s2cell(lon, lat) // default precision is 11
    | join kind=inner (
        Flights
        | extend key=geo_point_to_s2cell(lon, lat)
        | where onground
        | where Timestamp between (StartTime .. EndTime)
    ) on key
    | distinct callsign
};
flightsFromAirport("OTHH", datetime(2023-08-11 03:30:00), 2)
```

We find 19 flights and Krypto left on one. We are using the default s2_precision
of 11.

Now to match the other flights. We need to find all flights that departed after
5:30:00, were not on the ground and flew close to these 19 flights.

```
let departures = flightsFromAirport("OTHH", datetime(2023-08-11 03:30:00), 2);
Flights
| where Timestamp > datetime(2023-08-11 05:30:00)
| where onground == false
| where callsign in (departures)
| extend key=geo_point_to_s2cell(lon, lat)
| join kind = inner (Flights
    | where Timestamp > datetime(2023-08-11 05:30:00)
    | where onground == false
    | where callsign !in (departures) // don't track the same flight
    | extend key=geo_point_to_s2cell(lon, lat)
    ) on key, Timestamp
```

This gives us 915 flights with the default `s2_precision` of 11. According to
[geo_point_to_s2cell documentation][s2-doc] precision 11 is 5 km.

[s2-doc]: https://learn.microsoft.com/en-us/kusto/query/geo-point-to-s2cell-function

Going down to 13 (1225 meters) we're left with 137 flights which is still too
many.

```
let departures = flightsFromAirport("OTHH", datetime(2023-08-11 03:30:00), 2);
let s2_precision = 13;
Flights
| where Timestamp > datetime(2023-08-11 05:30:00)
| where onground == false
| where callsign in (departures)
| extend key=geo_point_to_s2cell(lon, lat, s2_precision)
| join kind = inner (Flights
    | where Timestamp > datetime(2023-08-11 05:30:00)
    | where onground == false
    | where callsign !in (departures) // don't track the same flight
    | extend key=geo_point_to_s2cell(lon, lat, s2_precision)
    ) on key, Timestamp
```

Let's reduce it from 13 to 15 which is 306 meters. Now we only have 9 flights
with only 5 callsigns! So we could, I guess find where each of these flights
landed right after that timestamp and bruteforce the address.

We can do another check. We can assume the second flight is flying at a lower
altitude. We modify our query accordingly.

```
let flightsFromAirport = (AirportIdent:string, StartTime:datetime, HoursToAdd:int) {
    let EndTime = datetime_add('hour', HoursToAdd, StartTime);
    Airports
    | where Ident == AirportIdent
    | extend key=geo_point_to_s2cell(lon, lat) // default precision is 11
    | join kind=inner (
        Flights
        | extend key=geo_point_to_s2cell(lon, lat)
        | where onground
        | where Timestamp between (StartTime .. EndTime)
    ) on key
    | distinct callsign
};
let departures = flightsFromAirport("OTHH", datetime(2023-08-11 03:30:00), 2);
let s2_precision = 15;
Flights
| where Timestamp > datetime(2023-08-11 05:30:00)
| where onground == false
| where callsign in (departures)
| extend key=geo_point_to_s2cell(lon, lat, s2_precision)
| project
    Timestamp, key,
    // renaming columns for easier use
    departure_callsign = callsign,
    departure_geoaltitude = geoaltitude
| join kind = inner (Flights
    | where Timestamp > datetime(2023-08-11 05:30:00)
    | where onground == false
    | where callsign !in (departures) // don't track the same flight
    | extend key=geo_point_to_s2cell(lon, lat, s2_precision)
    | project
        Timestamp, key,
        // renaming columns
        suspected_callsign = callsign,
        suspected_geoaltitude = geoaltitude
    ) on key, Timestamp
| where departure_geoaltitude > suspected_geoaltitude
| distinct suspected_callsign
```

And we get three callsigns

```
JJHM470
HFID97
MFDI779
```

Let's see where these end up and we get one result: `Barcelona`.

Complete query:

```
let flightsFromAirport = (AirportIdent:string, StartTime:datetime, HoursToAdd:int) {
    let EndTime = datetime_add('hour', HoursToAdd, StartTime);
    Airports
    | where Ident == AirportIdent
    | extend key=geo_point_to_s2cell(lon, lat) // default precision is 11
    | join kind=inner (
        Flights
        | extend key=geo_point_to_s2cell(lon, lat)
        | where onground
        | where Timestamp between (StartTime .. EndTime)
    ) on key
    | distinct callsign
};
let departures = flightsFromAirport("OTHH", datetime(2023-08-11 03:30:00), 2);
let s2_precision = 15;
Flights
| where Timestamp > datetime(2023-08-11 05:30:00)
| where onground == false
| where callsign in (departures)
| extend key=geo_point_to_s2cell(lon, lat, s2_precision)
| project
    Timestamp, key,
    // renaming columns for easier use
    departure_callsign = callsign,
    departure_geoaltitude = geoaltitude
| join kind = inner (Flights
    | where Timestamp > datetime(2023-08-11 05:30:00)
    | where onground == false
    | where callsign !in (departures) // don't track the same flight
    | extend key=geo_point_to_s2cell(lon, lat, s2_precision)
    | project
        Timestamp, key,
        // renaming columns
        suspected_callsign = callsign,
        suspected_geoaltitude = geoaltitude
    ) on key, Timestamp
| where departure_geoaltitude > suspected_geoaltitude
| distinct suspected_callsign
| join kind= inner (
    Flights
    | where onground == true
    | where Timestamp > datetime(2023-08-11 05:30:00)
    | extend key=geo_point_to_s2cell(lon, lat, 13)
) on $left.suspected_callsign == $right.callsign
| join kind=inner(
    Airports
    | extend key=geo_point_to_s2cell(lon, lat, 13)
) on key
| distinct municipality
```

# Case 8: Catchy Run
`Where can we catch the suspect?`

We get two functions `Dekrypt` and `SecretCodeToKey` and a table `Runs`.

```
Runs
| getschema
| project ColumnName, DataType

| ColumnName | DataType        |
| ---------- | --------------- |
| Timestamp  | System.DateTime |
| RunnerID   | System.String   |
| Distance   | System.Double   |
| Duration   | System.TimeSpan |
| StartLat   | System.Double   |
| StartLon   | System.Double   |
```

Let's look at the training for this case. It has a few hints about the Sagrada
Familia's Nativity and Passion facades. I am not sure how that helps.

The training also gives us a function to use Google Maps to find the location of
the final answer.

Looking at part of the decryption code:

```
let city_code=datatable(c1:long,c2:long,c3:long,c4:long)
[1, ?, ?,  4, 
 ?, 7, 6,  ?,
 8, ?, 10, 5,
 ?, 2, ?, 15];   
```

We can assume `?` needs to be replaced by a single number and the decrypted item
has the answer. 

Looks like we might have to find the Sagrada Familia location and then see what
numbers we need to plug into the function from the training to find it. It might
be the code to the puzzle:

```
let VirtualTourLink = (lat:real, lon:real) {
    print Link = strcat('https://www.google.com/maps/@', lat, ',', lon, 
        ',3a,75y,252.01h,89.45t/data=!3m6!1e1!3m4!1s-1P!2e0!7i16384!8i8192')
};
VirtualTourLink(lat, lon)
```

First I thought it was the location and Meta AI was not useful either.

However, Claude 4 found the answer for me.

```
The Sagrada Familia Magic Squares

Passion Facade Magic Square: The Passion
facade features a 4x4 magic square where each row, column, and diagonal sums to
33 (representing the age of Jesus at crucifixion):

1  14  14  4
11  7   6  9
8  10  10  5
13  2   3 15

Nativity Facade Magic Square: The Nativity facade has a different arrangement
but with similar properties.
```

And we can "dekrypt" the code.

Originally I though these numbers are unique and between 1-16. So we had to find
the seven missing numbers and a combination of 7! or 5040 (assuming no
duplicates), which can be bruteforced if we rewrote the decryption function in
a programming language. But it turns out numbers can be repeated, so our address
space is now 7 to the power of 7 or 823543 which is still easy to bruteforce.

The answer to the puzzle was:

```
Listen up, esteemed members of Kuanda, for we have encountered a slight hiccup
in our grand scheme.

I can sense your concern, as rumors of our true intentions have reached the ears
of the KDA. But fear not, my loyal comrades, for we shall not waver from our
path! If anything, we shall intensify our efforts until the KDA crumbles beneath
our feet.

I cannot share too much at this time, but rest assured, we are running our
"smoke tests", both figuratively and quite literally.

They shall expose the KDA's weaknesses and herald its epic downfall.

Now, let us address the matter of my well-being. I understand that there is a
great deal of curiosity regarding my safety.

Let me assure you, it was all a matter of impeccable timing. No doubt my
connecting flight was an experience of a lifetime!

Too bad my luggage failed to join me on this thrilling journey! :)

But fear not, my friends, leaving things to chance is not my style. I have
assembled a team of loyal bodyguards, who move with me like elusive phantoms,
ensuring my invincibility. At any given time, at least two of them discreetly
shadow my every move, even during my exhilarating runs through the city. Truly,
I feel untouchable. And let me tell you, this city is a hidden gem! It offers an
abundance of marvelous spots where one can indulge in a refreshing shake after
conquering a breathtaking 10K run. It is a perfect blend of mischief and
rejuvenation, a delightful concoction that fuels my strength.

So, my fellow rogues, let us keep our eyes fixed on the target. I will reveal
more details about our plans in due time.

Prepare yourselves to witness the spectacular downfall of the KDA, as we
relentlessly drill into its core at full speed!
 
Krypto
```

Looking at the clues:

1. Krypto is a runner.
2. Does 3-4 runs a week.
3. Running 8-12 KMs + gets a shake after.
4. He has at least two bodyguards running with him (close by so we can use
   geohash again).

So we have to use the runs to find the start of his runs and the location of the
hideout.

First, the distance:

```
Runs
| where Distance between (8 .. 12)
// 275915 runs
```

Next, runners with 3-4 runs a week.

```
Runs
| where Distance between (8.0 .. 12.0)
| extend Week = startofweek(Timestamp) // group by week
| summarize 
    RunsPerWeek = count()
    by RunnerID, Week
| where RunsPerWeek between (3 .. 4)   // 3-4 runs per week
| distinct RunnerID
// 25708 records
```

We need to use geohash to track a minimum of two bodyguards.

```
let suspectedRunners = Runs
| where Distance between (8.0 .. 12.0)
| extend Week = startofweek(Timestamp)
| summarize RunsPerWeek = count() by RunnerID, Week
| where RunsPerWeek between (3 .. 4)
| distinct RunnerID;
// Find groups of runners starting from same location at same time.
Runs
| where RunnerID in (suspectedRunners)
| where Distance between (8.0 .. 12.0)
| extend TimeBin = bin(Timestamp, 5m)  // start within 5 minutes?
// precision 18 is 38 meters.
| extend LocationHash = geo_point_to_s2cell(StartLon, StartLat, 18)
| summarize 
    Runners = make_set(RunnerID),
    RunnerCount = dcount(RunnerID)
    by TimeBin, LocationHash
| where RunnerCount >= 3  // at least 3 runners
| extend RunnerGroup = tostring(array_sort_asc(Runners))
| summarize 
    GroupOccurrences = count()
    by RunnerGroup, RunnerCount
| where GroupOccurrences >= 3  // groups that run together multiple times
| order by GroupOccurrences desc, RunnerCount desc
```

Changing the s2 precision from 15 to 18 returned the same three runners:

`["uid1063831570386","uid1549166190602","uid4027695575215"]`

Let's track their start location.

```
let targetRunners = dynamic(["uid1063831570386","uid1549166190602","uid4027695575215"]);
Runs
| where RunnerID in (targetRunners)
| where Distance between (8.0 .. 12.0)
| extend StartLocationHash = geo_point_to_s2cell(StartLon, StartLat, 16)
| summarize 
    AvgStartLat = avg(StartLat),
    AvgStartLon = avg(StartLon)
    by StartLocationHash
```

And the answer is:

```
| Column            | Value              |
| ----------------- | ------------------ |
| StartLocationHash | 12a4a2fe1          |
| AvgStartLat       | 41.38467253747556  |
| AvgStartLon       | 2.1833582740901267 |
```

Now if we plug this into the virtual tour link:

```
let VirtualTourLink = (lat:real, lon:real) {
    print Link = strcat('https://www.google.com/maps/@', lat, ',', lon, 
        ',3a,75y,252.01h,89.45t/data=!3m6!1e1!3m4!1s-1P!2e0!7i16384!8i8192')
};
VirtualTourLink(41.38467253747556, 2.1833582740901267)
```

We get
https://www.google.com/maps/@41.38467253747556,2.1833582740901269,3a,75y,252.01h,89.45t/data=!3m6!1e1!3m4!1s-1P!2e0!7i16384!8i8192

A picture of a shop named `Juice Dudes`.

And I quit after this one. Maybe I will continue in a bit, but I feel like I
know enough to sift through logs for now.