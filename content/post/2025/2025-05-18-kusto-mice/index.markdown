---
title: "Kusto-Mice: Optimizing Kusto joins"
date: 2025-05-18T14:52:43-07:00
draft: false
toc: true
comments: true
url: /blog/kusto-mice-join-optimization/
twitterImage: 01-trenchcoat.png
categories:
- Kusto
---

A few weeks ago I wrestled with a complex Kusto query. I shared what I learned
at work in a presentation. In this blog, I'll use a public example to walk you
through it.

<!--more-->

# What Are We Gonna Learn Here Today?
Moved to the top:

* joins:
    * The left side should be smaller.
    * Apply predicates before joining on both sides.
    * Use broadcast for cross-cluster queries.
    * Ditch join and use a predicate if one side is a single column.
* Result size:
    * Project only the columns you need.
    * Use summarize to deduplicate the results.

# What's Kusto?
Kusto, or Azure Data Explorer (ADX), is a distributed database. Honestly,
everyone calls it Kusto. It uses a language called [Kusto Query Language or KQL][kql].
Kusto is popular for threat hunting in Azure because, well, everything at Azure
and subsequently at Microsoft ends up in a Kusto database somewhere.

[kql]: https://learn.microsoft.com/en-us/kusto/query/

{{< imgcap title="Microsoft is three Kusto clusters in a trench coat. Image credit: Unknown" src="01-trenchcoat.png" >}}[^1]

[^1]: I couldn't find the original image. Please let me know if you do, so I can credit the artist (or remove it if usage isn't allowed). It's one of my favorite images.

I use [join] a lot, and it's probably one of the most expensive operators. It
retrieves data from multiple tables and combines them. For this example, we'll
use the web interface and the sample databases
https://dataexplorer.azure.com/clusters/help/databases/Samples. At work, I use
the [Kusto Explorer][ke] desktop app.

In the rest of the examples, I assume the web interface has automatically
selected the `Samples` database on the left side. If it hasn't, and you're using
multiple clusters, add the following (don't forget the `.` at the end) to the
beginning of the queries:
`cluster('help.kusto.windows.net').database('Samples').`

[join]: https://learn.microsoft.com/en-us/kusto/query/tutorials/join-data-from-multiple-tables
[ke]: https://aka.ms/ke

# Sample Tables
We'll use the `StormEvents` and `PopulationData` tables. To join them, we need
one or more columns with matching data. I usually start with  `take 5` to take
a peak:

```sql
StormEvents
| take 5

PopulationData
| take 5
```

Note that an empty line starts a new query in both Kusto Explorer and the ADX
web interface. You can have multiple queries in one window and run them
individually.

A pet peeve of mine is hitting `F5` in the web interface, which refreshes the
page instead of running the query like it does in the desktop app.

Both tables have a State column, so we can join them like this:

```sql
StormEvents
| join kind=inner(PopulationData) on State
```

Or, for different column names, we'd use `$left` and `$right`:

```sql
StormEvents
| join kind=inner(PopulationData) on $left.State == $right.OtherState
```

I mostly use inner join. See all join modes in
[Kusto docs - join operator][join-docs]. We'll filter to only data with matching
states, as  `StormEvents` includes locations like `Atlantic North` or
`Gulf of Mexico` (gets hauled away in an unmarked van).

In this case we get 57,714 rows, but in the real world I am usually dealing with
millions of rows and I hit the cluster limitations.

[join-docs]: https://learn.microsoft.com/en-us/kusto/query/join-operator

# Errors
After running a Kusto query, I usually see one of these errors:

1. Timeout: Query execution exceeds a specific limit (usually a few minutes).
2. `E_RUNAWAY_QUERY`: Query uses too much memory (usually a few GBs).
3. `E_QUERY_RESULT_SET_TOO_LARGE`: Result set is too big (64MB in my case).

Read more in [Kusto docs - Query Limits][query-limit].

[query-limit]: https://learn.microsoft.com/en-us/kusto/concepts/query-limits

{{< imgcap title="The banes of my Kusto queries" src="02-errors.jpg" >}}

# Avoiding E_RUNAWAY_QUERY
Joins often run out of memory due to excessive data matching. So our focus
should be on reducing both sides of the join before it happens. To quote Super
Troopers, "Enhance!"

You can monitor query memory usage and result size in both the web interface and
Kusto Explorer. In the web interface, click the `Stats` tab.

Note on performance: This isn't a scientific experiment. Due to warm-up,
caching, and other optimizations, measuring query performance can be
challenging. These tables are small, so the differences might be subtle, but
they were dramatic in my query.

{{< imgcap title="Performance of the original query" src="07-perf.png" >}}

## join: Use the Smaller Table First
The smaller table should be first. `PopulationData` only has 52 rows (50 states,
PR, and DC). Easy swap:

```sql
PopulationData
| join kind=inner(StormEvents) on State
```

To make the left side table smaller, apply all the ~~conditions~~ predicates
before the join. For example, if we want to look at events for states with a
population over 10 million, we can filter `PopulationData` first which leaves us
with only nine states:

```sql
PopulationData
| where Population > 10000000
| join kind=inner(StormEvents) on State
```

* Peak memory usage: 66MB.
* Result: 17,037 rows. 19,336,519 bytes.

Applying predicates after the join would produce the same results with
unnecessary computation matching the rows we don't care about.

```sql
PopulationData
| join kind=inner(StormEvents) on State
| where Population > 10000000
```

{{< imgcap title="Say 'predicate' to impress your functional programming friends" src="03-predicate.jpg" >}}

## join: Only Project the Columns You Need
To make the left side of the join as small as possible, include only needed
columns. Our left side table is small, but as a rule of thumb, don't project
columns with predicates unless needed. Let's remove Population:

```sql
PopulationData
| where Population > 10000000
| project State
| join kind=inner(StormEvents) on State
```

* Peak memory usage: Still around 66MB.
* Result: 17,037 rows. 19,183,186 bytes. Omitting the population column reduced it a little.

After the `project` line, the query only sees the `State` column. We can rename
columns, too. If `State` was originally named `UsState`, we could rename it. Two
show two ways to rename, we rename it with `project-rename`
and then use `project State = UsState`.

```SQL
PopulationData
| where Population > 10000000
| project-rename UsState = State
| project State = UsState
| join kind=inner(StormEvents) on State
```

Remember when I mentioned we can have multiple queries in one window separated
by empty lines? This works nicely here for experimenting. We can copy a query,
modify it and compare the results.

{{< imgcap title="Multiple queries in one window" src="04-multiple.png" >}}

## join: Move Predicates into Join
A teammate who is an expert in Kusto, Barry, reviewed my presentation and shared
some great tips. One suggestion was to move conditions into the join on the
right side. The `StormEvents` table has `BeginLocation` and `EndLocation`
columns. Let's filter events where these contain the word `beach`.

```sql
PopulationData
| where Population > 10000000
| project State
| join kind=inner(StormEvents) on State
| where (BeginLocation has 'beach') or (EndLocation has 'beach')
```

Move the filter into the right side:

```sql
PopulationData
| where Population > 10000000
| project State
| join kind=inner(
    StormEvents
    | where (BeginLocation has 'beach') or (EndLocation has 'beach')
) on State
```

`where` has move into the join. The fewer rows that we match on either side of
the join, the better.

* Peak memory usage: 18.15MB.
* Results: 55 rows. 53,882 bytes.

### Soapbox: has vs. contains
Using `contains` triggers a warning recommending `has` instead.

{{< imgcap title="Contains has a warning (har har)" src="05-contains-warning.png" >}}

`has` and `contains` are not interchangeable. `has` matches whole words, while
`contains` is like a substring function. For example, given `CLEARWATER BEACH`:

* Searching for `beach` returns true for both `has` and `contains` since it's a separate word.
* Searching for `clear` returns false for `has`, but true for `contains`.

Learn more about string operators at https://aka.ms/kusto.stringterms.

```sql
print Example = "CLEARWATER BEACH"
| extend Has_beach = (Example has "beach")           // true
| extend Contains_beach = (Example contains "beach") // true
| extend Has_clear = (Example has "clear")           // false
| extend Contains_clear = (Example contains "clear") // true
```

{{< imgcap title="has and contains in action" src="06-has-contains.png" >}}

Note both operators are case-insensitive; case-sensitive versions are `has_cs`
and `contains_cs`.

## join: Broadcast Strategy
Another tip from Barry.

When joining tables across clusters, a normal join is executed on a single
[eventhouse node][eventhouse], a group of databases sharing resources. While not
always correct, I assume databases on the same cluster are in the same
eventhouse and experiment with broadcast when joining cross-cluster tables.

[eventhouse]: https://learn.microsoft.com/en-us/fabric/real-time-intelligence/create-eventhouse

The [broadcast strategy][broadcast] distributes the join load between
eventhouses. However, the left side of
the join must be small, typically in the "10s of MBs".

[broadcast]: https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/broadcast-join

The documentation shows us a way to guesstimate the size of tables:

```sql
PopulationData
| summarize sum(estimate_data_size(*))
// 869
```

Applying a predicate reduces the size:

```sql
PopulationData
| where Population > 10000000
| summarize sum(estimate_data_size(*))
// 147
```

Projecting only the needed column:

```sql
PopulationData
| where Population > 10000000
| project State
| summarize sum(estimate_data_size(*)) 
// 75
```

We can apply the broadcast strategy:

```sql
PopulationData
| where Population > 10000000
| project State
| join hint.strategy = broadcast kind=inner( // <--- Only change
    StormEvents
    | where (BeginLocation has 'beach') or (EndLocation has 'beach')
) on State
```

* Peak memory usage: 25.93MB (interestingly, higher because of data duplication).
* Results: 55 rows, 49,913 bytes.
    * Slightly less than the previous query due to a bug? I checked and both
      queries return the exact same results.

## join: Codifying Queries
When working with multiple tables, queries can get complex. Kusto variables can
help us here. I'll use the full cluster and database names, as we often work
with multiple clusters.

```sql
let popData = cluster('help.kusto.windows.net').database('Samples').PopulationData
| where Population > 10000000
| project State;
let events = cluster('help.kusto.windows.net').database('Samples').StormEvents
| where (BeginLocation has 'beach') or (EndLocation has 'beach');
popData
| join hint.strategy = broadcast kind=inner(events) on State
```

This approach doesn't change peak memory usage or results, but makes the query
easier to read and modify. Note that variable declarations should be
consecutive, without empty lines, to be considered part of the same query.

## join: One Column? Ditch Join
"But wait, there's more!" 

When working with a single column, we can create a variable and use it in a
predicate.

```sql
let popData = cluster('help.kusto.windows.net').database('Samples').PopulationData
| where Population > 10000000
| project State;
cluster('help.kusto.windows.net').database('Samples').StormEvents
| where (BeginLocation has 'beach') or (EndLocation has 'beach')
| where State in (popData) // <--- See here
```

This approach replaces the join with a more efficient `in` operator,
significantly reducing peak memory usage.

* **Peak memory usage: 1.01MB!!** (dramatic decrease).
* Result: 55 rows, 49,526 bytes.
    * Again, results are identical to the last two queries, but the reported size is
      different. Maybe it includes metadata?

# Avoiding E_QUERY_RESULT_SET_TOO_LARGE
When returning too much data (typically over 64MB), you might encounter the `E_QUERY_RESULT_SET_TOO_LARGE` error and get truncated results. To mitigate this, focus on reducing the result size.

## Reducing the Result Size
One effective approach is to `project` only necessary columns, especially at the
end of the query like we did above before the join. When hitting the result
limit, I use two methods:


1. Paginate results in multiple queries.
2. Exclude unnecessary columns from the result.

In this example, we'll use the second solution. The `StormSummary` column is a
JSON object with redundant data, making it a prime candidate for removal using
the [project-away][project-away] operator.

[project-away]: https://learn.microsoft.com/en-us/kusto/query/project-away-operator

```json
// Example of StormSummary
{
  "TotalDamages": 6000000,
  "StartTime": "2007-02-02T04:22:00.0000000Z",
  "EndTime": "2007-02-02T04:27:00.0000000Z",
  "Details": {
    "Description": "The same mesocyclone that produced [...]",
    "Location": "FLORIDA"
  }
}
```

The query would look like:

```sql
let popData = cluster('help.kusto.windows.net').database('Samples').PopulationData
| where Population > 10000000
| project State;
cluster('help.kusto.windows.net').database('Samples').StormEvents
| where (BeginLocation has 'beach') or (EndLocation has 'beach')
| where State in (popData)
| project-away StormSummary
```

* Peak memory usage: 1.01MB.
* Result: 55 rows, 31,349 bytes.

Other good candidates are  `EpisodeNarrative` and `EventNarrative`, which would
drop the result size to 8,426 bytes.

## Deduplicate
When working with regularly captured data, you might want to see only the latest
instance. In our example, we have 55 rows, mostly about Florida. To get the last
event for each state, we can modify the query:

```sql
let popData = cluster('help.kusto.windows.net').database('Samples').PopulationData
| where Population > 10000000
| project State;
cluster('help.kusto.windows.net').database('Samples').StormEvents
| where (BeginLocation has 'beach') or (EndLocation has 'beach')
| where State in (popData)
| summarize arg_max(EndTime, *) by State
| project-away StormSummary, EpisodeNarrative, EventNarrative
```

This query returns 5 rows and 985 bytes, showing only the latest event for each
state.

{{< imgcap title="The result of the last query" src="08-end.png" >}}

# Wrapping Up
These basic tips helped me replace a query that was running out of memory (10GB
peak) and returning 200MB of data into one that finished in just 3 minutes, used
2GB of peak memory, and returned 21MB. I hope these tips will be useful for you,
too.
