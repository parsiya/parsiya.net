---
title: "Byzantine Generals' Problem"
date: 2018-02-21T15:58:41-05:00
draft: false
toc: false
comments: true
categories:
- Blockchain
tags:
- Byzantine Generals
- Distributed Networks
---

In the previous blog post, I talked about [Byzantine Fault Tolerance]({{< relref "post/2018/2018-02-19-byzantine-fault-tolerance.markdown" >}} "Byzantine Fault Tolerance and the Telephone Game"). It was sort of a jump into the middle of everything. In this post I will take a step back and look at the history behind BFT. This is my short post about the **Byzantine Generals' Problem**.

<!--more-->

**Byzantine Generals' Problem** was first introduced in a paper named after the problem ([PDF link][generals-paper]).

- Distributed Network: A commanding general, a few lieutenant-generals and their armies have surrounded a city (Byzantine).
- Reaching Consensus: Commanding general needs to send a decision to all generals. The network needs to agree on an attack date/time or retreat.
- Byzantine Fault: Not all generals (this includes the commanding general) are loyal.
- Byzantine Failure: If all armies do not attack together, the attack will fail.

Commanding general sends messages to other armies via messengers. However these messengers are going through a warzone. They might get captured or killed. The message might be dropped (a traitor kills the messenger and destroys the message) or modified (a traitor kills the messenger and sends out a modified message).

If you are interested, read the paper to see how it attempts to solve it. As interesting as it is, the solution is not really relevant to my current interests. But we can look at the BFT post and point out the similarities between the General's problem and a permissionless distributed blockchain.

- Both networks must agree on something (reach consensus).
- Both networks have nodes with Byzantine fault (faulty or malicious).
- Messages might be dropped or modified in both networks.
- General's personal seal == General's private key.
    + Messages sealed by the seal == Messages signed by general's private key.

<!-- Links -->

[generals-paper]: https://people.eecs.berkeley.edu/~luca/cs174/byzantine.pdf