---
title: "CAP Theorem and Credit Cards"
date: 2018-02-22T20:43:14-05:00
draft: false
toc: false
comments: true
categories:
- Blockchain
tags:
- Distributed Networks
- CAP Theorem
---

CAP Theorem is another of those `blockchain buzzwords`.

CAP stands for:

- **Consistency**: Every read should get up-to-date data.
- **Availability**: Every request should get a response.
- **Partition Tolerance**: If a section of the network is partitioned/cut-off (messages are dropped), the network should continue to work.

**CAP Theorem**: A distributed network **can only pick two**.

<!--more-->

# Payment Processing
Take payment processing as an example. It's a distributed network of Point-Of-Sale systems, payment processors, banks and other entities. Payment processing has chosen `consistency` and `availability`.

## Consistency
You swipe your credit card. Open your mobile banking application. The transaction is usually there after a small delay. The delay is most likely because of the time it takes for your bank to retrieve the transaction from the payment processor. If your bank reads off your list of transactions, it will always grab the latest data which includes your last credit card swipe.

## Availability
You swipe your card and you get a response. The bank asks for your data and gets a response. The system could be down for maintenance but after swiping your card you usually get an answer that says your transaction got through or was declined.

## Partition Tolerance
Payment processing did not choose this. In order for payment processing to work, you need to have access to the servers. A single POS cannot process transactions alone. It can store transactions but it cannot process them by itself. A POS on the plane is not connected to the network, it can take credit cards but the transactions do not clear or appear in the banking application after a short delay. The POS will send the transactions to the network when the plane lands.

### But POS can process transactions using plane's internet in real time
Did you honestly believe I would forget this edge case?[^1]  I had the same "brilliant moment." If the POS is connected to the network then it's not partitioned. Check mate atheists.

<!-- Footnote -->
[^1]: Complete quote from Kael'thas: "Don't look so smug! I know what you're thinking, but Tempest Keep was merely a set back. **Did you honestly believe I would trust the future to some blind, half-night elf mongrel?** Hahahaha… Oh no, no, no, he was merely an instrument, a stepping stone to a much larger plan! It has all led to this…and this time, you will not interfere!"