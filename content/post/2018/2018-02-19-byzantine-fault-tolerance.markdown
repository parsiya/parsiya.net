---
title: "Byzantine Fault Tolerance and the Telephone Game"
date: 2018-02-18T21:14:05-05:00
draft: false
toc: false
comments: true
categories:
- Blockchain
tags:
- Distributed Networks
---

This distributed ledger thing *clicked* when I realized **a blockchain is just a distributed network**. Like any other model, blockchains attempt to solve a few problems and as a result introduce some challenges. **Byzantine Fault Tolerance** or **BFT** is one of those buzzwords that go around during nowadays. Blockchains have consensus models that claim to achieve BFT.

Here are my notes on BFT and how it relates to blockchains. I do not claim these notes to be neither complete nor correct. I am still learning. This is not an academic paper. I am just writing down what worked for me in hopes of helping others. That said, if you have any feedback, you know where to find me.

<!--more-->

<!-- MarkdownTOC -->

- [Byzantine Fault](#byzantine-fault)
- [Byzantine Failure](#byzantine-failure)
- [Byzantine Fault Tolerance](#byzantine-fault-tolerance)
    - [How do we achieve BFT?](#how-do-we-achieve-bft)
    - [Why is Everyone Suddenly Talking about BFT?](#why-is-everyone-suddenly-talking-about-bft)

<!-- /MarkdownTOC -->


<a name="byzantine-fault"></a>
# Byzantine Fault
In any distributed network, there are many nodes. If all nodes are working correctly, then things are fine. However, in the real world there are always faulty nodes.

A **Byzantine fault** is a fault that displays different symptoms to different observers. OK that does not make much sense.

Let's use the Telephone game as an example. Players sit around in a circle. The first person whispers a sentence to the next person. Each person whispers what they heard to the next person. The last person repeats what they heard out loud. Then the first person says the original phrase and players see how much it was changed.

Each player is a node in the network and the sentence is a message going through. A node that is modifying the message in transition is a node with Byzantine fault.

`Node A > node B (faulty node) > node C`

Neither node `A` nor `C` know if `B` is working correctly. They do not have a way of knowing either. According to `A`, `B` has heard the sentence loud and clear. According to `C`, `B` is telling them the exact sentence they heard from `A`. Hence, `B` is presenting different symptoms to different observers (nodes `A` and `C`).

A node with Byzantine fault could either be faulty or malicious. In our example `B` can be:

- **Malicious**: Intentionally changing the sentence. A person who wants to mess with the game.
- **Faulty**: Not hearing the sentence clearly and/or not voicing it correctly. A non-native English speaker like me. My GF says my pronunciation is horrible.

<a name="byzantine-failure"></a>
# Byzantine Failure
Let's give our Telephone game an objective. We need to order pizza for everyone in the room. But as we know, people will never agree on toppings. A network agreeing on something is called `reaching consensus`. By dictatorial fiat the first person decides the toppings and whispers it to the next person. The last person orders the pizza. If the toppings have changed in the middle (either intentionally or unintentionally), wrong toppings will be ordered and pizza will be rejected. As a result the network has failed to fulfill its ~~destiny~~ function.

A network/system failing its objective because of Byzantine faults is called a **Byzantine Failure**. Unfortunately for us, our network is pretty prone to Byzantine failures. A single faulty node can cause a Byzantine failure (wrong toppings). We have only one path from sender to receiver.

<a name="byzantine-fault-tolerance"></a>
# Byzantine Fault Tolerance
If a network/system can reach consensus (agree on something) while having nodes with Byzantine faults, then it has achieved **Byzantine Fault Tolerance** or **BFT**.

<a name="how-do-we-achieve-bft"></a>
## How do we achieve BFT?
In a distributed network with non-malicious faulty nodes, we can use simple solutions like checksums or error detecting/correcting codes. If we send the checksum (e.g. CRC32) of the message along with it, the integrity of the message can be checked. Receiver (or other nodes) calculate the CRC32 checksum of the message and compare it to the checksum accompanying the message. The chance of a faulty (non-malicious) node altering both the message and checksum resulting in a valid checksum for the altered message is very low.

When malicious nodes are present, our checksum solution will not work. A malicious node can alter the message and calculate the new checksum. In this case we can use digital signatures or other cryptographic primitives. Sender signs the message and the signature is verified at destination. However, this introduces a new problem. The receiver must know the public key (or certificate) of sender beforehand. It cannot be sent with the message. This means we either need to have a central authority or an out-of-band channel to distribute this info.

<a name="why-is-everyone-suddenly-talking-about-bft"></a>
## Why is Everyone Suddenly Talking about BFT?
Because of Bitcoin, cryptocurrencies, blockchain and the snake-oil salespeople who follow every buzzword. It was DevOps a couple of years ago and cloud before that. Real professionals always struggle to have their voices heard in the middle of this mayhem. Kudos to them.

Blockchains are distributed networks. Bitcoin proposes a method for a decentralized network of untrusted nodes (nodes with Byzantine failures) to reach consensus. It's the [Proof of Work (PoW) Consensus Model]({{< relref "post/2018/2018-02-08-NISTIR-8202-blockchain-technology-overview-draft.markdown#41-proof-of-work-consensus-model" >}} "4.1 - Proof of Work Consensus Model") that I wrote about in the NIST draft review. The network agrees on who should create a new block by mining. When a node mines a block, it presents the proof of work to the network. After it's validated, the network agrees that it's the next block in the blockchain and everyone starts mining the next block. This introduces a major problem. All the time and resources wasted on mining. But that is a discussion for another time.

In a permissioned blockchain we are not really worried about malicious nodes. Usually, checksums are enough to ensure message integrity. There's also a central authority that can distribute certificates and act as the identity management authority (e.g. node A is who they say they are, here are their credentials). In such a network, we do not need to mine to agree on things (who is going to create the next block). The central authority can use a round-robin method and only needs to worry about faulty mining nodes (e.g. who is next in line for mining if a mining node is faulty).