# Routing
[![](https://img.shields.io/badge/Project%20SAFE-Approved-green.svg)](http://maidsafe.net/applications) [![](https://img.shields.io/badge/License-GPL3-green.svg)](https://github.com/maidsafe/routing/blob/master/COPYING)

**Primary Maintainer:**     Benjamin Bollen (benjamin.bollen@maidsafe.net)

**Secondary Maintainer:**   Brian Smith (brian.smith@maidsafe.net)

Routing - a specialised storage DHT

|Crate|Linux/OS X|ARM (Linux)|Windows|Coverage|Issues|
|:---:|:--------:|:---------:|:-----:|:------:|:----:|
|[![](http://meritbadge.herokuapp.com/routing)](https://crates.io/crates/routing)|[![Build Status](https://travis-ci.org/maidsafe/routing.svg?branch=master)](https://travis-ci.org/maidsafe/routing)|[![Build Status](http://ci.maidsafe.net:8080/buildStatus/icon?job=routing_arm_status_badge)](http://ci.maidsafe.net:8080/job/routing_arm_status_badge/)|[![Build status](https://ci.appveyor.com/api/projects/status/2w1joqd2h64o4xrh/branch/master?svg=true)](https://ci.appveyor.com/project/MaidSafe-QA/routing/branch/master)|[![Coverage Status](https://coveralls.io/repos/maidsafe/routing/badge.svg)](https://coveralls.io/r/maidsafe/routing)|[![Stories in Ready](https://badge.waffle.io/maidsafe/routing.png?label=ready&title=Ready)](https://waffle.io/maidsafe/routing)|

| [API Documentation - master branch](http://maidsafe.net/routing/master) | [SAFE Network System Documentation](http://systemdocs.maidsafe.net) | [MaidSafe website](http://maidsafe.net) | [SAFE Network Forum](https://forum.safenetwork.io) |
|:------:|:-------:|:-------:|:-------:|

## Overview

A secured [DHT](http://en.wikipedia.org/wiki/Distributed_hash_table), based on a [kademlia-like](http://en.wikipedia.org/wiki/Kademlia) implementation, but with some very stark differences. This is a recursive as opposed to iterative network, enabling easier NAT traversal and providing more efficient use of routers and larger networks. This also allows very fast reconfiguration of network changes, aleviating the requirement for a refresh algorithm. A recursive solution based on a network protocol layer that is 'connection oriented' also allows a close group to be aligned with security protocols.

This library makes use of [Public-key cryptography](http://en.wikipedia.org/wiki/Public-key_cryptography) to allow a mechanism to ensure nodes are well recognised and cryptographically secured. This pattern
allows the creation of a DHT based PKI and this in turn allows a decentralised network to make use of groups as fixed in relation to any address. This is particularly useful in a continually fluid network as described [here,](http://maidsafe.net/Whitepapers/pdf/MaidSafeDistributedHashTable.pdf) creating a server-less and [autonomous network](http://maidsafe.net/docs/SAFEnetwork.pdf).

This is a very under researched area. For a general introduction to some of the ideas behind the design related to XOR Space, watching [The SAFE Network from First Principles series](https://www.youtube.com/watch?v=Lr9FJRDcNzk&list=PLiYqQVdgdw_sSDkdIZzDRQR9xZlsukIxD) is recommended. The slides for XOR Distance Metric and Basic Routing lecture are also [available here](http://ericklavoie.com/talks/safenetwork/1-xor-routing.pdf). The last video from the series on how the same ideas were applied to decentralised BitTorrent trackers is available [here](https://www.youtube.com/watch?v=YFV908uoLPY). A proper formalisation of the Routing algorithm is in progress.


## Prerequisite

[libsodium](https://github.com/jedisct1/libsodium) is a native dependency, and can be installed by following the instructions [for Windows](https://github.com/maidsafe/QA/blob/master/Documentation/Install%20libsodium%20for%20Windows.md) or [for OS X and Linux](https://github.com/maidsafe/QA/blob/master/Documentation/Install%20libsodium%20for%20OS%20X%20or%20Linux.md).

## Todo Items

General note: please document code you touch, and introduce property-based unit tests where applicable.
