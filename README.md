# Routing
[![](https://img.shields.io/badge/Project%20SAFE-Approved-green.svg)](http://maidsafe.net/applications) [![](https://img.shields.io/badge/License-GPL3-green.svg)](https://github.com/maidsafe/routing/blob/master/COPYING)

**Primary Maintainer:**     Benjamin Bollen (benjamin.bollen@maidsafe.net)

**Secondary Maintainer:**   Peter Jankuliak (peter.jankuliak@maidsafe.net)

Routing - a specialised storage DHT

|Crate|Linux/OS X|ARM (Linux)|Windows|Appveyor|Coverage|Issues|
|:---:|:--------:|:---------:|:-----:|:------:|:------:|:----:|
|[![](http://meritbadge.herokuapp.com/routing)](https://crates.io/crates/routing)|[![Build Status](https://travis-ci.org/maidsafe/routing.svg?branch=master)](https://travis-ci.org/maidsafe/routing)|[![Build Status](http://ci.maidsafe.net:8080/buildStatus/icon?job=routing_arm_status_badge)](http://ci.maidsafe.net:8080/job/routing_arm_status_badge/)|[![Build Status](http://ci.maidsafe.net:8080/buildStatus/icon?job=routing_win64_status_badge)](http://ci.maidsafe.net:8080/job/routing_win64_status_badge/)|[![Build status](https://ci.appveyor.com/api/projects/status/25j4r0i55icw8wbi?svg=true)](https://ci.appveyor.com/project/dirvine/routing-rkdg1)|[![Coverage Status](https://coveralls.io/repos/maidsafe/routing/badge.svg)](https://coveralls.io/r/maidsafe/routing)|[![Stories in Ready](https://badge.waffle.io/maidsafe/routing.png?label=ready&title=Ready)](https://waffle.io/maidsafe/routing)|

| [API Documentation - master branch](http://maidsafe.net/routing/master/) | [SAFE Network System Documention](http://systemdocs.maidsafe.net) | [MaidSafe website](http://maidsafe.net) | [Safe Community site](https://forum.safenetwork.io) |
|:------:|:-------:|:-------:|:-------:|


#Important notice on 6 August 2015

The routing library is undergoing an important rewriting.  The external API and the internal outlines have been laid out.  The library is currently not in a functional state.  To obtain the last functional state of Routing we refer to Routing version 0.2.8, as published on crates.io.  We expect it to be a few more days of work before routing will be published as version 0.3.2, the first expected functional version of the new routing API. The published version 0.3.0 should only be used by a user library to compile against, and prepare for the upcoming new interface.

update on 18 August: the functionality in routing has been restored and some unit tests have been updated and asserted.  The basic behaviour of the routing example has been asserted in this version 0.3.2.  Final internal work has to be done, and expected soon in version 0.3.3

#Overview

A secured [DHT](http://en.wikipedia.org/wiki/Distributed_hash_table), based on a [kademlia-like](http://en.wikipedia.org/wiki/Kademlia) implementation, but with some very stark differences. This is a recursive as opposed to iterative network, enabling easier NAT traversal and providing more efficient use of routers and larger networks. This also allows very fast reconfiguration of network changes, aleviating the requirement for a refresh algorithm. A recursive solution based on a network protocol layer that is 'connection oriented' also allows a close group to be aligned with security protocols.

This library makes use of [Public-key cryptography](http://en.wikipedia.org/wiki/Public-key_cryptography) to allow a mechanism to ensure nodes are well recognised and cryptographically secured. This pattern
allows the creation of a DHT based PKI and this in turn allows a decentralised network to make use of groups as fixed in relation to any address. This is particularly useful in a continually fluid network as described [here,](http://maidsafe.net/Whitepapers/pdf/MaidSafeDistributedHashTable.pdf) creating a server-less and [autonomous network](http://maidsafe.net/docs/SAFEnetwork.pdf).

This is a very under researched area. For a general introduction to some of the ideas behind the design related to XOR Space, watching [The SAFE Network from First Principles series](https://www.youtube.com/watch?v=Lr9FJRDcNzk&list=PLiYqQVdgdw_sSDkdIZzDRQR9xZlsukIxD) is recommended. The slides for XOR Distance Metric and Basic Routing lecture are also [available here](http://ericklavoie.com/talks/safenetwork/1-xor-routing.pdf). The last video from the series on how the same ideas were applied to decentralised BitTorrent trackers is available [here](https://www.youtube.com/watch?v=YFV908uoLPY). A proper formalisation of the Routing algorithm is in progress.


###Pre-requisite:
libsodium is a native dependency for [sodiumxoide](https://github.com/dnaq/sodiumoxide). Thus, install sodium by following the instructions [here](http://doc.libsodium.org/installation/index.html).

For windows, download and use the [prebuilt mingw library](https://download.libsodium.org/libsodium/releases/libsodium-1.0.2-mingw.tar.gz).
Extract and place the libsodium.a file in "bin\x86_64-pc-windows-gnu" for 64bit System, or "bin\i686-pc-windows-gnu" for a 32bit system.

##Todo Items

General note: please document code you touch, and introduce property-based unit tests where applicable.

## RUST-3 Sprint tasks

### [0.3.0] Unified Data
- [x] [MAID-1158](https://maidsafe.atlassian.net/browse/MAID-1158) Unified Data
    - [x] [MAID-1159](https://maidsafe.atlassian.net/browse/MAID-1159) Implement PlainData
    - [x] [MAID-1160](https://maidsafe.atlassian.net/browse/MAID-1160) Implement ImmutableData
    - [x] [MAID-1163](https://maidsafe.atlassian.net/browse/MAID-1163) Implement StructuredData
    - [x] [MAID-1165](https://maidsafe.atlassian.net/browse/MAID-1165) StructuredData::is_valid_successor
    - [x] [MAID-1166](https://maidsafe.atlassian.net/browse/MAID-1166) Unit Tests for PlainData and ImmutableData
    - [x] [MAID-1167](https://maidsafe.atlassian.net/browse/MAID-1167) Unit Tests for StructuredData
    - [x] [MAID-1168](https://maidsafe.atlassian.net/browse/MAID-1168) Unit Test IsValidSuccessor for StructuredData
    - [x] [MAID-1171](https://maidsafe.atlassian.net/browse/MAID-1171) Implement UnifiedData enum
    - [x] [MAID-1172](https://maidsafe.atlassian.net/browse/MAID-1172) Update with UnifiedData: GetData and GetDataResponse
    - [x] [MAID-1173](https://maidsafe.atlassian.net/browse/MAID-1173) Update with UnifiedData: PutData and PutDataResponse
    - [x] [MAID-1175](https://maidsafe.atlassian.net/browse/MAID-1175) Update with UnifiedData: RoutingMembrane RoutingClient Put and Get
    - [x] [MAID-1176](https://maidsafe.atlassian.net/browse/MAID-1176) Update with UnifiedData: Interfaces and churn
- [x] [MAID-1179](https://maidsafe.atlassian.net/browse/MAID-1179) Implement Post and PostResponse
- [ ] [MAID-1178](https://maidsafe.atlassian.net/browse/MAID-1178) Enable Churn in Routing simple_key_value_store
- [ ] [MAID-1181](https://maidsafe.atlassian.net/browse/MAID-1181) Integration test for routing
- [x] [MAID-1170](https://maidsafe.atlassian.net/browse/MAID-1170) Update RoutingClient and relay node: RoutingMessage
- [x] [MAID-1251](https://maidsafe.atlassian.net/browse/MAID-1251) Remove option first from routing node

### Use public key for all messages
- [x] [MAID-1255](https://maidsafe.atlassian.net/browse/MAID-1255) RFC 0001 - Use public key for id on all messages
    - [x] [MAID-1256](https://maidsafe.atlassian.net/browse/MAID-1256) Remove redundant field header.source.reply_to
    - [x] [MAID-1257](https://maidsafe.atlassian.net/browse/MAID-1257) Modify Authority enum

### [0.3.1] Sentinel
- [ ] [MAID-1152](https://maidsafe.atlassian.net/browse/MAID-1152) Implement Sentinels into Routing (group task)
    - [ ] [MAID-1154](https://maidsafe.atlassian.net/browse/MAID-1154) Implement PureSentinel in RoutingMembrane::handle_put_data
    - [ ] [MAID-1157](https://maidsafe.atlassian.net/browse/MAID-1157) Implement KeySentinel for FindGroupResponse messages
    - [x] [MAID-1164](https://maidsafe.atlassian.net/browse/MAID-1164) Refactor RoutingMembrane::handle_put_data as preparation for adding PureSentinel
    - [x] [MAID-1169](https://maidsafe.atlassian.net/browse/MAID-1169) Refactor RoutingMembrane::handle_{get,put}_data_response as preparation for use with PureSentinel
    - [x] [MAID-1180](https://maidsafe.atlassian.net/browse/MAID-1180) Modify GetDataResponse and PutDataResponse to also contain source group keys
    - [ ] [MAID-1182](https://maidsafe.atlassian.net/browse/MAID-1182) Implement PureSentinel in RoutingMembrane::handle_put_data_response
    - [ ] [MAID-1183](https://maidsafe.atlassian.net/browse/MAID-1183) Implement PureSentinel in RoutingMembrane::handle_get_data_response
    - [ ] [MAID-1194](https://maidsafe.atlassian.net/browse/MAID-1194) Create test for from_group PUT messages
    - [ ] [MAID-1196](https://maidsafe.atlassian.net/browse/MAID-1196) Create test for from_group PUT response messages
    - [ ] [MAID-1197](https://maidsafe.atlassian.net/browse/MAID-1197) Create test for from_group GET response messages
    - [ ] [MAID-1207](https://maidsafe.atlassian.net/browse/MAID-1207) Implement PureSentinel for POST and DELETE messages


## Future sprints

Note 2015-06-22: below tasks will be affected by [proposed RFC: Remove Transaction Managers](https://github.com/maidsafe/rfcs/pull/1) ([view draft](https://github.com/dirvine/rfcs/blob/master/proposed/0000-Remove-Transaction-Managers.md))

### Old tasks for reference
- [x] [MAID-1063](https://maidsafe.atlassian.net/browse/MAID-1063) replace MessageTypeTag with full enum.
- [ ] [MAID-1065](https://maidsafe.atlassian.net/browse/MAID-1065) Return Result for Put Get Post-
- [ ] [MAID-1042](https://maidsafe.atlassian.net/browse/MAID-1042) Sentinel [Reference document](https://docs.google.com/document/d/1-x7pCq_YXm-P5xDi7y8UIYDbheVwJ10Q80FzgtnMD8A/edit?usp=sharing)
    - [ ] [MAID-1045](https://maidsafe.atlassian.net/browse/MAID-1045) Instantiate pure Sentinel for PUT GET (POST) / from node & from group
    - [ ] [MAID-1048](https://maidsafe.atlassian.net/browse/MAID-1048) Instantiate Key Sentinel for FindGroupResponse
    - [ ] [MAID-1049](https://maidsafe.atlassian.net/browse/MAID-1049) Instantiate Account Sentinel for orderable Refresh / AccountTransfer messages
    - [ ] [MAID-1046](https://maidsafe.atlassian.net/browse/MAID-1046) break down (header, body) into correct (request, claim) and dispatch
    - [ ]  update signature of handler functions to request and claim
    - [ ] [MAID-1051](https://maidsafe.atlassian.net/browse/MAID-1051) update construction of message_header
    - [ ] [MAID-1050](https://maidsafe.atlassian.net/browse/MAID-1050) block messages at filter once Sentinel has resolved
