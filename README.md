# routing

Routing - specialised storage DHT

| Travis build and test status | Appveyor build status | Code Coverage |
|:----------------------------:|:---------------------:|:--------------:|
|[![Build Status](https://travis-ci.org/dirvine/routing.svg?branch=master)](https://travis-ci.org/dirvine/routing)|[![Build status](https://ci.appveyor.com/api/projects/status/ni7c20e9aux3g01i?svg=true)](https://ci.appveyor.com/project/dirvine/routing)|[![Coverage Status](https://coveralls.io/repos/dirvine/routing/badge.svg?branch=master)](https://coveralls.io/r/dirvine/routing?branch=master)|

| [API Documentation](http://dirvine.github.io/routing/routing/)| [MaidSafe System Documention](http://systemdocs.maidsafe.net/) | [MaidSafe web site](http://www.maidsafe.net) | [Safe Community site](https://forum.safenetwork.io) |

#Overview

A secured [DHT](http://en.wikipedia.org/wiki/Distributed_hash_table), based on a [kademlia](http://en.wikipedia.org/wiki/Kademlia) like implementation, but with some very stark differences. This is a recursive as opposed to iterative network, this allows easier NAT traversal and makes more efficient use of routers and larger networks. This also allows very fast reconfiguration of network changes and aleviates the requirement of a refresh algorithm. A recursive solution based on a network protocol layer that is 'connection oriented' also allows a close group to be aligned with security protocols.

This library makes use of [Public-key cryptography](http://en.wikipedia.org/wiki/Public-key_cryptography) to allow a mechanism to ensure nodes are well recognised and cryptographically secured. This pattern allows the creation of a DHT based PKI and this in turn allows us to make use of groups as fixed in relation to any address, in a continually fluid network as described [here](http://maidsafe.net/Whitepapers/pdf/MaidSafeDistributedHashTable.pdf) and create serverless networks that can provide fully [autonomous networks](http://maidsafe.net/docs/SAFEnetwork.pdf). 

This is a very under-researched area. For a general introduction to some of the ideas behind the design related to XOR Space, please see the videos in [The SAFE Network from First Principles series](https://www.youtube.com/watch?v=Lr9FJRDcNzk&list=PLiYqQVdgdw_sSDkdIZzDRQR9xZlsukIxD). The slides for XOR Distance Metric and Basic Routing lecture are also [available here](http://ericklavoie.com/talks/safenetwork/1-xor-routing.pdf). The last video from the series on how the same ideas were applied to decentralized the Bittorrent trackers is available [here](https://www.youtube.com/watch?v=YFV908uoLPY). A proper formalization of the Routing algorithm is in progress.


###Pre-requisite:
libsodium is a native dependency for [sodiumxoide](https://github.com/dnaq/sodiumoxide). Thus, install sodium by following the instructions [here](http://doc.libsodium.org/installation/index.html).

For windows, download and use the [prebuilt mingw library](https://download.libsodium.org/libsodium/releases/libsodium-1.0.2-mingw.tar.gz).
Extract and place the libsodium.a file in "bin\x86_64-pc-windows-gnu" for 64bit System or "bin\i686-pc-windows-gnu" for a 32bit system.

SQLite3 is also native dependency for [rustsqlite](https://github.com/linuxfood/rustsqlite).
Steps to compile SQLite by,
1. Download SQLite Source code which includes a "configure" script from [SQLite download page](https://www.sqlite.org/download.html) 
2. On Linux, Run `./configure --prefix=/usr && make && sudo make install` to build the SQLite source. While on Windows Users can build using (mingw + msys) and run './configure && make' 
3. On Windows, Copy the `libsqlite3.a` file from the .libs folder to the "bin\{TARGET-TRIPLE}" (i.e. i686-pc-win32 or x86_64-pc-win32 etc.) in the project root folder (or at least in your path).
 
##Todo Items

- [x] Set up facade design pattern
- [x] Test facade pattern
- [x] Set up accumulator
- [x] Accumulator tests
- [x] Message header 
- [x] Message header tests
- [x] API version 0.0.6
- [x] Bootstrap handler implementation
- [x] Bootstrap handler test
- [ ] zero state network
- [ ] Test node network (process on single machine)
- [ ] Test node network (local area network)
- [ ] Test node network (across digital ocean images)
- [x] Create sort and bucket index methods 
- [x] Implement routing table
- [x] Test routing table 
- [x] Implement sentinel (initial)
- [x] Finalise sentinel in line with tests
- [x] Implement client node
- [ ] Test client node
- [ ] Integrate connection manager (bootstrapping)
- [ ] Implement routing node (handle messages , forwarding etc)
- [x] Test sentinel 
- [x] Implement routing message types (Connect FindNode)
- [x] Test message types
- [x] Implement Get Put Post messages
- [ ] Implement routing node
- [ ] Version 0.0.8
- [ ] Integrate with Sentinel
- [ ] Implement NAT traversal (requires crust v0.1.0)
- [ ] Test basic facade (normal DHT Get Put with republish)
- [ ] Version 0.1 (crates.io)
- [ ] Address re-location (security essential)
