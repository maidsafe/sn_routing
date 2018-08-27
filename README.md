# Routing

Routing - a specialised storage DHT

|Crate|Documentation|Linux/OS X|Windows|Issues|
|:---:|:-----------:|:--------:|:-----:|:----:|
|[![](http://meritbadge.herokuapp.com/routing)](https://crates.io/crates/routing)|[![Documentation](https://docs.rs/routing/badge.svg)](https://docs.rs/routing)|[![Build Status](https://travis-ci.org/maidsafe/routing.svg?branch=master)](https://travis-ci.org/maidsafe/routing)|[![Build status](https://ci.appveyor.com/api/projects/status/2w1joqd2h64o4xrh/branch/master?svg=true)](https://ci.appveyor.com/project/MaidSafe-QA/routing/branch/master)|[![Stories in Ready](https://badge.waffle.io/maidsafe/routing.png?label=ready&title=Ready)](https://waffle.io/maidsafe/routing)|

| [MaidSafe website](https://maidsafe.net) | [SAFE Dev Forum](https://forum.safedev.org) | [SAFE Network Forum](https://safenetforum.org) |
|:----------------------------------------:|:-------------------------------------------:|:----------------------------------------------:|

## Overview

A secured [DHT](http://en.wikipedia.org/wiki/Distributed_hash_table), based on a [kademlia-like](http://en.wikipedia.org/wiki/Kademlia) implementation, but with some very stark differences. This is a recursive as opposed to iterative network, enabling easier NAT traversal and providing more efficient use of routers and larger networks. This also allows very fast reconfiguration of network changes, aleviating the requirement for a refresh algorithm. A recursive solution based on a network protocol layer that is 'connection oriented' also allows a close group to be aligned with security protocols.

This library makes use of [Public-key cryptography](http://en.wikipedia.org/wiki/Public-key_cryptography) to allow a mechanism to ensure nodes are well recognised and cryptographically secured. This pattern
allows the creation of a DHT based PKI and this in turn allows a decentralised network to make use of groups as fixed in relation to any address. This is particularly useful in a continually fluid network as described [here,](http://docs.maidsafe.net/Whitepapers/pdf/MaidSafeDistributedHashTable.pdf) creating a server-less and [autonomous network](http://docs.maidsafe.net/Whitepapers/pdf/TheSafeNetwork.pdf).

This is a very under researched area. For a general introduction to some of the ideas behind the design related to XOR Space, watching [The SAFE Network from First Principles series](https://www.youtube.com/watch?v=Lr9FJRDcNzk&list=PLiYqQVdgdw_sSDkdIZzDRQR9xZlsukIxD) is recommended. The slides for XOR Distance Metric and Basic Routing lecture are also [available here](http://ericklavoie.com/talks/safenetwork/1-xor-routing.pdf). The last video from the series on how the same ideas were applied to decentralised BitTorrent trackers is available [here](https://www.youtube.com/watch?v=YFV908uoLPY). A proper formalisation of the Routing algorithm is in progress.

## Logging

Messages are logged via the standard `log` crate, and where enabled, printed
via `env_logger`. By default this prints messages of level "warn" and higher
("error"), but not lower levels ("info", "debug", "trace"). The level can be set
explicitly (any of the above or "off"), e.g.:

    export RUST_LOG=routing=info

Optionally, the following sub-targets can be controlled independently:

*   stats — messages about connections and routing table size
*   crust — messages from the mock Crust layer (not real Crust)

Example:

    export RUST_LOG=routing=info,stats=off


## License

Licensed under the General Public License (GPL), version 3 ([LICENSE](LICENSE) http://www.gnu.org/licenses/gpl-3.0.en.html).

### Linking exception

Routing is licensed under GPLv3 with linking exception. This means you can link to and use the library from any program, proprietary or open source; paid or gratis. However, if you modify Routing, you must distribute the source to your modified version under the terms of the GPLv3.

See the LICENSE file for more details.
