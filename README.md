# routing

Routing - specialised storage DHT

Travis build and test status

[![Build Status](https://travis-ci.org/dirvine/routing.svg?branch=master)](https://travis-ci.org/dirvine/routing)

Appveyor build status

[![Build status](https://ci.appveyor.com/api/projects/status/ni7c20e9aux3g01i?svg=true)](https://ci.appveyor.com/project/dirvine/routing)

Code Coverage

[![Coverage Status](https://coveralls.io/repos/dirvine/routing/badge.svg?branch=master)](https://coveralls.io/r/dirvine/routing?branch=master)

[Documentation](http://dirvine.github.io/routing)

###Pre-requisite:
libsodium is a native dependency for [sodiumxoide](https://github.com/dnaq/sodiumoxide). Thus, install sodium by following the instructions [here](http://doc.libsodium.org/installation/README.html).

For windows, download and use the [prebuilt mingw library](https://download.libsodium.org/libsodium/releases/libsodium-1.0.2-mingw.tar.gz).
Extract and place the libsodium.a file in "bin\x86_64-pc-windows-gnu" for 64bit System or "bin\i686-pc-windows-gnu" for a 32bit system.

SQLite3 is also native dependency for [rustsqlite](https://github.com/linuxfood/rustsqlite).
Steps to compile SQLite by,
1. Download SQLite Source code which includes a "configure" script from [SQLite download page](https://www.sqlite.org/download.html) 
2. On Linux, Run `./configure --prefix=/usr && make && sudo make install` to build the SQLite source. While on Windows Users can build using (mingw + msys) and run './configure && make' 
3. On Windows, Copy the `libsqlite3.a` file from the .libs folder to the "bin\{TARGET-TRIPLE}" in the project root folder.
 
 
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
- [ ] Tcp Networking
  - [x] Tcp live port and backup random port selection 
  - [x] Create send/rcv channel from routing to connections object
  - [x] Implement test for basic "hello world" two way communication
  - [ ] Integrate into connection_manager
  - [ ] Set up Udp broadcast and respond when we have live port available (5483)
  - [ ] Have connection manger start, broadcast on udp broadcast for port 5483 (later multicast for ipv6)
  - [ ] Link ability to read and write bootstrap file as well as send to any node requesting it. 
  - [ ] Add connection established/lost messages to be passed to routing (via channel)
  - [ ] Add maintain_connection() to connecton manager for lib.rs to be able to confirm a routing table contact we must keep. 
  - [ ] Benchmark tx/rv number of packets 
  - [ ] Benchmark tx/rc Bytes per second
- [ ] Allow node to create it's ID and store on network
- [ ] zero state network
- [ ] Network starts any number of nodes automatically (test)
- [x] Create sort and bucket index methods 
- [x] Implement routing table
- [ ] Test routing table 
- [x] Implement sentinel (initial)
- [ ] Finalise sentinel in line with tests
- [ ] Test sentinel 
- [ ] Allow tcp and then utp connections and wrap in connection object. [See here for tcp NAT traversal] (http://www.cmlab.csie.ntu.edu.tw/~franklai/NATBT.pdf) [and here fur ucp/dht NAT traversal
  ](http://maidsafe.net/Whitepapers/pdf/DHTbasedNATTraversal.pdf)
- [x] Implement routing message types (Connect FindNode)
- [ ] Test message types
- [x] Implement Get Put Post messages
- [ ] Implement routing node
- [ ] Test basic facade (normal DHT Get Put with republish)
- [ ] Version 0.0.8
- [ ] Utp Networking
  - [ ] Utp live port and backup random port selection 
  - [ ] Create send/rcv channel from routing to connections object
  - [ ] Implement test for basic "hello world" two way communication
  - [ ] Add connection established/lost messages to be passed to routing (via channel)
  - [ ] Benchmark tx/rv number of packets 
  - [ ] Benchmark tx/rc Bytes per second 
- [ ] Implement NAT traversal
- [ ] Version 0.1 (crates.io)
