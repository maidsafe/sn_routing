# routing

Routing - specialised storage DHT

Travis build and test status

[![Build Status](https://travis-ci.org/dirvine/routing.svg?branch=master)](https://travis-ci.org/dirvine/routing)

Appveyor build status

[![Build status](https://ci.appveyor.com/api/projects/status/ni7c20e9aux3g01i?svg=true)](https://ci.appveyor.com/project/dirvine/routing)

[Documentation](http://dirvine.github.io/routing)

###Pre-requisite:
libsodium is a native dependency for [sodiumxoide](https://github.com/dnaq/sodiumoxide). Thus, install sodium by following the instructions [here](http://doc.libsodium.org/installation/README.html).

For windows, download and use the [prebuilt mingw library](https://download.libsodium.org/libsodium/releases/libsodium-1.0.2-mingw.tar.gz).
Extract and place the libsodium.a file in "bin\x86_64-pc-windows-gnu" for 64bit System or "bin\i686-pc-windows-gnu" for a 32bit system.

Sqlite3 is also native dependency for [rustsqlite](https://github.com/linuxfood/rustsqlite). Compile Sqlite by following the instriction [here](https://www.sqlite.org/howtocompile.html)

Extract the libsqlite3.a file from the libs folder and place in usr\libs or in "bin\{TRIPLE}". Also place the .so or
.dll file in the project root folder.

 
##Todo Items

- [x] Set up facade design pattern
- [x] Test facade pattern
- [x] Set up accumulator
- [ ] Accumulator tests
- [x] Message header 
- [x] Message header tests
- [ ] API version 0.0.6
- [ ] Bootstrap handler implementation
- [ ] Bootstrap handler test
- [ ] Tcp Networking
  - [ ] Tcp live port and backup random port selection 
  - [ ] Create send/rcv channel from routing to connections object
  - [ ] Implement test for basic "hello world" two way communication
  - [ ] Add connection established/lost messages to be passed to routing (via channel)
  - [ ] Benchmark tx/rv number of packets 
  - [ ] Benchmark tx/rc Bytes per second 
- [x] Create sort and bucket index methods 
- [x] Implement routing table
- [ ] Test routing table 
- [ ] Implement sentinel 
- [ ] Test sentinel 
- [ ] Implement connection manager
- [ ] Allow tcp and then utp connections and wrap in connection object. [See here for tcp NAT traversal] (http://www.cmlab.csie.ntu.edu.tw/~franklai/NATBT.pdf) [and here fur ucp/dht NAT traversal
  ](http://maidsafe.net/Whitepapers/pdf/DHTbasedNATTraversal.pdf)
- [x] Implement routing message types (Connect FindNode)
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
