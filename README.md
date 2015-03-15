# routing

Routing - specialised storage DHT

Travis build and test status

[![Build Status](https://travis-ci.org/dirvine/self_encryption.svg?branch=master)](https://travis-ci.org/dirvine/self_encryption)

[Documentation](http://dirvine.github.io/routing)

##Todo Items

- [x] Set up facade design pattern
- [x] Test facade pattern
- [ ] Tcp Networking
  - [ ] Tcp live port and backup random port selection 
  - [ ] Create send/rcv channel from routing to connections object
  - [ ] Implement test for basic "hello world" two way communication
  - [ ] Add connection established/lost messages to be passed to routing (via channel)
  - [ ] Benchmark tx/rv number of packets 
  - [ ] Benchmark tx/rc Bytes per second 
- [ ] Create sort and bucket index methods 
- [ ] Implement routing table
- [ ] Test routing table 
- [ ] Implement sentinel 
- [ ] Test sentinel 
- [ ] Implement connection manager
- [ ] Allow tcp and then utp connections and wrap in connection object. [See here for tcp NAT traversal] (http://www.cmlab.csie.ntu.edu.tw/~franklai/NATBT.pdf) [and here fur ucp/dht NAT traversal
  ](http://maidsafe.net/Whitepapers/pdf/DHTbasedNATTraversal.pdf)
- [ ] Implement routing message types (Connect FindNode)
- [ ] Implement Get Put Post messages 
- [ ] Test basic facade (normal DHT Get Put with republish)
- [ ] Version 0.0.8
- [ ] Implement NAT traversal
- [ ] Version 0.1 (crates.io)
