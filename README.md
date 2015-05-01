# maidsafe_vault

|Crate|Travis|Appveyor|Coverage|
|:------:|:-------:|:-------:|:------:|
|[![](http://meritbadge.herokuapp.com/maidsafe_vault)](https://crates.io/crates/maidsafe_vault)|[![Build Status](https://travis-ci.org/dirvine/maidsafe_vault.svg?branch=master)](https://travis-ci.org/dirvine/maidsafe_vault) | [![Build status](https://ci.appveyor.com/api/projects/status/qglf0d3o28mxid6k?svg=true)](https://ci.appveyor.com/project/dirvine/maidsafe-vault-hyyvf) |[![Coverage Status](https://coveralls.io/repos/dirvine/maidsafe_vault/badge.svg)](https://coveralls.io/r/dirvine/maidsafe_vault)|


| [API Documentation](http://dirvine.github.io/maidsafe_vault/) | [MaidSafe System Documention](http://systemdocs.maidsafe.net/) | [MaidSafe web site](http://www.maidsafe.net) | [Safe Community site](https://forum.safenetwork.io) |

#Overview

An autonomous network capable of data storage/publishing/sharing as well as computation, value transfer (crypto currency support) and more. Please see below for a more detailed description of the operations involved in data storage.


#Todo

- [x] Implement VaultFacade
    - [x] Follow the interface design with routing (already in place as first go)
    - [x] Implement VaultFacade initally (provide a guide line for later on persona implementation)
- [x] Implement chunkstore
- [x] Test chunkstore
- [x] Implement MaidManager
- [x] Implement DataManager
- [x] Implement PmidManager
- [x] Implement PmidNode
- [x] Implement VersionHandler
- [x] Test MaidManager
- [x] Test DataManager
- [x] Test PmidManager
- [x] Test PmidNode
- [x] Complete Put Flow
- [x] Complete Get Flow
- [x] Complete Create Maid Account Flow  // may not be required for a simple implementation
- [x] Test Put Flow
- [x] Test Get Flow
- [ ] Test with client having simple put and get ability
- [ ] Integration Test
- [ ] Complete Post Flow
- [ ] Handle Churn
    - [ ] Implement Account Transfer
        - [x] Handle churn for all Persona (except PN)(retrive account, move to lru, apply account)
        - [x] Before retrieving accounts, pass close_group (get from routing) to DM and remove down pmids
        - [x] Before retrieving accounts, pass close_group to PM and remove accounts of down pmids
        - [ ] Implement HandlePut for Account transfer data (call apply accounts for relevant persona)
        - [ ] Implement merge trait for accounts of MM
        - [ ] Implement merge trait for accounts of DM
        - [ ] Implement merge trait for accounts of PM
        - [ ] Implement merge trait for accounts of VH
    - [ ] Churn Test
- [x] Installers (linux deb/rpm 32/64 bit, Windows 32 / 64. OSX)
- [ ] API version 0.0.9
- [ ] Test with client having file system feature
- [ ] Implement MpidManager
    - [ ] Complete the put route (sending message)
    - [ ] Complete the get route (checking message)
- [ ] Test with client having messaging ability
- [ ] Performance Test
- [x] Coverage analysis
- [ ] API version 0.1.0
#Detailed documentation

### Overview
The MaidSafe Network consists of software processes (nodes), referred to as vaults. These vaults perform many functions on the network and these functional components are referred to as personas. The underlying network, when linked with [routing](https://github.com/dirvine/routing), is an XOR network and as such a node may express closeness or responsibility to any other node or element on the network, if the node is in relative close proximity to the target. In this summary the phrase **NAE** (Network Addressable Element) is used to refer to anything with a network address including data. 

The vaults rely on [routing](https://github.com/dirvine/routing) to calculate responsibilities for NAE via the relevant [API calls](http://dirvine.github.io/routing/routing/). 

These calls allow us to calculate the network from the perspective of any NAE we may be responsible for. It cannot be stressed enough that the ONLY way to determine responsibility for an NAE is to see the network from the perspective on the NAE. If we sort the vector of nodes we know about and their close nodes (referred to as the group matrix) and we do not appear in the first K (replication count) nodes then we are not responsible for the NAE. This is a fundamental issue and the importance of this cannot be emphasised enough. 

As the network is very fluid in terms of churn and vault capabilities the vault network must measure and report on individual vaults and importantly ensure all the personas of any vault are performing their tasks for the NAE they are responsible for. In event of any churn around a given network segment, a Matrix change object is created by Routing and passed on to Vault. This object contains list of old and new nodes in group matrix. Based on this information, it provides helper function to derive certain information related to any given NAE :
If the node getting churn event is among first k nodes closest to provided NAE. If yes, which new node(s) need information related to the provided NAE. If not, delete any information stored related to the given NAE.

Churn, duplication of data and ensuring all members of a group agree is handled by a combination of Synchronisation, The Accumulator and group messages. This is a complex set of rules that requires significant attention to edge cases. 

# MaidSafe Language of the Network

### general considerations

Nodes and data both live in the same XOR space which is addressed with a 2^512 bit key; a Network-Addressable-Element (NAE).  A message flows from a NAE to a NAE.  An operation can be performed on a message flow by a manager group.

A message flow from start to end can be represented by

    < NAE_1 | manager | NAE_2 >

where the NAE can be a node (ie a vault or a client - Direct NAE) or a data element (Indirect NAE).  The manager group operating on the message flow will act forward `manager | NAE_2 >` under normal / successful conditions.  The manager will act backwards `< NAE_1 | manager` upon error.

If no operation is needed on the message flow then this special case is represented by

    < NAE | NAE >

For a given message type `ACTION` the functions shall be named

    < A::ACTION | B::ActOnACTION | C::PerformACTION >

The function `HandleACTION` is reserved for the VaultFacade. Currently these message types are Connect\*, ConnectResponse\*, FindGroup\*, FindGroupResponse\*, GetData, GetDataResponse, PutData, PostMessage, where message types with \* are completed in routing and exempt from this naming convention.

For clarity, a message is passed through RoutingNode and VaultFacade upto Persona according to following abstraction

    RoutingNode::MessageReceived {
      Parse; Filter; Cache; SendOn; Relay; Drop; Sentinel;
      Switch RoutingNode::HandleMessage(MessageType /* */) {
        Completed in routing or
        VaultFacade::HandleACTION {
          Switch on Authority & template on DataType {
            Persona::ActOnACTION or  // Currently both named HandleACTION
            Persona::PerformACTION
          }
        }
      }
    }


The triplet structure `< A | B | C >` captures the general characteristic of every message flow.  The structure is event-driven and the message id is preserved over the structure.

`< . ` corresponds to the creation of a new message flow.  A single node or client can initiate a routing call where a random message id is generated by routing.  It is noted that if a group starts a new message flow, the message id needs to be deterministically instantiated by routing.

`. | .` represents the full routing action over intermediate XOR space, as stated above,

    Parse; Filter; Cache; SendOn; Relay; Drop; Sentinel;

where `Sentinel;` is the dominant logical contribution and as such `. | .` is simply referred to as "sentinel".

`. >` terminates the message flow, and is the successful end-state of the action.  Only upon error is the flow reversed. From this it follows that the following functions should be implemented for a given action `< A | B | C >`

    A::ACTION()
    B::ActOnACTION()
    B::ACTIONFailure()
    C::PerformACTION()

Actions can be logically combined where the new start is identical to the preceding terminal,

    < A | B | C > < C | D | E >

and the joint `| C > < C |` can be considered a full consensus mechanism for an Indirect NAE C - for a Direct NAE C this consensus mechanism is trivial.  In this sense the operator `| C > < C |` transforms (a) message flow(s) into (a) new message flow(s).  Note that this joint can be trivial and in such case does not require consensus.

Where before the message flow in the structure `< A | B | C >` passes over different persona's, such messages are called "interpersona messages". The operator `| C > < C |` introduces "intrapersona messages"; [ Should these be handled as a separate type of messages in routing ? ]

## Flows

### Maid GetData and GetDataResponse

    < MaidClient | DataManager > < DataManager | MaidNode >
    < MaidClient | DataManager > < DataManager | PmidNode > < PmidNode | MaidNode >

Here `| DataManager > < DataManager |` is a consensus mechanism to decide whether DataManager has the requested data in active memory or needs to continue the GetData request as new message flows from DataManager to the archiving PmidNodes.  Note that based on Authority PmidNode can verify that the GetData request came from DataManager.  In both lines only the final message flow is GetDataResponse.

If an explicit caching at DataManager on Get is desired the second line above can be replaced by

    < MaidClient | DataManager > < DataManager | PmidNode > (< PmidNode | MaidNode > & < PmidNode | DataManager >)

where the two flows in parenthesis are both GetDataResponse.  The DataManager simply adds the data to LRUcache again.

### Maid PutData

    < MaidClient | MaidManager | DataManager > < DataManager | PmidManager | PmidNode >

Here `| DataManager > < DataManager |` can store the data in LRUcache and without delay trivially select K closest to D.name PmidNodes for archiving the data.

### Mpid Messaging

very brief, assumes knowledge on the MPID implementation

Send out message:

    < MPN_A | MPM_A > < MPM_A | MPM_B > < MPM_B | MPN_B >

Retrieve message:

    < MPN_B | MPM_B > < MPM_B | MPM_A > < MPM_A | MPN_B > < MPN_B | MPM_B >

where the last flow deviates from the existing implementation, but would notify MPM_B that the message has been retrieved and the header can be dropped.

### Remaining conventions:

    D      data
    H()    Hash512
    H^n()  n-th Hash512
    Manager{Address};
           {Address} omitted where evident,
           e.g. MaidManagers{MaidNode}
