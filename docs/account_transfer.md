# Account Transfer

## Introduction

The purpose of account transfer is to allow the network nodes to maintain the distributed state of the network. This state is held primarily as a key value store for various personas. As
nodes go on and off line the network reconfigures around it and all state held in the group around the node has to be reconfigured. The current network implementation maintains 4 accurate
copies of all state per address (address being a node or data element). To accurately manage 4 copies a network range for the 16 close nodes must be considered due to uni-directional
closeness. This means that to ensure we have the 4 closest nodes we much consider at least 16 nodes surrounding any address.

## Naming Conventions

Proximity Group - the 16 nodes close to an address

Close Group - the 4 nodes containing accurate information on any address.


## Motivation

The motivation behind this design is to provide an efficient mechanism to transfer accounts data between nodes, whilst reusing as much of the existing design patterns as possible. As the values for all data for the various personas are potentially different then there is a lean towards forcing account data values to be synchronise-able. This really means the account value data should be consistent and not prone to any consensus. An example of bad values would be measurements that may vary across keys. These varying values must be at the very least minimised, or better removed. The current proposal is to allow account transfer to be as fast as possible and with minimum network traffic cost.

## Overview

Account transfer resembles network sync with a noticeable exception that there is at least one node less to consider. By definition a node has altered, by either disappearing or indeed possibly joining. So worst case scenario there will be a maximum of three other nodes with the info we require. An account transfer packet may be delivered to a node from another node in this proximity group of 16 at any time based on any churn at all in the proximity group.

The reason we always consider a node less is rather complex, but if a node 'moves in' to the group then one is pushed out, so why not use it's account? The reason is that as this change occurs we cannot know did the 5th node get a new message or the new node. To alleviate this concern there is a hard rule in place; if a node synchronises any action it writes it to the database. If a later account transfer happens on that key and there is already a record in the database, it's considered the latest as it happened via a sync message. If the new node missed the sync message the remaining three should (may) have synced that action and will transfer it via an account transfer message, which will be written to the database. This rule covers a huge amount of edge cases, but may leave a very small amount of error in the account transfer. This error is anticipated to be resolved in further account transfers where the error will be outvoted (so to speak) by the remaining correct values of the majority of the nodes.

In cases of conflict, which is determined to be the case where the consensus required is not achieved, either through lack of copies or the copies not matching then the resolutions shall be; Send a synchronisation request on the key in question. i.e. if a key does reach consensus ie.the first X copes are all matching and X == min required match, then the key/value is accepted and written to the database if there is no key of that name already in place.

The routing library will present an interface that allows upper layers to query any changes to the proximity group. This is defined in the section below.

## Assumptions

Routing will fire a signal of proximity group change. This will include an object (node_change or churn) that allows queries to be made on that change. This API will allow upper layers to query each state key they have and return an object that states the key/value should be either:

1. Deleted
2. Sent on to at least 1 node (possibly more than 1)
3. Left as is

## Implementation

The implementation of the account transfer is presented in pseudo code below

```
struct Record {
  Identity key;
  NonEmptyString value;
};


Action routing::node_change(Record); or
Action routing::node_change(Record::key);
```

The action will determine whether to delete, send or ignore any action to be taken on this key.

Prior to calling this method in routing the node must provide a method similar to the accumulator in a normal message flow. This means that a vector or container similar will 'collect' account transfer messages and match them to call this method.

This takes the form
```
struct Message {
  Identity key;
  NonEmptyString value;
};

struct MessageQueue {
  Message message;
  int count;
}
class OnMessage {
 public:
    void account_transfer_received(Message); // add to Queue
 private:
  std::vector<MessageQueue> messages_;
};

void OnMessage::account_transfer_received(Message) {
  auto found messages_.find(message.key);
  if (found != std::end(messages_) {
    ++found->count;
    if(found.value != message.value) {
      messages_.erase(found);
      DoSyncRequest(message.key);
    }
    if (count == (routing::parameters::close_group + 1) / 2)

     TryAddToDataBase(Message) // fail if already in database

    if (count == routing::parameteres::close_group -1)
     messages_.erase(found); // all transferred now
  } else {
    messages_.push_back(Message);
  }
}

 // Add in a mechanism to prune this list in a similar fashion to that which will be applied in routing firewall.
```
The `OnMessage::Action routing::node_change(Record);` will return a value that triggers an action (such as delete, send to one/many, etc. or ignore) on adding to this map. It should be noted that account transfers could happen at any time for any node and any persona.

For integer based transfers where there may be slight differences in the integer values take the median value of the values obtained when the majority of transfers has been received.
