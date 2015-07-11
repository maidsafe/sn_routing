# MAID (client anonymous store/get data) account

## Naming Conventions

MaidClient  -> is now referred to as ```storage_client```
MaidManager -> is now referred to as ```storage_client_manager```

## Introduction

The ```storage_client``` is a 2nd degree key pair, it's is signed by the pure keypair referred to a ANMAID (Anonmous). This identity is not published and does not require to be published. It is an anoymous identity used purely for put/get/delete (later) data onto the network. This is data and not communications, safecoin, computing etc. it is only data (immutable and mutable) data for private, public and private shared files. The account is held in the close group this ID connect to and is referred to as the ```storage_client_manager```group.

The account information will allow the network to measure data stored and available. This allows users of the system to interact with the network in terms of data storing.


## Motivation

To allow the network to expand at the fastest rate then as many nodes as possible need to be considered as routing nodes. At the moment this is not possible, due to the size of account information. The ```storage_client``` has been a huge amount of data, to allow deletes to be counted and reduce storage. With safecoin this delete was abandoned and the likelihood of the ```storage_client``` account being removed was considered. This is not a good mechnaism as people can abuse the network, unless a measure is in place. Therefor an account is required, but it must be minimal.

As all the machinery is in place to link accounts to vaults then there is a quick win. To allow actual storage measurements though, the delete issue is still relevant, how can we know a delete is allowed unless we know the corresponding PUT took place? The answer to that will be another design document, it's as simple as removing duplicate private data and make all data unique and signed. A signature to delete will allow reduction in storage for the client. This is considered later though and mentioned here for clarity.


## Overview

The ```storage_client``` account information can be split into two integers (64 bit). These are :
```Data Stored```
```Space Available```

These two integers are updated as so:

1. On storing any data, the stored value is incremented with the size stored. This data is syncronised amongst the group (as is already) and account transferred as per todays design. (deletes are a later design, this is increment only at the moment)

2. Space available is dependent on the number of safecoin used to purchase space. The mechanism to get safecoin or to calculate the space per coin is not part of this document. The ability to record a safecoin and be awarded space is though. This should be set at 1 safecoin per gB for now, this is a test figure and will be adjusted in the design doc for that coin. Initially we assume everyone has a safecoin in arrears limit (i.e. a free Gb)

## Implementation
