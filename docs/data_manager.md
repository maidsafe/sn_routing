# WIP - Do not use !!!
# Introduction

The `DataManager` [base type == `NaeManager`] is the persona that is responsible for data availability and integrity. To do so these personas must know where the data currently resides and the state of that data. This state is twofold, is the `Pmid Node` [base type ==`Node`] on-line and is the data itself intact and secure. The former is arguably the main issue as the data itself is self-validating (i.e. to construct an immutable chunk itself validates the content). To ensure this, a `DataManager` must know which nodes hold the data, and whether they are currently on or off line. These are currently the most data-heavy personas and under constant scrutiny to reduce the amount of data they hold.

## Motivation

Unlike the other personas the data manager has currently no easy win in terms of reducing the amount of information the persona holds. There is a very valid opportunity though via a better holding mechanism (via sqlite) and also the length of the keys held. So there are two factors involved in this case: more efficient engine for managing the data and also the size of the data we are managing.

In the SAFE network there are three `DataManager` groups per chunk and each group will ensure two copies are stored. These groups are deterministic and are either group zero (where hash of content == name) or group 1 (where hash(hash of content) == name, or group 3 where hash(hash(hash of content)) == name).

## Overview

The heart of the `DataManager` will be a mini SQL database. This will be managed via sqlite3. The table structure will be very simple.

| ChunkName | Version [0..3]| `PmidNodes`    |
| --------- | --------------- | --------------|

### Farming Rate

There is also a `Farming Rate` held by each `DataManager` which controls the supply and demand of storage space. This number has a base value of `2^^10` at this time. This number must be investigated further as there is no scientific reason for this value of `2^^10`. This number is only a seed number though and will not appear in a live network after the initial change.

This rate alters as the network dynamic alters and does so in this manner.

1. As a store is attempted for a third copy (version 2)

  a. If attempt fails then farming rate is halved (shift right 1 bit) from it's current value.

  b. If attempt succeeds farming rate is doubled (shift left 1 bit) from it's current value **only** when all failed 3rd copies have been successfully stored again. If there are no currently failed stores the farming rate is not altered.

Each ChunkName will have a list of associated `PmidNodes`s. The on-/off-line status of these nodes is held in the routing table of the `DataManager` already and need not be replicated in the database.

On a churn event, the SQL database should be searched for every chunk that old node had and joined with what chunks the new nodes has. Any chunk with less than two holders should now be stored to the node closest to the chunk name.
Records of nodes holding a chunk should be held in a manner so that as a new node comes on line, it is put to the top of the list.
