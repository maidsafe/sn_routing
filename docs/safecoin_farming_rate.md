# SafeCoin Farming Rate (version 0.8) DRAFT

## Introduction

The farming rate is a mechanism to allow the network to balance supply and demand of the network capabilities. This includes primarily storage, but takes into account bandwidth, cpu and any other resources involved in the management of network data. To achieve this the network requires to know when there is too much, just enough or too little resources.

## DataManager groups

A DataManager is a specialisation of a NaeManager. It has the responsibility of storing data and ensuring it's integrity. Each DM group will monitor 2 copies of each ImmutableData type. There is a primary DM group, a backup DM group and sacrificial DM group for the three types created for every ImmutableData packet.

## Data types.

ImmutableData has three types, these are ImmutableData, ImmutableDataBackup & ImmutableDataSacrificial. These types all contain the same data (see [types lib](https://github.com/maidsafe/maidsafe_types)) and are monitored by the DataManagers.

## Sacrifical copies

The third data type ImmutableDataSacrificial which is the network measuring stick. These types are only attempted to be stored, whereas other types MUST be stored. In the case where other types cannot be stored then copies of Sacrificial data will be deleted from the PMID nodes, and a notification will be sent from pmid_node back to PmidManager then eventually reach DataManager (see [put_flow](https://github.com/maidsafe/safe_vault/blob/master/docs/put_flow.md) and check put_response part for detail).

## Farming Rate
This rate calculation is a simple approach and meant as a tool to investigate the algorithm. A simple add/subtract mechanism is in place to allow measurement. This is not intended for production and will undergo vigorous proofs (which are not complex, but need to be linked to cost of storage from client side)

The initial Farming rate mechanism is as follows:

1. Start at FM == 1
2. For every Sacrificial data store (both copies) the rate increases by 1.
3. For every Sacrificial data unable to be stored (or indeed deleted) the farming rate shall drop by 1.

[It is very likely this rate will exponentially increase and linearly drop after measurements]

Vaults will keep a placeholder and on churn attempt to store Sacrificial data lost by requesting copies of the backup immutable data, this happens until we get back to a position of full nodes again.

## Accounting

The Farming rate is held by all DM in a group, on a churn event this specific account info is transferred as a refresh command. The account type is orderable and the routing sentinel will get the median value to return back to vaults.
