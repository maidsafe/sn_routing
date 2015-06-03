# SafeCoin Farming Rate (version 0.8) DRAFT

## Introduction

The farming rate is a mechanism to allow the network to balance supply and demand of the network cpabilities. This includes primarily storage, but takes into account bandwidth, cpu and any other resources involved in the management of network data. To achieve this the network requires to know when there is too much, just enough or too little resources.

## DataManager groups

A DataManager is a specialisation of a NaeManager. It has teh responsibility of storing data and ensuring it's integrity. Each DM group will store 2 copies of each ImmutableData type. There is a primary DM a backup DM and sacrifical DM for the three types created for every ImmutabelData packet.

## Data types. 

ImmutableData has three types, these are ImmutableData, ImmutableDataBackup & ImmutableDataSacrificial. These types all contain the same data (see [types lib](https://github.com/maidsafe/maidsafe_types)) and are monitored by the DataManagers. 

##Sacrifical copies 

The third data type ImmutableDataSacrificial which is the network measuring stick. These types are only attempted to be stored, whereas other types MUST be stored. In the case where other types cannot be stored then teh 2 copies of Sacrifical data will be deleted form the PMID nodes, by sending a delete data message to the PmidManagers of that node. 

##Farming Rate
This rate calculation is a simple approach and meant as a tool to investigate the algorithm. A simple add/subtract mechnism is in place to allow measurement. This is not intended for production and will undergo vigerous proofs (which are not complex, but need to be linked to cost of storage from client side)

The initial Farming rate mechnism is as follows:

1. Start at FM == 1
2. For every Sacrifical data store (both copies) the rate increases by 1.
3. For every Sacrifical data unable to be stored (or indeed deleted) the farming rate shall drop by 1. 

[It is very likely this rate will exponentially increase and linearly drop after measurements]

Vaults will keep a placeholder and on churn attempt to store Sacrifical data lost by requestiong copies of the backup immutable data, this happens until we get back to a position of full nodes again. 

## Accounting 

The Farming rate is held by all DM in a group, on a churn event this specific account info is transferred as a refresh command. The account type is orderable and the routing sentinel will get the median value to return back to vaults. 

