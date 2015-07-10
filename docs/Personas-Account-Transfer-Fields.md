# Persona Account Transfer

To offer a reliable information, on each churn managing personas must update relevant nodes with appropriate account information. Following presents information required to be transferred on account transfer by managing personas.


## Storage client manager
Storage client manager keeps records about the storage clients it is responsible for. The information kept represent the amount of network space the storage client is entitled to.

| Storage client id | Available space | Stored space |
| ------------------| --------------- | ------------ |


## Data manager
Data manages holds account information about chunks it is responsible for. The account information for a chunk represent the chunk name and the id and status of nodes storing the chunk.

| ChunkName | chunk size | `storage_node`s |
| --------- | ---------- | --------------- |

storage node info has id and the status (online / offline) for the node storing the chunk. We require 4 on line nodes and a max of 4 off line nodes. The off line is a FIFO queue and if any node is pushed off then its lost space is increased and stored is decreased.

## Storage node manager

Storage node manager holds account information about `storage nodes` it is responsible for. The account information for a storage node represent the id of the storage node along with store success/failure statistics related to that storage node.

| Storage node id | offered space | data stored | data lost |
| ----------------| ------------- | ------------ |--------- |
