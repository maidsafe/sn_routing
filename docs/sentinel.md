#Sentinel overview

## Quick intro to network consensus, authority and crypto usage.

In a decentralised and autonomous network there are many challenges to face. One such challenge is the range of attacks that consist of Sybil / Sparticus and Forgery attacks (did the message really come from who you think). One of the simplest attack to foil is the forgery attack, thanks to asymmetric cryptography. This allows for a public key to be known by everyone and when anything is encrypted with this key it can only (supposedly) be decrypted by the private key of that key pair. Assuming a reasonable algorithm, adequate key size and an effective implementation, this holds true.

This also removes the Sparticus type attacks (claim to be another identity), but not necessarily Sybil attacks, where an attack on a section of a network is enough to persuade the rest of the network that any request is valid, or indeed, anything asked of that part of the network is genuine. To overcome this, several techniques are used in parallel, these are:

1. Have nodes create key chains (a chain of keys each signing the next until one is selected). We call these Fobs. A PublicFob consists of a public_key, a signature and a name field. The name is the SHA512HASH(public_key+signature), making forging a key very difficult (we can confirm the signature is also signed by a valid key pair by checking the signature, where this 'pure key' is self signed). The Fob type is this PublicFob + the private key.

2: Ask the network to store the PublicFob for a node. The network will accept this if the node has certain characteristics (based on rank) and the key has less than three leading bits that are different from the current group of nodes. This ensures key placement distributes equally across the address range, With regard to rank, consider only a single non-ranked node allowed per group (more on groups in point four). Failure to increase rank means that the key is deleted from the network and has to be re-stored.

3. This now resembles a PKI network where to speak to node ABC, the PublicFob at ABC must be retrieved, and to ensure validity, a message encrypted to the node. Alternatively, checking a message from the node is signed using that PublicFob.public_key would also ensure authenticity. This implementation is unique as no central authority exists and the network distributes and collects keys, as any DHT would, except in this case the DHT is secured by the very PKI it manages. In short, this is very secure implementation and does not require any human intervention, unlike a certificate authority.

4. Assemble nodes into groups that will act in unison on any request/response. Groups are selected to be large enough to ensure a Sybil attack would require at least 3X network size of attackers to be able to join (a single attacker with no other node types joining) the network. Each group requires 28 of 32 (the close group size) to reach consensus. 

5. Allow a failure rate, as failures will definitely happen. This is implemented by having a GroupSize of say 32 and a QuorumSize of 28. This means for any action we require 28 nodes close to a target address to agree and carry out an action.

This Quorum creates a mechanism where another group or node can confirm a network state. This is called group consensus.

The group consensus provides the network a way to request or carry out actions and ensure requests are valid and actions completed. This is required as the network is self regulating and autonomous.

A client has a close group and requires to persuade this group to request the network take an action which *Puts* something on the network (a data element/message etc.) Clients create data and messages, the network handles these. As the client cannot just connect to an arbitrary group and demand something be done, they connect to their close group and register themselves (with their Fob) an account. The close group can then be persuaded by the client to request another part of the network create something (a Put). In the case of the SAFE Network, the close group requests the client pay via safecoin (the crypto currency/network token of the SAFE Network) to put data.

In short, a client can sign request to the group (crypto secure) and the group can check validity of the request and then ask the appropriate group close to the address of the data, or message, to accept this request.

After anything is put, the client can mutate certain types of data directly (if they have signed it). This is the case for directory entries, where a client can add versions to a list (StructuredDataVersion) as it was put signed by the client. So, the owner of the signature can sign a request to alter directory entries. This is crypto secured authority and does not require the close group for consensus.

In the case of groups requesting actions, the SAFE Network employs group based consensus. The network grants authority based on a group that can be measured as a valid close group, where each member has signed a request confirming membership of that close group. This authority is what the sentinel confirms prior to the routing object processing an action request. Almost all messages are checked by the Sentinel, with the exception of get_group, as this fetches Fobs which are self-validating and fetch a copy of all Fobs from all group members, confirming they agree and validate. Get_group is only used for making sure we connect to our close group as a client or node.  

##Sentinel components

The sentinel consists of few components and requires no network connection. This is to allow crucial elements to be fully tested. The elements are limited to two accumulator pairs, with each pair represents a different authority type:

1. Node level direct authority (i.e. could be a client)

2. Group base consensus

In 1 we just accumulate a single message and get the Fob to check a signature.
In 2 we require to get at least QuorumSize messages, for group based consensus, before retrieving the Fobs to check signatures and confirm the group. We also check the nodes are as close to each other in XOR space as our own group (with varying error rate). The process is as follows:

1. Message Arrives

2. Check Accumulator has seen it, if not Send a GetKey request (for a group or single node)

3. Add to accumulator. If return is true then check the key accumulator of that pair -> if true then confirm the signature with the Fob (asymm::CheckSignature(Fob.public_key, message)

If the key accumulator did not have the key(s) accumulated (i.e. accumulator.CheckQuorumReached) the network takes no action. Alternatively: 

1. The key arrives (from GetKey response)

2. Check value accumulators have(address). The address is the source_id+messge_id of the request and may be a group ID or nodeId

3. If not found then ignore message

4. Otherwise accumulator.Add(key) to the proper key accumulator of the pair

5. If this returns true, the keys and value (via accumulator.GetAll() calls are received from both accumulators and signatures are confirmed. The group  returns a valid message to the object holding the sentinel (the sentinel add call will be async)

The accumulators are LRU cache based and will empty old messages that do not confirm in this manner.

## One Explicit Example

    < Client {
       Generate payload
       Sign payload  // currently not the case
       Generate message (payload, signature)
       Sign message
       Assign message id
       Generate header (message id, signature, source={client node, no group})
       Send to Client Manager
      }
    | Client Manager {
        Filter on message id + source=client node
        Swarm
        (Handle pre-sentinel skipped, only for GetGroupKey, GetKey, PutKey)
        Sentinel {
          Receive single message
          GetKey
           - to this Client Manager group
           - from each manager, to all other managers
           - preserve message id
           - add signature
           - from_authority = Client Manager
          {
            Filter on same message id + source=group node from client manager
                         --> add MessageTypeTag to FilterValue
                         --> add from_authority to FilterValue
            Swarm
            Handle pre-sentinel {
              GetKey->
              GetKeyResponse (preserve message id, Group Keys + Client Key,
                              // original signature from GetKey)
            }
          }
          Accumulate original message and GetKeyResponses
                                          (only if we have called for it)
          Merge keys to verify group
          Check signature of client
          Return Sentinel
        }
        Handle Message in Persona
        Send to NAE Manager, preserve message id
      }
    | NAE Manager {
        Filter on message id + source = client manager node + MessageTypeTag
        Swarm
        (Handle pre-sentinel skipped)
        Sentinel {
          Receive first message from group
          GetGroupKey
           - to Client Manager group (target_id)
           - preserve message id
           - add signature
           - from_authority = NAE-manager
          {
            Filter in Client Manager node on same message_id
                                             + source = NAE-node
                                             + from_authority = NAE_manager
                                             + MessageTypeTag
            Swarm
            Handle pre-sentinel {
              GetGroupKey->
              GetGroupKeyResponse (preserve message id, Group Keys,
                                   // original signature from GetGroupKey)

            }
          }
          Accumulate original message and GetKeyResponse (one per source.node)
                                          (only if we have called for it)
          Merge keys to verify group
          Return Sentinel
        }
        Handle Message in Persona
      }
    >
