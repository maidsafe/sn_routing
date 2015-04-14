#Sentinel overview

## Quick intro to network consensus, authority and crypto usage.

In a decentralised autonomous network there are many challenges to face. One such challenge is the range of attacks that consist of sybil / sparticus and forgery attacks (did the message really come from who you think). One of the simplest attack to foil is the forgery attack, thanks to asymmetric cryptography. This allows for a public key to be known by everyone and when anything is encrypted with this key it can only (supposedly) be decrypted by the private key of that keypair. Assuming a reasonable algorithm, keysize and implementation this holds true.

This also removes the Sparticus type attacks (claim to be another identity)., but not necessarily sybil attacks, where an attack on a bit of a network is ehough to persuade the rest of the network that any request is valid or indeed anything asked of that part of th enetwork is done as expected. To overcome this MAidSafe have several techniques used in parallel. These boil down to

1. Have nodes create key chains (a chain of keys each signing the next intil one is selected). We call these Fobs. A Publicfob consists of a public_key & signature as well as a name field. The name is the SHA512HASH(public_key+signature) making forging a key crypto hard (we can confirm the signature is also signed by a valid key pair by checking the signature there, where this 'pure key' is self signed). The Fob type is this PublicFob + the private key.

2: Ask network to store the PublicFob for a node. The network will accept this if the node has certain characteristics (based on rank - later discussion) and the key is less than 3 leading bits different from the current group of nodes. This makes key placement distribute equally across the address range (as for rank consider only a single non ranked node allowed per group, and failure to increase rank means the key is deleted form the network adn has to be re-stored if possible).

3. This now resembles a PKI network where to speak to node ABC you go get the PublicFob at ABC and either encrypt a message to the node or check a message from the node is signed by using that PublicFob.public_key. The difference being no central authority exists and the network distributes and collects keys as any DHT would (except in this case the DHT is secured by the very PKI it manages). So this is very secure and does not require any human intervention (unlike a certificate authority).

4. Assemble nodes into groups that will act in unison on any request/response. So these groups are selected to be large enough to ensure a sybil attack would require at least 3X network size of attackers to be able to join (a single attacker with no other node types joining). The magic number here is 28, realistically this number is closer to 17.

5. Allow a failure rate as failures will defnitely happen. This is done by having a GroupSize of say 32 and set the QuorumSize to 28. Thie means for any action we require 28 nodes close to a target address to agreee and carry out an action.

This Quorum creates a mechnism where another group or node can belive the action is correct and valid. This is called group consensus.

The group consesnus provides the network a way to request or carry out actions and ensure such requests are valid and actions actually done. This is required as the network looks after itself (autonomous).

A client has a close group and requires to persuade this group to request the network take an action which *Puts* something on the network (a data element/message etc.) Clients create data and messages, the network handles these. As the client cannot just connect to an arbitary group and demand something be done, they connect to their close group and register themselves (with their Fob) an account. The close group can then be persuaded by the client to request another part of the network create something (a Put). In the case of Maidsafe the close group request the client pay via safecoin (it used to be they paid with storage that another group managed and agreed). So the client persuades the close group to put data. (ignore how payment is made, it actually requires client send safecoin to a provable recycle part of the network (another group confirms this)).

So a client can sign request to the group (crypto secure) and the group can check validity of the request and then ask the appropriate group close to the address of the data or message to accept this request.

After anything is put, the client can mutate this thing directly (if they have signed it). This is the case for directory entries, wehre a client can add versions to a list (StructuredDataVersion) as it was Put signed by the client. So the owner of the signature can sign a request to alter this. This is crypto secured authority and does not require the close group for consensus.

In the case of groups requesting actions then we have group based consensus and the network grants authority based on a group that can be measured as a valid close group, where each memeber has signed a request as being from that close group. This authority is what the sentinel confirms prior to the routing object processing an action request.
Almost all messages are Sentinel checked, with the exception of get_group as this fetches Fob's which are self validating and it fetches a copy of all Fobs from all group members and confirms they agree and validate. Get_group is only used for making sure we connect to our close group as a client or node.  

##Sentinel components

The sentinel consists of few components and requires no network connection. This is to allow for such a crucial element to be fully tested. The elements are limited to two (2)accumulator pairs. There are two pairs for two different authority types,

1. Node level direct authority (i.e. could be a client)

2. Group base consensus

In 1 we just accumulate a single message and get the Fob to check a signature.
In 2 we require to get at least QuorumSize messages and this is for group based consensus and then we get the Fobs and again check signature to confrim the group. We also check the nodes are as close to each other in xor space as our own group is (with varying error rate)

To achieve this the process is

1. Message Arrives

2. Check Accumulator has seen it, if not Send a GetKey request (for a group or single node)

3. Add to accumulator. If return is true then check the key accumulator of that pair -> if true then confirm the signature with the Fob (asymm::CheckSignature(Fob.public_key, message)

If the key accumulator did not have the key(s) accumulated (i.e. accumulator.CheckQuorumReached) then we do nothing and continue with other work. Then though

1. Key arrives (from GetKey response)

2. Check value accumulators have(address) the address is the source_id+messge_id of the request, may be a group ID or nodeId

3. If not found then ignore message

4. Otherwise accumulator.Add(key) to the proper key accumulator of the pair

5. If this returns true, then we get the keys and values (via accumulator.GetAll() calls from both accumulators and confirm signatures. group and return a valid message to the object holding the sentinel (the sentinel add call will be async)

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
