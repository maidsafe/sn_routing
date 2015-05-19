# Routing - Change Log

## [0.1.5]

- [ ] Address relocation

    < new node ABC | routing at ABC { mutate name to PQR } | routing at PQR {cache PublicId} >
  - [ ] add optional 'relocated' name field to put_public_id message
  - [ ] put_public_id handler
    - on from node; node_sentinel; SendOn with new name, signed
    - on from group; group_sentinel is crucial here; Cache PublicId
    - put_public_id_response message; only return relocated name
  - [ ] enable Id, PublicId and NodeInfo with 'relocated' name
- [ ] Sentinel
  - [ ] remove old sentinel (archive in sentinel crate until tests are carried over)
  - [ ] plug in Sentinel crate into Routing [Reference document](https://docs.google.com/document/d/1-x7pCq_YXm-P5xDi7y8UIYDbheVwJ10Q80FzgtnMD8A/edit?usp=sharing)
  - [ ] break down (header, body) into correct (request, claim) and dispatch
  - [ ] update signature of handler functions to request and claim
  - [ ] block messages at filter once Sentinel has resolved
  - [ ] update construction of message_header (original header lost after Sentinel)
- [ ] Message Handling
    - [ ] move all handler functions to separate module
        - [ ] finish implementation of handle get_data (and verify all others)
    - [ ] make event loop in routing internal for
        - receiving messages from CRUST
        - resolved claims from Sentinels (keep Optional return type for now)
        - possibly host Sentinels in their own thread
    - [ ] rename types::Action -> types::MessageAction; rename RoutingNodeAction -> MethodCall
    - [ ] Interface handle Result < Option < Action >, >
- [ ] new authority "our_close_group" for account transfer; source_group = element = destination
- [ ] replace MessageTypeTag with full enum.
    - [ ] POC first and move UnauthorisedPut into explicit message structure.
- [ ] correct name calculation of pure Id; hash should include signature
- [ ] limit swarm to targeted group (ie, add target to send_swarm_or_parallel or extract from header)

------------
### carry over
- [ ] Implement relay id exchange for client node
- [ ] Complete Client Interface (Facade)
- [ ] Implement routing node (100%)
- [ ] Examples:
  - [ ] zero state network
  - [ ] Routing Node with type erased cache
  - [x] Routing Client accepting key, value as string for GET/PUT
  - [x] Local Network Test. 12 Linux, 2 OSX, 2 WIN
  - [ ] 101 Droplet test
- [ ] Version 0.1.6 (crates.io)


## [0.0.9 - 0.1.4]

- [x] Move bootstrap out of routing
- [x] Complete Routing Node Interface to accomodate churn
- [x] Add caching to node interface
- [x] Handle ID Caching
- [x] Handle Cache / Get / Check calls
- [x] Routing message handling
- [ ] Sentinel:
  - [x] Handover existing implementation
  - [x] Account transfer merge
  - [x] Group response merge
  - [x] Signature checks
  - [ ] QA Sentinel including code review from system design perspective
- [x] Check Authority (Ensure use and implementation of Authority is in line with the design doc / blog.)
- [x] Implement unauthorised_put in routing_node and routing_client (this skips Sentinel checks)
- [x] Implement routing connections management


## [0.0.7 - 0.0.8]

- [x] Bootstrap handler implementation
- [x] Bootstrap handler test
- [x] Create sort and bucket index methods
- [x] Implement routing table
- [x] Test routing table
- [x] Implement sentinel (initial)
- [x] Finalise sentinel in line with tests
- [x] Implement client node
- [x] Test sentinel
- [x] Implement routing message types (Connect FindNode)
- [x] Test message types
- [x] Implement Get Put Post messages
- [x] Version 0.0.8

## [0.0.6]

- [x] Set up facade design pattern
- [x] Test facade pattern
- [x] Set up accumulator
- [x] Accumulator tests
- [x] Message header
- [x] Message header tests
- [x] API version 0.0.6
