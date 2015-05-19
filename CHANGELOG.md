# Routing - Change Log

## [0.1.5]

- [ ] Address relocation

    < new node ABC | routing at ABC { mutate name to PQR } | >
  - [ ] add optional 'relocated' name field to put_public_id message
  - [ ] put_public_id handler
    - on from node; node_sentinel; SendOn with new name, signed
    - on from group; group_sentinel; Cache PublicId
  - [ ] update Id, PublicId and NodeInfo with 
------------

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
- [ ] Address re-location (security essential)
- [ ] Implement routing connections management

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
