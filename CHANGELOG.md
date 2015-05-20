# Routing - Change Log

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
