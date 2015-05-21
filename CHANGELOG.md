# Routing - Change Log

## [0.1.1]
- Remove FailedToConnect Event

## [0.1.0]

-  Re-expose crust::Endpoint as routing::routing_client::Endpoint

## [0.0.9]

-  Move bootstrap out of routing
-  Complete Routing Node Interface to accomodate churn
-  Add caching to node interface
-  Handle ID Caching
-  Handle Cache / Get / Check calls
-  Routing message handling
-  Sentinel:
  -  Handover existing implementation
  -  Account transfer merge
  -  Group response merge
  -  Signature checks
-  Check Authority (Ensure use and implementation of Authority is in line with the design doc / blog.)
-  Implement unauthorised_put in routing_node and routing_client (this skips Sentinel checks)
-  Implement routing connections management
-  Added encodable/decodable for ClientIdPacket

Version 0.1.1

## [0.0.7 - 0.0.8]

-  Bootstrap handler implementation
-  Bootstrap handler test
-  Create sort and bucket index methods
-  Implement routing table
-  Test routing table
-  Implement sentinel (initial)
-  Finalise sentinel in line with tests
-  Implement client node
-  Test sentinel
-  Implement routing message types (Connect FindNode)
-  Test message types
-  Implement Get Put Post messages
-  Version 0.0.8

## [0.0.6]

-  Set up facade design pattern
-  Test facade pattern
-  Set up accumulator
-  Accumulator tests
-  Message header
-  Message header tests
-  API version 0.0.6
