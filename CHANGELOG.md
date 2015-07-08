# Routing - Change Log

## [0.2.8] - Version updates and minor fixes

- Updated dependencies' versions
- Fixed lint warnings caused by latest Rust nightly

## [0.2.7] - Activate act on churn

- [#426](https://github.com/maidsafe/routing/pull/426) close bootstrap connection
- [#426](https://github.com/maidsafe/routing/pull/426) routing acts on churn
- [#426](https://github.com/maidsafe/routing/pull/426) group size 8; quorum 6
- [#426](https://github.com/maidsafe/routing/pull/426) improve refresh routing_table
- [#426](https://github.com/maidsafe/routing/pull/426) cache on connect_response
- [#426](https://github.com/maidsafe/routing/pull/426) reflect own group: on FindGroupResponse in our range is seen, ask for FindGroup for our name.

## [0.2.6] - Temporary patch for Vault behaviour

- [#424](https://github.com/maidsafe/routing/pull/424) Patch for Vaults handle put behaviour

## [0.2.1 - 0.2.5] - debug with upper layers

- [0.2.5] [#421](https://github.com/maidsafe/routing/pull/421) Set Authority unauthorised put to ManagedNode to accommodate Vaults for now
- [0.2.4] [#419](https://github.com/maidsafe/routing/pull/419) Correct ClientInterface::HandlePutResponse
- [0.2.3] [#416](https://github.com/maidsafe/routing/pull/416) Activate HandleChurn (but don't act on the resulting MethodCall yet)
- [0.2.2] Update sodiumoxide dependency to `*`
- [0.2.2] Update crust dependency to `*`
- [0.2.1] Update sodiumoxide dependency to `0.0.5`

## [0.1.72] - documentation

- Fix master documentation url in readme
- [#406](https://github.com/maidsafe/routing/pull/406) enable handler for unauthorised put
- [#369](https://github.com/maidsafe/routing/issues/369) clean up unneeded features

## [0.1.71] - Finish Rust-2

- [#360](https://github.com/maidsafe/routing/issues/360) Fix intermittent failure in Relay
- [#372](https://github.com/maidsafe/routing/issues/372) Introduce unit tests for Routing Membrane
- [#388](https://github.com/maidsafe/routing/issues/388) Handle PutDataResponse for routing_client
- [#395](https://github.com/maidsafe/routing/issues/395) Preserve message_id

## [0.1.70] - Activate AccountTransfer


- [#354](https://github.com/maidsafe/routing/issues/354) Fix release builds
- [MAID-1069](https://maidsafe.atlassian.net/browse/MAID-1069) OurCloseGroup Authority
- [#363](https://github.com/maidsafe/routing/issues/363) Refresh message and ad-hoc accumulator
- [#290](https://github.com/maidsafe/routing/issues/290) Remove NodeInterface::handle_get_key
- [#373](https://github.com/maidsafe/routing/issues/373) Reduce group size for QA to 23

## [0.1.64] - bug fixes

- [#330](https://github.com/maidsafe/routing/issues/330) Who-Are-You / I-Am message for identifying new connections
- [#312](https://github.com/maidsafe/routing/issues/312) Fix never-connecting client
- [#343](https://github.com/maidsafe/routing/issues/343) Filter escalating number of connect requests
- [#342](https://github.com/maidsafe/routing/issues/342) Clean up overloaded debug command line printout
- [#347](https://github.com/maidsafe/routing/issues/347) Relay GetDataResponses and cached GetDataResponses back to relayed node

## [0.1.63] - bug fixes

- [#314](https://github.com/maidsafe/routing/issues/314) simple_key_value_store input validation lacking
- [#324](https://github.com/maidsafe/routing/issues/324) simple_key_value_store peer option
- [#336](https://github.com/maidsafe/routing/issues/336) Routing `0.1.62` causes API inconsistency in usage of RoutingClient

## [0.1.62] - restructure core of routing

- [MAID-1037](https://maidsafe.atlassian.net/browse/MAID-1037) Address relocation
  - [MAID-1038](https://maidsafe.atlassian.net/browse/MAID-1038) Integrate handlers with RelayMap
  - [MAID-1039](https://maidsafe.atlassian.net/browse/MAID-1039) put_public_id handler
- [MAID-1052](https://maidsafe.atlassian.net/browse/MAID-1052) Message Handling
  - [MAID-1055](https://maidsafe.atlassian.net/browse/MAID-1055) full review of implementation of handlers
  - [MAID-1057](https://maidsafe.atlassian.net/browse/MAID-1057) make event loop in routing_node internal
- [MAID-1062](https://maidsafe.atlassian.net/browse/MAID-1062) extract all_connections into a module
- [MAID-1070](https://maidsafe.atlassian.net/browse/MAID-1070) drop_bootstrap in coordination with CRUST
- [MAID-1071](https://maidsafe.atlassian.net/browse/MAID-1071) Implement relay id exchange for client node
- [MAID-1066](https://maidsafe.atlassian.net/browse/MAID-1066) Routing Example : update to internal event loop

## [0.1.61] - Relay module, relocatable Id, update NodeInterface

- [MAID-1114](https://maidsafe.atlassian.net/browse/MAID-1114) Relay module
- [MAID-1060](https://maidsafe.atlassian.net/browse/MAID-1060) update Interface for Vaults
- [MAID-1040](https://maidsafe.atlassian.net/browse/MAID-1040) enable Id, PublicId and NodeInfo with 'relocated' name

## [0.1.60] - essential logical corrections
- [MAID-1007](https://maidsafe.atlassian.net/browse/MAID-1007) limit swarm to targeted group
 - [MAID-1105](https://maidsafe.atlassian.net/browse/MAID-1105) delay RoutingTable new ConnectRequests
 - [MAID-1106](https://maidsafe.atlassian.net/browse/MAID-1106) examine Not For Us
- [MAID-1032](https://maidsafe.atlassian.net/browse/MAID-1032)
correct name calculation of pure Id
- [MAID-1034](https://maidsafe.atlassian.net/browse/MAID-1034) ConnectResponse needs to include original signed ConnectRequest
- [MAID-1043](https://maidsafe.atlassian.net/browse/MAID-1043) remove old sentinel
- [MAID-1059](https://maidsafe.atlassian.net/browse/MAID-1059) rename types::Action -> types::MessageAction; rename RoutingNodeAction -> MethodCall

## [0.1.1]
- Remove FailedToConnect Event

## [0.1.0]

- Re-expose crust::Endpoint as routing::routing_client::Endpoint

## [0.0.9]

- Move bootstrap out of routing
- Complete Routing Node Interface to accomodate churn
- Add caching to node interface
- Handle ID Caching
- Handle Cache / Get / Check calls
- Routing message handling
- Sentinel:
  - Handover existing implementation
  - Account transfer merge
  - Group response merge
  - Signature checks
- Check Authority (Ensure use and implementation of Authority is in line with the design doc / blog.)
- Implement unauthorised_put in routing_node and routing_client (this skips Sentinel checks)
- Implement routing connections management
- Added encodable/decodable for ClientIdPacket

Version 0.1.1

## [0.0.7 - 0.0.8]

- Bootstrap handler implementation
- Bootstrap handler test
- Create sort and bucket index methods
- Implement routing table
- Test routing table
- Implement sentinel (initial)
- Finalise sentinel in line with tests
- Implement client node
- Test sentinel
- Implement routing message types (Connect FindNode)
- Test message types
- Implement Get Put Post messages
- Version 0.0.8

## [0.0.6]

- Set up facade design pattern
- Test facade pattern
- Set up accumulator
- Accumulator tests
- Message header
- Message header tests
- API version 0.0.6
