# Routing - Change Log
## [0.3.12]
- [MAID-1360](https://maidsafe.atlassian.net/browse/MAID-1360) unit tests for RoutingCore
- [MAID-1357](https://maidsafe.atlassian.net/browse/MAID-1357) unit tests for message and refresh accumulator
- [MAID-1359](https://maidsafe.atlassian.net/browse/MAID-1359) unit tests for Relay
- [MAID-1362](https://maidsafe.atlassian.net/browse/MAID-1362) more unit tests for StructuredData, Types and Utils
- [MAID-1350](https://maidsafe.atlassian.net/browse/MAID-1350) introduce simple measuring tools for establishing the threshold for the accumulators
- [MAID-1348](https://maidsafe.atlassian.net/browse/MAID-1348) ChurnNode for integration tests

## [0.3.11]
- [#699](https://github.com/maidsafe/routing/pull/699) implement debug for StructuredData
- [#696](https://github.com/maidsafe/routing/pull/696) expose NAME_TYPE_LEN and random traits
- [#695](https://github.com/maidsafe/routing/pull/695) correct style error in error.rs
- [#692](https://github.com/maidsafe/routing/pull/692) add cause and event::DoRefresh for improvements to churn
- [#691](https://github.com/maidsafe/routing/pull/691) update QA libsodium documentation
- [#690](https://github.com/maidsafe/routing/pull/690) correct failing test
- [MAID-1361](https://maidsafe.atlassian.net/browse/MAID-1361) unit tests for id, public_id, error, data, direct_messages
- [MAID-1356](https://maidsafe.atlassian.net/browse/MAID-1356) unit test filter.rs
- [MAID-1358](https://maidsafe.atlassian.net/browse/MAID-1358) unit test signed_message

## [0.3.10]
- [#685](https://github.com/maidsafe/routing/pull/685) use latest accumulator

## [0.3.9]
- [MAID-1349](https://maidsafe.atlassian.net/browse/MAID-1349) refresh_request to use authority
- [MAID-1363](https://maidsafe.atlassian.net/browse/MAID-1363) remove wake_up.rs
- [MAID-1344](https://maidsafe.atlassian.net/browse/MAID-1344) ::error::ResponseError::LowBalance
- [MAID-1364](https://maidsafe.atlassian.net/browse/MAID-1364) clean out types.rs
- [#663](https://github.com/maidsafe/routing/issues/663) only churn on QUORUM connected nodes
- [#662](https://github.com/maidsafe/routing/issues/662) enable dynamic caching
- [#670](https://github.com/maidsafe/routing/issues/670) update Travis with ElfUtils
- [#669](https://github.com/maidsafe/routing/issues/669) update Travis with install_libsodium.sh

## [0.3.8]
- [#664](https://github.com/maidsafe/routing/pull/664) update to match Crust's api change

## [0.3.7] Unique signed messages
- [#660](https://github.com/maidsafe/routing/pull/660) Unique SignedMessage with random bits and routing event loop

## [0.3.6]
-  Fixed [#560](https://github.com/maidsafe/routing/issues/560) Removed unstable features.
-  Updated "hello" messages
-  Updated cache-handling in line with current Routing requirements
-  Further work on churn handling

## [0.3.5] improvements to ResponseError and testing

- [#647](https://github.com/maidsafe/routing/pull/647) CI disallow failures on windows x86 (32bit) architecture
- [#646](https://github.com/maidsafe/routing/pull/646) correct ResponseError::HadToClearSacrificial to return NameType and u32 size
- [#645](https://github.com/maidsafe/routing/pull/645) key_value_store to test < Client | ClientManager > < ClientManager | NaeManager > behaviour

## [0.3.4] Improvements to filter and accumulator behavior

- [#642](https://github.com/maidsafe/routing/pull/642) improve filter to block resolved messages
- [#640](https://github.com/maidsafe/routing/pull/640) Enable duplicate get requests

## [0.3.3] Events and refresh

- [#638](https://github.com/maidsafe/routing/pull/638) debug formatting for Data
- [#637](https://github.com/maidsafe/routing/pull/637) our authority API update
- [#626](https://github.com/maidsafe/routing/pull/626) refresh messages
- [#636](https://github.com/maidsafe/routing/pull/636) rustfmt formatting
- [#634](https://github.com/maidsafe/routing/pull/634) rename fob to public_id in routing table
- [#628](https://github.com/maidsafe/routing/pull/628) initial handlers for cache
- [#624](https://github.com/maidsafe/routing/pull/624) remove peers from example CLI, small improvements
- [#620](https://github.com/maidsafe/routing/pull/620) event bootstrapped, connected, disconnected
- [#623](https://github.com/maidsafe/routing/pull/623) maximum allowed size for structured data

## [0.3.2] Final public API for version 0.3

- internal bug fixes
- partial restoration of unit tests
- fine-tuning public API in correspondence with user projects

## [0.3.1] Implementing internal functionality

- [#582](https://github.com/maidsafe/routing/pull/582) implement routing public api channel to routing_node
- [#580](https://github.com/maidsafe/routing/pull/580) review message_received in routing_node
- [#579](https://github.com/maidsafe/routing/pull/579) simplify example to a pure DHT (no client_managers)
- [#578](https://github.com/maidsafe/routing/pull/578) implement connect request and connect response
- [#577](https://github.com/maidsafe/routing/pull/577) implement sending events to user
- [#576](https://github.com/maidsafe/routing/pull/576) implement accumulator as stand-in for sentinel
- [#575](https://github.com/maidsafe/routing/pull/575) temporarily remove sentinel dependency
- [#574](https://github.com/maidsafe/routing/pull/574) fix sodiumoxide problems with Travis CI
- [#573](https://github.com/maidsafe/routing/pull/573) use signature as filter type, deprecating message id
- [#572](https://github.com/maidsafe/routing/pull/572) implement request network name
- [#571](https://github.com/maidsafe/routing/pull/571) refactor example to new api
- [#567](https://github.com/maidsafe/routing/pull/567) implement generic send for signed message
- [#566](https://github.com/maidsafe/routing/pull/566) implement bootstrap connections in core
- [#565](https://github.com/maidsafe/routing/pull/565) implement target nodes in core
- [#564](https://github.com/maidsafe/routing/pull/564) pruning and clean up

## [0.3.0] Unified Data and refactor for channel interface
- [MAID-1158](https://maidsafe.atlassian.net/browse/MAID-1158) Unified Data
    - [MAID-1159](https://maidsafe.atlassian.net/browse/MAID-1159) Implement PlainData
    - [MAID-1160](https://maidsafe.atlassian.net/browse/MAID-1160) Implement ImmutableData
    - [MAID-1163](https://maidsafe.atlassian.net/browse/MAID-1163) Implement StructuredData
    - [MAID-1165](https://maidsafe.atlassian.net/browse/MAID-1165) StructuredData::is_valid_successor
    - [MAID-1166](https://maidsafe.atlassian.net/browse/MAID-1166) Unit Tests for PlainData and ImmutableData
    - [MAID-1167](https://maidsafe.atlassian.net/browse/MAID-1167) Unit Tests for StructuredData
    - [MAID-1168](https://maidsafe.atlassian.net/browse/MAID-1168) Unit Test IsValidSuccessor for StructuredData
    - [MAID-1171](https://maidsafe.atlassian.net/browse/MAID-1171) Implement UnifiedData enum
    - [MAID-1172](https://maidsafe.atlassian.net/browse/MAID-1172) Update with UnifiedData: GetData and GetDataResponse
    - [MAID-1173](https://maidsafe.atlassian.net/browse/MAID-1173) Update with UnifiedData: PutData and PutDataResponse
    - [MAID-1175](https://maidsafe.atlassian.net/browse/MAID-1175) Update with UnifiedData: RoutingMembrane RoutingClient Put and Get
    - [MAID-1176](https://maidsafe.atlassian.net/browse/MAID-1176) Update with UnifiedData: Interfaces and churn
- [MAID-1179](https://maidsafe.atlassian.net/browse/MAID-1179) Implement Post and PostResponse
- [MAID-1170](https://maidsafe.atlassian.net/browse/MAID-1170) Update RoutingClient and relay node: RoutingMessage
- [MAID-1251](https://maidsafe.atlassian.net/browse/MAID-1251) Remove option first from routing node
- [MAID-1255](https://maidsafe.atlassian.net/browse/MAID-1255) RFC 0001 - Use public key for id on all messages
    - [MAID-1256](https://maidsafe.atlassian.net/browse/MAID-1256) Remove redundant field header.source.reply_to
    - [MAID-1257](https://maidsafe.atlassian.net/browse/MAID-1257) Modify Authority enum
- [MAID-1063](https://maidsafe.atlassian.net/browse/MAID-1063) replace MessageTypeTag with full enum.

- [#557](https://github.com/maidsafe/routing/pull/557) channel architecture and simplified message

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
