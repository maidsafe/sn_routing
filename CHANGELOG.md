# Routing - Change Log

## [0.33.2]
- Depend on Crust 0.28.1.

## [0.33.1]
- Increase MAX_MUTABLE_DATA_ENTRIES from 100 to 1000.

## [0.33.0]
- Rate limiter refund on overcharge for get response.
- Rate limiter having soft capacity for clients.
- Bugfix to not mutate peer on receiving conn_info_response.
- Bugfix to remove expired peers(normalise peers) when receiving TunnelSuccess or TunnelRequest.
- Enforce one client per IP only on bootstrap request.
- Add Rand impl for PermissionSet.
- Resend rate exceeded user message parts and remove Event::ProxyRateLimitExceeded
- Bugfix to not reject BootstrapRequest messages invalidly.

## [0.32.2]
- Bugfix to avoid adding nodes to disconnected client list.

## [0.32.1]
- Bugfix to avoid handling recently-disconnected client direct messages.

## [0.32.0]
- Allow mock-crust network to support multiple nodes/clients with the same IPs.
- Allow only one client ip per proxy.
- Modify the client Rate Limiter paradigm to not put an upper threshold on number of clients with unique IPs to bootstrap off a proxy.
- Add dev configuration options for routing such that these options can be supplied in a routing config file that routing would read to tweak parameters such as disable resource proof etc.
- Update to use Rust Stable 1.19.0 / Nightly 2017-07-20, clippy 0.0.144, and rustfmt 0.9.0.
- Make MutableData errors more descriptive.

## [0.31.0]
- Remove support for Structured, PrivAppendable and PubAppendable Data
- Add Support for MutableData instead.
- Introduce mock-crypto which provides efficient mocking of the crypto primitives for faster test runs for cases where we don't care about tightness of security.
- Code rate-limiter to restrict proxy from relaying more than the agreed threshold to the Network on behalf of the clients (each client being identified on IP level).
- Detect malformed messages and invalid/disallowed RPCs and ban such a sender on IP level.

## [0.30.0]
- Replace all sha256 from rust_sodium with sha3_256 from tiny_keccak.
- Move `AccountPacket` type required by vaults and clients into a `common_types` module.

## [0.29.0]
- Integration with templatised Crust where now routing specifies what to use as a UID so that crust and routing use a common UID to identify peer.
- Peer manager clean up as connect success now tells us everything about the peer. Previously we needed to wait additionally for NodeIdentify for instance as crust-uid (PeerId) and routing-uid (PublicId) were separate and each layer informed about the id specific to that layer only.

## [0.28.5]
- Add section update requests to make merges more stable.
- Don't approve new node if routing table is invalid.
- Work around cases where `OtherSectionMerge` would not accumulate.
- Several fixes to tunnel nodes and peer manager.
- Remove more sources of randomness to make tests deterministic.
- Add new error types related to invitation-based account creation.
- Replace rustc-serialize with serde.

## [0.28.4]
- Don't try to reconnect to candidates that are not yet approved.
- Don't include peers in `sent_to` that are not directly connected.
- Use SHA3 everywhere instead of SipHash.
- `PrefixSection` authorities now always refer to all sections _compatible_
  with the given prefix.
- Cache `OwnSectionMerge` messages until both merging sections have sent one.
  Only then update the routing table.
- Cache any routing table updates while merging, and relay them afterwards.
- Other merge and tunnel fixes, and additional tests for merging and tunnels.
- Try to reconnect after a connection drops.

## [0.28.2]
- Extend the tests for tunnelling and the churn tests.
- Fix several peer manager issues related to tunnel nodes and candidates.
- Send `SectionSplit` messages as `PrefixSection` authority to allow resending.
- Fix several issues related to merging sections.
- Some improvements to the log messages.

## [0.28.1]
- Retry preparing connection info if Crust returns an error.

## [0.28.0]
- Profile the bandwidth of nodes joining the network. Reject slow nodes.
- Organise nodes into disjoint sections. Introduce the `Section` and
  `PrefixSection` authorities.
- Maintain lists of signatures of neighbouring sections, which will enable
  secure  message validation.
- Accumulate messages in the sending group/section, then send the messages with
  all the signatures across a single route. This reduces the number of total
  invididual hop messages that need to be sent.
- Routes are now disjoint: Retrying to send a message along a different route
  cannot potentially fail on the same node again.
- Merge the routing_table crate into routing.
- Remove the internal event handling thread. Events should be handled in the
  upper library's event loop. That way, some message passing can be replaced by
  direct calls to routing methods.
- Remove the `PlainData` type which was only used in tests.

## [0.27.1]
- Increase the ID size limit by 10 kB.

## [0.27.0]
- add `NO_OWNER_PUB_KEY` to make data effectively immutable
- disallow that key together with other owners (new error `InvalidOwners`)
- provide API for data chunk size validation (new error `DataTooLarge`)
- support new deletion paradigm for structured data

## [0.26.0]
- Add the public and private appendable data types.
- Allow whitelisting nodes via the crust config file.
- Randomise message handling order in the mock crust tests.

## [0.25.1]
- Fix a panic in ack manager.

## [0.25.0]
- Refactoring: Further split up and reorganise the states and move more logic
  into the peer manager module.
- Several bug fixes and test improvements.

## [0.24.2]
- Refactoring: Turn `Core` into a state machine with `Client` and `Node` states.
  Move some more logic onto the `PeerManager`.
- Fix a bug that caused some nodes to refuse to close an unneeded connection.

## [0.24.1]
- Fix redundant calls to Crust `connect`.

## [0.24.0]
- Fix sodiumoxide to v0.0.10 as the new released v0.0.12 does not support
  rustc-serializable types anymore and breaks builds.
- Avoid redundant hash calculations by making the data `name` method a simple
  getter.
- Fix ack handling when resending a message.
- Some refactoring and test updates.

## [0.23.2]
- Don't cache as a member of recipient group: this can cause redundant
  responses.
- Disconnect previous bootstrap node when retrying to bootstrap.

## [0.23.1]
- Fix tests involving sorting nodes by names.
- Fix random seeds when multiple tests are run at once.

## [0.23.0]
- Add seeded rng support to mock crust tests.
- Add support for response caching.
- Add various mock crust tests.
- Prevent multiple routing nodes from starting on same LAN.

## [0.22.0]
- Migrate to the mio-based Crust.
- Replace redundant group messages by hashes to save bandwidth.
- Split up large messages into 20 kB chunks.
- Improve message statistics; add total message size and count failures.
- Restart with blacklist if the proxy node denied the connection.
- Merge message_filter into routing.
- Some refactoring to clean up the logic in `Core`.
- Several bug fixes.

## [0.21.0]
- Reduce the `XorName` size from 512 to 256 bits.

## [0.20.0]
- Send acknowledgement messages (acks) and resend via a different route only if
  no ack is received. Previously, several routes were used simultaneously,
  wasting a lot of bandwidth.
- Merge xor_name into routing.
- Simplify the message type hierarchy and the API.
- Fix sending redundant connection info.

## [0.19.1]
- network size < GROUP_SIZE will only accept new nodes via first node

## [0.19.0]
- Only start a network if explicitly designated as first node.
- Use a Crust priority based on message type.

## [0.18.5]
- Don't send `Tick` events to clients.
- Use a size limit for the data cache instead of a timeout.
- More detailed message stats logging.

## [0.18.4]
- Allow up to 40 tunnel client pairs.
- Migrate to Crust 0.12.0.
- Add sequence diagrams to the documentation.
- Improve logging.
- Fix several bugs.

## [0.18.3]
- Depend on latest Crust.
- Add the 'Stats' prefix to all statistics log messages.

## [0.18.2]
- Add a periodic tick event.
- Increase the timeout for polling bucket groups.
- Extract the statistics module and gather more statistics.

## [0.18.1]
- Some improvements to the log messages.
- Fix several lint warnings.

## [0.18.0]
- Add the routing table to `NodeAdded` and `NodeLost` events.
- Add `NetworkStartupFailed` and `StartListeningFailed` events.
- Improve join limit to prevent damage to the network in case of many
  simultaneously joining nodes.
- Drop unneeded connections from the routing table.
- Replace node harvesting with periodic bucket polling.

## [0.17.0]
- Depend on Crust 0.11.0.

## [0.16.3]
- Add `HEARTBEAT_ATTEMPTS` constant to configure when an unresponsive peer is considered lost.
- Fix a bug that caused unneeded node harvesting attempts.

## [0.16.2]
- Reduce network traffic by including recipients in hop message that have handled the message.

## [0.16.1]
- Bug fix: DataIdentifier now correctly returns the structured data computed name in its name() function

## [0.16.0]
- Add `identifier()` method to all data elements (type + name)
- All `ImmutableData` types now concrete (not variants)

## [0.15.1]
- Fix a message handling bug.
- Add `MessageId::zero` constructor.
- Always send `NodeAdded` for a new peer, even if not in a common group.

## [0.15.0]
- Implement Rand for mock PeerId.
- Add data name to Put, Post and Delete success responses.

## [0.14.0]
- Add message id to Refresh messages
- Node numbers only increase during node addition in churn for ci_test example
- Update dependencies

## [0.13.0]
- Add tunnel nodes.
- Optimise the `GetNetworkName` message flow for quicker joining.
- Make caching optional.
- Send keepalive signals to detect lost peers.
- Implement full `Put` response flow in the example node.
- Remove digest from success responses; it has been replaced by `MessageId`.
- Migrate to Crust 0.10.0.
- Various bug fixes.

## [0.12.0]
- Make the mock_crust module public

## [0.11.1]
- Send a Disconnected event if client fails to bootstrap.

## [0.11.0]
- Replace CBOR usage with maidsafe_utilites::serialisation.
- Updated dependencies.

## [0.10.0]
- Take `MessageId`s as an argument in the Client methods.

## [0.9.0]
- Add mock Crust and network-less tests for `Core`.
- Return `MessageId`s from Client methods.
- Allow a user to connect to the same proxy node with several clients.

## [0.8.0]
- Send a Disconnected event if the network connection is lost.
- Log disconnecting clients.

## [0.7.1]
- Several bug fixes.

## [0.7.0]
- Migrate to the new Crust API.
- Add some timeouts to check for stale connections.
- Limit proxy connections to one.
- Make node discovery more efficient.
- Shorten log messages and debug formats to make the logs clearer.
- Some updates to churn handling in the example.
- Fix lots of Clippy warnings.
- Fix lots of bugs.

## [0.6.3]
- Added several tests
- Further documentation improvements
- Improved debug output of several types

## [0.6.2]
- Reject clients if the routing table is too small
- Fix computation of remaining required signatures for StructuredData
- Limit the number of concurrently joining nodes
- Remove unneeded files
- Expand documentation
- Distinct message IDs for added and lost nodes
- Ignore double puts in the example

## [0.6.1]
- Update core to send on only first connection

## [0.6.0]
- Further updates to examples
- Moved CI scripts to use Stable Rust

## [0.5.3]
- Getting examples updated
- Updating the API to expose the routing node name and close group

## [0.5.2]
- Bug fix - Blocking InterfaceError not returning
- Changing mutable to immutable for stop() function in routing.rs

## [0.5.1]
- Expose ImmutableDataType

## [0.5.0]
- Cleanup of routing API
- Exposing of success and failure event for GET, PUT, POST and DELETE
- Separating XorName and Routing Table into their own crates

## [0.4.2]
- Remove wildcard dependencies

## [0.4.1] Updated to CRUST 0.4

## [0.4.0] Updated to CRUST 0.3
- [#711](https://github.com/maidsafe/routing/pull/711) remove unneeded state on ::connect
- [MAID-1366](https://maidsafe.atlassian.net/browse/MAID-1366) update routing to crust 0.3 API
- [#369](https://github.com/maidsafe/routing/pull/369) enforce LINT checks

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
