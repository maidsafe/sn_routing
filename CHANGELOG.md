# Safe Vault - Change Log

## [0.9.0]
- Migrate to the mio-based Crust and the new Routing Request/Response API.
- Handle `GetAccountInfo` requests to provide information about a client's used
  and remaining chunk count.

## [0.8.1]
- Allow passing `--first` via command line to start the first Vault of a new network.
- Updated dependencies.

## [0.8.0]
- Several tweaks to churn handling in data_manager.
- Implement process to automatically build release binaries.
- Re-organise the tests to use mock Crust instead of mock Routing.
- Improve logging.
- Fix several bugs.

## [0.7.0]
- Restart routing if it failed to join the network.
- Reimplement the refresh algorithm for structured and immutable data to make it
  less wasteful and more reliable.

## [0.6.0]
- Major change of persona strategy regarding `ImmutableData` (removal of three personas)
- Major refactoring of integration tests (uses mock Crust feature)
- Default test runner to unit tests (previously run using the mock Routing feature)

## [0.5.0]
- Replaced use of local Client errors for those in safe_network_common
- Swapped dependency on mpid_messaging crate for safe_network_common dependency
- Removed Mpid tests from CI suite
- Updated some message flows
- Completed churn-handling for ImmutableDataManager
- Added many unit tests
- Fixed Clippy warnings
- Several bugfixes

## [0.4.0]
- Accommodated updates to dependencies' APIs
- Ensured that the network can correctly handle Clients doing a Get for ImmutableData immediately after doing a Put
- Reduced `REPLICANTS` and `MIN_REPLICANTS` to 4

## [0.3.0]
- Major refactor to accommodate changed Routing

## [0.1.6]
- Default to use real Routing rather than the mock
- Updated config file to match Crust changes
- Refactored flow for put_response
- Added churn tests
- Refactored returns from most persona functions to not use Result

## [0.1.5]
- Major refactor of production code and tests to match Routing's new API, allowing testing on a real network rather than a mock
- Updated installers to match Crust's config/bootstrap file changes
- Added tarball to packages being generated
- Dropped usage of feature-gated items

## [0.1.4]
- [MAID-1283](https://maidsafe.atlassian.net/browse/MAID-1283) Rename repositories from "maidsafe_" to "safe_"

## [0.1.3]
- [MAID-1186](https://maidsafe.atlassian.net/browse/MAID-1186) Handling of unified Structrued Data
    - [MAID-1187](https://maidsafe.atlassian.net/browse/MAID-1187) Updating Version Handler
    - [MAID-1188](https://maidsafe.atlassian.net/browse/MAID-1188) Updating other personas if required

## [0.1.2] - code clean up
- [MAID 1185](https://maidsafe.atlassian.net/browse/MAID-1185) using unwrap unsafely

## [0.1.1]
- Updated dependencies' versions
- Fixed lint warnings caused by latest Rust nightly
- [Issue 117](https://github.com/maidsafe/safe_vault/issues/117) meaningful type_tag
- [PR 124](https://github.com/maidsafe/safe_vault/pull/124) integration test with client
    - client log in / log out
    - complete put flow
    - complete get flow

## [0.1.0] - integrate with routing and safecoin farming initial work [rust-2 Sprint]
- [MAID-1107](https://maidsafe.atlassian.net/browse/MAID-1107) Rename actions (changes in routing v0.1.60)
- [MAID-1008](https://maidsafe.atlassian.net/browse/MAID-1008) Documentation
    - [MAID-1009](https://maidsafe.atlassian.net/browse/MAID-1009) Personas
        - ClientManager : MaidManager
        - NodeManager : PmidManager
        - Node : PmidNode
        - NAE : DataManager, VersionHandler
    - [MAID-1011](https://maidsafe.atlassian.net/browse/MAID-1011) Accounting
        - MaidAccount : create, update and monitor
        - PmidAccount : create, update and monitor
    - [MAID-1010](https://maidsafe.atlassian.net/browse/MAID-1010) Flows
        - PutData / PutResponse
        - GetData / GetResponse
        - PostData
- [MAID-1013](https://maidsafe.atlassian.net/browse/MAID-1013) Complete unfinished code (if it will be covered by the later-on tasks in this sprint, explicitly mention it as in-code TODO comment), especially in vault.rs
    - [MAID-1109](https://maidsafe.atlassian.net/browse/MAID-1109) handle_get_key
    - [MAID-1112](https://maidsafe.atlassian.net/browse/MAID-1112) handle_put_response
    - [MAID-1113](https://maidsafe.atlassian.net/browse/MAID-1113) handle_cache_get
    - [MAID-1113](https://maidsafe.atlassian.net/browse/MAID-1113) handle_cache_put
- [MAID-1014](https://maidsafe.atlassian.net/browse/MAID-1014) Integration test with new routing and crust (vaults bootstrap and network setup)
    - [MAID-1028](https://maidsafe.atlassian.net/browse/MAID-1028) local joining test (process counting)
    - [MAID-1016](https://maidsafe.atlassian.net/browse/MAID-1016) network example (nodes populating)
- [MAID-1012](https://maidsafe.atlassian.net/browse/MAID-1012) SafeCoin farming (new persona may need to be introduced, the task needs to be ‘expandable’ ) documentation
    - farming
    - account
- [MAID-1021](https://maidsafe.atlassian.net/browse/MAID-1021) Implement handling for Safecoin farming rate
    - Farming rate determined by the Sacrificial copies.
    - Farming rate drops when more copies are available and rises when less copies are available.

## [0.0.0 - 0.0.3]
- VaultFacade initial implementation
- Chunkstore implementation and test
- Initial Persona implementation :
    - Implement MaidManager and test
    - Implement DataManager and test
    - Implement PmidManager and test
    - Implement PmidNode and test
    - Implement VersionHandler
- Flow related work :
    - Complete simple Put flow and test
    - Complete simple Get flow and test
    - Complete Create Maid Account Flow
- Installers (linux deb/rpm 32/64 bit, Windows 32 / 64. OSX)
- Coverage analysis
