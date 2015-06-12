# Vault - Change Log

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

## [0.0.4]
- Rename actions (changes in routing v0.1.60)
- Documentation
    - Personas
        - ClientManager : MaidManager
        - NodeManager : PmidManager
        - Node : PmidNode
        - NAE : DataManager, VersionHandler
    - Accounting
        - MaidAccount : create, update and monitor
        - PmidAccount : create, update and monitor
    - Flows
        - PutData / PutResponse
        - GetData / GetResponse
        - PostData
- Complete unfinished code (if it will be covered by the later-on tasks in this sprint, explicitly mention it as in-code TODO comment), especially in vault.rs
    - handle_get_key
    - handle_put_response
    - handle_cache_get
    - handle_cache_put
- Integration test with new routing and crust (vaults bootstrap and network setup)
    - local joining test (process counting)
    - network example (nodes populating)
- SafeCoin farming (new persona may need to be introduced, the task needs to be ‘expandable’ ) documentation
    - farming
    - account
- Implement handling for Safecoin farming rate
    - Farming rate determined by the Sacrificial copies.  
    - Farming rate drops when more copies are available and rises when less copies are available.
