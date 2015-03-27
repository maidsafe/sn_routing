# maidsafe_vault

Travis build status

[![Build Status](https://travis-ci.org/dirvine/maidsafe_vault.svg?branch=master)](https://travis-ci.org/dirvine/maidsafe_vault)

Appveyor build status (Windows)

[![Build status](https://ci.appveyor.com/api/projects/status/qglf0d3o28mxid6k?svg=true)](https://ci.appveyor.com/project/dirvine/maidsafe-vault-hyyvf)

[Documentation](http://dirvine.github.io/maidsafe_vault/)

#Todo

- [ ] Implement VaultFacade
    - [ ] Follow the interface design with routing (already in place as first go)
    - [ ] Implement VaultFacade initally (provide a guide line for later on persona implementation)
- [x] Implement chunkstore
- [ ] Test chunkstore
- [ ] Implement MaidManager
- [ ] Implement DataManager
- [ ] Implement PmidManager
- [ ] Implement PmidNode
- [ ] Complete Put Flow
- [ ] Complete Get Flow
- [ ] Complete Create Maid Account Flow  // may not be required for a simple implementation
- [ ] Test Put Flow
- [ ] Test Get Flow
- [ ] Test with client having simple put and get ability
- [ ] Handle Churn
    - [ ] Implement Account Transfer
    - [ ] Churn Test
- [ ] Implement VersionHandler
- [ ] Complete Post Flow
- [ ] Test with client having file system feature
- [ ] Implement MpidManager
    - [ ] Complete the put route (sending message)
    - [ ] Complete the get route (checking message)
- [ ] Test with client having messaging ability
- [ ] Integration Test
- [ ] API version 0.1.0
- [ ] Performance Test
- [ ] Coverage analysis
