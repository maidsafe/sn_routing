# maidsafe_vault

Travis build status

[![Build Status](https://travis-ci.org/dirvine/maidsafe_vault.svg?branch=master)](https://travis-ci.org/dirvine/maidsafe_vault)

Appveyor build status (Windows)

[![Build status](https://ci.appveyor.com/api/projects/status/qglf0d3o28mxid6k?svg=true)](https://ci.appveyor.com/project/dirvine/maidsafe-vault-hyyvf)

Code Coverage

[![Coverage Status](https://coveralls.io/repos/dirvine/maidsafe_vault/badge.svg)](https://coveralls.io/r/dirvine/maidsafe_vault)


[Documentation](http://dirvine.github.io/maidsafe_vault/)

#Todo

- [x] Implement VaultFacade
    - [x] Follow the interface design with routing (already in place as first go)
    - [x] Implement VaultFacade initally (provide a guide line for later on persona implementation)
- [x] Implement chunkstore
- [x] Test chunkstore
- [x] Implement MaidManager
- [x] Implement DataManager
- [x] Implement PmidManager
- [x] Implement PmidNode
- [ ] Test MaidManager
- [x] Test DataManager
- [ ] Test PmidManager
- [ ] Test PmidNode
- [x] Complete Put Flow
- [x] Complete Get Flow
- [ ] Complete Create Maid Account Flow  // may not be required for a simple implementation
- [ ] Test Put Flow
- [ ] Test Get Flow
- [ ] Test with client having simple put and get ability
- [ ] Integration Test
- [ ] Installers
    - [ ] linux 32 bit .deb installer (oldest possible version)
    - [ ] linux 64 bit .deb installer (oldest possible version)
    - [ ] linux 32 bit .rpm installer (oldest possible version)
    - [ ] linux 64 bit .rpm installer (oldest possible version)
    - [ ] linux 32 bit .zip/gzip installer (oldest possible version)
    - [ ] linux 64 bit .zip/gzip installer (oldest possible version)
    - [ ] OS/X installer (fpm)
    - [ ] Win32 installer (windows advanced installer)
    - [ ] Win64 installer (windows advanced installer)
- [ ] API version 0.1.0
- [ ] Complete Post Flow
- [ ] Handle Churn
    - [ ] Implement Account Transfer
    - [ ] Churn Test
- [ ] Implement VersionHandler
- [ ] Test with client having file system feature
- [ ] Implement MpidManager
    - [ ] Complete the put route (sending message)
    - [ ] Complete the get route (checking message)
- [ ] Test with client having messaging ability
- [ ] Performance Test
- [ ] Coverage analysis
