# Expectations for Installer

- [Windows](#windows)
  - [Fresh Install](#fresh-install)
  - [Installing Over an Existing Version](#installing-over-an-existing-version)
  - [Uninstall](#uninstall)
- [OS X](#os-x)
  - [Fresh Install](#fresh-install-1)
  - [Installing Over an Existing Version](#installing-over-an-existing-version-1)
  - [Uninstall](#uninstall-1)
- [Linux](#linux)
  - [Fresh Install](#fresh-install-2)
  - [Installing Over an Existing Version](#installing-over-an-existing-version-2)
  - [Uninstall](#uninstall-2)

----------------------------------------------------------------------------------------------------

## Windows

### Fresh Install

- installer should be called `safe_vault_installer_<PLATFORM>_<VERSION>.exe`, e.g. `safe_vault_installer_x64_0.2.0.exe`
- it should install `safe_vault.exe` to `C:\Program Files\safe_vault\` (`safe_vault.exe` should be the only item in that folder)
- it should install `safe_vault.crust.config` and `safe_vault.vault.config` to `C:\ProgramData\safe_vault\`
- it should start `safe_vault.exe` which should keep running forever
- running the executable should cause `safe_vault.bootstrap.cache` to be created in `C:\ProgramData\safe_vault\`

### Installing Over an Existing Version

- it should stop the currently-running `safe_vault.exe`
- it should replace `C:\Program Files\safe_vault\safe_vault.exe`
- it should replace `C:\ProgramData\safe_vault\safe_vault.crust.config`
- it should replace `C:\ProgramData\safe_vault\safe_vault.vault.config`
- it should leave `C:\ProgramData\safe_vault\safe_vault.bootstrap.cache` untouched
- it should start the new `safe_vault.exe` which should keep running forever

### Uninstall

Re-run the installer of the currently-installed version.

- it should stop the currently-running `safe_vault.exe`
- it should remove `C:\Program Files\safe_vault\safe_vault.exe` and `C:\Program Files\safe_vault\`
- it should remove `C:\ProgramData\safe_vault\safe_vault.crust.config`
- it should remove `C:\ProgramData\safe_vault\safe_vault.vault.config`
- it should leave `C:\ProgramData\safe_vault\safe_vault.bootstrap.cache` untouched

----------------------------------------------------------------------------------------------------

## OS X

### Fresh Install

- installer should be called `safe_vault-<VERSION>.pkg`, e.g. `safe_vault-0.2.0.pkg`
- it should create a hidden user and group called `safe`
- it should install `safe_vault` to `/usr/local/bin/` with `safe:safe` as the owner:group
- it should install `uninstall_safe_vault.sh` to `/usr/local/bin/` with `root:wheel` as the owner:group
- it should install `safe_vault.crust.config` and `safe_vault.vault.config` to `/var/cache/safe_vault/` with `safe:safe` as the owner:group
- it should start the `safe_vault` executable as the `safe` user and it should keep running forever
- running the executable should cause `safe_vault.bootstrap.cache` to be created in `/var/cache/safe_vault/` with `safe:safe` as the owner:group

### Installing Over an Existing Version

- it should stop the currently-running `safe_vault` executable
- it should replace `/usr/local/bin/safe_vault`
- it should replace `/usr/local/bin/safe_vault/uninstall_safe_vault.sh`
- it should replace `/var/cache/safe_vault/safe_vault.crust.config`
- it should replace `/var/cache/safe_vault/safe_vault.vault.config`
- it should leave `/var/cache/safe_vault/safe_vault.bootstrap.cache` untouched
- it should start the new `safe_vault` executable which should keep running forever

### Uninstall

Run `sudo uninstall_safe_vault.sh`

- it should stop the currently-running `safe_vault` executable
- it should remove `/usr/local/bin/safe_vault`
- it should remove `/var/cache/safe_vault/safe_vault.crust.config`
- it should remove `/var/cache/safe_vault/safe_vault.vault.config`
- it should leave `/var/cache/safe_vault/safe_vault.bootstrap.cache` untouched
- it should remove the `safe` user and `safe` group

----------------------------------------------------------------------------------------------------

## Linux

### Fresh Install

- it should be invoked via `sudo apt-get install safe-vault` or `sudo yum install safe_vault` (see http://apt.maidsafe.net or http://yum.maidsafe.net for further details)
- it should create a hidden user and group called `safe`
- it should install `safe_vault` to `/usr/bin/` with `safe:safe` as the owner:group
- it should install `safe_vault.crust.config` and `safe_vault.vault.config` to `/var/cache/safe_vault/` with `safe:safe` as the owner:group
- it should start the `safe_vault` executable as the `safe` user and it should keep running forever
- running the executable should cause `safe_vault.bootstrap.cache` to be created in `/var/cache/safe_vault/` with `safe:safe` as the owner:group

### Installing Over an Existing Version

- it should stop the currently-running `safe_vault` executable
- it should replace `/usr/bin/safe_vault`
- it should replace `/var/cache/safe_vault/safe_vault.crust.config`
- it should replace `/var/cache/safe_vault/safe_vault.vault.config`
- it should leave `/var/cache/safe_vault/safe_vault.bootstrap.cache` untouched
- it should start the new `safe_vault` executable which should keep running forever

### Uninstall

`sudo apt-get remove safe-vault` or `sudo yum remove safe_vault`

- it should stop the currently-running `safe_vault` executable
- it should remove `/usr/bin/safe_vault`
- it should remove `/var/cache/safe_vault/safe_vault.crust.config`
- it should remove `/var/cache/safe_vault/safe_vault.vault.config`
- it should leave `/var/cache/safe_vault/safe_vault.bootstrap.cache` untouched
- it should remove the `safe` user and `safe` group
