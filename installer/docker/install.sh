#! /bin/sh

set -e

# These packages are needed only during build and can be removed afterwards
TMP_PACKAGES="build-essential curl file pkg-config sudo"

# Install build dependencies
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y $TMP_PACKAGES libsodium-dev

# Install the rust ecosystem
curl -o rustup.sh -sSf https://static.rust-lang.org/rustup.sh
sh rustup.sh -y

# Build safe_vault
cargo install safe_vault --git https://github.com/maidsafe/safe_vault.git

# Remove stuff that is no longer needed, to save some space.
sh rustup.sh -y --uninstall
rm rustup.sh

SUDO_FORCE_REMOVE=yes apt-get remove -y --purge $TMP_PACKAGES
apt-get autoremove -y --purge
apt-get clean
rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

cp /root/.cargo/bin/safe_vault .

# Remove rust crates
rm -rf /root/.cargo
