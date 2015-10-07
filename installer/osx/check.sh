#!/bin/sh
dscl . -search /Groups name safe
dscl . -search /Users name safe
ls -laG /usr/local/bin/*safe*
ls -laG /var/cache/safe_vault/
ls -laG /Library/LaunchDaemons/org.maidsafe*
ls -laG /var/log/safe/safe_vault.log
ls -laG /var/log/safe/safe_vault.err
sudo launchctl list org.maidsafe.safe_vault
