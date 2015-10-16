#!/bin/sh
id safe
ls -la /usr/local/bin/*safe*
ls -la /var/cache/safe_vault/
ls -la /Library/LaunchDaemons/org.maidsafe*
ls -la /var/log/safe/safe_vault.log
ls -la /var/log/safe/safe_vault.err
sudo launchctl list org.maidsafe.safe_vault
/usr/local/bin/safe_vault --version
