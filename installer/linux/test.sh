#!/bin/sh
id safe
ls -la /usr/bin/*safe*
ls -la /var/cache/safe_vault/
ls -la /var/log/safe-vault.log
ls -la /var/log/safe-vault.err
echo "safe_vault PID: $(pgrep safe_vault)"
/usr/bin/safe_vault --version
