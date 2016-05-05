#!/bin/bash

set -ev

APT_HOST=ci@apt.maidsafe.net
YUM_HOST=ci@yum.maidsafe.net

# Suppress confirmation before ssh connects to the new host.
SSH_OPTS="-o StrictHostKeyChecking=no"

# APT
export SSHPASS=$APT_PASSWORD
sshpass -e ssh $SSH_OPTS $APT_HOST 'mkdir -p ~/systemd/ && mkdir -p ~/SysV-style/'
sshpass -e scp $SSH_OPTS ./packages/linux/safe_vault_*.tar.gz           $APT_HOST:~/ &
sshpass -e scp $SSH_OPTS ./packages/linux/systemd/safe*.deb             $APT_HOST:~/systemd/ &
sshpass -e scp $SSH_OPTS ./packages/linux/SysV-style/safe*.deb          $APT_HOST:~/SysV-style/ &
sshpass -e scp $SSH_OPTS ./packages/linux/safe_vault_latest_version.txt $APT_HOST:~/ &

wait

# YUM
export SSHPASS=$YUM_PASSWORD
sshpass -e ssh $SSH_OPTS $YUM_HOST 'mkdir -p ~/systemd/ && mkdir -p ~/SysV-style/'
sshpass -e scp $SSH_OPTS ./packages/linux/systemd/safe*.rpm             $YUM_HOST:~/systemd/ &
sshpass -e scp $SSH_OPTS ./packages/linux/SysV-style/safe*.rpm          $YUM_HOST:~/SysV-style/ &
sshpass -e scp $SSH_OPTS ./packages/linux/safe_vault_latest_version.txt $YUM_HOST:~/ &

wait
