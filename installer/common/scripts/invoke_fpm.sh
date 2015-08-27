#!/bin/bash
#
# Create a package for Vault Release binaries

# Stop the script if any command fails
set -o errtrace
trap 'exit' ERR

# Get current version and executable's name from Cargo.toml
RootDir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
Version=$(sed -n 's/[ \t]*version[ \t]*=[ \t]*"\([^"]*\)".*/\1/p' "$RootDir/Cargo.toml")
VaultName=$(sed -n 's/[ \t]*name[ \t]*=[ \t]*"\([^"]*\)".*/\1/p' "$RootDir/Cargo.toml")
VaultPath=/usr/bin/
ConfigFilePath=/var/cache/safe_vault/
Platform=$1
Description="SAFE Network vault"

function add_file_check {
  local TargetFileName=$1
  local TargetPath=$2
  printf 'if [ ! -f %s ]; then\n' "$TargetPath$TargetFileName" >>  after_install.sh
  printf '  echo "%s is missing from %s" >&2\n' "$TargetFileName" "$TargetPath" >>  after_install.sh
  printf '  exit 1\nfi\n\n' >>  after_install.sh
}

function add_safe_user {
  printf 'useradd safe --system --shell /bin/false --user-group\n\n' >> after_install.sh
}

function remove_safe_user {
  printf 'userdel safe\n' >> before_remove.sh
}

function set_owner {
  printf 'chown -R safe:safe %s\n' "$ConfigFilePath" >> after_install.sh
  printf 'chown safe:safe %s\n' "$VaultPath$VaultName" >> after_install.sh
  printf 'chmod 775 %s\n\n' "$VaultPath$VaultName" >> after_install.sh
}

function prepare_for_tar {
  mkdir -p "$RootDir/packages/$Platform"
  cd "$RootDir/packages/$Platform"
  Bits=$(getconf LONG_BIT)
  PackageName="$VaultName"_"$Version"_"$Bits"-bit
  AfterInstallCommand=
  BeforeRemoveCommand=
  ExtraFilesCommand=
}

function prepare_systemd_scripts {
  ServiceName=safe-vault.service
  ServicePath=/usr/lib/systemd/system/

  mkdir -p "$RootDir/packages/$Platform/systemd/scripts"
  cd "$RootDir/packages/$Platform/systemd/scripts"

  # This will:
  #   * check the exe and service files are installed
  #   * create a user and group called "safe" if they don't already exist
  #   * set these as the owner/group for the installed files
  #   * add and start the service
  printf '#!/bin/sh\n' > after_install.sh
  add_file_check "$VaultName" "$VaultPath"
  add_file_check "$ServiceName" "$ServicePath"
  add_safe_user
  set_owner
  printf 'systemctl enable %s\n' "$ServiceName" >> after_install.sh
  printf 'systemctl start %s\n' "$ServiceName" >> after_install.sh

  # This will remove the "safe" user and group then stop and remove the service
  printf '#!/bin/sh\n' > before_remove.sh
  printf 'systemctl stop %s\n' "$ServiceName" >> before_remove.sh
  printf 'systemctl disable %s\n' "$ServiceName" >> before_remove.sh
  remove_safe_user

  # This specifies the service
  printf '[Unit]\nDescription=%s\n\n' "$Description" > $ServiceName
  printf '[Service]\nExecStart=%s\nRestart=on-failure\nUser=safe\n\n' "$VaultPath$VaultName" >> $ServiceName
  printf '[Install]\nWantedBy=multi-user.target' >> $ServiceName

  # Set vars to allow fpm to include the after_install and before_remove scripts and the service file
  PackageName=$VaultName
  AfterInstallCommand='--after-install scripts/after_install.sh'
  BeforeRemoveCommand='--before-remove scripts/before_remove.sh'
  ExtraFilesCommand=scripts/$ServiceName=$ServicePath

  chmod 755 after_install.sh before_remove.sh
  cd ..
}

function prepare_sysv_style_scripts {
  InitName=safe-vault

  mkdir -p "$RootDir/packages/$Platform/SysV-style/scripts"
  cd "$RootDir/packages/$Platform/SysV-style/scripts"

  # This will:
  #   * check the exe is installed
  #   * install the init script
  #   * create a user and group called "safe" if they don't already exist
  #   * set these as the owner/group for the installed files
  #   * start the vault
  printf '#!/bin/sh\n' > after_install.sh
  add_file_check "$VaultName" "$VaultPath"
  add_safe_user
  set_owner
  printf 'if [ $(command -v update-rc.d >/dev/null; echo $?) -eq 0 ]; then\n' >> after_install.sh
  printf '  update-rc.d %s defaults\n' "$InitName" >> after_install.sh
  printf 'elif [ $(command -v chkconfig >/dev/null; echo $?) -eq 0 ]; then\n' >> after_install.sh
  printf '  chkconfig --add %s\n' "$InitName" >> after_install.sh
  printf '  chkconfig --level 2345 %s on\n' "$InitName" >> after_install.sh
  printf '  chkconfig --level 016 %s off\n' "$InitName" >> after_install.sh
  printf 'else\n' >> after_install.sh
  printf '  echo "Need update-rc.d or chkconfig."\n' >> after_install.sh
  printf '  exit 1\n' >> after_install.sh
  printf 'fi\n\n' >> after_install.sh
  printf '/etc/init.d/%s start\n' "$InitName" >> after_install.sh

  # This will:
  #   * remove the "safe" user and group
  #   * stop the vault
  #   * remove the init script
  printf '#!/bin/sh\n' > before_remove.sh
  printf '/etc/init.d/%s stop\n\n' "$InitName" >> before_remove.sh
  printf 'if [ $(command -v update-rc.d >/dev/null; echo $?) -eq 0 ]; then\n' >> before_remove.sh
  printf '  update-rc.d -f %s remove\n' "$InitName" >> before_remove.sh
  printf 'elif [ $(command -v chkconfig >/dev/null; echo $?) -eq 0 ]; then\n' >> before_remove.sh
  printf '  chkconfig --del %s\n' "$InitName" >> before_remove.sh
  printf 'else\n' >> before_remove.sh
  printf '  echo "Need update-rc.d or chkconfig."\n' >> before_remove.sh
  printf '  exit 1\n' >> before_remove.sh
  printf 'fi\n\n' >> before_remove.sh
  remove_safe_user

  # This specifies the init script
  printf '#!/bin/sh\n' > $InitName
  printf '### BEGIN INIT INFO\n' >> $InitName
  printf '# Provides:          %s\n' "$InitName" >> $InitName
  printf '# Required-Start:    $remote_fs $syslog $mountnfs\n' >> $InitName
  printf '# Required-Stop:     $remote_fs $syslog $mountnfs\n' >> $InitName
  printf '# Default-Start:     2 3 4 5\n' >> $InitName
  printf '# Default-Stop:      0 1 6\n' >> $InitName
  printf '# Short-Description: Start or stop the %s.\n' "$Description" >> $InitName
  printf '### END INIT INFO\n\n' >> $InitName
  printf 'Dir="%s"\n' "$VaultPath" >> $InitName
  printf 'Command="./%s"\n' "$VaultName" >> $InitName
  printf 'User="safe"\n\n' >> $InitName
  printf 'Name=`basename $0`\n' >> $InitName
  printf 'PidFile="/var/run/$Name.pid"\n' >> $InitName
  printf 'StdoutLog="/var/log/$Name.log"\n' >> $InitName
  printf 'StderrLog="/var/log/$Name.err"\n\n' >> $InitName
  printf 'get_pid() {\n' >> $InitName
  printf '  cat "$PidFile"\n' >> $InitName
  printf '}\n\n' >> $InitName
  printf 'is_running() {\n' >> $InitName
  printf '  [ -f "$PidFile" ] && ps `get_pid` > /dev/null 2>&1\n' >> $InitName
  printf '}\n\n' >> $InitName
  printf 'case "$1" in\n' >> $InitName
  printf '  start)\n' >> $InitName
  printf '  if is_running; then\n' >> $InitName
  printf '    echo "Already started"\n' >> $InitName
  printf '    exit 1\n' >> $InitName
  printf '  else\n' >> $InitName
  printf '    echo "Starting $Name"\n' >> $InitName
  printf '    cd "$Dir"\n' >> $InitName
  printf '    if [ -z "$User" ]; then\n' >> $InitName
  printf '      sudo $Command >> "$StdoutLog" 2>> "$StderrLog" &\n' >> $InitName
  printf '    else\n' >> $InitName
  printf '      sudo -u "$User" $Command >> "$StdoutLog" 2>> "$StderrLog" &\n' >> $InitName
  printf '    fi\n' >> $InitName
  printf '    echo $! > "$PidFile"\n' >> $InitName
  printf '    if ! is_running; then\n' >> $InitName
  printf '      echo "Unable to start, see $StdoutLog and $StderrLog"\n' >> $InitName
  printf '      exit 2\n' >> $InitName
  printf '    fi\n' >> $InitName
  printf '  fi\n' >> $InitName
  printf '  ;;\n' >> $InitName
  printf '  stop)\n' >> $InitName
  printf '  if is_running; then\n' >> $InitName
  printf '    echo -n "Stopping $Name.."\n' >> $InitName
  printf '    kill `get_pid`\n\n' >> $InitName
  printf '    for i in 0 1 2 3 4 5 6 7 8 9\n' >> $InitName
  printf '    do\n' >> $InitName
  printf '      if ! is_running; then\n' >> $InitName
  printf '        break\n' >> $InitName
  printf '      fi\n\n' >> $InitName
  printf '      echo -n "."\n' >> $InitName
  printf '      sleep 1\n' >> $InitName
  printf '    done\n' >> $InitName
  printf '    echo\n\n' >> $InitName
  printf '    if is_running; then\n' >> $InitName
  printf '      echo "Not stopped; may still be shutting down or shutdown may have failed"\n' >> $InitName
  printf '      exit 2\n' >> $InitName
  printf '    else\n' >> $InitName
  printf '      echo "Stopped"\n' >> $InitName
  printf '      if [ -f "$PidFile" ]; then\n' >> $InitName
  printf '        rm "$PidFile"\n' >> $InitName
  printf '      fi\n' >> $InitName
  printf '    fi\n' >> $InitName
  printf '  else\n' >> $InitName
  printf '    echo "Not running"\n' >> $InitName
  printf '    rm -f "$PidFile"\n' >> $InitName
  printf '    exit 1\n' >> $InitName
  printf '  fi\n' >> $InitName
  printf '  ;;\n' >> $InitName
  printf '  restart)\n' >> $InitName
  printf '  $0 stop\n' >> $InitName
  printf '  if is_running; then\n' >> $InitName
  printf '    echo "Unable to stop, will not attempt to start"\n' >> $InitName
  printf '    exit 2\n' >> $InitName
  printf '  fi\n' >> $InitName
  printf '  $0 start\n' >> $InitName
  printf '  ;;\n' >> $InitName
  printf '  status)\n' >> $InitName
  printf '  if is_running; then\n' >> $InitName
  printf '    echo "Running"\n' >> $InitName
  printf '  else\n' >> $InitName
  printf '    echo "Stopped"\n' >> $InitName
  printf '    exit 2\n' >> $InitName
  printf '  fi\n' >> $InitName
  printf '  ;;\n' >> $InitName
  printf '  *)\n' >> $InitName
  printf '  echo "Usage: $0 {start|stop|restart|status}"\n' >> $InitName
  printf '  exit 1\n' >> $InitName
  printf '  ;;\n' >> $InitName
  printf 'esac\n\n' >> $InitName
  printf 'exit 0\n' >> $InitName

  # Set vars to allow fpm to include the after_install, before_remove and the init scripts
  PackageName=$VaultName
  AfterInstallCommand='--after-install scripts/after_install.sh'
  BeforeRemoveCommand='--before-remove scripts/before_remove.sh'
  ExtraFilesCommand=scripts/$InitName=/etc/init.d/

  chmod 755 after_install.sh before_remove.sh $InitName
  cd ..
}

function create_package {
  fpm \
    -t $1 \
    -s dir \
    --force \
    --name $PackageName \
    --version $Version \
    --license GPLv3 \
    --vendor MaidSafe \
    --directories $ConfigFilePath \
    --maintainer "MaidSafeQA <qa@maidsafe.net>" \
    --description "$Description" \
    --url "http://maidsafe.net" \
    $AfterInstallCommand \
    $BeforeRemoveCommand \
    "$RootDir/target/release/$VaultName"=$VaultPath \
    "$RootDir/installer/common/$VaultName.crust.config"=$ConfigFilePath \
    $ExtraFilesCommand
}

cd "$RootDir"
cargo update
cargo build --release
rm -rf "$RootDir/packages/$Platform" || true
if [[ "$1" == "linux" ]]
then
  prepare_for_tar
  create_package tar
  gzip $PackageName.tar

  prepare_systemd_scripts
  create_package deb
  create_package rpm

  prepare_sysv_style_scripts
  create_package deb
  create_package rpm
elif [[ "$1" == "osx" ]]
then
  prepare_for_tar
  create_package tar

  create_package osxpkg
fi
