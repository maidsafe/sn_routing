#!/bin/bash
#
# Create a package for Vault Release binaries

# Stop the script if any command fails
set -e

# Get current version and executable's name from Cargo.toml
RootDir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
Version=$(sed -n 's/[ \t]*version[ \t]*=[ \t]*"\([^"]*\)".*/\1/p' $RootDir/Cargo.toml)
VaultName=$(sed -n 's/[ \t]*name[ \t]*=[ \t]*"\([^"]*\)".*/\1/p' $RootDir/Cargo.toml)
VaultPath=/usr/local/bin/
Platform=$1
Description="SAFE Network vault"

function add_file_check {
  local Output=$1
  local TargetFileName=$2
  local TargetPath=$3
  printf 'if [ ! -f %s ] ; then\n' "$TargetPath$TargetFileName" >> $Output
  printf '  echo "%s is missing from %s" >&2\n' "$TargetFileName" "$TargetPath" >> $Output
  printf '  exit 1\nfi\n\n' >> $Output
}

function prepare_systemd_scripts {
  ServiceName=safe-vault.service
  ServicePath=/usr/lib/systemd/system/

  mkdir -p $RootDir/packages/$Platform/systemd/scripts
  cd $RootDir/packages/$Platform/systemd/scripts

  # This will check the exe and service files are installed and will add and start the service
  printf '#!/bin/sh\n' > after_install.sh
  add_file_check after_install.sh "$VaultName" "$VaultPath"
  add_file_check after_install.sh "$ServiceName" "$ServicePath"
  printf 'systemctl enable %s\n' "$ServiceName" >> after_install.sh
  printf 'systemctl start %s\n' "$ServiceName" >> after_install.sh

  # This will stop and remove the service
  printf '#!/bin/sh\n' > before_remove.sh
  printf 'systemctl stop %s\n' "$ServiceName" >> before_remove.sh
  printf 'systemctl disable %s\n' "$ServiceName" >> before_remove.sh

  # This specifies the service
  printf '[Unit]\nDescription=%s\n\n' "$Description" > $ServiceName
  printf '[Service]\nExecStart=%s\nRestart=on-failure\n\n' "$VaultPath$VaultName" >> $ServiceName
  printf '[Install]\nWantedBy=multi-user.target' >> $ServiceName

  # Set var to allow fpm to include the service file
  ExtraFilesCommand=scripts/$ServiceName=$ServicePath

  chmod 755 after_install.sh before_remove.sh
  cd ..
}

function prepare_sysv_style_scripts {
  InitName=safe-vault

  mkdir -p $RootDir/packages/$Platform/SysV-style/scripts
  cd $RootDir/packages/$Platform/SysV-style/scripts

  # This will check the exe is installed, will install the init script and will start the vault
  printf '#!/bin/sh\n' > after_install.sh
  add_file_check after_install.sh "$VaultName" "$VaultPath"
  printf 'update-rc.d %s defaults\n' "$InitName" >> after_install.sh
  printf '/etc/init.d/%s start\n' "$InitName" >> after_install.sh

  # This will stop the vault, and remove the init script
  printf '#!/bin/sh\n' > before_remove.sh
  printf '/etc/init.d/%s stop\n' "$InitName" >> before_remove.sh
  printf 'update-rc.d -f %s remove\n' "$InitName" >> before_remove.sh

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
  printf 'PATH=/sbin:/usr/sbin:/bin:/usr/bin\n' >> $InitName
  printf 'Description="%s"\n' "$Description" >> $InitName
  printf 'Name=%s\n' "$InitName" >> $InitName
  printf 'Daemon=%s\n' "$VaultPath$VaultName" >> $InitName
  printf 'PidFile=/var/run/$Name.pid\n\n' >> $InitName
  printf '# Exit if the package is not installed\n' >> $InitName
  printf '[ -x "%s" ] || exit 0\n\n' "$VaultPath$VaultName" >> $InitName
  printf '# Load the VERBOSE setting and other rcS variables\n' >> $InitName
  printf '. /lib/init/vars.sh\n\n' >> $InitName
  printf '# Define LSB log_* functions.\n' >> $InitName
  printf '# Depend on lsb-base (>= 3.0-6) to ensure that this file is present.\n' >> $InitName
  printf '. /lib/lsb/init-functions\n\n' >> $InitName
  printf '# Returns\n' >> $InitName
  printf '#   0 if daemon has been started\n' >> $InitName
  printf '#   1 if daemon was already running\n' >> $InitName
  printf '#   2 if daemon could not be started\n' >> $InitName
  printf 'do_start() {\n' >> $InitName
  printf '  start-stop-daemon --start --quiet --pidfile $PidFile --exec $Daemon --test > /dev/null || return 1\n' >> $InitName
  printf '  start-stop-daemon --start --background --quiet --pidfile $PidFile --exec $Daemon || return 2\n' >> $InitName
  printf '}\n\n' >> $InitName
  printf '# Returns\n' >> $InitName
  printf '#   0 if daemon has been stopped\n' >> $InitName
  printf '#   1 if daemon was already stopped\n' >> $InitName
  printf '#   2 if daemon could not be stopped\n' >> $InitName
  printf '#   other if a failure occurred\n' >> $InitName
  printf 'do_stop() {\n' >> $InitName
  printf '  start-stop-daemon --stop --quiet --retry=TERM/30/KILL/5 --pidfile $PidFile --name $Name\n' >> $InitName
  printf '  ReturnValue="$?"\n' >> $InitName
  printf '  [ "$ReturnValue" = 2 ] && return 2\n' >> $InitName
  printf '#  rm -f $PidFile\n' >> $InitName
  printf '  return "$ReturnValue"\n' >> $InitName
  printf '}\n\n' >> $InitName
  printf 'case "$1" in\n' >> $InitName
  printf '  start)\n' >> $InitName
  printf '  [ "$VERBOSE" != no ] && log_daemon_msg "Starting $Description" "$Name"\n' >> $InitName
  printf '  do_start\n' >> $InitName
  printf '  case "$?" in\n' >> $InitName
  printf '    0|1) [ "$VERBOSE" != no ] && log_end_msg 0 ;;\n' >> $InitName
  printf '    2) [ "$VERBOSE" != no ] && log_end_msg 1 ;;\n' >> $InitName
  printf '  esac\n' >> $InitName
  printf '  ;;\n' >> $InitName
  printf '  stop)\n' >> $InitName
  printf '  [ "$VERBOSE" != no ] && log_daemon_msg "Stopping $Description" "$Name"\n' >> $InitName
  printf '  do_stop\n' >> $InitName
  printf '  case "$?" in\n' >> $InitName
  printf '    0|1) [ "$VERBOSE" != no ] && log_end_msg 0 ;;\n' >> $InitName
  printf '    2) [ "$VERBOSE" != no ] && log_end_msg 1 ;;\n' >> $InitName
  printf '  esac\n' >> $InitName
  printf '  ;;\n' >> $InitName
  printf '  status)\n' >> $InitName
  printf '       status_of_proc "$Daemon" "$Name" && exit 0 || exit $?\n' >> $InitName
  printf '       ;;\n' >> $InitName
  printf '  restart|force-reload)\n' >> $InitName
  printf '  log_daemon_msg "Restarting $Description" "$Name"\n' >> $InitName
  printf '  do_stop\n' >> $InitName
  printf '  case "$?" in\n' >> $InitName
  printf '    0|1)\n' >> $InitName
  printf '    do_start\n' >> $InitName
  printf '    case "$?" in\n' >> $InitName
  printf '      0) log_end_msg 0 ;;\n' >> $InitName
  printf '      1) log_end_msg 1 ;; # Old process is still running\n' >> $InitName
  printf '      *) log_end_msg 1 ;; # Failed to start\n' >> $InitName
  printf '    esac\n' >> $InitName
  printf '    ;;\n' >> $InitName
  printf '    *)\n' >> $InitName
  printf '    # Failed to stop\n' >> $InitName
  printf '    log_end_msg 1\n' >> $InitName
  printf '    ;;\n' >> $InitName
  printf '  esac\n' >> $InitName
  printf '  ;;\n' >> $InitName
  printf '  *)\n' >> $InitName
  printf '  echo "Usage: %s {start|stop|status|restart|force-reload}" >&2\n' "/etc/init.d/$InitName" >> $InitName
  printf '  exit 3\n' >> $InitName
  printf '  ;;\n' >> $InitName
  printf 'esac\n\n' >> $InitName
  printf ':\n' >> $InitName

  # Set var to allow fpm to include the init script
  ExtraFilesCommand=scripts/$InitName=/etc/init.d/

  chmod 755 after_install.sh before_remove.sh $InitName
  cd ..
}

function create_package {
  fpm \
    -t $1 \
    -s dir \
    --force \
    --name $VaultName \
    --version $Version \
    --license GPLv3 \
    --vendor MaidSafe \
    --directories /var/cache/safe/ \
    --maintainer "MaidSafeQA <qa@maidsafe.net>" \
    --description "$Description" \
    --url "http://maidsafe.net" \
    --after-install scripts/after_install.sh\
    --before-remove scripts/before_remove.sh \
    $RootDir/target/release/$VaultName=$VaultPath \
    $RootDir/installer/common/$VaultName.bootstrap.cache=/var/cache/safe/ \
    $ExtraFilesCommand
}

cd $RootDir
cargo update
cargo build --release
if [[ "$1" == "linux" ]]
then
  prepare_systemd_scripts
  create_package deb
  create_package rpm
  prepare_sysv_style_scripts
  create_package deb
  create_package rpm
elif [[ "$1" == "osx" ]]
then
  create_package osxpkg
fi
