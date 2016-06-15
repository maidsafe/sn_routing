#!/bin/bash
#
# Create a package for Vault Release binaries

set -e

# Get current version and executable's name from Cargo.toml
RootDir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

ConfigSourceDir="$HOME/config/safe_vault"

if [ -n "$PROJECT_NAME" ]; then
  VaultName="$PROJECT_NAME"
else
  VaultName=$(cargo pkgid | sed -e "s/.*\(\<.*\>\)[:#].*/\1/")
fi

if [ -n "$PROJECT_VERSION" ]; then
  Version="$PROJECT_VERSION"
else
  Version=$(cargo pkgid | sed -e "s/.*[:#]\(.*\)/\1/")
fi

if [[ "$1" == "linux" ]]
then
  VaultPath=/usr/bin/
elif [[ "$1" == "osx" ]]
then
  VaultPath=/usr/local/bin/
fi

ConfigFileParentDir=/var/cache
ConfigFileDir="$ConfigFileParentDir/$VaultName/"
Platform=$1
Description="SAFE Network vault"

function add_file_check {
  local TargetFileName=$1
  local TargetPath=$2
  printf 'if [ ! -f %s ]; then\n' "$TargetPath$TargetFileName" >> after_install.sh
  printf '  echo "%s is missing from %s" >&2\n' "$TargetFileName" "$TargetPath" >> after_install.sh
  printf '  exit 1\nfi\n\n' >> after_install.sh
}

function add_safe_user {
  printf 'useradd safe --system --shell /bin/false --user-group\n\n' >> after_install.sh
}

function remove_safe_user {
  printf 'userdel safe\n' >> before_remove.sh
}

function set_owner {
  printf 'chown -R safe:safe %s\n' "$ConfigFileDir" >> after_install.sh
  printf 'chown safe:safe %s\n' "$VaultPath$VaultName" >> after_install.sh
  printf 'chmod 775 %s\n' "$VaultPath$VaultName" >> after_install.sh
}

function prepare_for_tar {
  mkdir -p "$RootDir/packages/$Platform"
  cd "$RootDir/packages/$Platform"
  Bits=$(getconf LONG_BIT)
  PackageName="$VaultName"_"$Version"_"$Bits"-bit
  AfterInstallCommand=
  BeforeRemoveCommand=
  ExtraFile1=
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
  printf '\nsystemctl enable %s\n' "$ServiceName" >> after_install.sh
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
  ExtraFile1=scripts/$ServiceName=$ServicePath

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
  printf '\nif [ $(command -v update-rc.d >/dev/null; echo $?) -eq 0 ]; then\n' >> after_install.sh
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
  ExtraFile1=scripts/$InitName=/etc/init.d/

  chmod 755 after_install.sh before_remove.sh $InitName
  cd ..
}

function prepare_for_osx {
  UninstallScript=uninstall_"$VaultName".sh
  PlistFile=org.maidsafe."$VaultName".plist

  mkdir -p "$RootDir/packages/$Platform"
  cd "$RootDir/packages/$Platform"
  cp "$RootDir/installer/osx/$PlistFile" "./$PlistFile"

  # This will:
  #   * check the exe file is installed
  #   * create a user and group called "safe" if they don't already exist
  #   * set these as the owner/group for the installed files
  #   * add and start the service
  printf '#!/bin/sh\n' > after_install.sh
  add_file_check "$VaultName" "$VaultPath"
  printf 'function get_new_user_id() {\n' >> after_install.sh
  printf '  local UserIds=$(dscl . -list /Users UniqueID | awk '"'"'{print $2}'"'"' | sort -ugr)\n' >> after_install.sh
  printf '  local NewId\n' >> after_install.sh
  printf '  for NewId in $UserIds\n' >> after_install.sh
  printf '  do\n' >> after_install.sh
  printf '    if [[ $NewId -lt 499 ]]\n' >> after_install.sh
  printf '    then\n' >> after_install.sh
  printf '      break;\n' >> after_install.sh
  printf '    fi\n' >> after_install.sh
  printf '  done\n' >> after_install.sh
  printf '  echo $((NewId + 1))\n' >> after_install.sh
  printf '}\n\n' >> after_install.sh
  printf 'function get_new_group_id {\n' >> after_install.sh
  printf '  PreferredId=$1\n' >> after_install.sh
  printf '  # Try to use the same ID for UserID and GroupID\n' >> after_install.sh
  printf '  if dscl . -list /Groups PrimaryGroupID | awk '"'"'{print $2}'"'"' | grep $PreferredId >/dev/null 2>&1\n' >> after_install.sh
  printf '  then\n' >> after_install.sh
  printf '    local GroupIds=$(dscl . -list /Groups PrimaryGroupID | awk '"'"'{print $2}'"'"' | sort -ugr)\n' >> after_install.sh
  printf '    local NewId\n' >> after_install.sh
  printf '    for NewId in $GroupIds\n' >> after_install.sh
  printf '    do\n' >> after_install.sh
  printf '      if [[ $NewId -lt 499 ]]\n' >> after_install.sh
  printf '      then\n' >> after_install.sh
  printf '        break;\n' >> after_install.sh
  printf '      fi\n' >> after_install.sh
  printf '    done\n' >> after_install.sh
  printf '    echo $((NewId + 1))\n' >> after_install.sh
  printf '  else\n' >> after_install.sh
  printf '    echo $PreferredId\n' >> after_install.sh
  printf '  fi\n' >> after_install.sh
  printf '}\n\n' >> after_install.sh
  printf 'UserId=$(get_new_user_id)\n' >> after_install.sh
  printf 'GroupId=$(get_new_group_id $UserId)\n\n' >> after_install.sh
  printf 'dscl . -create /Users/safe\n' >> after_install.sh
  printf 'dscl . -create /Users/safe UniqueID "$UserId"\n' >> after_install.sh
  printf 'dscl . -create /Users/safe PrimaryGroupID "$GroupId"\n' >> after_install.sh
  printf 'dscl . -create /Users/safe UserShell /usr/bin/false\n' >> after_install.sh
  printf 'dseditgroup -o create -i "$GroupId" safe\n\n' >> after_install.sh
  printf 'mkdir -p /var/log/safe\n' >> after_install.sh
  set_owner
  printf 'chown safe:safe /var/log/safe\n' >> after_install.sh
  printf 'chmod 775 %s\n\n' "$VaultPath$UninstallScript" >> after_install.sh
  printf 'launchctl load /Library/LaunchDaemons/%s\n' "$PlistFile" >> after_install.sh
  printf 'osascript -e '"'"'tell app "System Events" to display dialog "To remove %s, run %s" buttons {"OK"} default button "OK" giving up after 10'"'"'\n' "$VaultName" "$VaultPath$UninstallScript" >> after_install.sh

  # This will be a script to allow users to uninstall safe_vault
  printf '#!/bin/sh\n' > $UninstallScript
  printf 'if [ $EUID != 0 ]; then\n' >> $UninstallScript
  printf '  sudo "$0" "$@"\n' >> $UninstallScript
  printf '  exit $?\n' >> $UninstallScript
  printf 'fi\n\n' >> $UninstallScript
  printf 'launchctl unload /Library/LaunchDaemons/%s\n' "$PlistFile" >> $UninstallScript
  printf 'rm /Library/LaunchDaemons/%s\n\n' "$PlistFile" >> $UninstallScript
  printf 'dscl . -delete /Users/safe\n' >> $UninstallScript
  printf 'dseditgroup -o delete safe\n\n' >> $UninstallScript
  printf 'rm -rf %s\n' "$ConfigFileDir" >> $UninstallScript
  printf 'rm %s\n' "$VaultPath$VaultName" >> $UninstallScript
  printf 'rm %s\n\n' "$VaultPath$UninstallScript" >> $UninstallScript
  printf 'if [[ "$1" == "-y" ]]; then\n' >> $UninstallScript
  printf '  rm -rf /var/log/safe\n' >> $UninstallScript
  printf 'elif [[ "$1" != "-n" ]]; then\n' >> $UninstallScript
  printf '  read -p "Do you wish to remove the logfiles from /var/log/safe/  [y/N]? " -r\n' >> $UninstallScript
  printf '  if [[ $REPLY =~ ^[Yy]$ ]]; then\n' >> $UninstallScript
  printf '    rm -rf /var/log/safe\n' >> $UninstallScript
  printf '  fi\n' >> $UninstallScript
  printf 'fi\n\n' >> $UninstallScript
  printf 'echo "\nFinished uninstalling safe_vault.\n\n"\n' "$VaultPath" >> $UninstallScript

  # This will invoke the previously-installed version's uninstall script if it exists.  If the name
  # of the uninstall script changes between this version and previous versions, we need to invoke
  # all variants of the script, hence the script's name should be hard-coded rather than using the
  # $UninstallScript variable which may only apply to this version of the installer.
  printf '#!/bin/sh\n' > before_install.sh
  printf '/bin/sh /usr/local/bin/uninstall_safe_vault.sh -n&\n' >> before_install.sh  # First version of uninstall script

  # Set vars to allow fpm to include these files
  PackageName=$VaultName
  AfterInstallCommand='--after-install after_install.sh'
  BeforeInstallCommand='--before-install before_install.sh'
  OsxCommands='--osxpkg-identifier-prefix org.maidsafe'
  ExtraFile1=$UninstallScript=$VaultPath
  ExtraFile2=./$PlistFile=/Library/LaunchDaemons/$PlistFile

  chmod 755 after_install.sh "$UninstallScript"
}

function create_package {
  if [ -n "$TARGET" ]; then
    local vault_binary="$RootDir/target/$TARGET/release/$VaultName"
  else
    local vault_binary="$RootDir/target/release/$VaultName"
  fi

  case $TARGET in
  *x86_64*)
    local arch=x86_64
    ;;
  *i386*|*i686*)
    local arch=i386
    ;;
  *)
    local arch=native
    ;;
  esac

  fpm \
    -t $1 \
    -s dir \
    --force \
    --name $PackageName \
    --version $Version \
    --architecture $arch \
    --license GPLv3 \
    --vendor MaidSafe \
    --directories $ConfigFileDir \
    --maintainer "MaidSafe QA <qa@maidsafe.net>" \
    --description "$Description" \
    --url "http://maidsafe.net" \
    $BeforeInstallCommand \
    $AfterInstallCommand \
    $BeforeRemoveCommand \
    $OsxCommands \
    "$vault_binary"=$VaultPath \
    "$ConfigSourceDir"="$ConfigFileParentDir" \
    $ExtraFile1 \
    $ExtraFile2
}


if [ -n "$TARGET" ]; then
  BuiltVault="$RootDir/target/$TARGET/release/$VaultName"
else
  BuiltVault="$RootDir/target/release/$VaultName"
fi

# If we are not running on travis CI, delete the binary to force a fresh build.
# If we are running on travis, the binary should be freshly built already, and
# there is no need to rebuild it.
if [ -z "$TRAVIS" ]; then
  rm -f "$BuiltVault"
fi

if [ ! -f "$BuiltVault" ]; then
  cd "$RootDir"
  cargo update

  if [ -n "$TARGET" ]; then
    cargo build --target $TARGET --release
  else
    cargo build --release
  fi
fi

strip "$BuiltVault"
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

  printf '%s' "$Version" > "$RootDir/packages/$Platform/$VaultName"_latest_version.txt
elif [[ "$1" == "osx" ]]
then
  prepare_for_osx

  if [ -z "$SKIP_SIGN_PACKAGE" ]; then
    # Sign the binary
    codesign -s "Developer ID Application: MaidSafe.net Ltd (MEGSB2GXGZ)" "$BuiltVault"
    codesign -vvv -d "$BuiltVault"
  fi

  create_package osxpkg

  if [ -z "$SKIP_SIGN_PACKAGE" ]; then
    # Sign the installer
    OsxPackage="$RootDir/packages/$Platform/$PackageName-$Version.pkg"
    productsign --sign "Developer ID Installer: MaidSafe.net Ltd (MEGSB2GXGZ)" "$OsxPackage" "$OsxPackage.signed"
    mv "$OsxPackage.signed" "$OsxPackage"
    spctl -a -v --type install "$OsxPackage"
  fi
fi
