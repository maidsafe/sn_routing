
cargo build --release

# Tag this commit if not already tagged.
git config --global user.name MaidSafe-QA
git config --global user.email qa@maidsafe.net
git fetch --tags

if (git tag -l "$env:PROJECT_VERSION") {
  echo "Tag $env:PROJECT_VERSION already exists"
} else {
  echo "Creating tag $env:PROJECT_VERSION"
  git tag $env:PROJECT_VERSION -am "Version $env:PROJECT_VERSION" $APPVEYOR_REPO_COMMIT 2>&1 | Out-Null
  git push -q "https://$env:GH_TOKEN@github.com/$env:APPVEYOR_REPO_NAME" tag $env:PROJECT_VERSION 2>&1 | Out-Null
}

# Create the release archive
$NAME = "$env:PROJECT_NAME-v$env:PROJECT_VERSION-windows-$env:PLATFORM"

New-Item -ItemType directory -Path staging
New-Item -ItemType directory -Path staging\$NAME
New-Item -ItemType directory -Path config

$RELEASE_CONFIG_REPO_NAME = "maidsafe/release_config"
git clone -q "https://$env:GH_TOKEN@github.com/$RELEASE_CONFIG_REPO_NAME" config 2>&1 | Out-Null

Copy-Item target\release\$env:PROJECT_NAME.exe staging\$NAME
Copy-Item config\safe_vault\* staging\$NAME

cd staging
7z a ../$NAME.zip *
Push-AppveyorArtifact ../$NAME.zip

# TODO: build the installer:

# Create the installer
# $INSTALLER_NAME = "$($env:PROJECT_NAME)_installer_$($env:PLATFORM)_$($env:PROJECT_VERSION)"

# # $ADVANCED_INSTALLER_VERSION="12.8"
# # $ADVANCED_INSTALLER_URL="http://www.advancedinstaller.com/downloads/$ADVANCED_INSTALLER_VERSION/advinst.msi"

# # HACK: using rehosted url, as the official one was giving me corrupted file
# $ADVANCED_INSTALLER_URL="https://dl.dropboxusercontent.com/u/1003097/advinst.msi"

# echo "Downloading AdvancedInstaller"
# Invoke-WebRequest $ADVANCED_INSTALLER_URL -OutFile "$env:TEMP\advinst.msi"

# # Run the installer for AdvancedInstaller and wait for it to finish
# echo "Installing AdvancedInstaller..."
# msiexec.exe /i "$env:TEMP\advinst.msi" /qn | Out-Null

# if (!($LASTEXITCODE -eq 0)) {
#   echo "Error installing AdvancedInstaller (error code: $LASTEXITCODE)"
#   Exit 1
# }

# # Add AdvancedInstaller to PATH
# Get-ItemProperty 'hklm:\SOFTWARE\Wow6432Node\Caphyon\Advanced Installer' -ErrorAction SilentlyContinue | select -ExpandProperty 'Advanced Installer Path' -OutVariable ADVANCED_INSTALLER_PATH >$null

# If (!$ADVANCED_INSTALLER_PATH) {
#   Get-ItemProperty 'hklm:\SOFTWARE\Caphyon\Advanced Installer' -ErrorAction SilentlyContinue | select -ExpandProperty 'Advanced Installer Path' -OutVariable ADVANCED_INSTALLER_PATH >$null

#   If (!$ADVANCED_INSTALLER_PATH) {
#     "AdvancedInstaller not installed correctly"
#     Exit 1
#   }
# }

# $ADVANCED_INSTALLER_PATH = Join-Path $ADVANCED_INSTALLER_PATH "bin\x86"

# echo "Adding $ADVANCED_INSTALLER_PATH to PATH"
# $env:PATH = "$ADVANCED_INSTALLER_PATH;$env:PATH"

# # # TODO: register AdvancedInstaller
# # # AdvancedInstaller.com /register $env:ADVANCED_INSTALLER_LICENSE_ID

# echo "Building $env:PROJECT_NAME installer"

# $AIP_FILE = "installer\windows\$($env:PROJECT_NAME)_32_and_64_bit.aip"
# AdvancedInstaller.com /edit $AIP_FILE /SetVersion $env:PROJECT_VERSION
# AdvancedInstaller.com /build $AIP_FILE -buildslist $env:PLATFORM

# Push-AppveyorArtifact packages\windows\$INSTALLER_NAME.exe
