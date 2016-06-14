
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
