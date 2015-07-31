# Check we've installed AdvancedInstaller
Get-ItemProperty 'hklm:\SOFTWARE\Wow6432Node\Caphyon\Advanced Installer' -ErrorAction SilentlyContinue | select -ExpandProperty 'Advanced Installer Path' -OutVariable AdvancedInstallerPath >$null
If (!$AdvancedInstallerPath) {
    "You need to install Advanced Installer (see www.advancedinstaller.com)"
    Exit 1
}

# Update the PATH to allow us to use AdvancedInstaller and Rust
$AdvancedInstallerPath = Join-Path $AdvancedInstallerPath bin\x86
$env:PATH = "$env:RUST_NIGHTLY\bin;$AdvancedInstallerPath;$env:PATH"

# Get the current project version and name from Cargo.toml
$project_root = (get-item $PSScriptRoot).parent.parent.FullName
$cargo_toml = Join-Path $project_root Cargo.toml
$matches = Get-Content "$cargo_toml" | Select-String -Pattern 'version[= \t]*"([^"]*)"'
$project_version = $matches[0].Matches.Groups[1].Value
$matches = Get-Content "$cargo_toml" | Select-String -Pattern 'name[= \t]*"([^"]*)"'
$project_name = $matches[0].Matches.Groups[1].Value

# Build the main target
cd $project_root
cargo update
cargo rustc --release -- -C link-args="-Wl,--subsystem,windows"

# Update the AdvancedInstaller project file and build the package
$aip_file = Join-Path $PSScriptRoot "$project_name.aip"
AdvancedInstaller.com /edit $aip_file /SetVersion $project_version
AdvancedInstaller.com /build $aip_file
