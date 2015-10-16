# Check we've installed AdvancedInstaller
Get-ItemProperty 'hklm:\SOFTWARE\Wow6432Node\Caphyon\Advanced Installer' -ErrorAction SilentlyContinue | select -ExpandProperty 'Advanced Installer Path' -OutVariable AdvancedInstallerPath >$null
If (!$AdvancedInstallerPath) {
    Get-ItemProperty 'hklm:\SOFTWARE\Caphyon\Advanced Installer' -ErrorAction SilentlyContinue | select -ExpandProperty 'Advanced Installer Path' -OutVariable AdvancedInstallerPath >$null
    If (!$AdvancedInstallerPath) {
        "You need to install Advanced Installer (see www.advancedinstaller.com)"
        Exit 1
    }
}

# Update the PATH to allow us to use AdvancedInstaller and Rust
$AdvancedInstallerPath = Join-Path $AdvancedInstallerPath bin\x86
$env:PATH = "$env:RUST_NIGHTLY\bin;$AdvancedInstallerPath;$env:PATH"

# Get the current project version and name from Cargo.toml
$PSScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
$project_root = (get-item $PSScriptRoot).parent.parent.FullName
$cargo_toml = Join-Path $project_root Cargo.toml
$cargo_content = Get-Content "$cargo_toml"
$project_version = (($cargo_content -match 'version[= \t]*"[^"]*"') -replace 'version[= \t]*"', '') -replace '"', ''
$matches = Get-Content "$cargo_toml" | Select-String -Pattern 'name[= \t]*"([^"]*)"'
$project_name = (($cargo_content -match 'name[= \t]*"[^"]*"') -replace 'name[= \t]*"', '') -replace '"', ''

# Build the main target
cd $project_root
cargo update
cargo rustc --release '--' -C link-args="-Wl,--subsystem,windows"
strip target\release\$project_name.exe

# Update the AdvancedInstaller project file and build the 32-bit or 64-bit package
If ($env:PROCESSOR_ARCHITECTURE -eq "x86") {
    $build_name = "x86"
} Else {
    $build_name = "x64"
}
$aip_file = Join-Path $PSScriptRoot ("$project_name" + "_32_and_64_bit.aip")
AdvancedInstaller.com /edit $aip_file /SetVersion $project_version
AdvancedInstaller.com /build $aip_file -buildslist $build_name
