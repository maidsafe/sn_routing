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

# Get the current project version and name
$PSScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
$ProjectRoot = (get-item $PSScriptRoot).parent.parent.FullName
cd $ProjectRoot
$ProjectVersion = (cargo pkgid) -replace '.*[:#](.*)', '$1'
$ProjectName = (cargo pkgid) -replace '/*([^/#]*[/#])*((\w+)[:#]).*', '$3'

# Build the main target
cargo update
cargo rustc --release '--' -C link-args="-Wl,--subsystem,windows"
strip target\release\$ProjectName.exe

# Update the AdvancedInstaller project file and build the 32-bit or 64-bit package
If ($env:PROCESSOR_ARCHITECTURE -eq "x86") {
    $BuildName = "x86"
} Else {
    $BuildName = "x64"
}
$AipFile = Join-Path $PSScriptRoot ("$ProjectName" + "_32_and_64_bit.aip")
AdvancedInstaller.com /edit $AipFile /SetVersion $ProjectVersion
AdvancedInstaller.com /build $AipFile -buildslist $BuildName
