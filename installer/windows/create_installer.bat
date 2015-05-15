@echo off
where /q AdvancedInstaller.com
if not %ERRORLEVEL%==0 (
  echo Advanced Installer is required for the Installer to be built. Please add it to your PATH
  exit /B 1
)
cargo build --release
AdvancedInstaller.com /build installer\windows\maidsafe_vault.aip
