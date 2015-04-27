@echo off
where /q AdvancedInstaller.com
if not %ERRORLEVEL%==0 (
  echo Windows Advanced Installer is required for the Installer to be built. Please add it to your PATH
  exit /B 1
)
AdvancedInstaller.com /build maidsafe_vault.aip
