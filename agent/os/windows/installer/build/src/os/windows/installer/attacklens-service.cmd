@echo off
:: attacklens-service.cmd — CMD shim for attacklens-service.ps1
:: Installed to C:\Program Files\AttackLens\scripts\ (on system PATH)
::
:: Usage: attacklens-service <command> [args]
:: Examples:
::   attacklens-service status
::   attacklens-service start
::   attacklens-service logs
::   attacklens-service diagnose
::   attacklens-service set-manager 34.224.174.38
::   attacklens-service help
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass ^
    -File "%~dp0attacklens-service.ps1" %*
endlocal
