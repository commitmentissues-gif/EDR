@echo off
setlocal
set SCRIPT_DIR=%~dp0

if "%1"=="" goto usage
if /i "%1"=="install" goto install
if /i "%1"=="uninstall" goto uninstall
if /i "%1"=="start" goto start
if /i "%1"=="stop" goto stop
if /i "%1"=="restart" goto restart
if /i "%1"=="status" goto status

:usage
echo ==========================================================
echo        LocalEDR Windows Service Command Manager
echo ==========================================================
echo Usage: service-manager.bat [command]
echo.
echo Commands:
echo   install    - Install LocalEDR_Agent with Auto-Start & Crash Recovery
echo   uninstall  - Gracefully stop and remove LocalEDR_Agent
echo   start      - Start LocalEDR_Agent
echo   stop       - Gracefully stop LocalEDR_Agent
echo   restart    - Restart LocalEDR_Agent
echo   status     - Inspect service state, memory, and recovery actions
echo.
goto end

:install
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%install-service.ps1"
goto end

:uninstall
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%uninstall-service.ps1"
goto end

:start
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%start-service.ps1"
goto end

:stop
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%stop-service.ps1"
goto end

:restart
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%restart-service.ps1"
goto end

:status
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%status-service.ps1"
goto end

:end
endlocal
