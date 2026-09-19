@echo off
rem Hideout - double-click to scan this PC for malware hiding spots. Read-only.
rem Right-click > Run as administrator to include system-level tasks.
setlocal
set "PS=pwsh"
where pwsh >nul 2>nul || set "PS=powershell"
%PS% -NoProfile -ExecutionPolicy Bypass -File "%~dp0hideout.ps1" -Open
if errorlevel 1 pause
