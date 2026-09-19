@echo off
rem Hideout hunt - a read-only evidence snapshot of everywhere malware usually hides.
rem Needs admin to see everything: Windows will ask you to allow it (click Yes).
rem It never deletes, moves, disables, runs or uploads anything.
setlocal
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
set "PS=pwsh"
where pwsh >nul 2>nul || set "PS=powershell"
%PS% -NoProfile -ExecutionPolicy Bypass -File "%~dp0hunt.ps1"
echo.
echo Done. The snapshot is in the "out" folder next to this file.
timeout /t 15
