@echo off
setlocal
cd /d "%~dp0"

echo [AI Firewall] Starting demo environment...
echo [1/4] Starting Docker containers...
docker compose up -d
if errorlevel 1 (
  echo Docker start failed. Make sure Docker Desktop is open, then run this file again.
  exit /b 1
)

echo [2/4] Starting Windows host monitor services...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0ensure_windows_monitors.ps1"

echo [3/4] Waiting for services to settle...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Sleep -Seconds 6"

echo [4/4] Current status:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0demo_status_report.ps1"

echo.
echo Dashboard: http://localhost:5173
echo If Device Safety still shows Offline or your pendrive is missing, run fix_demo_status.cmd and then refresh the page with Ctrl+F5.
start "" "http://localhost:5173"

endlocal
