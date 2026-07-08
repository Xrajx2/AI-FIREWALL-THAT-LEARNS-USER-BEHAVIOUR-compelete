@echo off
setlocal
cd /d "%~dp0"

echo [AI Firewall] Repairing demo environment...
echo [1/3] Ensuring Docker containers are running...
docker compose up -d

echo [2/3] Restarting Windows host monitor services if needed...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0ensure_windows_monitors.ps1"

echo [3/3] Waiting and checking status...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Sleep -Seconds 6"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0demo_status_report.ps1"

echo.
echo Refresh http://localhost:5173 with Ctrl+F5 after this finishes.
endlocal
