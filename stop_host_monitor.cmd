@echo off
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$targets = Get-CimInstance Win32_Process -Filter \"Name = 'powershell.exe'\" | Where-Object { $_.CommandLine -like '*host_system_monitor.ps1*' }; foreach ($target in $targets) { Stop-Process -Id $target.ProcessId -Force }"
