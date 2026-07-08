@echo off
cd /d "%~dp0"
set "ENABLE_USB_SCANNING=true"
start "AI Firewall Host Monitor" /min powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0host_system_monitor.ps1"
