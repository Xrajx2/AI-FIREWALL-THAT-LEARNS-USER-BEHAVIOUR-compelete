@echo off
cd /d "%~dp0"
set "ENABLE_USB_SCANNING=true"
start "AI Firewall USB Scanner" /min powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0usb_av_scanner.ps1"
