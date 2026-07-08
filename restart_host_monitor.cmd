@echo off
cd /d "%~dp0"
call "%~dp0stop_host_monitor.cmd"
timeout /t 1 /nobreak >nul
call "%~dp0start_host_monitor.cmd"
