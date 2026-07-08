$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$watchdogPath = Join-Path $projectRoot "windows_monitors_watchdog.ps1"
$startupFolder = [Environment]::GetFolderPath("Startup")
$startupFile = Join-Path $startupFolder "AI Firewall Windows Monitors.cmd"

if (-not (Test-Path -LiteralPath $watchdogPath)) {
    throw "Watchdog script not found: $watchdogPath"
}

$startupContent = @"
@echo off
cd /d "$projectRoot"
start "AI Firewall Monitor Watchdog" /min powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$watchdogPath"
"@

Set-Content -LiteralPath $startupFile -Value $startupContent -Encoding ASCII

Start-Process `
    -FilePath "powershell.exe" `
    -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $watchdogPath) `
    -WorkingDirectory $projectRoot `
    -WindowStyle Minimized | Out-Null

Write-Host "Installed AI Firewall Windows monitor auto-start for the current user."
Write-Host "Startup file: $startupFile"
