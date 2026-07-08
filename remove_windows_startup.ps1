$ErrorActionPreference = "Stop"

$startupFolder = [Environment]::GetFolderPath("Startup")
$startupFile = Join-Path $startupFolder "AI Firewall Windows Monitors.cmd"

if (Test-Path -LiteralPath $startupFile) {
    Remove-Item -LiteralPath $startupFile -Force
    Write-Host "Removed startup launcher: $startupFile"
} else {
    Write-Host "Startup launcher not present: $startupFile"
}
