$ErrorActionPreference = "Continue"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$statusPath = Join-Path $projectRoot "backend\runtime\device_safety_status.json"

function Test-ProcessRunning {
    param(
        [string]$ExecutablePattern,
        [string]$CommandPattern
    )

    try {
        $processes = Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
            $_.Name -match $ExecutablePattern -and
            $_.CommandLine -and
            $_.CommandLine -match $CommandPattern
        }
        return @($processes).Count -gt 0
    } catch {
        return $false
    }
}

function Write-StatusLine {
    param(
        [string]$Label,
        [string]$Value
    )

    Write-Host ("{0,-24} {1}" -f $Label, $Value)
}

$dockerRows = @()
try {
    $dockerRows = @(docker ps --format "{{.Names}}|{{.Status}}" 2>$null)
} catch {
    $dockerRows = @()
}

$frontendRunning = $dockerRows | Where-Object { $_ -match "^aifirewall_project-frontend-1\|" }
$backendRunning = $dockerRows | Where-Object { $_ -match "^aifirewall_project-backend-1\|" }

$hostMonitorRunning = Test-ProcessRunning -ExecutablePattern "powershell|pwsh" -CommandPattern "host_system_monitor\.ps1"
$usbScannerRunning = Test-ProcessRunning -ExecutablePattern "powershell|pwsh" -CommandPattern "usb_av_scanner\.ps1"
$watchdogRunning = Test-ProcessRunning -ExecutablePattern "powershell|pwsh" -CommandPattern "windows_monitors_watchdog\.ps1"
$deviceSafetyRunning = Test-ProcessRunning -ExecutablePattern "python|pythonw|py" -CommandPattern "device_safety_agent\.py"

$statusPayload = $null
$heartbeatText = "missing"
$targetsText = "none"
if (Test-Path -LiteralPath $statusPath) {
    try {
        $statusPayload = Get-Content $statusPath -Raw | ConvertFrom-Json
        if ($statusPayload.agent.last_heartbeat_at) {
            $heartbeat = [DateTimeOffset]::Parse($statusPayload.agent.last_heartbeat_at)
            $heartbeatAge = [int](([DateTimeOffset]::UtcNow - $heartbeat).TotalSeconds)
            $heartbeatText = "$heartbeatAge sec ago"
        }
        if ($statusPayload.targets) {
            $targetsText = (($statusPayload.targets | ForEach-Object { $_.label }) -join ", ")
        }
    } catch {
        $heartbeatText = "unreadable"
        $targetsText = "unreadable"
    }
}

$removableDrives = @()
try {
    $removableDrives = Get-CimInstance Win32_LogicalDisk -ErrorAction Stop | Where-Object { $_.DriveType -eq 2 }
} catch {
    $removableDrives = @()
}

$driveText = if ($removableDrives.Count -gt 0) {
    ($removableDrives | ForEach-Object {
        if ($_.VolumeName) {
            "$($_.DeviceID) $($_.VolumeName)"
        } else {
            "$($_.DeviceID)"
        }
    }) -join ", "
} else {
    "none"
}

Write-Host ""
Write-Host "AI Firewall Demo Status"
Write-Host "-----------------------"
Write-StatusLine "Docker frontend:" ($(if ($frontendRunning) { "running" } else { "not running" }))
Write-StatusLine "Docker backend:" ($(if ($backendRunning) { "running" } else { "not running" }))
Write-StatusLine "Host monitor:" ($(if ($hostMonitorRunning) { "running" } else { "not running" }))
Write-StatusLine "USB scanner:" ($(if ($usbScannerRunning) { "running" } else { "not running" }))
Write-StatusLine "Watchdog:" ($(if ($watchdogRunning) { "running" } else { "not running" }))
Write-StatusLine "Safety agent:" ($(if ($deviceSafetyRunning) { "running" } else { "not running" }))
Write-StatusLine "Heartbeat:" $heartbeatText
Write-StatusLine "Windows USB drives:" $driveText
Write-StatusLine "Visible targets:" $targetsText
Write-Host ""
