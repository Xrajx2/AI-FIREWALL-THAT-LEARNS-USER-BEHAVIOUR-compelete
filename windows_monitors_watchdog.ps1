$ErrorActionPreference = "Continue"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$watchdogScript = $MyInvocation.MyCommand.Path
$logPath = Join-Path $env:TEMP "aifirewall-monitor-watchdog.log"

function Write-WatchdogLog {
    param([string]$Message)

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -LiteralPath $logPath -Value "$timestamp $Message" -Encoding UTF8
}

function Test-WatchdogAlreadyRunning {
    try {
        $escapedPath = [Regex]::Escape($watchdogScript)
        $matches = Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe' OR Name = 'pwsh.exe'" -ErrorAction Stop |
            Where-Object {
                $_.ProcessId -ne $PID -and
                $_.CommandLine -and
                $_.CommandLine -match $escapedPath
            }
        return @($matches).Count -gt 0
    } catch {
        return $false
    }
}

if (Test-WatchdogAlreadyRunning) {
    exit 0
}

$ensureScript = Join-Path $projectRoot "ensure_windows_monitors.ps1"
if (-not (Test-Path -LiteralPath $ensureScript)) {
    Write-WatchdogLog "ensure_windows_monitors.ps1 not found."
    exit 1
}

Write-WatchdogLog "AI Firewall monitor watchdog started."

while ($true) {
    try {
        & $ensureScript | Out-Null
    } catch {
        Write-WatchdogLog "Monitor ensure failed: $($_.Exception.Message)"
    }

    Start-Sleep -Seconds 300
}
