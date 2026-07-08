$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$env:ENABLE_USB_SCANNING = "true"

function Test-MonitorRunning {
    param([string]$ScriptName)

    try {
        $expectedPath = (Join-Path $projectRoot $ScriptName)
        $escapedPath = [Regex]::Escape($expectedPath)
        $processes = Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe' OR Name = 'pwsh.exe'" -ErrorAction Stop |
            Where-Object {
                $_.CommandLine -and (
                    $_.ProcessId -ne $PID -and
                    $_.CommandLine -match "-File\s+`"?$escapedPath`"?"
                )
            }
        return @($processes).Count -gt 0
    } catch {
        return $false
    }
}

function Start-MonitorIfNeeded {
    param(
        [string]$ScriptName,
        [string]$Label,
        [string[]]$ExtraArgs = @()
    )

    if (Test-MonitorRunning -ScriptName $ScriptName) {
        Write-Host "$Label is already running."
        return $false
    }

    $scriptPath = Join-Path $projectRoot $ScriptName
    if (-not (Test-Path -LiteralPath $scriptPath)) {
        throw "$Label script not found: $scriptPath"
    }

    $argumentList = @(
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        $scriptPath
    ) + $ExtraArgs

    Start-Process `
        -FilePath "powershell.exe" `
        -ArgumentList $argumentList `
        -WorkingDirectory $projectRoot `
        -WindowStyle Minimized | Out-Null

    Write-Host "Started $Label."
    return $true
}

function Test-PythonAgentRunning {
    param([string]$RelativeScriptPath)

    try {
        $expectedPath = (Join-Path $projectRoot $RelativeScriptPath)
        $escapedPath = [Regex]::Escape($expectedPath)
        $processes = Get-CimInstance Win32_Process -Filter "Name = 'python.exe' OR Name = 'pythonw.exe' OR Name = 'py.exe'" -ErrorAction Stop |
            Where-Object {
                $_.CommandLine -and (
                    $_.ProcessId -ne $PID -and
                    $_.CommandLine -match $escapedPath
                )
            }
        return @($processes).Count -gt 0
    } catch {
        return $false
    }
}

function Start-PythonAgentIfNeeded {
    param(
        [string]$RelativeScriptPath,
        [string]$Label
    )

    if (Test-PythonAgentRunning -RelativeScriptPath $RelativeScriptPath) {
        Write-Host "$Label is already running."
        return $false
    }

    $scriptPath = Join-Path $projectRoot $RelativeScriptPath
    if (-not (Test-Path -LiteralPath $scriptPath)) {
        throw "$Label script not found: $scriptPath"
    }

    Start-Process `
        -FilePath "py.exe" `
        -ArgumentList @("-3", $scriptPath) `
        -WorkingDirectory $projectRoot `
        -WindowStyle Minimized | Out-Null

    Write-Host "Started $Label."
    return $true
}

$startedHost = Start-MonitorIfNeeded -ScriptName "host_system_monitor.ps1" -Label "AI Firewall Host Monitor"
$startedUsb = Start-MonitorIfNeeded -ScriptName "usb_av_scanner.ps1" -Label "AI Firewall USB Scanner"
$startedDeviceSafety = Start-PythonAgentIfNeeded -RelativeScriptPath "backend\device_safety_agent.py" -Label "AI Firewall Device Safety Agent"

if (-not $startedHost -and -not $startedUsb -and -not $startedDeviceSafety) {
    Write-Host "All AI Firewall monitor services are already running."
}
