param(
    [string]$BackendUrl = "http://localhost:8000",
    [string]$AgentUsername = "system-monitor-agent",
    [string]$AgentPassword = "SystemMonitor!2026",
    [int]$PollSeconds = 5,
    [int]$FileWindowSeconds = 20,
    [string[]]$MonitoredPaths = @(),
    [int]$AutoBlockThreshold = 55,
    [switch]$DisableConnectionBlocking,
    [switch]$RunOnce
)

$monitorVersion = "2026.03.19.2"
$ignoredDirNames = @(".git", ".venv", "__pycache__", "node_modules", "dist", "build", ".next")
$script:AuthToken = $null
$script:KnownProcessIds = @{}
$script:KnownUsbIds = @{}
$script:FileState = @{}
$script:KnownRemoteIpsByProcess = @{}
$script:BlockedRemoteIps = @{}
$script:LastEventAt = @{}
$script:MonitorRoots = @()
$script:ConnectionBlockingEnabled = $true

function Get-EnvFlag {
    param(
        [string]$Name,
        [bool]$Default = $false
    )

    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($value)) {
        return $Default
    }

    return @("1", "true", "yes", "on") -contains $value.Trim().ToLowerInvariant()
}

$script:UsbScanningEnabled = Get-EnvFlag -Name "ENABLE_USB_SCANNING" -Default $true

function Get-PlatformLabel {
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop | Select-Object -First 1 Caption, Version
        if ($os -and $os.Caption) {
            return "$($os.Caption.Trim()) $($os.Version)"
        }
    } catch {
    }

    if ($PSVersionTable.OS) {
        return $PSVersionTable.OS
    }

    return "Windows"
}

function Test-IsAdministrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Resolve-MonitoredPaths {
    param([string[]]$ConfiguredPaths)

    $candidates = @()
    if ($ConfiguredPaths -and $ConfiguredPaths.Count -gt 0) {
        $candidates += $ConfiguredPaths
    } else {
        $userProfile = $env:USERPROFILE
        foreach ($name in @("Desktop", "Documents", "Downloads")) {
            $candidate = Join-Path $userProfile $name
            if (Test-Path -LiteralPath $candidate) {
                $candidates += $candidate
            }
        }

        $oneDriveRoot = Join-Path $userProfile "OneDrive"
        foreach ($name in @("Desktop", "Documents", "Downloads")) {
            $candidate = Join-Path $oneDriveRoot $name
            if (Test-Path -LiteralPath $candidate) {
                $candidates += $candidate
            }
        }
    }

    $resolved = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    foreach ($path in $candidates) {
        if ([string]::IsNullOrWhiteSpace($path)) {
            continue
        }

        try {
            $resolvedPath = (Resolve-Path -LiteralPath $path -ErrorAction Stop).Path
            $key = $resolvedPath.ToLowerInvariant()
            if (-not $seen.ContainsKey($key)) {
                $seen[$key] = $true
                $resolved.Add($resolvedPath)
            }
        } catch {
        }
    }

    return @($resolved)
}

function Get-AgentToken {
    if ($script:AuthToken) {
        return $script:AuthToken
    }

    $loginBody = @{
        username = $AgentUsername
        password = $AgentPassword
    }

    try {
        $loginRes = Invoke-RestMethod `
            -Uri "$BackendUrl/api/auth/login" `
            -Method Post `
            -Body $loginBody `
            -ContentType "application/x-www-form-urlencoded"
        $script:AuthToken = $loginRes.access_token
        return $script:AuthToken
    } catch {
        try {
            $registerBody = @{
                username = $AgentUsername
                password = $AgentPassword
            } | ConvertTo-Json

            Invoke-RestMethod `
                -Uri "$BackendUrl/api/auth/register" `
                -Method Post `
                -Body $registerBody `
                -ContentType "application/json" | Out-Null
        } catch {
        }

        try {
            $loginRes = Invoke-RestMethod `
                -Uri "$BackendUrl/api/auth/login" `
                -Method Post `
                -Body $loginBody `
                -ContentType "application/x-www-form-urlencoded"
            $script:AuthToken = $loginRes.access_token
            return $script:AuthToken
        } catch {
            Write-Host "Failed to authenticate host monitor with backend."
            return $null
        }
    }
}

function Test-EventCooldown {
    param(
        [string]$Key,
        [int]$CooldownSeconds
    )

    $now = Get-Date
    if ($script:LastEventAt.ContainsKey($Key)) {
        $elapsed = ($now - $script:LastEventAt[$Key]).TotalSeconds
        if ($elapsed -lt $CooldownSeconds) {
            return $false
        }
    }

    $script:LastEventAt[$Key] = $now
    return $true
}

function Test-IgnoredPath {
    param([string]$FullPath)

    $normalizedPath = $FullPath.ToLowerInvariant()
    foreach ($ignored in $ignoredDirNames) {
        $needle = "\" + $ignored.ToLowerInvariant() + "\"
        if ($normalizedPath.Contains($needle)) {
            return $true
        }
    }

    return $false
}

function Get-RiskLevelFromScore {
    param([double]$Score)

    if ($Score -le 30) {
        return "Normal"
    }
    if ($Score -le 70) {
        return "Suspicious"
    }
    return "Dangerous"
}

function Get-RecommendedActionFromScore {
    param([double]$Score)

    if ($Score -le 30) {
        return "allow"
    }
    if ($Score -le 70) {
        return "monitor"
    }
    return "block"
}

function Get-IpScope {
    param([string]$RemoteIp)

    if ([string]::IsNullOrWhiteSpace($RemoteIp)) {
        return @{
            scope = "unknown"
            is_trusted = $true
        }
    }

    try {
        $ipAddress = [System.Net.IPAddress]::Parse($RemoteIp)
    } catch {
        return @{
            scope = "unknown"
            is_trusted = $true
        }
    }

    if ([System.Net.IPAddress]::IsLoopback($ipAddress)) {
        return @{
            scope = "loopback"
            is_trusted = $true
        }
    }

    if ($ipAddress.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        $bytes = $ipAddress.GetAddressBytes()
        if ($bytes[0] -eq 10) {
            return @{ scope = "private"; is_trusted = $true }
        }
        if ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) {
            return @{ scope = "private"; is_trusted = $true }
        }
        if ($bytes[0] -eq 192 -and $bytes[1] -eq 168) {
            return @{ scope = "private"; is_trusted = $true }
        }
        if ($bytes[0] -eq 169 -and $bytes[1] -eq 254) {
            return @{ scope = "link_local"; is_trusted = $true }
        }
        return @{ scope = "public"; is_trusted = $false }
    }

    if ($ipAddress.IsIPv6LinkLocal) {
        return @{ scope = "link_local"; is_trusted = $true }
    }
    if ($ipAddress.IsIPv6SiteLocal) {
        return @{ scope = "private"; is_trusted = $true }
    }

    $normalizedIp = $RemoteIp.ToLowerInvariant()
    if ($normalizedIp.StartsWith("fc") -or $normalizedIp.StartsWith("fd")) {
        return @{ scope = "private"; is_trusted = $true }
    }

    return @{ scope = "public"; is_trusted = $false }
}

function Register-ProcessRemoteIp {
    param(
        [string]$ProcessKey,
        [string]$RemoteIp
    )

    if ([string]::IsNullOrWhiteSpace($ProcessKey) -or [string]::IsNullOrWhiteSpace($RemoteIp)) {
        return $false
    }

    if (-not $script:KnownRemoteIpsByProcess.ContainsKey($ProcessKey)) {
        $script:KnownRemoteIpsByProcess[$ProcessKey] = @{}
    }

    $isNewRemote = -not $script:KnownRemoteIpsByProcess[$ProcessKey].ContainsKey($RemoteIp)
    $script:KnownRemoteIpsByProcess[$ProcessKey][$RemoteIp] = $true
    return $isNewRemote
}

function Ensure-BlockedRemoteIp {
    param(
        [string]$RemoteIp,
        [string]$ProcessName,
        [int]$RemotePort,
        [string]$Reason
    )

    if (-not $script:ConnectionBlockingEnabled -or [string]::IsNullOrWhiteSpace($RemoteIp)) {
        return $false
    }

    if ($script:BlockedRemoteIps.ContainsKey($RemoteIp)) {
        return $true
    }

    $ruleName = "AI Firewall Auto Block $RemoteIp"
    try {
        $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if (-not $existingRule) {
            New-NetFirewallRule `
                -DisplayName $ruleName `
                -Direction Outbound `
                -Action Block `
                -RemoteAddress $RemoteIp `
                -Profile Any `
                -Description "Blocked by AI Firewall because $ProcessName contacted $RemoteIp`:$RemotePort ($Reason)" | Out-Null
        }

        $script:BlockedRemoteIps[$RemoteIp] = @{
            blocked_at = (Get-Date).ToUniversalTime().ToString("o")
            process = $ProcessName
            remote_port = $RemotePort
            reason = $Reason
        }
        return $true
    } catch {
        return $false
    }
}

function New-NetworkAnalysis {
    param(
        [string]$ProcessName,
        [string]$RemoteIp,
        [int]$RemotePort
    )

    $processKey = ($ProcessName | ForEach-Object { $_.ToLowerInvariant() })
    $scopeInfo = Get-IpScope -RemoteIp $RemoteIp
    $isNewRemote = Register-ProcessRemoteIp -ProcessKey $processKey -RemoteIp $RemoteIp
    $knownRemoteCount = if ($script:KnownRemoteIpsByProcess.ContainsKey($processKey)) { $script:KnownRemoteIpsByProcess[$processKey].Keys.Count } else { 0 }

    $score = 0.0
    $reasons = New-Object System.Collections.Generic.List[string]
    $highRiskPorts = @(21, 23, 25, 135, 139, 445, 3389, 4444, 5555, 5985, 5986, 6667)
    $safePorts = @(53, 80, 123, 443)
    $suspiciousProcesses = @("bitsadmin", "certutil", "cmd", "cscript", "mshta", "powershell", "python", "regsvr32", "rundll32", "wscript", "wmic")

    if (-not $scopeInfo.is_trusted -and $scopeInfo.scope -eq "public") {
        $score += 18
        $reasons.Add("it targets a public remote IP outside the local network")
    }
    if ($isNewRemote -and -not $scopeInfo.is_trusted) {
        $score += 18
        $reasons.Add("the process connected to a remote IP that has not been seen before")
    }
    if ($RemotePort -gt 0 -and ($safePorts -notcontains $RemotePort)) {
        $score += 10
        $reasons.Add("it uses a non-standard outbound port")
    }
    if ($highRiskPorts -contains $RemotePort) {
        $score += 22
        $reasons.Add("it uses a high-risk outbound port")
    }
    if ($suspiciousProcesses -contains $processKey) {
        $score += 28
        $reasons.Add("the connection originated from a scripting or administrative process")
    }
    if (-not $scopeInfo.is_trusted -and $knownRemoteCount -ge 8) {
        $score += 12
        $reasons.Add("the process is spreading traffic across many different remote IPs")
    }

    $riskScore = [Math]::Min(100, [Math]::Round($score, 2))
    $riskLevel = Get-RiskLevelFromScore -Score $riskScore
    $recommendedAction = Get-RecommendedActionFromScore -Score $riskScore
    $blocked = $false
    $blockReason = $null

    if ($script:ConnectionBlockingEnabled -and -not $scopeInfo.is_trusted -and $riskScore -ge $AutoBlockThreshold) {
        $blockReason = if ($reasons.Count -gt 0) { ($reasons | Select-Object -First 2) -join ", " } else { "outbound policy threshold exceeded" }
        $blocked = Ensure-BlockedRemoteIp -RemoteIp $RemoteIp -ProcessName $ProcessName -RemotePort $RemotePort -Reason $blockReason
    }

    return @{
        risk_score = $riskScore
        risk_level = $riskLevel
        recommended_action = $recommendedAction
        ip_scope = $scopeInfo.scope
        public_ip = (-not $scopeInfo.is_trusted -and $scopeInfo.scope -eq "public")
        is_new_remote = $isNewRemote
        reasons = @($reasons | Select-Object -First 3)
        blocked = $blocked
        block_reason = $blockReason
    }
}

function New-NetworkSecurityEvent {
    param(
        [string]$ActionType,
        [hashtable]$Connection
    )

    $leadingReason = if ($Connection.reasons.Count -gt 0) { $Connection.reasons[0] } else { "the outbound policy threshold was exceeded" }
    return @{
        action_type = $ActionType
        device = $env:COMPUTERNAME
        network_activity = [double]$Connection.risk_score
        details = "$($Connection.risk_level) outbound connection: $($Connection.process) -> $($Connection.remote_ip):$($Connection.remote_port) because $leadingReason"
        behavior_context = @{
            applications = @(
                @{
                    name = $Connection.process
                    source = $ActionType
                }
            )
        }
    }
}

function Get-ProcessTelemetry {
    $errors = New-Object System.Collections.Generic.List[string]
    $topProcesses = @()
    $inventory = @()

    try {
        $topProcesses = @(
            Get-Process -ErrorAction Stop |
                Sort-Object -Property CPU -Descending |
                Select-Object -First 12 `
                    Id,
                    ProcessName,
                    @{Name = "CPU"; Expression = { if ($_.CPU) { [Math]::Round($_.CPU, 2) } else { 0 } }},
                    @{Name = "MemoryMB"; Expression = { [Math]::Round($_.WorkingSet64 / 1MB, 2) }},
                    Path
        )
    } catch {
        $errors.Add($_.Exception.Message)
    }

    try {
        $inventory = @(Get-Process -ErrorAction Stop | Select-Object Id, ProcessName)
    } catch {
        $errors.Add($_.Exception.Message)
    }

    $processIndex = @{}
    $normalizedTop = @()
    $allProcessIds = New-Object System.Collections.Generic.List[int]

    foreach ($item in $topProcesses) {
        if ($null -eq $item.Id) {
            continue
        }

        $processId = [int]$item.Id
        $processIndex[$processId] = $item.ProcessName
        $normalizedTop += @{
            pid = $processId
            name = $item.ProcessName
            cpu = [double]$item.CPU
            memory_mb = [double]$item.MemoryMB
            path = if ($item.Path) { $item.Path } else { "" }
        }
    }

    foreach ($item in $inventory) {
        if ($null -eq $item.Id) {
            continue
        }

        $processId = [int]$item.Id
        $allProcessIds.Add($processId)
        if (-not $processIndex.ContainsKey($processId)) {
            $processIndex[$processId] = $item.ProcessName
        }
    }

    $hadPreviousProcesses = $script:KnownProcessIds.Count -gt 0
    $uniqueProcessIds = @($allProcessIds | Select-Object -Unique)
    $newProcessIds = @(
        $uniqueProcessIds |
            Where-Object { -not $script:KnownProcessIds.ContainsKey([string]$_) } |
            Sort-Object
    )

    $script:KnownProcessIds = @{}
    foreach ($processId in $uniqueProcessIds) {
        $script:KnownProcessIds[[string]$processId] = $true
    }

    $events = @()
    if ($hadPreviousProcesses) {
        foreach ($processId in @($newProcessIds | Select-Object -First 5)) {
            $processName = if ($processIndex.ContainsKey($processId)) { $processIndex[$processId] } else { "unknown" }
            $events += @{
                action_type = "process_start"
                device = $env:COMPUTERNAME
                network_activity = 0.0
                details = "New process detected: $processName (PID $processId)"
                behavior_context = @{
                    applications = @(
                        @{
                            name = $processName
                            source = "process_start"
                        }
                    )
                }
            }
        }
    }

    return @{
        summary = @{
            count = $uniqueProcessIds.Count
            new_since_last_scan = $newProcessIds.Count
            top = $normalizedTop
            index = $processIndex
            errors = @($errors)
        }
        events = $events
    }
}

function Get-UsbTelemetry {
    if (-not $script:UsbScanningEnabled) {
        return @{
            summary = @{
                enabled = $false
                connected_count = 0
                recent_insertions = @()
                devices = @()
                errors = @()
            }
            events = @()
        }
    }

    $errors = New-Object System.Collections.Generic.List[string]
    $devices = @()
    $currentIds = @{}

    try {
        $volumes = @(
            Get-CimInstance Win32_LogicalDisk -ErrorAction Stop |
                Where-Object { $_.DriveType -eq 2 } |
                Select-Object DeviceID, VolumeName, Size, FreeSpace
        )

        foreach ($item in $volumes) {
            if (-not $item.DeviceID) {
                continue
            }

            $instanceId = "$($item.DeviceID)\"
            $currentIds[$instanceId] = $true

            $label = if ($item.VolumeName) { "$($item.DeviceID) ($($item.VolumeName))" } else { $item.DeviceID }
            $devices += @{
                name = $label
                instance_id = $instanceId
                status = "Online"
                class = "RemovableDrive"
                size_gb = if ($item.Size) { [Math]::Round(([double]$item.Size / 1GB), 2) } else { 0.0 }
                free_gb = if ($item.FreeSpace) { [Math]::Round(([double]$item.FreeSpace / 1GB), 2) } else { 0.0 }
            }
        }
    } catch {
        $errors.Add($_.Exception.Message)
    }

    $insertedIds = @()
    foreach ($instanceId in $currentIds.Keys) {
        if (-not $script:KnownUsbIds.ContainsKey($instanceId)) {
            $insertedIds += $instanceId
        }
    }

    $script:KnownUsbIds = @{}
    foreach ($instanceId in $currentIds.Keys) {
        $script:KnownUsbIds[$instanceId] = $true
    }

    $insertions = @($devices | Where-Object { $insertedIds -contains $_.instance_id } | Select-Object -First 5)

    $events = @()
    foreach ($device in $insertions) {
        $events += @{
            action_type = "usb_insertion"
            device = $device.name
            network_activity = 0.0
            details = "USB device inserted: $($device.name)"
        }
    }

    return @{
        summary = @{
            enabled = $true
            connected_count = $devices.Count
            recent_insertions = $insertions
            devices = $devices
            errors = @($errors)
        }
        events = $events
    }
}

function Get-FileTelemetry {
    $errors = New-Object System.Collections.Generic.List[string]
    $recentChanges = New-Object System.Collections.Generic.List[hashtable]
    $nextState = @{}
    $nowUtc = [DateTime]::UtcNow

    foreach ($root in $script:MonitorRoots) {
        try {
            $items = Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                if (Test-IgnoredPath -FullPath $item.FullName) {
                    continue
                }

                $fullPath = $item.FullName
                $modifiedUtc = $item.LastWriteTimeUtc
                $modifiedTicks = $modifiedUtc.Ticks
                $nextState[$fullPath] = $modifiedTicks

                if (-not $script:FileState.ContainsKey($fullPath)) {
                    continue
                }

                if ($modifiedTicks -gt $script:FileState[$fullPath] -and ($nowUtc - $modifiedUtc).TotalSeconds -le $FileWindowSeconds) {
                    $recentChanges.Add(@{
                        path = $fullPath
                        modified_at = $modifiedUtc.ToString("o")
                        size_kb = [Math]::Round(($item.Length / 1KB), 2)
                    })
                }
            }
        } catch {
            $errors.Add("File scan failed for ${root}: $($_.Exception.Message)")
        }
    }

    $script:FileState = $nextState
    $recentChanges = @($recentChanges | Sort-Object { $_.modified_at } -Descending | Select-Object -First 20)

    $events = @()
    if ($recentChanges.Count -gt 0 -and (Test-EventCooldown -Key "file_access" -CooldownSeconds 15)) {
        $samplePaths = @($recentChanges | Select-Object -First 3 | ForEach-Object { [System.IO.Path]::GetFileName($_.path) }) -join ", "
        $events += @{
            action_type = "file_access"
            device = $env:COMPUTERNAME
            network_activity = 0.0
            details = "Detected $($recentChanges.Count) file changes. Sample: $samplePaths"
            behavior_context = @{
                files = @(
                    $recentChanges | Select-Object -First 10 | ForEach-Object {
                        @{
                            path = $_.path
                            directory = [System.IO.Path]::GetDirectoryName($_.path)
                            extension = if ([System.IO.Path]::GetExtension($_.path)) { [System.IO.Path]::GetExtension($_.path).ToLowerInvariant() } else { "[no extension]" }
                        }
                    }
                )
            }
        }
    }

    return @{
        summary = @{
            changed_count = $recentChanges.Count
            recent = $recentChanges
            watched_paths = $script:MonitorRoots
            errors = @($errors)
        }
        events = $events
    }
}

function Get-NetworkTelemetry {
    param([hashtable]$ProcessIndex)

    $errors = New-Object System.Collections.Generic.List[string]
    $connections = @()
    $suspiciousConnections = New-Object System.Collections.Generic.List[hashtable]
    $blockedConnections = New-Object System.Collections.Generic.List[hashtable]
    $remoteIps = @{}
    $processCounters = @{}
    $trackedIpIndex = @{}

    try {
        $tcpConnections = @(
            Get-NetTCPConnection -State Established -ErrorAction Stop |
                Select-Object -First 40 LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess
        )

        foreach ($item in $tcpConnections) {
            $owningProcess = if ($null -ne $item.OwningProcess) { [int]$item.OwningProcess } else { $null }
            $processName = if ($owningProcess -and $ProcessIndex.ContainsKey($owningProcess)) { $ProcessIndex[$owningProcess] } elseif ($owningProcess) { "PID $owningProcess" } else { "Unknown" }
            $remoteAddress = if ($item.RemoteAddress) { $item.RemoteAddress } else { "" }
            $remotePort = if ($null -ne $item.RemotePort) { [int]$item.RemotePort } else { 0 }
            if ($remoteAddress) {
                $remoteIps[$remoteAddress] = $true
            }

            if (-not $processCounters.ContainsKey($processName)) {
                $processCounters[$processName] = 0
            }
            $processCounters[$processName] += 1

            $analysis = New-NetworkAnalysis -ProcessName $processName -RemoteIp $remoteAddress -RemotePort $remotePort
            $connection = @{
                process = $processName
                pid = $owningProcess
                local = "$($item.LocalAddress):$($item.LocalPort)"
                remote = "$remoteAddress`:$($item.RemotePort)"
                local_address = if ($item.LocalAddress) { $item.LocalAddress } else { "" }
                local_port = if ($null -ne $item.LocalPort) { [int]$item.LocalPort } else { 0 }
                remote_ip = $remoteAddress
                remote_port = $remotePort
                ip_scope = $analysis.ip_scope
                public_ip = $analysis.public_ip
                is_new_remote = $analysis.is_new_remote
                risk_score = [double]$analysis.risk_score
                risk_level = $analysis.risk_level
                recommended_action = $analysis.recommended_action
                blocked = [bool]$analysis.blocked
                reasons = @($analysis.reasons)
                direction = "outbound"
            }
            $connections += $connection

            if ($remoteAddress) {
                if (-not $trackedIpIndex.ContainsKey($remoteAddress)) {
                    $trackedIpIndex[$remoteAddress] = @{
                        ip = $remoteAddress
                        scope = $analysis.ip_scope
                        count = 0
                        highest_risk_score = 0.0
                        highest_risk_level = "Normal"
                        processes = @{}
                    }
                }

                $trackedIpIndex[$remoteAddress].count += 1
                if ([double]$analysis.risk_score -gt [double]$trackedIpIndex[$remoteAddress].highest_risk_score) {
                    $trackedIpIndex[$remoteAddress].highest_risk_score = [double]$analysis.risk_score
                    $trackedIpIndex[$remoteAddress].highest_risk_level = $analysis.risk_level
                }
                $trackedIpIndex[$remoteAddress].processes[$processName] = $true
            }

            if ([double]$analysis.risk_score -gt 30) {
                $suspiciousConnections.Add($connection)
            }
            if ($analysis.blocked) {
                $blockedConnections.Add($connection)
            }
        }
    } catch {
        $errors.Add($_.Exception.Message)
    }

    $topProcesses = @(
        $processCounters.GetEnumerator() |
            Sort-Object -Property Value -Descending |
            Select-Object -First 5 |
            ForEach-Object {
                @{
                    name = $_.Key
                    connections = $_.Value
                }
            }
    )

    $trackedIps = @(
        $trackedIpIndex.GetEnumerator() |
            Sort-Object `
                @{ Expression = { [double]$_.Value.highest_risk_score }; Descending = $true }, `
                @{ Expression = { [int]$_.Value.count }; Descending = $true } |
            ForEach-Object {
                @{
                    ip = $_.Value.ip
                    scope = $_.Value.scope
                    count = $_.Value.count
                    highest_risk_score = [Math]::Round([double]$_.Value.highest_risk_score, 2)
                    highest_risk_level = $_.Value.highest_risk_level
                    processes = @($_.Value.processes.Keys | Sort-Object | Select-Object -First 5)
                }
            }
    )

    $sortedSuspicious = @($suspiciousConnections | Sort-Object -Property risk_score -Descending)
    $sortedBlocked = @($blockedConnections | Sort-Object -Property risk_score -Descending)

    $events = @()
    if ($connections.Count -ge 12 -and (Test-EventCooldown -Key "network_spike" -CooldownSeconds 30)) {
        $events += @{
            action_type = "network_spike"
            device = $env:COMPUTERNAME
            network_activity = [double]$connections.Count
            details = "Detected $($connections.Count) established TCP connections across $($remoteIps.Keys.Count) remote IPs"
        }
    }
    if ($sortedSuspicious.Count -gt 0 -and (Test-EventCooldown -Key "network_connection_suspicious" -CooldownSeconds 20)) {
        foreach ($connection in @($sortedSuspicious | Select-Object -First 3)) {
            $events += New-NetworkSecurityEvent -ActionType "network_connection_suspicious" -Connection $connection
        }
    }
    if ($sortedBlocked.Count -gt 0 -and (Test-EventCooldown -Key "network_connection_blocked" -CooldownSeconds 20)) {
        foreach ($connection in @($sortedBlocked | Select-Object -First 3)) {
            $events += New-NetworkSecurityEvent -ActionType "network_connection_blocked" -Connection $connection
        }
    }

    return @{
        summary = @{
            connection_count = $connections.Count
            unique_remote_ips = $remoteIps.Keys.Count
            tracked_ip_count = $trackedIps.Count
            top_processes = $topProcesses
            tracked_ips = @($trackedIps | Select-Object -First 12)
            connections = @($connections | Select-Object -First 12)
            suspicious_connections = @($sortedSuspicious | Select-Object -First 8)
            blocked_connections = @($sortedBlocked | Select-Object -First 8)
            auto_block_enabled = $script:ConnectionBlockingEnabled
            block_threshold = $AutoBlockThreshold
            errors = @($errors)
        }
        events = $events
    }
}

function Send-MonitorSnapshot {
    param(
        [hashtable]$Snapshot,
        [array]$Events
    )

    $token = Get-AgentToken
    if (-not $token) {
        return $false
    }

    $headers = @{
        Authorization = "Bearer $token"
        "Content-Type" = "application/json"
    }
    $body = @{
        snapshot = $Snapshot
        events = @($Events)
    } | ConvertTo-Json -Depth 8

    try {
        Invoke-RestMethod `
            -Uri "$BackendUrl/api/system-monitor/ingest" `
            -Method Post `
            -Headers $headers `
            -Body $body | Out-Null
        return $true
    } catch {
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode.value__ -eq 401) {
            $script:AuthToken = $null
        }
        Write-Host "Failed to send system monitor snapshot to backend."
        return $false
    }
}

function Invoke-MonitorCycle {
    try {
        $processTelemetry = Get-ProcessTelemetry
        $usbTelemetry = Get-UsbTelemetry
        $fileTelemetry = Get-FileTelemetry
        $networkTelemetry = Get-NetworkTelemetry -ProcessIndex $processTelemetry.summary.index

        $snapshot = @{
            timestamp = [DateTime]::UtcNow.ToString("o")
            status = "running"
            collector = "windows-host-agent"
            scope = "host"
            host = $env:COMPUTERNAME
            platform = Get-PlatformLabel
            poll_interval_seconds = $PollSeconds
            monitored_paths = $script:MonitorRoots
            processes = @{
                count = $processTelemetry.summary.count
                new_since_last_scan = $processTelemetry.summary.new_since_last_scan
                top = $processTelemetry.summary.top
            }
            files = @{
                changed_count = $fileTelemetry.summary.changed_count
                recent = $fileTelemetry.summary.recent
            }
            usb = @{
                enabled = [bool]$usbTelemetry.summary.enabled
                connected_count = $usbTelemetry.summary.connected_count
                recent_insertions = $usbTelemetry.summary.recent_insertions
                devices = $usbTelemetry.summary.devices
            }
            network = @{
                connection_count = $networkTelemetry.summary.connection_count
                unique_remote_ips = $networkTelemetry.summary.unique_remote_ips
                tracked_ip_count = $networkTelemetry.summary.tracked_ip_count
                top_processes = $networkTelemetry.summary.top_processes
                tracked_ips = $networkTelemetry.summary.tracked_ips
                connections = $networkTelemetry.summary.connections
                suspicious_connections = $networkTelemetry.summary.suspicious_connections
                blocked_connections = $networkTelemetry.summary.blocked_connections
                auto_block_enabled = $networkTelemetry.summary.auto_block_enabled
                block_threshold = $networkTelemetry.summary.block_threshold
            }
            errors = @(
                $processTelemetry.summary.errors +
                $usbTelemetry.summary.errors +
                $fileTelemetry.summary.errors +
                $networkTelemetry.summary.errors
            )
        }

        $events = @(
            $processTelemetry.events +
            $usbTelemetry.events +
            $fileTelemetry.events +
            $networkTelemetry.events
        )

        Send-MonitorSnapshot -Snapshot $snapshot -Events $events | Out-Null
    } catch {
        $snapshot = @{
            timestamp = [DateTime]::UtcNow.ToString("o")
            status = "degraded"
            collector = "windows-host-agent"
            scope = "host"
            host = $env:COMPUTERNAME
            platform = Get-PlatformLabel
            poll_interval_seconds = $PollSeconds
            monitored_paths = $script:MonitorRoots
            processes = @{ count = 0; new_since_last_scan = 0; top = @() }
            files = @{ changed_count = 0; recent = @() }
            usb = @{ enabled = [bool]$script:UsbScanningEnabled; connected_count = 0; recent_insertions = @(); devices = @() }
            network = @{
                connection_count = 0
                unique_remote_ips = 0
                tracked_ip_count = 0
                top_processes = @()
                tracked_ips = @()
                connections = @()
                suspicious_connections = @()
                blocked_connections = @()
                auto_block_enabled = $script:ConnectionBlockingEnabled
                block_threshold = $AutoBlockThreshold
            }
            errors = @($_.Exception.Message)
        }

        Send-MonitorSnapshot -Snapshot $snapshot -Events @() | Out-Null
    }
}

$mutex = New-Object System.Threading.Mutex($false, "Global\AIFirewallHostSystemMonitor")
$mutexAcquired = $false

try {
    $mutexAcquired = $mutex.WaitOne(0, $false)
    if (-not $mutexAcquired) {
        Write-Host "AI Firewall host monitor is already running."
        exit 0
    }

    $script:MonitorRoots = Resolve-MonitoredPaths -ConfiguredPaths $MonitoredPaths
    $script:ConnectionBlockingEnabled = (-not $DisableConnectionBlocking)
    if ($script:ConnectionBlockingEnabled -and -not (Test-IsAdministrator)) {
        $script:ConnectionBlockingEnabled = $false
        Write-Host "Connection blocking disabled because this PowerShell session is not running as Administrator."
    }

    Write-Host "AI Firewall Windows Host Monitor Active. Version: $monitorVersion"
    Write-Host "Streaming host telemetry to $BackendUrl/api/system-monitor/ingest"
    Write-Host "Outbound connection blocking: $(if ($script:ConnectionBlockingEnabled) { "Enabled (threshold $AutoBlockThreshold)" } else { 'Monitor only' })"
    if ($script:MonitorRoots.Count -gt 0) {
        Write-Host "Watching paths: $($script:MonitorRoots -join ', ')"
    } else {
        Write-Host "No watched paths resolved. File telemetry will stay empty until you pass -MonitoredPaths."
    }
    Write-Host "Press Ctrl+C to stop."

    do {
        Invoke-MonitorCycle
        if ($RunOnce) {
            break
        }
        Start-Sleep -Seconds $PollSeconds
    } while ($true)
} finally {
    if ($mutexAcquired) {
        $mutex.ReleaseMutex() | Out-Null
    }
    $mutex.Dispose()
}
