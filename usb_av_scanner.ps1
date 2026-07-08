param(
    [string]$BackendUrl = "http://localhost:8000",
    [string]$AgentUsername = "usb-security-agent",
    [string]$AgentPassword = "UsbSecurity!2026",
    [string]$QuarantineRoot = "$env:ProgramData\AIFirewall\Quarantine",
    [string]$SignatureDbPath = "",
    [int]$PollSeconds = 2,
    [string]$TestDrivePath = "",
    [switch]$DisableUi,
    [switch]$StrictMode
)

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

$usbScanningEnabled = Get-EnvFlag -Name "ENABLE_USB_SCANNING" -Default $true
if (-not $usbScanningEnabled) {
    Write-Host "AI Firewall USB scanning is disabled (ENABLE_USB_SCANNING=false). Exiting without monitoring or scanning."
    exit 0
}

$scannerVersion = "2026.03.19.5"
$scriptExtensions = @(
    ".bat", ".cmd", ".com", ".hta", ".js", ".jse", ".lnk",
    ".ps1", ".pif", ".reg", ".scr", ".vbe", ".vbs", ".wsf"
)
$binaryExtensions = @(".dll", ".exe", ".msi")
$signedExecutableExtensions = @(".exe", ".msi")
$contentInspectionExtensions = @(
    ".bat", ".cmd", ".com", ".docm", ".hta", ".inf", ".js", ".jse",
    ".ps1", ".reg", ".scr", ".txt", ".vbe", ".vbs", ".wsf", ".xlsm", ".pptm"
)
$macroExtensions = @(".docm", ".xlsm", ".pptm")
$doubleExtensionPattern = '\.(pdf|doc|docx|xls|xlsx|ppt|pptx|jpg|jpeg|png|gif|txt|zip)\.(exe|bat|cmd|scr|js|vbs|ps1)$'
$suspiciousNamePattern = '(autorun|backdoor|crack|dropper|keygen|loader|payload|ransom|stealer|trojan)'
$eicarSignature = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
$global:UsbSecurityAgentToken = $null
$global:MalwareSignatureIndex = @{}
$global:DriveSnapshots = @{}
$global:DriveLastScanAt = @{}
$rescanCooldownSeconds = [Math]::Max(6, $PollSeconds * 2)

if ([string]::IsNullOrWhiteSpace($SignatureDbPath)) {
    $SignatureDbPath = Join-Path $PSScriptRoot "security\malware_signatures.json"
}

function Ensure-Directory {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Initialize-SignatureDatabase {
    $global:MalwareSignatureIndex = @{}

    if (-not (Test-Path -LiteralPath $SignatureDbPath)) {
        Write-Host "Signature database not found at $SignatureDbPath"
        return
    }

    try {
        $entries = Get-Content -LiteralPath $SignatureDbPath -Raw | ConvertFrom-Json
        foreach ($entry in @($entries)) {
            if (-not $entry.sha256) {
                continue
            }

            $hashKey = $entry.sha256.ToUpperInvariant()
            $global:MalwareSignatureIndex[$hashKey] = $entry
        }

        Write-Host "Loaded $($global:MalwareSignatureIndex.Count) file intelligence signatures."
    } catch {
        Write-Host "Failed to load signature database from $SignatureDbPath"
    }
}

function Get-AgentToken {
    if ($global:UsbSecurityAgentToken) {
        return $global:UsbSecurityAgentToken
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
        $global:UsbSecurityAgentToken = $loginRes.access_token
        return $global:UsbSecurityAgentToken
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
            # Ignore register failures if the user already exists.
        }

        try {
            $loginRes = Invoke-RestMethod `
                -Uri "$BackendUrl/api/auth/login" `
                -Method Post `
                -Body $loginBody `
                -ContentType "application/x-www-form-urlencoded"
            $global:UsbSecurityAgentToken = $loginRes.access_token
            return $global:UsbSecurityAgentToken
        } catch {
            Write-Host "Failed to authenticate with AI Firewall backend."
            return $null
        }
    }
}

function Invoke-BackendLog {
    param(
        [string]$ActionType,
        [string]$Details,
        [double]$NetworkActivity = 0.0,
        [string]$Device = $env:COMPUTERNAME
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
        action_type = $ActionType
        device = $Device
        network_activity = $NetworkActivity
        details = $Details
    } | ConvertTo-Json

    try {
        Invoke-RestMethod `
            -Uri "$BackendUrl/api/activity/log" `
            -Method Post `
            -Headers $headers `
            -Body $body | Out-Null
        return $true
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 401) {
            $global:UsbSecurityAgentToken = $null
        }
        Write-Host "Failed to send $ActionType event to backend."
        return $false
    }
}

function Write-StatusWindowState {
    param(
        $Ui,
        [hashtable]$State
    )

    if (-not $Ui -or -not $Ui.StatusFilePath) {
        return
    }

    try {
        $payload = $State | ConvertTo-Json -Depth 5
        $tempPath = "$($Ui.StatusFilePath).tmp"
        Set-Content -LiteralPath $tempPath -Value $payload -Encoding UTF8
        Move-Item -LiteralPath $tempPath -Destination $Ui.StatusFilePath -Force
    } catch {
        # Ignore popup write failures so the scanner keeps running.
    }
}

function New-StatusWindow {
    param([string]$DriveName)

    if ($DisableUi) {
        return $null
    }

    $popupScriptPath = Join-Path $PSScriptRoot "usb_scan_popup.ps1"
    if (-not (Test-Path -LiteralPath $popupScriptPath)) {
        Write-Host "Popup helper not found; continuing in console mode."
        return $null
    }

    $statusFilePath = Join-Path $env:TEMP ("aifirewall-usb-status-" + [Guid]::NewGuid().ToString("N") + ".json")
    $ui = @{
        DriveName = $DriveName
        StatusFilePath = $statusFilePath
    }

    Write-StatusWindowState -Ui $ui -State @{
        drive_name = $DriveName
        title_text = "[ USB SECURITY SCAN ($DriveName) ]"
        current_text = "Initializing USB security module..."
        stats_text = "Preparing scan..."
        status_text = "Awaiting analysis results..."
        progress_mode = "marquee"
        current_value = 0
        maximum_value = 0
        threat_found = $false
        state = "running"
        close_after_seconds = 8
    }

    try {
        Start-Process `
            -FilePath "powershell.exe" `
            -ArgumentList @(
                "-Sta",
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-File", "`"$popupScriptPath`"",
                "-StatusFilePath", "`"$statusFilePath`""
            ) `
            -WindowStyle Hidden | Out-Null
    } catch {
        Write-Host "Failed to start popup helper; continuing in console mode."
        return $null
    }

    return $ui
}

function Update-StatusWindow {
    param(
        $Ui,
        [string]$CurrentText,
        [string]$StatsText,
        [string]$StatusText,
        [int]$CurrentValue,
        [int]$MaximumValue
    )

    if (-not $Ui) {
        return
    }

    $progressMode = if ($MaximumValue -gt 0) { "determinate" } else { "marquee" }
    Write-StatusWindowState -Ui $Ui -State @{
        drive_name = $Ui.DriveName
        title_text = "[ USB SECURITY SCAN ($($Ui.DriveName)) ]"
        current_text = $CurrentText
        stats_text = $StatsText
        status_text = $StatusText
        progress_mode = $progressMode
        current_value = $CurrentValue
        maximum_value = $MaximumValue
        threat_found = $false
        state = "running"
        close_after_seconds = 8
    }
}

function Invoke-UiHeartbeat {
    param($Ui)

    if (-not $Ui) {
        return
    }

    Write-StatusWindowState -Ui $Ui -State @{
        drive_name = $Ui.DriveName
        title_text = "[ USB SECURITY SCAN ($($Ui.DriveName)) ]"
        current_text = $null
        stats_text = $null
        status_text = $null
        progress_mode = "heartbeat"
        current_value = 0
        maximum_value = 0
        threat_found = $false
        state = "running"
        close_after_seconds = 8
        heartbeat = (Get-Date).ToString("o")
    }
}

function Complete-StatusWindow {
    param(
        $Ui,
        [string]$TitleText,
        [string]$SummaryText,
        [string]$FooterText,
        [bool]$ThreatFound
    )

    if (-not $Ui) {
        return
    }

    Write-StatusWindowState -Ui $Ui -State @{
        drive_name = $Ui.DriveName
        title_text = $TitleText
        current_text = $SummaryText
        stats_text = ""
        status_text = $FooterText
        progress_mode = "determinate"
        current_value = 1
        maximum_value = 1
        threat_found = $ThreatFound
        state = "completed"
        close_after_seconds = 8
    }
}

function Close-StatusWindow {
    param($Ui, [int]$SecondsToDisplay = 8)

    if (-not $Ui) {
        return
    }

    Write-StatusWindowState -Ui $Ui -State @{
        drive_name = $Ui.DriveName
        title_text = $null
        current_text = $null
        stats_text = $null
        status_text = $null
        progress_mode = $null
        current_value = $null
        maximum_value = $null
        threat_found = $null
        state = "completed"
        close_after_seconds = $SecondsToDisplay
    }
}

function Get-SafeRelativePath {
    param(
        [string]$FilePath,
        [string]$RootPath
    )

    $normalizedRoot = $RootPath.TrimEnd('\')
    if ($FilePath.StartsWith($normalizedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $FilePath.Substring($normalizedRoot.Length).TrimStart('\')
    }
    return [System.IO.Path]::GetFileName($FilePath)
}

function Get-UniqueDestinationPath {
    param([string]$DesiredPath)

    if (-not (Test-Path -LiteralPath $DesiredPath)) {
        return $DesiredPath
    }

    $directory = [System.IO.Path]::GetDirectoryName($DesiredPath)
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($DesiredPath)
    $extension = [System.IO.Path]::GetExtension($DesiredPath)
    $suffix = [Guid]::NewGuid().ToString("N").Substring(0, 8)
    return (Join-Path $directory "$baseName-$suffix$extension")
}

function Block-FileInPlace {
    param([System.IO.FileInfo]$File)

    try {
        $blockedPath = Get-UniqueDestinationPath -DesiredPath ($File.FullName + ".blocked")
        Rename-Item -LiteralPath $File.FullName -NewName ([System.IO.Path]::GetFileName($blockedPath)) -ErrorAction Stop
        return @{
            Success = $true
            Path = $blockedPath
            Mode = "blocked_in_place"
        }
    } catch {
        return @{
            Success = $false
            Path = $null
            Mode = "failed"
        }
    }
}

function Get-DriveFiles {
    param(
        [string]$RootPath,
        $Ui,
        [string]$DriveLabel
    )

    $files = New-Object System.Collections.Generic.List[System.IO.FileInfo]
    $discoveredCount = 0
    $pendingDirectories = New-Object System.Collections.Generic.Stack[string]
    $pendingDirectories.Push($RootPath)

    while ($pendingDirectories.Count -gt 0) {
        $currentDirectory = $pendingDirectories.Pop()

        try {
            foreach ($childDirectory in [System.IO.Directory]::EnumerateDirectories($currentDirectory)) {
                $pendingDirectories.Push($childDirectory)
            }
        } catch {
            continue
        }

        try {
            foreach ($filePath in [System.IO.Directory]::EnumerateFiles($currentDirectory)) {
                $files.Add([System.IO.FileInfo]::new($filePath))
                $discoveredCount++

                if (($discoveredCount % 200) -eq 0) {
                    Update-StatusWindow `
                        -Ui $Ui `
                        -CurrentText "Discovering files on $DriveLabel..." `
                        -StatsText "Files discovered: $discoveredCount" `
                        -StatusText "Building the scan queue before SHA-256 analysis..." `
                        -CurrentValue 0 `
                        -MaximumValue 0
                }
            }
        } catch {
            # Ignore directories that become inaccessible during enumeration.
        }
    }

    Update-StatusWindow `
        -Ui $Ui `
        -CurrentText "Discovery complete for $DriveLabel." `
        -StatsText "Files discovered: $discoveredCount" `
        -StatusText "Starting file intelligence analysis..." `
        -CurrentValue 0 `
        -MaximumValue 0

    return @($files)
}

function Get-FileSha256 {
    param(
        [System.IO.FileInfo]$File,
        $Ui = $null
    )

    try {
        $stream = New-Object System.IO.FileStream(
            $File.FullName,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::ReadWrite
        )
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $buffer = New-Object byte[] (1024 * 1024)

        try {
            while (($bytesRead = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                [void]$sha256.TransformBlock($buffer, 0, $bytesRead, $buffer, 0)
                Invoke-UiHeartbeat -Ui $Ui
            }

            [void]$sha256.TransformFinalBlock($buffer, 0, 0)
            return ([System.BitConverter]::ToString($sha256.Hash)).Replace("-", "")
        } finally {
            $sha256.Dispose()
            $stream.Dispose()
        }
    } catch {
        return $null
    }
}

function Quarantine-File {
    param(
        [System.IO.FileInfo]$File,
        [string]$DriveRoot
    )

    try {
        $safeDriveName = (($DriveRoot.TrimEnd('\') -replace ':', '') -replace '[^a-zA-Z0-9_-]', '_')
        $relativePath = Get-SafeRelativePath -FilePath $File.FullName -RootPath $DriveRoot
        $relativeDirectory = [System.IO.Path]::GetDirectoryName($relativePath)
        $targetRoot = Join-Path $QuarantineRoot $safeDriveName
        $targetDirectory = $targetRoot

        if ($relativeDirectory) {
            $targetDirectory = Join-Path $targetRoot $relativeDirectory
        }

        Ensure-Directory -Path $targetDirectory
        $targetPath = Join-Path $targetDirectory $File.Name
        $targetPath = Get-UniqueDestinationPath -DesiredPath $targetPath

        Move-Item -LiteralPath $File.FullName -Destination $targetPath -Force -ErrorAction Stop
        return @{
            Success = $true
            Path = $targetPath
            Mode = "quarantined"
        }
    } catch {
        return (Block-FileInPlace -File $File)
    }
}

function Protect-FileByReputation {
    param(
        [System.IO.FileInfo]$File,
        [string]$DriveRoot,
        [string]$Reputation,
        [switch]$StrictMode
    )

    if ($Reputation -eq "Dangerous") {
        return (Quarantine-File -File $File -DriveRoot $DriveRoot)
    }

    if ($Reputation -eq "Suspicious") {
        if (-not $StrictMode) {
            return @{
                Success = $true
                Path = $File.FullName
                Mode = "flagged_only"
            }
        }

        $blocked = Block-FileInPlace -File $File
        if ($blocked.Success) {
            return $blocked
        }

        return (Quarantine-File -File $File -DriveRoot $DriveRoot)
    }

    return @{
        Success = $true
        Path = $File.FullName
        Mode = "allowed"
    }
}

function Get-ReputationFromScore {
    param([int]$Score)

    if ($Score -ge 8) {
        return "Dangerous"
    }

    if ($Score -ge 4) {
        return "Suspicious"
    }

    return "Safe"
}

function Get-ThreatProfile {
    param(
        $SignatureMatch,
        [string[]]$Reasons,
        [string]$Extension
    )

    if ($SignatureMatch) {
        return [PSCustomObject]@{
            ThreatCategory = "KnownMalwareSignature"
            ThreatName = [string]$SignatureMatch.name
            ThreatFamily = if ($SignatureMatch.family) { [string]$SignatureMatch.family } else { "UnknownFamily" }
            ThreatDescription = if ($SignatureMatch.description) { [string]$SignatureMatch.description } else { "Matched a known malware signature in the local SHA-256 database." }
            DetectionSource = "signature_database"
        }
    }

    if ($Reasons -contains "eicar_test_signature") {
        return [PSCustomObject]@{
            ThreatCategory = "TestMalware"
            ThreatName = "EICAR Test File"
            ThreatFamily = "TestMalware"
            ThreatDescription = "Matched the standard anti-malware EICAR test payload."
            DetectionSource = "content_heuristic"
        }
    }

    if ($Reasons -contains "autorun_file") {
        return [PSCustomObject]@{
            ThreatCategory = "AutorunAbuse"
            ThreatName = "Autorun USB Persistence"
            ThreatFamily = "USB Worm Behavior"
            ThreatDescription = "Detected an autorun-style file that can be used for USB-borne persistence or automatic execution."
            DetectionSource = "heuristic"
        }
    }

    if ($Reasons -contains "double_extension") {
        return [PSCustomObject]@{
            ThreatCategory = "DisguisedExecutable"
            ThreatName = "Double Extension Disguise"
            ThreatFamily = "Masquerading"
            ThreatDescription = "Detected a file that disguises an executable/script as a document or media file by using a double extension."
            DetectionSource = "heuristic"
        }
    }

    if ($Reasons -contains "macro_enabled_document") {
        return [PSCustomObject]@{
            ThreatCategory = "MacroEnabledDocument"
            ThreatName = "Macro-Enabled Document"
            ThreatFamily = "Document Malware"
            ThreatDescription = "Detected a macro-capable Office document that can deliver staged malware."
            DetectionSource = "heuristic"
        }
    }

    if ($Reasons -contains "tampered_signature") {
        return [PSCustomObject]@{
            ThreatCategory = "TamperedBinary"
            ThreatName = "Tampered Signed Binary"
            ThreatFamily = "Binary Integrity"
            ThreatDescription = "The file appears to have a broken or mismatched digital signature."
            DetectionSource = "signature_validation"
        }
    }

    if (($Reasons -contains "invalid_signature") -or ($Reasons -contains "untrusted_signature")) {
        return [PSCustomObject]@{
            ThreatCategory = "UntrustedBinary"
            ThreatName = "Untrusted Executable"
            ThreatFamily = "Binary Trust"
            ThreatDescription = "Detected an executable with an invalid or untrusted code signature."
            DetectionSource = "signature_validation"
        }
    }

    if (($Reasons -contains "suspicious_filename") -and ($scriptExtensions -contains $Extension)) {
        return [PSCustomObject]@{
            ThreatCategory = "SuspiciousScript"
            ThreatName = "Suspicious Script Payload"
            ThreatFamily = "Script-Based Threat"
            ThreatDescription = "Detected a script-like payload with a suspicious malware-associated name."
            DetectionSource = "heuristic"
        }
    }

    if (($Reasons -contains "hidden_or_system") -and (($scriptExtensions + $binaryExtensions) -contains $Extension)) {
        return [PSCustomObject]@{
            ThreatCategory = "HiddenPayload"
            ThreatName = "Hidden Executable Payload"
            ThreatFamily = "Stealth Delivery"
            ThreatDescription = "Detected an executable or script file marked as hidden or system."
            DetectionSource = "heuristic"
        }
    }

    if ($scriptExtensions -contains $Extension) {
        return [PSCustomObject]@{
            ThreatCategory = "ScriptArtifact"
            ThreatName = "Potentially Risky Script"
            ThreatFamily = "Script-Based Threat"
            ThreatDescription = "Detected an active script or shell payload that deserves review on removable media."
            DetectionSource = "heuristic"
        }
    }

    return [PSCustomObject]@{
        ThreatCategory = "SuspiciousArtifact"
        ThreatName = "Suspicious File Artifact"
        ThreatFamily = "Heuristic Detection"
        ThreatDescription = "Detected a file that triggered one or more security heuristics."
        DetectionSource = "heuristic"
    }
}

function Get-FileIntelligence {
    param(
        [System.IO.FileInfo]$File,
        $Ui = $null
    )

    $reasons = @()
    $score = 0
    $extension = $File.Extension.ToLowerInvariant()
    $name = $File.Name.ToLowerInvariant()
    $sha256 = Get-FileSha256 -File $File -Ui $Ui
    $signatureMatch = $null
    $isRootLevelFile = ($File.DirectoryName.TrimEnd('\') -eq [System.IO.Path]::GetPathRoot($File.FullName).TrimEnd('\'))

    if ($sha256 -and $global:MalwareSignatureIndex.ContainsKey($sha256)) {
        $signatureMatch = $global:MalwareSignatureIndex[$sha256]
        $signatureSeverity = 100
        if ($null -ne $signatureMatch.severity) {
            $signatureSeverity = [int]$signatureMatch.severity
        }
        $score = [Math]::Max($score, $signatureSeverity)
        $reasons += "sha256_match:$($signatureMatch.name)"
    }

    if ($scriptExtensions -contains $extension) {
        $score += 1
        $reasons += "script_extension:$extension"
    }

    if ($macroExtensions -contains $extension) {
        $score += 4
        $reasons += "macro_enabled_document"
    }

    if ($name -eq "autorun.inf") {
        $score += 8
        $reasons += "autorun_file"
    }

    if ($name -match $doubleExtensionPattern) {
        $score += 8
        $reasons += "double_extension"
    }

    if ($name -match $suspiciousNamePattern) {
        $score += 3
        $reasons += "suspicious_filename"
    }

    if ($File.Attributes.ToString() -match 'Hidden|System') {
        $score += 2
        $reasons += "hidden_or_system"
    }

    if (($signedExecutableExtensions -contains $extension) -and ($score -gt 0 -or $isRootLevelFile)) {
        try {
            Invoke-UiHeartbeat -Ui $Ui
            $signature = Get-AuthenticodeSignature -FilePath $File.FullName
            switch ([string]$signature.Status) {
                "HashMismatch" {
                    $score += 4
                    $reasons += "tampered_signature"
                }
                "NotTrusted" {
                    $score += 3
                    $reasons += "untrusted_signature"
                }
                "NotSignatureValid" {
                    $score += 3
                    $reasons += "invalid_signature"
                }
            }
        } catch {
            # Ignore signature lookup failures for conservative default scanning.
        }
    }

    if (($File.Length -le 1MB) -and (($contentInspectionExtensions -contains $extension) -or $name -like '*eicar*' -or $name -eq 'autorun.inf')) {
        try {
            Invoke-UiHeartbeat -Ui $Ui
            $content = Get-Content -LiteralPath $File.FullName -Raw -ErrorAction Stop
            if ($content -match [Regex]::Escape($eicarSignature)) {
                $score = [Math]::Max($score, 10)
                $reasons += "eicar_test_signature"
            }
        } catch {
            # Ignore non-text content read failures.
        }
    }

    $reputation = Get-ReputationFromScore -Score $score
    if ($signatureMatch -and $signatureMatch.reputation) {
        $reputation = [string]$signatureMatch.reputation
    }
    $threatProfile = Get-ThreatProfile -SignatureMatch $signatureMatch -Reasons $reasons -Extension $extension

    return [PSCustomObject]@{
        Sha256 = $sha256
        Score = $score
        Reputation = $reputation
        Reasons = $reasons
        SignatureName = if ($signatureMatch) { [string]$signatureMatch.name } else { $null }
        SignatureSource = if ($signatureMatch) { [string]$signatureMatch.source } else { $null }
        SignatureDescription = if ($signatureMatch) { [string]$signatureMatch.description } else { $null }
        ThreatCategory = $threatProfile.ThreatCategory
        ThreatName = $threatProfile.ThreatName
        ThreatFamily = $threatProfile.ThreatFamily
        ThreatDescription = $threatProfile.ThreatDescription
        DetectionSource = $threatProfile.DetectionSource
    }
}

function Get-UsbDrives {
    $results = @()
    $seen = @{}

    try {
        $usbDisks = Get-CimInstance Win32_DiskDrive -ErrorAction Stop |
            Where-Object {
                $_.InterfaceType -eq 'USB' -or
                $_.PNPDeviceID -like 'USBSTOR*'
            }

        foreach ($disk in @($usbDisks)) {
            $partitions = Get-CimAssociatedInstance -InputObject $disk -ResultClassName Win32_DiskPartition -ErrorAction SilentlyContinue
            foreach ($partition in @($partitions)) {
                $logicalDisks = Get-CimAssociatedInstance -InputObject $partition -ResultClassName Win32_LogicalDisk -ErrorAction SilentlyContinue
                foreach ($logicalDisk in @($logicalDisks)) {
                    if (-not $logicalDisk.DeviceID -or $seen.ContainsKey($logicalDisk.DeviceID)) {
                        continue
                    }

                    $seen[$logicalDisk.DeviceID] = $true
                    $results += [PSCustomObject]@{
                        DeviceID = $logicalDisk.DeviceID
                        VolumeName = $logicalDisk.VolumeName
                        Size = $logicalDisk.Size
                        FreeSpace = $logicalDisk.FreeSpace
                        Model = $disk.Model
                        PNPDeviceID = $disk.PNPDeviceID
                    }
                }
            }
        }
    } catch {
        Write-Host "USB disk enumeration failed, falling back to removable drive detection."
    }

    if ($results.Count -gt 0) {
        return $results
    }

    $fallbackDrives = Get-CimInstance Win32_LogicalDisk -ErrorAction SilentlyContinue |
        Where-Object { $_.DriveType -eq 2 } |
        Select-Object DeviceID, VolumeName, Size, FreeSpace

    if ($null -eq $fallbackDrives) {
        return @()
    }

    return @($fallbackDrives)
}

function Get-DriveStateKey {
    param([string]$DrivePath)

    try {
        return ((Resolve-Path -LiteralPath $DrivePath).Path.TrimEnd('\')).ToUpperInvariant()
    } catch {
        return ($DrivePath.TrimEnd('\')).ToUpperInvariant()
    }
}

function Get-DriveSnapshot {
    param([string]$DrivePath)

    $snapshot = @{}
    if (-not (Test-Path -LiteralPath $DrivePath)) {
        return $snapshot
    }

    try {
        $items = Get-ChildItem -LiteralPath $DrivePath -Force -Recurse -ErrorAction SilentlyContinue
        foreach ($item in @($items)) {
            $key = [string]$item.FullName
            if ([string]::IsNullOrWhiteSpace($key)) {
                continue
            }

            $isDirectory = [bool]$item.PSIsContainer
            $signature = if ($isDirectory) {
                "dir"
            } else {
                "file|$($item.Length)|$($item.LastWriteTimeUtc.Ticks)"
            }

            $snapshot[$key] = [PSCustomObject]@{
                path = $key
                name = $item.Name
                is_directory = $isDirectory
                length = if ($isDirectory) { 0 } else { [int64]$item.Length }
                last_write_time = $item.LastWriteTimeUtc.ToString("o")
                signature = $signature
            }
        }
    } catch {
        Write-Host "Failed to snapshot drive $DrivePath"
    }

    return $snapshot
}

function Compare-DriveSnapshots {
    param(
        [hashtable]$PreviousSnapshot,
        [hashtable]$CurrentSnapshot,
        [string]$DriveLabel
    )

    $changes = @()
    $counts = @{
        created_files = 0
        modified_files = 0
        deleted_files = 0
        created_directories = 0
        deleted_directories = 0
    }

    foreach ($path in $CurrentSnapshot.Keys) {
        $currentItem = $CurrentSnapshot[$path]
        if (-not $PreviousSnapshot.ContainsKey($path)) {
            $changeType = "created"
            $entityType = if ($currentItem.is_directory) { "directory" } else { "file" }
            if ($currentItem.is_directory) {
                $counts.created_directories++
            } else {
                $counts.created_files++
            }
            $changes += [PSCustomObject]@{
                path = $currentItem.path
                name = $currentItem.name
                change_type = $changeType
                entity_type = $entityType
                size_bytes = [int64]$currentItem.length
                last_write_time = $currentItem.last_write_time
            }
            continue
        }

        $previousItem = $PreviousSnapshot[$path]
        if (-not $currentItem.is_directory -and $currentItem.signature -ne $previousItem.signature) {
            $counts.modified_files++
            $changes += [PSCustomObject]@{
                path = $currentItem.path
                name = $currentItem.name
                change_type = "modified"
                entity_type = "file"
                size_bytes = [int64]$currentItem.length
                last_write_time = $currentItem.last_write_time
            }
        }
    }

    foreach ($path in $PreviousSnapshot.Keys) {
        if ($CurrentSnapshot.ContainsKey($path)) {
            continue
        }

        $previousItem = $PreviousSnapshot[$path]
        $entityType = if ($previousItem.is_directory) { "directory" } else { "file" }
        if ($previousItem.is_directory) {
            $counts.deleted_directories++
        } else {
            $counts.deleted_files++
        }
        $changes += [PSCustomObject]@{
            path = $previousItem.path
            name = $previousItem.name
            change_type = "deleted"
            entity_type = $entityType
            size_bytes = [int64]$previousItem.length
            last_write_time = $previousItem.last_write_time
        }
    }

    if ($changes.Count -eq 0) {
        return @{
            has_changes = $false
            change_count = 0
            summary = $null
            items = @()
            counts = $counts
            rescan_required = $false
        }
    }

    $summaryParts = @()
    if ($counts.created_files -gt 0) { $summaryParts += "$($counts.created_files) file created" + $(if ($counts.created_files -gt 1) { "s" } else { "" }) }
    if ($counts.modified_files -gt 0) { $summaryParts += "$($counts.modified_files) file modified" + $(if ($counts.modified_files -gt 1) { "s" } else { "" }) }
    if ($counts.deleted_files -gt 0) { $summaryParts += "$($counts.deleted_files) file deleted" + $(if ($counts.deleted_files -gt 1) { "s" } else { "" }) }
    if ($counts.created_directories -gt 0) { $summaryParts += "$($counts.created_directories) folder created" + $(if ($counts.created_directories -gt 1) { "s" } else { "" }) }
    if ($counts.deleted_directories -gt 0) { $summaryParts += "$($counts.deleted_directories) folder deleted" + $(if ($counts.deleted_directories -gt 1) { "s" } else { "" }) }

    $sampleNames = @($changes | Select-Object -First 4 | ForEach-Object { $_.name })
    $summary = "Live USB activity detected on ${DriveLabel}: $($summaryParts -join ', ')."
    if ($sampleNames.Count -gt 0) {
        $summary += " Sample: $($sampleNames -join ', ')."
    }

    return @{
        has_changes = $true
        change_count = $changes.Count
        summary = $summary
        items = @($changes | Select-Object -First 8)
        counts = $counts
        rescan_required = (($counts.created_files + $counts.modified_files) -gt 0)
    }
}

function Publish-UsbLiveActivity {
    param(
        [string]$DriveLabel,
        [hashtable]$ChangeResult
    )

    if (-not $ChangeResult.has_changes) {
        return
    }

    $payload = @{
        activity_type = "usb_live_activity"
        scanner_version = $scannerVersion
        drive = $DriveLabel
        summary = $ChangeResult.summary
        created_files = [int]$ChangeResult.counts.created_files
        modified_files = [int]$ChangeResult.counts.modified_files
        deleted_files = [int]$ChangeResult.counts.deleted_files
        created_directories = [int]$ChangeResult.counts.created_directories
        deleted_directories = [int]$ChangeResult.counts.deleted_directories
        items = @($ChangeResult.items | Select-Object path, name, change_type, entity_type, size_bytes, last_write_time)
    } | ConvertTo-Json -Depth 6 -Compress

    Invoke-BackendLog `
        -ActionType "usb_live_activity" `
        -Details $payload `
        -Device $DriveLabel | Out-Null
}

function Publish-UsbRemoval {
    param([string]$DriveLabel)

    Invoke-BackendLog `
        -ActionType "usb_removal" `
        -Details "USB drive removed: $DriveLabel" `
        -Device $DriveLabel | Out-Null
}

function Should-RescanDrive {
    param([string]$DrivePath)

    $stateKey = Get-DriveStateKey -DrivePath $DrivePath
    if (-not $global:DriveLastScanAt.ContainsKey($stateKey)) {
        return $true
    }

    $lastScan = $global:DriveLastScanAt[$stateKey]
    if (-not $lastScan) {
        return $true
    }

    return ((Get-Date) - $lastScan).TotalSeconds -ge $rescanCooldownSeconds
}

function Scan-Drive {
    param(
        [string]$DrivePath,
        [string]$TriggerReason = "insertion"
    )

    Start-Sleep -Seconds 2

    if (-not (Test-Path -LiteralPath $DrivePath)) {
        Write-Host "Drive path $DrivePath is not accessible."
        return $null
    }

    Ensure-Directory -Path $QuarantineRoot

    $resolvedDrive = (Resolve-Path -LiteralPath $DrivePath).Path
    $driveLabel = $resolvedDrive.TrimEnd('\')
    $ui = New-StatusWindow -DriveName $driveLabel
    Update-StatusWindow `
        -Ui $ui `
        -CurrentText "Preparing USB security scan for $driveLabel..." `
        -StatsText "Discovering files..." `
        -StatusText "Initializing file intelligence engine..." `
        -CurrentValue 0 `
        -MaximumValue 0

    if ($TriggerReason -eq "insertion" -or $TriggerReason -eq "startup") {
        Invoke-BackendLog `
            -ActionType "usb_insertion" `
            -Details "USB drive inserted: $driveLabel" `
            -Device $driveLabel | Out-Null
    }

    $files = @(Get-DriveFiles -RootPath $resolvedDrive -Ui $ui -DriveLabel $driveLabel)
    $totalFiles = $files.Count
    $scannedFiles = 0
    $hits = @()
    $safeCount = 0
    $suspiciousCount = 0
    $dangerousCount = 0
    $quarantinedCount = 0
    $blockedCount = 0
    $flaggedOnlyCount = 0

    if ($totalFiles -eq 0) {
        Update-StatusWindow `
            -Ui $ui `
            -CurrentText "No files found on the inserted USB drive." `
            -StatsText "Files scanned: 0 | Safe: 0 | Suspicious: 0 | Dangerous: 0" `
            -StatusText "USB drive is empty or inaccessible." `
            -CurrentValue 0 `
            -MaximumValue 1
    }

    foreach ($file in $files) {
        $scannedFiles++

        Update-StatusWindow `
            -Ui $ui `
            -CurrentText "Analyzing: $($file.FullName)" `
            -StatsText "Files scanned: $scannedFiles / $totalFiles | Safe: $safeCount | Suspicious: $suspiciousCount | Dangerous: $dangerousCount" `
            -StatusText "Hashing file and comparing against threat signatures..." `
            -CurrentValue $scannedFiles `
            -MaximumValue ([Math]::Max(1, $totalFiles))

        $intel = Get-FileIntelligence -File $file -Ui $ui

        if ($intel.Reputation -eq "Safe") {
            $safeCount++
            continue
        }

        if ($intel.Reputation -eq "Dangerous") {
            $dangerousCount++
        } else {
            $suspiciousCount++
        }

        $disposition = Protect-FileByReputation `
            -File $file `
            -DriveRoot $resolvedDrive `
            -Reputation $intel.Reputation `
            -StrictMode:$StrictMode
        if ($disposition.Mode -eq "quarantined") {
            $quarantinedCount++
        } elseif ($disposition.Mode -eq "blocked_in_place") {
            $blockedCount++
        } elseif ($disposition.Mode -eq "flagged_only") {
            $flaggedOnlyCount++
        }

        $hits += [PSCustomObject]@{
            Path = $file.FullName
            Sha256 = $intel.Sha256
            Reputation = $intel.Reputation
            Score = $intel.Score
            Reasons = $intel.Reasons
            SignatureName = $intel.SignatureName
            SignatureSource = $intel.SignatureSource
            ThreatCategory = $intel.ThreatCategory
            ThreatName = $intel.ThreatName
            ThreatFamily = $intel.ThreatFamily
            ThreatDescription = $intel.ThreatDescription
            DetectionSource = $intel.DetectionSource
            Disposition = $disposition.Mode
            OutputPath = $disposition.Path
        }
    }

    $sampleFindings = @($hits | Select-Object -First 5 | ForEach-Object {
        $hashPreview = if ($_.Sha256) { $_.Sha256.Substring(0, 12) } else { "nohash" }
        "$($_.Reputation): $($_.ThreatName) | $($_.Path) [$($_.Disposition)] SHA256=$hashPreview"
    })
    $threatBreakdown = @($hits | Group-Object ThreatName | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object {
        [PSCustomObject]@{
            ThreatName = $_.Name
            Count = $_.Count
        }
    })
    $threatBreakdownText = @($threatBreakdown | ForEach-Object {
        "$($_.ThreatName): $($_.Count)"
    })

    $summary = if ($dangerousCount -gt 0) {
        "SEVERE: File intelligence found $($hits.Count) risky files on $driveLabel. Dangerous: $dangerousCount. Suspicious: $suspiciousCount. Quarantined: $quarantinedCount. Blocked: $blockedCount. Flagged only: $flaggedOnlyCount."
    } elseif ($suspiciousCount -gt 0) {
        "REVIEW: File intelligence flagged $suspiciousCount suspicious files on $driveLabel. Dangerous: 0. Quarantined: $quarantinedCount. Blocked: $blockedCount. Flagged only: $flaggedOnlyCount."
    } else {
        "Scanned $totalFiles files on $driveLabel. File intelligence rated all files Safe."
    }

    if ($threatBreakdownText.Count -gt 0) {
        $summary += " Threat types: $($threatBreakdownText -join ', ')."
    }

    if ($sampleFindings.Count -gt 0) {
        $summary += " Sample: $($sampleFindings -join '; ')"
    }

    $scanDetailsPayload = @{
        scan_type = "usb_file_intelligence"
        scanner_version = $scannerVersion
        drive = $driveLabel
        trigger_reason = $TriggerReason
        total_files = $totalFiles
        safe_count = $safeCount
        dangerous_count = $dangerousCount
        suspicious_count = $suspiciousCount
        quarantined_count = $quarantinedCount
        blocked_count = $blockedCount
        flagged_only_count = $flaggedOnlyCount
        strict_mode = [bool]$StrictMode
        summary = $summary
        threat_types = $threatBreakdown
        findings = @($hits | Select-Object -First 10 `
            Path, Sha256, Reputation, ThreatCategory, ThreatName, ThreatFamily, ThreatDescription, DetectionSource, Disposition, OutputPath)
    } | ConvertTo-Json -Depth 6 -Compress

    Invoke-BackendLog `
        -ActionType "usb_scan_complete" `
        -Details $scanDetailsPayload `
        -Device $driveLabel | Out-Null

    if ($dangerousCount -gt 0 -or $blockedCount -gt 0 -or $quarantinedCount -gt 0) {
        $mitigationPayload = @{
            scan_type = "usb_file_intelligence"
            scanner_version = $scannerVersion
            drive = $driveLabel
            summary = "USB threat mitigation completed on $driveLabel. Quarantined: $quarantinedCount. Blocked: $blockedCount. Flagged only: $flaggedOnlyCount."
            dangerous_count = $dangerousCount
            suspicious_count = $suspiciousCount
            quarantined_count = $quarantinedCount
            blocked_count = $blockedCount
            flagged_only_count = $flaggedOnlyCount
            threat_types = $threatBreakdown
            findings = @($hits | Select-Object -First 10 `
                Path, Sha256, Reputation, ThreatCategory, ThreatName, ThreatFamily, ThreatDescription, DetectionSource, Disposition, OutputPath)
        } | ConvertTo-Json -Depth 6 -Compress

        Invoke-BackendLog `
            -ActionType "usb_threat_mitigated" `
            -Details $mitigationPayload `
            -Device $driveLabel | Out-Null
    }

    if ($dangerousCount -gt 0) {
        $displaySummary = $sampleFindings -join "`n"
        if (-not $displaySummary) {
            $displaySummary = $summary
        }

        Complete-StatusWindow `
            -Ui $ui `
            -TitleText "!! USB THREAT DETECTED ($driveLabel) !!" `
            -SummaryText $displaySummary `
            -FooterText "File intelligence complete. Quarantined: $quarantinedCount | Blocked: $blockedCount" `
            -ThreatFound $true
    } elseif ($suspiciousCount -gt 0) {
        $displaySummary = $sampleFindings -join "`n"
        if (-not $displaySummary) {
            $displaySummary = $summary
        }

        Complete-StatusWindow `
            -Ui $ui `
            -TitleText "[ USB REVIEW ADVISED ($driveLabel) ]" `
            -SummaryText $displaySummary `
            -FooterText "Safe mode active. Suspicious files were flagged only; nothing was moved." `
            -ThreatFound $false
    } else {
        Complete-StatusWindow `
            -Ui $ui `
            -TitleText "[ USB DRIVE SAFE ($driveLabel) ]" `
            -SummaryText "Scanned $totalFiles files. Reputation: Safe." `
            -FooterText "USB scan completed successfully." `
            -ThreatFound $false
    }

    Close-StatusWindow -Ui $ui

    $stateKey = Get-DriveStateKey -DrivePath $resolvedDrive
    $global:DriveSnapshots[$stateKey] = Get-DriveSnapshot -DrivePath $resolvedDrive
    $global:DriveLastScanAt[$stateKey] = Get-Date

    return [PSCustomObject]@{
        Drive = $driveLabel
        TotalFiles = $totalFiles
        ThreatCount = $hits.Count
        SafeCount = $safeCount
        DangerousCount = $dangerousCount
        SuspiciousCount = $suspiciousCount
        QuarantinedCount = $quarantinedCount
        BlockedCount = $blockedCount
        FlaggedOnlyCount = $flaggedOnlyCount
        StrictMode = [bool]$StrictMode
        ScannerVersion = $scannerVersion
        ThreatTypes = $threatBreakdown
        Findings = $hits
    }
}

function Start-UsbSecurityMonitor {
    Write-Host "============================================="
    Write-Host "USB Security Module Active. Scanner version: $scannerVersion"
    Write-Host "Monitoring for USB insertions..."
    Write-Host "Quarantine path: $QuarantineRoot"
    Write-Host "Signature DB: $SignatureDbPath"
    if ($StrictMode) {
        Write-Host "Mode: Strict (Dangerous files are quarantined, Suspicious files are blocked)."
    } else {
        Write-Host "Mode: Safe default (Dangerous files are quarantined, Suspicious files are flagged only)."
    }
    Write-Host "Press Ctrl+C to stop."
    Write-Host "============================================="

    $knownDrives = @{}
    foreach ($drive in Get-UsbDrives) {
        $knownDrives[$drive.DeviceID] = $drive
        Write-Host "USB drive available at startup: $($drive.DeviceID)"
        Scan-Drive -DrivePath "$($drive.DeviceID)\" -TriggerReason "startup"
    }

    while ($true) {
        Start-Sleep -Seconds $PollSeconds
        $currentDrives = @{}

        foreach ($drive in Get-UsbDrives) {
            $currentDrives[$drive.DeviceID] = $drive
            if (-not $knownDrives.ContainsKey($drive.DeviceID)) {
                Write-Host "New USB drive detected: $($drive.DeviceID)"
                Scan-Drive -DrivePath "$($drive.DeviceID)\" -TriggerReason "insertion"
                continue
            }

            $drivePath = "$($drive.DeviceID)\"
            $stateKey = Get-DriveStateKey -DrivePath $drivePath
            $previousSnapshot = if ($global:DriveSnapshots.ContainsKey($stateKey)) { $global:DriveSnapshots[$stateKey] } else { @{} }
            $currentSnapshot = Get-DriveSnapshot -DrivePath $drivePath
            $changeResult = Compare-DriveSnapshots `
                -PreviousSnapshot $previousSnapshot `
                -CurrentSnapshot $currentSnapshot `
                -DriveLabel $drive.DeviceID

            $global:DriveSnapshots[$stateKey] = $currentSnapshot

            if ($changeResult.has_changes) {
                Write-Host $changeResult.summary
                Publish-UsbLiveActivity -DriveLabel $drive.DeviceID -ChangeResult $changeResult

                if ($changeResult.rescan_required -and (Should-RescanDrive -DrivePath $drivePath)) {
                    Write-Host "Re-scanning $($drive.DeviceID) because live file activity was detected."
                    Scan-Drive -DrivePath $drivePath -TriggerReason "live_activity"
                }
            }
        }

        foreach ($driveId in @($knownDrives.Keys)) {
            if ($currentDrives.ContainsKey($driveId)) {
                continue
            }

            Write-Host "USB drive removed: $driveId"
            Publish-UsbRemoval -DriveLabel $driveId
            $stateKey = Get-DriveStateKey -DrivePath "$driveId\"
            $global:DriveSnapshots.Remove($stateKey) | Out-Null
            $global:DriveLastScanAt.Remove($stateKey) | Out-Null
        }

        $knownDrives = $currentDrives
    }
}

Initialize-SignatureDatabase

if ($TestDrivePath) {
    $result = Scan-Drive -DrivePath $TestDrivePath
    if ($result) {
        $result | ConvertTo-Json -Depth 6
    }
    exit 0
}

Start-UsbSecurityMonitor
