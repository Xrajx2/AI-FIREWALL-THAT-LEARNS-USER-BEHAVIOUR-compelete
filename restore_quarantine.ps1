param(
    [string]$QuarantineRoot = "$env:ProgramData\AIFirewall\Quarantine",
    [string]$DriveLetter = "",
    [switch]$Preview,
    [switch]$Force
)

function Get-DriveToken {
    param([string]$InputDriveLetter)

    if ([string]::IsNullOrWhiteSpace($InputDriveLetter)) {
        return ""
    }

    return ($InputDriveLetter.Trim().TrimEnd(':', '\').ToUpperInvariant())
}

function Ensure-Directory {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

$driveToken = Get-DriveToken -InputDriveLetter $DriveLetter

if (-not (Test-Path -LiteralPath $QuarantineRoot)) {
    Write-Host "Quarantine root not found: $QuarantineRoot"
    exit 1
}

if ([string]::IsNullOrWhiteSpace($driveToken)) {
    Write-Host "Quarantined drive snapshots found:"
    Get-ChildItem -LiteralPath $QuarantineRoot -Directory -ErrorAction SilentlyContinue |
        ForEach-Object {
            $count = @(Get-ChildItem -LiteralPath $_.FullName -Recurse -File -ErrorAction SilentlyContinue).Count
            [PSCustomObject]@{
                Drive = $_.Name
                FileCount = $count
                Path = $_.FullName
            }
        } | Format-Table -AutoSize
    Write-Host ""
    Write-Host "Run again with -DriveLetter <letter>, for example:"
    Write-Host "powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\restore_quarantine.ps1 -DriveLetter D"
    exit 0
}

$sourceRoot = Join-Path $QuarantineRoot $driveToken
$destinationRoot = "$driveToken`:\"

if (-not (Test-Path -LiteralPath $sourceRoot)) {
    Write-Host "No quarantined files found for drive $driveToken at $sourceRoot"
    exit 1
}

if (-not (Test-Path -LiteralPath $destinationRoot)) {
    Write-Host "Destination drive is not mounted: $destinationRoot"
    exit 1
}

$files = @(Get-ChildItem -LiteralPath $sourceRoot -Recurse -File -ErrorAction SilentlyContinue)
if ($files.Count -eq 0) {
    Write-Host "No files found under $sourceRoot"
    exit 0
}

$restoredCount = 0
$skippedCount = 0
$failedCount = 0

Write-Host "Restore mode: $(if ($Preview) { 'Preview only' } else { 'Move files back' })"
Write-Host "Source: $sourceRoot"
Write-Host "Destination: $destinationRoot"
Write-Host "Files discovered: $($files.Count)"

foreach ($file in $files) {
    $relativePath = $file.FullName.Substring($sourceRoot.Length).TrimStart('\')
    $targetPath = Join-Path $destinationRoot $relativePath
    $targetDirectory = Split-Path -Parent $targetPath

    if ((Test-Path -LiteralPath $targetPath) -and (-not $Force)) {
        Write-Host "Skipped existing file: $targetPath"
        $skippedCount++
        continue
    }

    if ($Preview) {
        Write-Host "Would restore: $($file.FullName) -> $targetPath"
        $restoredCount++
        continue
    }

    try {
        Ensure-Directory -Path $targetDirectory
        Move-Item -LiteralPath $file.FullName -Destination $targetPath -Force:$Force -ErrorAction Stop
        Write-Host "Restored: $targetPath"
        $restoredCount++
    } catch {
        Write-Host "Failed: $($file.FullName) -> $targetPath"
        $failedCount++
    }
}

[PSCustomObject]@{
    Drive = $driveToken
    Preview = [bool]$Preview
    RestoredCount = $restoredCount
    SkippedCount = $skippedCount
    FailedCount = $failedCount
    SourceRoot = $sourceRoot
    DestinationRoot = $destinationRoot
}
