param(
    [Parameter(Mandatory = $true)]
    [string]$StatusFilePath
)

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$script:lastState = @{}
$script:lastSeenAt = Get-Date
$script:closeAt = $null

function Merge-StatusState {
    param(
        [hashtable]$CurrentState,
        $IncomingState
    )

    if ($null -eq $IncomingState) {
        return $CurrentState
    }

    foreach ($property in $IncomingState.PSObject.Properties) {
        if ($property.Name -eq "heartbeat") {
            continue
        }

        if ($null -ne $property.Value) {
            $CurrentState[$property.Name] = $property.Value
        }
    }

    return $CurrentState
}

function Apply-StatusState {
    param(
        [hashtable]$State,
        $Form,
        $TitleLabel,
        $CurrentFileLabel,
        $ProgressBar,
        $StatsLabel,
        $StatusLabel
    )

    if ($State.ContainsKey("title_text")) {
        $TitleLabel.Text = [string]$State["title_text"]
    }
    if ($State.ContainsKey("current_text")) {
        $CurrentFileLabel.Text = [string]$State["current_text"]
    }
    if ($State.ContainsKey("stats_text")) {
        $StatsLabel.Text = [string]$State["stats_text"]
    }
    if ($State.ContainsKey("status_text")) {
        $StatusLabel.Text = [string]$State["status_text"]
    }

    $progressMode = if ($State.ContainsKey("progress_mode")) { [string]$State["progress_mode"] } else { "marquee" }
    if ($progressMode -eq "determinate") {
        $maxValue = 1
        if ($State.ContainsKey("maximum_value")) {
            $maxValue = [Math]::Max(1, [int]$State["maximum_value"])
        }
        $currentValue = 0
        if ($State.ContainsKey("current_value")) {
            $currentValue = [Math]::Min($maxValue, [Math]::Max(0, [int]$State["current_value"]))
        }

        $ProgressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Continuous
        $ProgressBar.Maximum = $maxValue
        $ProgressBar.Value = $currentValue
    } else {
        $ProgressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Marquee
    }

    $threatFound = $false
    if ($State.ContainsKey("threat_found")) {
        $threatFound = [bool]$State["threat_found"]
    }

    $stateMode = if ($State.ContainsKey("state")) { [string]$State["state"] } else { "running" }
    if ($threatFound) {
        $Form.BackColor = [System.Drawing.Color]::FromArgb(255, 239, 68, 68)
        $TitleLabel.ForeColor = [System.Drawing.Color]::FromArgb(255, 239, 68, 68)
    } elseif ($stateMode -eq "completed") {
        $Form.BackColor = [System.Drawing.Color]::FromArgb(255, 34, 197, 94)
        $TitleLabel.ForeColor = [System.Drawing.Color]::FromArgb(255, 34, 197, 94)
    } else {
        $Form.BackColor = [System.Drawing.Color]::FromArgb(255, 59, 130, 246)
        $TitleLabel.ForeColor = [System.Drawing.Color]::FromArgb(255, 59, 130, 246)
    }
}

$form = New-Object System.Windows.Forms.Form
$form.Text = "USB Security Module"
$form.Size = New-Object System.Drawing.Size(430, 290)
$form.StartPosition = "Manual"
$screen = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
$form.Location = New-Object System.Drawing.Point(20, [Math]::Max(20, ($screen.Height / 2) - 130))
$form.FormBorderStyle = "None"
$form.TopMost = $true
$form.ShowInTaskbar = $false
$form.Padding = New-Object System.Windows.Forms.Padding(4)
$form.BackColor = [System.Drawing.Color]::FromArgb(255, 59, 130, 246)

$innerPanel = New-Object System.Windows.Forms.Panel
$innerPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
$innerPanel.BackColor = [System.Drawing.Color]::FromArgb(255, 15, 23, 42)
$form.Controls.Add($innerPanel)

$titleLabel = New-Object System.Windows.Forms.Label
$titleLabel.Text = "[ USB SECURITY SCAN ]"
$titleLabel.ForeColor = [System.Drawing.Color]::FromArgb(255, 59, 130, 246)
$titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
$titleLabel.AutoSize = $true
$titleLabel.Location = New-Object System.Drawing.Point(20, 20)
$innerPanel.Controls.Add($titleLabel)

$currentFileLabel = New-Object System.Windows.Forms.Label
$currentFileLabel.Text = "Initializing USB security module..."
$currentFileLabel.ForeColor = [System.Drawing.Color]::White
$currentFileLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Regular)
$currentFileLabel.AutoSize = $false
$currentFileLabel.Size = New-Object System.Drawing.Size(380, 90)
$currentFileLabel.Location = New-Object System.Drawing.Point(20, 60)
$innerPanel.Controls.Add($currentFileLabel)

$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Location = New-Object System.Drawing.Point(20, 165)
$progressBar.Size = New-Object System.Drawing.Size(380, 20)
$progressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Marquee
$innerPanel.Controls.Add($progressBar)

$statsLabel = New-Object System.Windows.Forms.Label
$statsLabel.Text = "Preparing scan..."
$statsLabel.ForeColor = [System.Drawing.Color]::Gray
$statsLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Italic)
$statsLabel.AutoSize = $true
$statsLabel.Location = New-Object System.Drawing.Point(20, 200)
$innerPanel.Controls.Add($statsLabel)

$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Text = "Awaiting analysis results..."
$statusLabel.ForeColor = [System.Drawing.Color]::White
$statusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Regular)
$statusLabel.AutoSize = $true
$statusLabel.Location = New-Object System.Drawing.Point(20, 225)
$innerPanel.Controls.Add($statusLabel)

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 250
$timer.Add_Tick({
    if (Test-Path -LiteralPath $StatusFilePath) {
        try {
            $raw = Get-Content -LiteralPath $StatusFilePath -Raw -ErrorAction Stop
            if (-not [string]::IsNullOrWhiteSpace($raw)) {
                $incomingState = $raw | ConvertFrom-Json
                $script:lastState = Merge-StatusState -CurrentState $script:lastState -IncomingState $incomingState
                Apply-StatusState `
                    -State $script:lastState `
                    -Form $form `
                    -TitleLabel $titleLabel `
                    -CurrentFileLabel $currentFileLabel `
                    -ProgressBar $progressBar `
                    -StatsLabel $statsLabel `
                    -StatusLabel $statusLabel

                $script:lastSeenAt = Get-Date
                if (($script:lastState["state"] -eq "completed") -and (-not $script:closeAt)) {
                    $closeAfter = 8
                    if ($script:lastState.ContainsKey("close_after_seconds")) {
                        $closeAfter = [Math]::Max(1, [int]$script:lastState["close_after_seconds"])
                    }
                    $script:closeAt = (Get-Date).AddSeconds($closeAfter)
                }
            }
        } catch {
            # Ignore partial writes while the scanner updates the file.
        }
    }

    if ($script:closeAt -and (Get-Date) -ge $script:closeAt) {
        $form.Close()
        return
    }

    if ((-not (Test-Path -LiteralPath $StatusFilePath)) -and ((Get-Date) -gt $script:lastSeenAt.AddSeconds(10))) {
        $form.Close()
    }
})

$form.Add_Shown({
    $timer.Start()
})

$form.Add_FormClosed({
    $timer.Stop()
    $timer.Dispose()
    if (Test-Path -LiteralPath $StatusFilePath) {
        Remove-Item -LiteralPath $StatusFilePath -Force -ErrorAction SilentlyContinue
    }
})

[void]$form.ShowDialog()
