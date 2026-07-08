<#
.SYNOPSIS
AI Firewall Endpoint Agent for Windows
Monitors the local machine for physical USB Pendrive insertions.
When detected, it displays a custom floating popup on the left side of the screen
and forwards the activity log to the AI Firewall Backend for analysis.
#>

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

if (-not (Get-EnvFlag -Name "ENABLE_USB_SCANNING" -Default $true)) {
    Write-Host "AI Firewall USB monitoring is disabled (ENABLE_USB_SCANNING=false). Exiting."
    exit 0
}

# 1. Start listening to Windows Management Instrumentation (WMI) for Volume Changes (Event=2 is Insertion)
$query = "SELECT * FROM Win32_VolumeChangeEvent WHERE EventType = 2"
$Action = {
    $e = $Event.SourceEventArgs.NewEvent
    $driveName = $e.DriveName
    
    # 2. Add Windows Forms and Drawing abilities to PowerShell
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    # 3. Create a Custom Floating GUI Popup on the left side
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Endpoint Security Alert"
    $form.Size = New-Object System.Drawing.Size(350, 150)
    $form.StartPosition = "Manual"
    # Position: X=20 (Left edge padding), Y=ScreenHeight/2 (Middle height)
    $screen = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
    $form.Location = New-Object System.Drawing.Point(20, ($screen.Height / 2) - 100)
    $form.BackColor = [System.Drawing.Color]::FromArgb(255, 15, 23, 42) # Dark Slate
    $form.FormBorderStyle = "None" # Make it borderless like our web app
    $form.TopMost = $true # Always on top
    $form.ShowInTaskbar = $false
    
    # Yellow Warning Border Effect
    $form.Padding = New-Object System.Windows.Forms.Padding(4)
    $form.BackColor = [System.Drawing.Color]::FromArgb(255, 234, 179, 8) # Warning Yellow
    
    $innerPanel = New-Object System.Windows.Forms.Panel
    $innerPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
    $innerPanel.BackColor = [System.Drawing.Color]::FromArgb(255, 15, 23, 42) # Dark Slate Inner
    $form.Controls.Add($innerPanel)

    $titleLabel = New-Object System.Windows.Forms.Label
    $titleLabel.Text = "⚠️ USB DEVICE INSERTED"
    $titleLabel.ForeColor = [System.Drawing.Color]::FromArgb(255, 234, 179, 8) # Yellow text
    $titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $titleLabel.AutoSize = $true
    $titleLabel.Location = New-Object System.Drawing.Point(20, 20)
    $innerPanel.Controls.Add($titleLabel)

    $descLabel = New-Object System.Windows.Forms.Label
    $descLabel.Text = "Drive $($driveName) connected.`nReporting to AI Firewall..."
    $descLabel.ForeColor = [System.Drawing.Color]::White
    $descLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Regular)
    $descLabel.AutoSize = $true
    $descLabel.Location = New-Object System.Drawing.Point(20, 60)
    $innerPanel.Controls.Add($descLabel)

    # Automatically close the popup after 5 seconds
    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 5000 
    $timer.add_Tick({ $form.Close() })
    $timer.Start()

    # Async display of the form
    [void]$form.ShowDialog()

    # 4. SILENTLY send the real log to your Docker Backend!
    try {
        # Note: You must have logged into the web UI once and copied the Token if you want to enforce security, 
        # but for a local test demo, we can just login here or hit an unprotected endpoint.
        # Let's hit the registration/login flow to get a token, then fire the log.
        
        $loginBody = @{
            username = "testuser"
            password = "password123"
        }
        $loginRes = Invoke-RestMethod -Uri "http://localhost:8000/api/auth/login" -Method Post -Body $loginBody
        $token = $loginRes.access_token

        $headers = @{
            "Authorization" = "Bearer $token"
            "Content-Type"  = "application/json"
        }

        $logBody = @{
            action_type = "usb_insertion"
            device = $env:COMPUTERNAME
            network_activity = 0
            details = "Physical Pendrive $driveName Connected."
        } | ConvertTo-Json

        Invoke-RestMethod -Uri "http://localhost:8000/api/activity/log" -Method Post -Headers $headers -Body $logBody
        Write-Host "Sent anomaly report to AI Firewall."
    } catch {
        Write-Host "Failed to connect to AI Firewall Backend. Is Docker running?"
    }
}

Write-Host "Endpoint Agent Active."
Write-Host "Monitoring for physical USB insertions..."
Write-Host "Press Ctrl+C to stop."

Register-WmiEvent -Query $query -SourceIdentifier "USB_Detector" -Action $Action | Out-Null

# Keep script running
while ($true) {
    Start-Sleep -Seconds 1
}
