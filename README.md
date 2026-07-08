# AI Firewall that Learns User Behavior

A complete cybersecurity system that detects and stops suspicious user activity by learning normal behavior patterns and applying machine learning to detect anomalies in real time.

## Project Architecture

1. **Frontend**: React + TailwindCSS (Vite)
2. **Backend**: Python FastAPI
3. **Database**: PostgreSQL
4. **Caching/Messaging**: Redis (with WebSockets for real-time pushing)
5. **AI Module**: Scikit-Learn powered adaptive anomaly detection

## Features

- **Behavioral Learning**: Establishes baselines for users (e.g., login times, data transfer volume).
- **Adaptive ML Anomaly Detection**: Uses Isolation Forest, KMeans clustering, and learned sequence behavior to detect unusual access times, workflow drift, and anomalous transfer patterns.
- **User Behavior Tracking**: Tracks login time patterns, frequently used applications, and file access habits per user and exposes them in the dashboard.
- **Anomaly Detection**: Assigns a Threat Score (0-100) to interactions.
- **Automated Responses**: Locks sessions or sends alerts when High/Critical threats are detected.
- **Live Dashboard**: Watch network activity flow in real-time via WebSockets.
- **System Telemetry Monitoring**: Streams real Windows host telemetry for running processes, recent file changes, and live TCP connection behavior into the dashboard.

## Setup & Deployment (Docker)

Ensure you have Docker and Docker Compose installed.

1. Clone or navigate to the project directory.
2. Build and run the entire stack:
   ```bash
   docker-compose up --build
   ```
3. Access the components:
   - **Frontend Dashboard**: [http://localhost:5173](http://localhost:5173)
   - **Backend API**: [http://localhost:8000](http://localhost:8000)
   - **API Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)

## Environment Variables

For production, modify the `.env` file (or `docker-compose.yml`):
- `DATABASE_URL=postgresql://admin:password@db:5432/aifirewall`
- `SECRET_KEY=supersecretkey_change_in_production`
- `DATA_ENCRYPTION_KEY=replace_with_a_long_random_secret` to encrypt emails, login metadata, activity details, and threat logs at rest
- `ADMIN_SIGNUP_CODE=replace_with_an_invite_code` to require an invite code for new admin accounts after the first admin exists
- `ALLOW_FIRST_ADMIN_BOOTSTRAP=true` allows the first admin account to be created without an invite code
- `REDIS_URL=redis://redis:6379/0`
- `MONITORED_PATHS=C:\path\one;C:\path\two` to override the default watched directories for file activity monitoring
- `MONITOR_INTERVAL_SECONDS=5` to control how frequently the host telemetry poller refreshes
- `ENABLE_USB_SCANNING=false` disables all USB detection, scanning, logging, and event ingestion

## Secure Authentication

The app now supports:
- secure signup and login with hashed passwords
- `admin` and `user` roles
- protected frontend routes for `/dashboard` and `/admin`
- encrypted sensitive fields and stored logs in the backend database
- per-user dashboard, activity, and threat visibility for normal users

Behavior notes:
- The first admin can sign up without an invite code while no admin account exists and `ALLOW_FIRST_ADMIN_BOOTSTRAP=true`.
- Additional admin signups require `ADMIN_SIGNUP_CODE`.
- Standard users should sign in through the normal dashboard at [http://localhost:5173/dashboard](http://localhost:5173/dashboard).
- Admin users can access the full telemetry dashboard at [http://localhost:5173/admin](http://localhost:5173/admin).

## USB Security Agent

If you are running the backend in Docker on Windows, the website needs the Windows host monitor and USB scanner so it can see your real PC instead of the Linux container.

## Demo Day Quick Start

For the simplest and safest startup before a presentation:

1. Open Docker Desktop and wait until it says Docker is running.
2. Double-click `start_demo_day.cmd`.
3. Wait for the status summary window to finish.
4. Open the dashboard at [http://localhost:5173](http://localhost:5173) if it does not open automatically.
5. Refresh once with `Ctrl+F5`.
6. Plug in the pendrive after the dashboard is already open.

If the `Device Safety` page ever shows `Offline`, or the pendrive does not appear, run:

```powershell
.\fix_demo_status.cmd
```

That repair helper:
- makes sure Docker containers are running
- restarts the Windows host monitor services if needed
- prints the current host/USB/agent status in one place

The detailed status checker can also be run by itself:

```powershell
.\demo_status_report.ps1
```

One-time setup to make this permanent after each Windows sign-in:

```powershell
.\install_windows_startup.cmd
```

That installer adds a Startup-folder launcher for the current Windows user and starts a lightweight watchdog that keeps the host monitor and USB scanner alive in the background.

If you only want to launch them manually right now:

```powershell
.\ensure_windows_monitors.ps1
```

You can still run the legacy launchers individually:

```powershell
.\start_host_monitor.cmd
.\start_usb_scanner.cmd
```

To remove the auto-start tasks later:

```powershell
.\remove_windows_startup.cmd
```

## Standalone Python Realtime Monitor

For a simple host-side realtime monitor built with Python, `psutil`, and `watchdog`, install the backend dependencies and run:

```powershell
py -3 -m pip install -r .\backend\requirements.txt
py -3 .\backend\realtime_system_monitor.py --watch-path . --watch-path $env:USERPROFILE\Downloads
```

What it does:
- Tracks running processes with name, PID, CPU, and memory snapshots.
- Watches file activity in real time and logs create, delete, modify, and move events.
- Detects removable USB storage insertion and removal events.
- Monitors active network connections, remote IPs, ports, and per-scan data usage deltas.
- Raises console alerts for new processes outside the learned baseline, bulk file access spikes, and unusual network activity.

The monitor logs timestamped events to both the console and `backend/logs/realtime_system_monitor.log`. Data usage is reported as sent/received deltas per polling interval.

## Standalone USB Security Module

For a simple Python USB protection workflow with automatic insertion/removal detection, file scanning, quarantine, and console alerts, run:

```powershell
py -3 -m pip install -r .\backend\requirements.txt
py -3 .\backend\usb_security_module.py
```

Helpful options:
- `--quarantine-level suspicious` quarantines both suspicious and malicious files.
- `--test-device-path C:\path\to\folder --once` scans a normal folder as if it were a USB device for safe testing.
- `--signature-db .\security\malware_signatures.json` uses the bundled SHA-256 signature database explicitly.

What it does:
- Detects removable USB storage insertion and removal automatically.
- Scans every file on the detected USB device.
- Flags risky files using extension rules, size checks, suspicious names, double extensions, content patterns, the EICAR test signature, and bundled SHA-256 signatures.
- Quarantines harmful files into `backend/quarantine/usb`.
- Logs every action with timestamps to the console and `backend/logs/usb_security_module.log`.

## Standalone User Behavior Tracking Module

For a simple Python user-behavior tracker that stores activity, learns a baseline, and alerts on unusual behavior, run:

```powershell
py -3 -m pip install -r .\backend\requirements.txt
py -3 .\backend\user_behavior_tracking_module.py --username alice monitor --watch-path . --login-now
```

Other useful commands:
- `py -3 .\backend\user_behavior_tracking_module.py --username alice login` records a login event and checks if the time is unusual.
- `py -3 .\backend\user_behavior_tracking_module.py --username alice app chrome.exe` records application usage manually.
- `py -3 .\backend\user_behavior_tracking_module.py --username alice file C:\path\report.docx --action open` records a file-access event manually.
- `py -3 .\backend\user_behavior_tracking_module.py --username alice baseline` prints the learned baseline for that user.

What it does:
- Stores login, application, and file-access activity with timestamps in the existing backend database.
- Builds a normal behavior baseline using the project’s `behavior_profiles` data model.
- Detects unusual login times, unknown application usage, and abnormal file access patterns.
- Shows alerts in the console and writes timestamped logs to `backend/logs/user_behavior_tracking.log`.
