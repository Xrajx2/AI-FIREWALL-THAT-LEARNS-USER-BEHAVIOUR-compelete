# AI Firewall API Documentation

The backend dynamically serves Swagger UI at `http://localhost:8000/docs`, but here is a brief overview of the main endpoints.

### Authentication

**`POST /api/auth/register`**
- Registers a new user.
- **Body**: `{ "username": "admin", "password": "password" }`

**`POST /api/auth/login`**
- Authenticates and returns a JWT token.
- **Body** (Form Data): `username`, `password`
- Also returns an adaptive anomaly assessment for the login event, so unusual access time patterns can be flagged immediately.

### Activity Logic

**`POST /api/activity/log`**
- Submits an action log for the user. Triggers AI behavior processing.
- **Headers**: `Authorization: Bearer <TOKEN>`
- If `ENABLE_USB_SCANNING=false`, all `usb_*` events are ignored and are not stored, scored, or broadcast.
- **Body**:
  ```json
  {
    "action_type": "file_transfer",
    "device": "desktop-01",
    "network_activity": 128.5,
    "details": "Uploaded a large archive to an external destination"
  }
  ```
- **Returns**: Analyzed `anomaly_score` and assessment.
- Assessment output now includes:
  - learned anomaly `score` and `level`
  - `summary` and `reasons` explaining why the event was flagged
  - `component_scores` for Isolation Forest, clustering drift, sequence behavior, and heuristics
  - `learning_state` showing training sample count and whether the adaptive models are ready
- Supported high-signal activity types include process, file, login, and network events.

**`GET /api/threats`**
- Fetches recent threat logs.
- **Returns**: List of `ThreatLog` objects.

**`GET /api/activity`**
- Fetches all recent activity.

**`GET /api/behavior-profiles`**
- Returns tracked user behavior baselines.
- Includes:
  - Login time patterns and peak login hours
  - Frequently used applications
  - File access habits such as common directories and file types
  
### Real-Time Monitoring

**`WS /api/ws/monitor`**
- WebSocket endpoint for the frontend dashboard.
- Pushes JSON messages on new activity, calculated threats, and periodic `SYSTEM_MONITOR_UPDATE` snapshots.

**`GET /api/system-monitor`**
- Returns the latest in-memory host telemetry snapshot.
- Includes:
  - Running process counts and top processes
  - Recent file change activity in watched paths
  - Active TCP connections and top network-active processes
- The `usb` section remains present for schema stability, but when `ENABLE_USB_SCANNING=false` it stays disabled and empty.
- When Docker is used on Windows, this endpoint shows container telemetry until the Windows host monitor agent starts streaming host data.

**`POST /api/system-monitor/ingest`**
- Accepts a telemetry snapshot from the Windows host monitor agent and makes it the active live monitor snapshot.
- **Headers**: `Authorization: Bearer <TOKEN>`
- **Body**:
  ```json
  {
    "snapshot": {
      "collector": "windows-host-agent",
      "scope": "host",
      "host": "DESKTOP-01"
    },
    "events": []
  }
  ```
