# SecureWatch Endpoint Agent Enrollment Guide

## 1. Overview
The SecureWatch Endpoint Agent runs as a transparent, authorized background service on authorized endpoint devices. It strictly collects security telemetry (auth, processes, network connections, FIM, security posture) and never captures private documents, passwords, or keystrokes.

---

## 2. Enrollment Workflow

```mermaid
sequenceDiagram
    participant Admin as SOC Administrator
    participant Server as Central Server
    participant Agent as Endpoint Agent

    Admin->>Server: Generate Enrollment Token (POST /api/v1/devices/enrollment-token)
    Server-->>Admin: Returns 48-char one-time token (expires in 24h)
    Admin->>Agent: Runs installation script with Token
    Agent->>Server: Authenticate & Register (POST /api/v1/devices/enroll)
    Server-->>Agent: Issues per-device JWT credential & device ID
    Agent->>Server: Streams telemetry & Heartbeats (POST /events/ingest, /heartbeat)
    Server-->>Admin: Displays connected device on SOC dashboard
```

---

## 3. Windows 10/11 Installation
1. Open PowerShell as **Administrator**.
2. Run the automated installer:
   ```powershell
   cd d:\DHANUZ\Apps\Antigravity\endpoint-agent\installers\windows
   .\install.ps1 -ServerUrl "http://localhost:8000" -EnrollmentToken "<YOUR_TOKEN>"
   ```
3. Verify status:
   ```powershell
   python main.py --status
   ```

---

## 4. Linux Installation (Ubuntu / Debian / Kali)
1. Run as root:
   ```bash
   cd /path/to/endpoint-agent/installers/linux
   sudo chmod +x install.sh
   sudo ./install.sh
   ```
2. Verify systemd service:
   ```bash
   sudo systemctl status securewatch-agent
   ```

---

## 5. Uninstallation Process
To completely remove the agent:
- **Windows:** Run `.\uninstall.ps1` as Administrator.
- **Linux:** Run `sudo ./uninstall.sh`.
