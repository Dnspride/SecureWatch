# SecureWatch Administrator & SOC Analyst Operations Guide

## 1. Role-Based Access Control (RBAC) Hierarchy

The platform provides 7 predefined roles out of the box, with granular backend API authorization:

1. **Super Administrator:** Unrestricted control over all IAM, devices, SIEM detections, and system settings.
2. **Security Administrator:** Manages devices, security policies, detection rules, alert investigations, and reports.
3. **IAM Administrator:** Dedicated to user provisioning, role assignments, department groups, and access reviews.
4. **SOC Analyst:** Investigates incoming alerts, reviews normalized security events, and documents findings.
5. **IT Administrator:** Handles endpoint onboarding, token generation, and hardware fleet status.
6. **Auditor:** Read-only visibility across users, devices, security events, audit logs, and compliance evidence.
7. **Standard User:** Zero access to SOC dashboard; authenticated only for agent credential binding.

---

## 2. Managing Users & 2FA Enforcement
- Navigate to **Users** in the sidebar.
- Click **Create User** to provision credentials.
- Users can enable Time-Based One-Time Passwords (TOTP) by calling `/api/v1/auth/mfa/setup` and scanning the generated QR code in an authenticator app.
- Excessive invalid logins (5 attempts) automatically lock accounts for 15 minutes, generating an immutable audit entry.

---

## 3. Investigating Security Incidents
1. Alerts trigger automatically when events match rule thresholds (e.g. Brute Force, Suspicious Scripting, Disabled Firewall).
2. Click **Investigate** on any alert to inspect:
   - Associated host and user identity.
   - Exact triggering process execution tree and command line.
   - Network destination IP and port metadata.
   - Monitored file changes (FIM).
3. Record analyst notes in the timeline thread.
4. Update status: `Acknowledge` → `Investigating` → `Resolve` or `False Positive`.

---

## 4. Quarantining Compromised Endpoints
If malicious activity is identified on an endpoint:
1. Open the device record under **Devices**.
2. Click **Quarantine Device**.
3. All existing cryptographic credentials and API tokens for that device are immediately revoked server-side, preventing further server communication.
