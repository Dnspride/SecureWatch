# SecureWatch REST & WebSocket API Specification

## 1. Base URL & Authentication
- REST Base URL: `https://soc.company.com/api/v1`
- WebSocket Endpoint: `wss://soc.company.com/ws/dashboard`
- Authentication Header:
  ```http
  Authorization: Bearer <JWT_ACCESS_TOKEN>
  ```

---

## 2. API Endpoint Catalog

### Authentication (`/auth`)
- `POST /auth/login`: Authenticate username/password with Argon2id and optional TOTP MFA.
- `POST /auth/refresh`: Rotate refresh token and obtain new access token.
- `POST /auth/logout`: Revoke active session.
- `GET /auth/me`: Profile of currently authenticated user.
- `POST /auth/mfa/setup`: Generate TOTP secret and QR code PNG.
- `POST /auth/mfa/verify`: Verify and activate 2FA.

### Users & IAM (`/users`)
- `GET /users`: Paginated user list with filters.
- `POST /users`: Create user account.
- `GET /users/{id}`: Detailed user record.
- `PUT /users/{id}`: Update user attributes or roles.
- `DELETE /users/{id}`: Deactivate and delete account.
- `POST /users/{id}/lock`: Administrative account lockout.
- `POST /users/{id}/unlock`: Unlock account.
- `GET /users/{id}/login-history`: History of login attempts and source IPs.

### Devices & Enrollment (`/devices`)
- `POST /devices/enrollment-token`: Generate short-lived (24h) single-use enrollment token.
- `POST /devices/enroll`: Called by agent to authenticate and register hardware identity.
- `POST /devices/heartbeat`: Periodic telemetry ping with CPU, memory, and security status.
- `GET /devices`: List enrolled endpoints.
- `GET /devices/{id}`: Endpoint details and investigation metrics.
- `POST /devices/{id}/approve`: Approve pending enrollment.
- `POST /devices/{id}/revoke`: Quarantine device and revoke credentials.

### SIEM Events (`/events`)
- `POST /events/ingest`: Agent authenticated telemetry ingestion batch.
- `POST /events/search`: Query normalized security logs with category and severity filters.
- `GET /events/{id}`: Full raw normalized event JSON.

### Alerts (`/alerts`)
- `GET /alerts`: List detected threat alerts.
- `GET /alerts/{id}`: Detailed alert investigation file.
- `POST /alerts/{id}/acknowledge`: Mark alert acknowledged.
- `POST /alerts/{id}/resolve`: Mark alert resolved with resolution summary.
- `POST /alerts/{id}/assign`: Assign alert to analyst UUID.
- `POST /alerts/{id}/notes`: Add analyst observation note.

### Audit & Compliance (`/audit-logs`)
- `GET /audit-logs`: List immutable audit logs.
- `POST /audit-logs/verify-integrity`: Cryptographically verifies SHA-256 hash chain.
