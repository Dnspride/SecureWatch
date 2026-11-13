# SecureWatch Security & Privacy Architecture

## 1. Authentication & Cryptography

| Layer | Standard / Implementation |
|---|---|
| **Password Hashing** | Argon2id (Memory: 64MB, Time Cost: 3 iterations, Salt: 16 bytes) |
| **API Authentication** | RS256 Asymmetric JWT with short 15-minute expiration |
| **Session Refresh** | Opaque CSPRNG 64-byte tokens stored in Redis with Token Rotation |
| **Two-Factor Authentication** | RFC 6238 TOTP (Google Authenticator, 1Password) with encrypted secrets |
| **Per-Device Credentials** | Cryptographically signed device JWTs bound to hardware UUIDs |
| **Audit Logging** | Append-only SHA-256 hash chaining to detect database tampering |

---

## 2. Privacy & Ethical Guardrails

- **Explicit Authorization:** Agents must be intentionally enrolled via one-time cryptographically generated tokens.
- **Strictly Security Metadata:**
  - **Process Monitoring:** Tracks executable names, PIDs, parent processes, and execution times. Passwords in command lines (e.g. `--password`, `-p`) are automatically redacted before transmission.
  - **Network Monitoring:** Collects socket metadata (IP, port, protocol, PID). Packet payload inspection is never conducted.
  - **FIM Monitoring:** Computes local SHA-256 hashes of critical system files. File contents are never uploaded to the server.
  - **No Invasive Surveillance:** Keylogging, screen capture, camera access, and browser document harvesting are explicitly excluded from design and implementation.
