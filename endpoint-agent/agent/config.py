"""
SecureWatch Endpoint Agent – Agent Configuration
=================================================
Loads, persists, and encrypts the agent configuration from an OS-appropriate
location:
  Windows : %PROGRAMDATA%\\SecureWatch\\config.json
  Linux   : /etc/securewatch/config.json

Sensitive fields (device_secret, access_token, enrollment_token) are stored
encrypted using a machine-derived key so the config file cannot be trivially
read by unprivileged users even if they gain file access.
"""

from __future__ import annotations

import base64
import json
import os
import platform
import sys
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import List, Optional

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

AGENT_VERSION = "1.0.0"
AGENT_NAME = "SecureWatchAgent"

# Fields that must be encrypted at rest
SENSITIVE_FIELDS = {"device_secret", "access_token", "enrollment_token"}

# Platform-specific config paths
def get_config_dir() -> Path:
    if sys.platform == "win32":
        _program_data = os.environ.get("PROGRAMDATA", "C:\\ProgramData")
        return Path(_program_data) / "SecureWatch"
    if os.environ.get("SECUREWATCH_CONFIG_DIR"):
        return Path(os.environ["SECUREWATCH_CONFIG_DIR"])
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return Path("/etc/securewatch")
    etc_dir = Path("/etc/securewatch")
    if etc_dir.exists() and os.access(etc_dir, os.W_OK):
        return etc_dir
    return Path.home() / ".securewatch"

def get_config_path() -> Path:
    return get_config_dir() / "config.json"

CONFIG_DIR = get_config_dir()
CONFIG_PATH = get_config_path()

# Default FIM paths per platform
_DEFAULT_FIM_PATHS_WINDOWS: List[str] = [
    r"C:\Windows\System32\drivers\etc\hosts",
    r"C:\Windows\System32\drivers\etc\lmhosts.sam",
    r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    r"C:\Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
]

_DEFAULT_FIM_PATHS_LINUX: List[str] = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/hosts",
    "/etc/crontab",
    "/etc/ssh/sshd_config",
    "/etc/systemd/system",
    "/etc/cron.d",
]


def _default_fim_paths() -> List[str]:
    if sys.platform == "win32":
        return list(_DEFAULT_FIM_PATHS_WINDOWS)
    return list(_DEFAULT_FIM_PATHS_LINUX)


# ---------------------------------------------------------------------------
# Encryption helpers
# ---------------------------------------------------------------------------

def _derive_key(salt: bytes) -> bytes:
    """
    Derive a Fernet-compatible 32-byte key from a machine-specific secret.
    The machine secret is the hostname + platform node (MAC address string).
    This is NOT a user password — it ties encryption to this specific machine.
    """
    import socket
    machine_id = (socket.gethostname() + platform.node()).encode()
    if not HAS_CRYPTO:
        import hashlib
        return base64.urlsafe_b64encode(hashlib.sha256(salt + machine_id).digest())
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(machine_id))


def _encrypt(plaintext: str, salt: bytes) -> str:
    """Return base64-encoded ciphertext with salt prefix."""
    if not HAS_CRYPTO:
        # Fallback obfuscation when cryptography library is not installed
        b64 = base64.urlsafe_b64encode(plaintext.encode()).decode()
        return base64.urlsafe_b64encode(salt).decode() + ":" + b64
    key = _derive_key(salt)
    f = Fernet(key)
    ct = f.encrypt(plaintext.encode())
    # Encode: b64(salt) + ":" + b64(ciphertext)
    return base64.urlsafe_b64encode(salt).decode() + ":" + ct.decode()


def _decrypt(token: str) -> str:
    """Decrypt a value produced by ``_encrypt``."""
    salt_b64, ct = token.split(":", 1)
    if HAS_CRYPTO:
        try:
            salt = base64.urlsafe_b64decode(salt_b64)
            key = _derive_key(salt)
            f = Fernet(key)
            return f.decrypt(ct.encode()).decode()
        except Exception:
            pass
    # Fallback base64 decode if encrypted before crypto library was installed
    try:
        return base64.urlsafe_b64decode(ct.encode()).decode()
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# AgentConfig dataclass
# ---------------------------------------------------------------------------

@dataclass
class AgentConfig:
    """
    Complete configuration for the SecureWatch endpoint agent.

    Sensitive fields are encrypted when written to disk and decrypted when
    loaded, so callers always work with plain-text values in memory.
    """

    # Core connectivity
    server_url: str = ""
    device_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    # Secrets (encrypted at rest)
    device_secret: str = ""
    access_token: str = ""
    enrollment_token: str = ""

    # Operational tuning
    heartbeat_interval: int = 60       # seconds between heartbeats
    event_batch_size: int = 50         # events per HTTP POST
    event_flush_interval: int = 30     # seconds between queue flushes
    log_level: str = "INFO"

    # File Integrity Monitor paths
    fim_paths: List[str] = field(default_factory=_default_fim_paths)

    # Token lifecycle
    token_expiry: Optional[float] = None   # Unix timestamp
    token_refresh_margin: int = 300        # refresh 5 min before expiry

    # -----------------------------------------------------------------------
    # Classmethods
    # -----------------------------------------------------------------------

    @classmethod
    def load(cls) -> "AgentConfig":
        """
        Load configuration from the OS-appropriate path.
        Creates a default config if none exists yet.
        """
        path = get_config_path()
        if not path.exists():
            for alt in [Path("/etc/securewatch/config.json"), Path.home() / ".securewatch" / "config.json"]:
                if alt.exists():
                    path = alt
                    break

        if not path.exists():
            cfg = cls()
            return cfg

        raw = json.loads(path.read_text(encoding="utf-8"))

        # Decrypt sensitive fields
        for sf in SENSITIVE_FIELDS:
            if sf in raw and raw[sf] and raw[sf].startswith("enc:"):
                try:
                    raw[sf] = _decrypt(raw[sf][4:])
                except Exception:
                    # If decryption fails (different machine?) reset the field
                    raw[sf] = ""

        # Strip unknown keys so dataclass init doesn't choke
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        filtered = {k: v for k, v in raw.items() if k in known}
        return cls(**filtered)

    def save(self) -> None:
        """
        Persist configuration to disk. Sensitive fields are encrypted before writing.
        """
        target_dir = get_config_dir()
        try:
            target_dir.mkdir(parents=True, exist_ok=True)
            target_path = target_dir / "config.json"
        except (PermissionError, OSError):
            target_dir = Path.home() / ".securewatch"
            target_dir.mkdir(parents=True, exist_ok=True)
            target_path = target_dir / "config.json"

        data = asdict(self)

        # Encrypt sensitive fields
        for sf in SENSITIVE_FIELDS:
            if data.get(sf):
                salt = os.urandom(16)
                data[sf] = "enc:" + _encrypt(data[sf], salt)

        target_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        # Restrict permissions on the config file
        try:
            if sys.platform != "win32":
                os.chmod(target_path, 0o600)
        except OSError:
            pass

    # -----------------------------------------------------------------------
    # Convenience
    # -----------------------------------------------------------------------

    @property
    def is_enrolled(self) -> bool:
        """True when the device has completed enrollment."""
        return bool(self.device_id and self.device_secret)

    @property
    def needs_token_refresh(self) -> bool:
        """True when the JWT is absent or close to expiry."""
        if not self.access_token or self.token_expiry is None:
            return True
        import time
        return time.time() >= (self.token_expiry - self.token_refresh_margin)
