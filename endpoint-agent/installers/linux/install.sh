#!/bin/bash
# ==============================================================================
# SecureWatch Linux Endpoint Agent - Installation Script
# Supports: Ubuntu, Debian, Kali, Debian-based Linux, RHEL/CentOS
# ==============================================================================

set -e

echo "=========================================================="
echo " SecureWatch Endpoint Agent Installer (Linux)             "
echo "=========================================================="

# Check root elevation
if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run as root (sudo ./install.sh)"
  exit 1
fi

INSTALL_DIR="/opt/securewatch-agent"
CONFIG_DIR="/etc/securewatch"

# 1. Install system prerequisites
echo "[*] Checking Python3 and pip..."
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y -qq python3 python3-pip python3-venv >/dev/null
elif command -v yum >/dev/null 2>&1; then
    yum install -y python3 python3-pip >/dev/null
fi

# 2. Create directories
mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"

# 3. Copy source files
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
if [ -d "$SOURCE_DIR/agent" ]; then
    cp -r "$SOURCE_DIR/"* "$INSTALL_DIR/"
elif [ -d "$SOURCE_DIR/endpoint-agent" ]; then
    cp -r "$SOURCE_DIR/endpoint-agent/"* "$INSTALL_DIR/"
fi

# 4. Create virtual environment & install dependencies
echo "[*] Setting up Python virtual environment..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip --quiet
"$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt" --quiet

# 5. Prompt for enrollment if not pre-set
if [ -z "$ENROLLMENT_TOKEN" ]; then
    read -p "Enter SecureWatch Server URL [https://soc.company.com]: " SERVER_URL
    SERVER_URL=${SERVER_URL:-"https://soc.company.com"}
    read -p "Enter Enrollment Token: " ENROLLMENT_TOKEN
fi

# 6. Run enrollment
echo "[*] Registering device with server..."
"$INSTALL_DIR/venv/bin/python" "$INSTALL_DIR/main.py" --enroll --server-url "$SERVER_URL" --token "$ENROLLMENT_TOKEN"

# 7. Install Systemd Service
echo "[*] Installing systemd background service..."
cat << 'EOF' > /etc/systemd/system/securewatch-agent.service
[Unit]
Description=SecureWatch Endpoint Security Agent
Documentation=https://github.com/securewatch/platform
After=network.target

[Service]
Type=simple
Restart=always
RestartSec=10
ExecStart=/opt/securewatch-agent/venv/bin/python /opt/securewatch-agent/main.py --start
WorkingDirectory=/opt/securewatch-agent
StandardOutput=journal
StandardError=journal
SyslogIdentifier=securewatch-agent

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable securewatch-agent.service
systemctl start securewatch-agent.service

echo ""
echo "[+] SecureWatch Agent successfully installed and started as systemd service!"
echo "[*] Check service status using: sudo systemctl status securewatch-agent"
