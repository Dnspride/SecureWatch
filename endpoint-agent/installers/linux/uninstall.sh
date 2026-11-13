#!/bin/bash
# ==============================================================================
# SecureWatch Linux Endpoint Agent - Uninstallation Script
# ==============================================================================

set -e

if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run as root (sudo ./uninstall.sh)"
  exit 1
fi

echo "[*] Stopping and disabling SecureWatch systemd service..."
systemctl stop securewatch-agent.service 2>/dev/null || true
systemctl disable securewatch-agent.service 2>/dev/null || true
rm -f /etc/systemd/system/securewatch-agent.service
systemctl daemon-reload

echo "[*] Removing application files..."
rm -rf /opt/securewatch-agent
rm -rf /etc/securewatch
rm -f /var/run/securewatch-agent.pid

echo "[+] SecureWatch Endpoint Agent has been completely uninstalled."
