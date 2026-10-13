#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then
  echo 'Run as root.' >&2
  exit 1
fi
binary=${1:-target/release/easy-connect}
profile=${2:-/etc/easy-connect/profile.json}
credentials=${3:-/etc/easy-connect/credentials}
if [ ! -f "$binary" ] || [ ! -f "$profile" ] || [ ! -f "$credentials" ]; then
  echo 'Provide the Linux binary, profile JSON, and two-line credentials file.' >&2
  exit 1
fi
command -v ip >/dev/null
command -v tailscale >/dev/null
command -v systemctl >/dev/null
"$binary" check-config --config "$profile"
# Stop and clean the previous instance before replacing its executable/config.
if systemctl cat easy-connect.service >/dev/null 2>&1; then
  systemctl stop easy-connect.service
fi
install -d -m 0700 /etc/easy-connect
if [ "$profile" != /etc/easy-connect/profile.json ]; then
  install -m 0600 "$profile" /etc/easy-connect/profile.json
fi
if [ "$credentials" != /etc/easy-connect/credentials ]; then
  install -m 0600 "$credentials" /etc/easy-connect/credentials
fi
chown root:root /etc/easy-connect/profile.json /etc/easy-connect/credentials
chmod 0600 /etc/easy-connect/profile.json /etc/easy-connect/credentials
install -m 0755 "$binary" /usr/local/bin/easy-connect
install -m 0644 deploy/linux/easy-connect.service /etc/systemd/system/easy-connect.service
systemctl daemon-reload
systemctl enable --now easy-connect.service
