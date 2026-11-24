#!/usr/bin/env bash
# Spike auf einem Raspberry mit Raspberry Pi OS (oder Debian/Ubuntu) installieren:
#   curl -fsSL https://raw.githubusercontent.com/joelschories/spike-server/main/install.sh | sudo bash
# Installiert Spike als eigenen Systemdienst, der beim Hochfahren automatisch startet.
set -euo pipefail

REPO="${SPIKE_REPO:-https://github.com/joelschories/spike-server}"
BRANCH="${SPIKE_BRANCH:-main}"
APP_DIR=/opt/spike
DATA_DIR=/var/lib/spike

say() { printf '\033[1;32m▸\033[0m %s\n' "$1"; }
fail() { printf '\033[1;31m✗ %s\033[0m\n' "$1"; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "Bitte mit sudo ausführen."
command -v apt-get >/dev/null || fail "Dieses Installationsprogramm unterstützt Raspberry Pi OS, Debian und Ubuntu."

say "Benötigte Pakete installieren …"
apt-get update -qq
apt-get install -y -qq python3 python3-venv curl ca-certificates >/dev/null

say "Spike herunterladen …"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
curl -fsSL "$REPO/archive/refs/heads/$BRANCH.tar.gz" | tar -xz -C "$TMP"
SRC=$(find "$TMP" -maxdepth 2 -type d -name spike | head -n1)
[ -d "$SRC/spike_server" ] || fail "Download unvollständig."

say "Spike installieren …"
id spike >/dev/null 2>&1 || useradd --system --home "$DATA_DIR" --shell /usr/sbin/nologin spike
mkdir -p "$APP_DIR" "$DATA_DIR"
rm -rf "$APP_DIR/spike_server"
cp -r "$SRC/spike_server" "$SRC/requirements.txt" "$APP_DIR/"
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install -q --upgrade pip
"$APP_DIR/venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"
chown -R spike:spike "$DATA_DIR"
chmod 700 "$DATA_DIR"

cat > /etc/systemd/system/spike.service <<UNIT
[Unit]
Description=Spike – Heimnetz-Sicherheit
After=network-online.target
Wants=network-online.target

[Service]
User=spike
Environment=SPIKE_DATA=$DATA_DIR
Environment=SPIKE_MODE=standalone
WorkingDirectory=$APP_DIR
ExecStart=$APP_DIR/venv/bin/python -m spike_server
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$DATA_DIR

[Install]
WantedBy=multi-user.target
UNIT

cat > /usr/local/bin/spike-reset-pairing <<RESET
#!/usr/bin/env bash
# Nur im Notfall: alle verbundenen Geräte entfernen.
set -e
systemctl stop spike
sudo -u spike SPIKE_DATA=$DATA_DIR $APP_DIR/venv/bin/python -m spike_server --reset-pairing
systemctl start spike
RESET
chmod 755 /usr/local/bin/spike-reset-pairing

systemctl daemon-reload
systemctl enable --now spike >/dev/null

sleep 3
if systemctl is-active --quiet spike; then
  say "Fertig! Spike läuft. Öffne jetzt die Spike-App, sie findet deinen Raspberry automatisch."
else
  fail "Spike ließ sich nicht starten. Details: journalctl -u spike"
fi
