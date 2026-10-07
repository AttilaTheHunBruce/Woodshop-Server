#!/usr/bin/env bash
# Woodshop server: idempotent install / rebuild script for DietPi.
#
# First-time install AND every later "rebuild the whole server program"
# both run this same script:
#
#   curl -fsSL https://raw.githubusercontent.com/<you>/<repo>/main/deploy/bootstrap.sh | bash
#
# It's safe to re-run any time: pulls the latest code, rebuilds the venv,
# and restarts both services. It never touches data/, the sqlite db, or the
# access log -- those live outside git and survive every rebuild.
#
# It also keeps reference copies of the CLIENT firmware source and the
# system DOCUMENTATION on the Pi (step 8), so everything needed to maintain
# the system can be found in one place:
#
#   ~/README.txt           map of where everything is
#   ~/woodshop/            server source (the running code)
#   ~/reference/Client/    ESP32 client firmware (Arduino sketch)
#   ~/reference/Docs/      system document (PDF / Markdown)
#
# Fill in REPO_URL below (or export WOODSHOP_REPO_URL before running).
# Override the other repos with WOODSHOP_CLIENT_URL / WOODSHOP_DOCS_URL.

set -euo pipefail

REPO_URL="${WOODSHOP_REPO_URL:-https://github.com/AttilaTheHunBruce/Woodshop-Server.git}"
CLIENT_URL="${WOODSHOP_CLIENT_URL:-https://github.com/AttilaTheHunBruce/Woodshop-Client.git}"
DOCS_URL="${WOODSHOP_DOCS_URL:-https://github.com/AttilaTheHunBruce/Woodshop-Docs.git}"
BRANCH="${WOODSHOP_BRANCH:-main}"
APP_USER="woodshop"
APP_HOME="/home/${APP_USER}/woodshop"
REF_DIR="/home/${APP_USER}/reference"
VENV="${APP_HOME}/venv"

if [[ "${REPO_URL}" == *YOUR_USER/YOUR_REPO* ]]; then
    echo "ERROR: edit deploy/bootstrap.sh (or set WOODSHOP_REPO_URL) to point at your actual repo." >&2
    exit 1
fi

echo "==> [1/8] Installing system packages..."
sudo apt-get update
sudo apt-get install -y git python3 python3-venv python3-pip authbind sqlite3

echo "==> [2/8] Ensuring dedicated '${APP_USER}' service account exists..."
if ! id "${APP_USER}" &>/dev/null; then
    sudo useradd --create-home --shell /usr/sbin/nologin "${APP_USER}"
    echo "    Created ${APP_USER} (home /home/${APP_USER}, no login shell)."
else
    echo "    ${APP_USER} already exists -- leaving as is."
fi
# Needed for gpiozero to open /dev/gpiochip0 for the status LEDs.
sudo usermod -aG gpio "${APP_USER}"
# SPI access for the admin-card reader (rfid_admin_card.py); group may not exist.
getent group spi >/dev/null && sudo usermod -aG spi "${APP_USER}" || true

echo "==> [3/8] Fetching source (${REPO_URL}, branch ${BRANCH})..."
if [ -d "${APP_HOME}/.git" ]; then
    echo "    Existing checkout found -- pulling latest."
    sudo -u "${APP_USER}" git -C "${APP_HOME}" fetch origin "${BRANCH}"
    sudo -u "${APP_USER}" git -C "${APP_HOME}" reset --hard "origin/${BRANCH}"
else
    echo "    No checkout yet -- cloning fresh."
    sudo -u "${APP_USER}" git clone --branch "${BRANCH}" "${REPO_URL}" "${APP_HOME}"
fi

echo "==> [4/8] Building Python venv and installing dependencies..."
sudo -u "${APP_USER}" python3 -m venv "${VENV}"
sudo -u "${APP_USER}" "${VENV}/bin/pip" install --upgrade pip
sudo -u "${APP_USER}" "${VENV}/bin/pip" install -r "${APP_HOME}/requirements.txt"
# Card-reader libraries for the Admin Card page. Optional: warn, never fail.
if [ -f "${APP_HOME}/requirements-card.txt" ]; then
    sudo -u "${APP_USER}" "${VENV}/bin/pip" install -r "${APP_HOME}/requirements-card.txt" \
        || echo "    WARNING: card reader libraries not installed -- the Admin Card page will report an error until they are (SPI must also be enabled)." >&2
fi

echo "==> [5/8] Ensuring runtime data directories exist (not tracked in git)..."
sudo -u "${APP_USER}" mkdir -p "${APP_HOME}/data/diag" "${APP_HOME}/firmware"

echo "==> [6/8] Configuring authbind so app.py can bind :80 as ${APP_USER}..."
sudo touch /etc/authbind/byport/80
sudo chown "${APP_USER}" /etc/authbind/byport/80
sudo chmod 500 /etc/authbind/byport/80

echo "==> [7/8] Installing systemd units and (re)starting services..."
sudo cp "${APP_HOME}/deploy/woodshop.service"     /etc/systemd/system/woodshop.service
sudo cp "${APP_HOME}/deploy/woodshop-tcp.service" /etc/systemd/system/woodshop-tcp.service
sudo systemctl daemon-reload
sudo systemctl enable woodshop woodshop-tcp
sudo systemctl restart woodshop woodshop-tcp

# ---------------------------------------------------------------------------
# Step 8: reference copies (client source + docs). Failure here is reported
# but never stops the install -- the running server does not depend on them.
# ---------------------------------------------------------------------------
echo "==> [8/8] Updating reference copies (client source, documentation)..."
sudo -u "${APP_USER}" mkdir -p "${REF_DIR}"

sync_ref() {   # sync_ref <folder-name> <git-url>
    local name="$1" url="$2" dir="${REF_DIR}/$1"
    if [ -d "${dir}/.git" ]; then
        sudo -u "${APP_USER}" git -C "${dir}" fetch origin "${BRANCH}" \
            && sudo -u "${APP_USER}" git -C "${dir}" reset --hard "origin/${BRANCH}" \
            && echo "    ${name}: updated." \
            || echo "    WARNING: could not update ${name} (continuing)." >&2
    else
        sudo -u "${APP_USER}" git clone --branch "${BRANCH}" "${url}" "${dir}" \
            && echo "    ${name}: cloned." \
            || echo "    WARNING: could not clone ${name} from ${url} (continuing)." >&2
    fi
}
sync_ref Client "${CLIENT_URL}"
sync_ref Docs   "${DOCS_URL}"

sudo -u "${APP_USER}" tee "/home/${APP_USER}/README.txt" >/dev/null <<'EOF'
WOODSHOP ACCESS CONTROL - where everything is
=============================================
  ~/woodshop/            Server source (the running code): app.py,
                         master_server.py, set_ota.py, deploy/
  ~/woodshop/data/       Live members, machines, logs, daily CSVs
                         (NOT in git -- back this up)
  ~/reference/Client/    ESP32 machine-client firmware (Arduino sketch;
                         open Client.ino in the Arduino IDE)
  ~/reference/Docs/      System document (PDF / Markdown): START HERE

Services:  woodshop (web, port 80)   woodshop-tcp (machines 35487, kiosk 45432)
Rebuild / update everything:  run deploy/bootstrap.sh (Docs, section 13)
Source repos: github.com/AttilaTheHunBruce/Woodshop-Server, -Client, -Docs
EOF

echo
echo "==> Done. Service status:"
sudo systemctl --no-pager --lines=0 status woodshop woodshop-tcp || true

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo
echo "==> Web UI:      http://${IP}/"
echo "==> TCP server:  ${IP}:35487  (machine controllers)"
echo "==> Login port:  ${IP}:45432  (login/logout)"
echo "==> Logs:        journalctl -u woodshop -f   /   journalctl -u woodshop-tcp -f"
echo "==> Reference:   ${REF_DIR}/Client, ${REF_DIR}/Docs  (see /home/${APP_USER}/README.txt)"
