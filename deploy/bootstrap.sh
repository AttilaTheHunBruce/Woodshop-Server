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
# Fill in REPO_URL below (or export WOODSHOP_REPO_URL before running).

set -euo pipefail

REPO_URL="${WOODSHOP_REPO_URL:-https://github.com/YOUR_USER/YOUR_REPO.git}"
BRANCH="${WOODSHOP_BRANCH:-main}"
APP_USER="woodshop"
APP_HOME="/home/${APP_USER}/woodshop"
VENV="${APP_HOME}/venv"

if [[ "${REPO_URL}" == *YOUR_USER/YOUR_REPO* ]]; then
    echo "ERROR: edit deploy/bootstrap.sh (or set WOODSHOP_REPO_URL) to point at your actual repo." >&2
    exit 1
fi

echo "==> [1/7] Installing system packages..."
sudo apt-get update
sudo apt-get install -y git python3 python3-venv python3-pip authbind sqlite3

echo "==> [2/7] Ensuring dedicated '${APP_USER}' service account exists..."
if ! id "${APP_USER}" &>/dev/null; then
    sudo useradd --create-home --shell /usr/sbin/nologin "${APP_USER}"
    echo "    Created ${APP_USER} (home /home/${APP_USER}, no login shell)."
else
    echo "    ${APP_USER} already exists -- leaving as is."
fi

echo "==> [3/7] Fetching source (${REPO_URL}, branch ${BRANCH})..."
if [ -d "${APP_HOME}/.git" ]; then
    echo "    Existing checkout found -- pulling latest."
    sudo -u "${APP_USER}" git -C "${APP_HOME}" fetch origin "${BRANCH}"
    sudo -u "${APP_USER}" git -C "${APP_HOME}" reset --hard "origin/${BRANCH}"
else
    echo "    No checkout yet -- cloning fresh."
    sudo -u "${APP_USER}" git clone --branch "${BRANCH}" "${REPO_URL}" "${APP_HOME}"
fi

echo "==> [4/7] Building Python venv and installing dependencies..."
sudo -u "${APP_USER}" python3 -m venv "${VENV}"
sudo -u "${APP_USER}" "${VENV}/bin/pip" install --upgrade pip
sudo -u "${APP_USER}" "${VENV}/bin/pip" install -r "${APP_HOME}/requirements.txt"

echo "==> [5/7] Ensuring runtime data directories exist (not tracked in git)..."
sudo -u "${APP_USER}" mkdir -p "${APP_HOME}/data/diag" "${APP_HOME}/firmware"

echo "==> [6/7] Configuring authbind so app.py can bind :80 as ${APP_USER}..."
sudo touch /etc/authbind/byport/80
sudo chown "${APP_USER}" /etc/authbind/byport/80
sudo chmod 500 /etc/authbind/byport/80

echo "==> [7/7] Installing systemd units and (re)starting services..."
sudo cp "${APP_HOME}/deploy/woodshop.service"     /etc/systemd/system/woodshop.service
sudo cp "${APP_HOME}/deploy/woodshop-tcp.service" /etc/systemd/system/woodshop-tcp.service
sudo systemctl daemon-reload
sudo systemctl enable woodshop woodshop-tcp
sudo systemctl restart woodshop woodshop-tcp

echo
echo "==> Done. Service status:"
sudo systemctl --no-pager --lines=0 status woodshop woodshop-tcp || true

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo
echo "==> Web UI:      http://${IP}/"
echo "==> TCP server:  ${IP}:35487  (machine controllers)"
echo "==> Login port:  ${IP}:45432  (login/logout)"
echo "==> Logs:        journalctl -u woodshop -f   /   journalctl -u woodshop-tcp -f"
