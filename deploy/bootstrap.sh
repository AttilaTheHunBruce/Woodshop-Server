#!/usr/bin/env bash
# Woodshop server: idempotent install / rebuild script for Raspberry Pi OS
# (Raspbian).
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
# system DOCUMENTATION on the Pi (step 9), so everything needed to maintain
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

echo "==> [1/10] Installing system packages..."
sudo apt-get update
# python3-dev + gcc: requirements-card.txt's Adafruit-Blinka pulls in RPi.GPIO
# as its backend on 32-bit Pi OS, which pip builds from source -- without
# these the build fails quietly (step 6 only warns, it doesn't stop the
# script) and the Admin Card page ends up unable to import board/busio.
sudo apt-get install -y git python3 python3-venv python3-pip python3-dev gcc authbind sqlite3

echo "==> [2/10] Enabling SPI (needed for the PN532 admin-card reader)..."
# Adding the 'woodshop' user to the spi group (below) only helps once the SPI
# interface itself is turned on -- on a clean image it isn't, and the PN532
# reader can't be talked to at all until it is ("Failed to detect the PN532"
# from rfid_admin_card.py is the symptom). This needs a reboot to take effect
# -- see the note this script prints at the end if it just turned SPI on for
# the first time.
SPI_NEEDS_REBOOT=0
if command -v raspi-config >/dev/null 2>&1; then
    # Raspberry Pi OS / Raspbian: raspi-config is the supported, scriptable way
    # to do this ('do_spi 0' enables; it's a no-op if SPI is already on).
    SPI_WAS="$(raspi-config nonint get_spi 2>/dev/null || echo 1)"   # 0=enabled, 1=disabled
    sudo raspi-config nonint do_spi 0
    if [[ "${SPI_WAS}" != "0" ]]; then
        echo "    SPI enabled via raspi-config -- a reboot is needed before it takes effect."
        SPI_NEEDS_REBOOT=1
    else
        echo "    SPI already enabled."
    fi
else
    # Fallback for images without raspi-config (e.g. DietPi): edit config.txt directly.
    CONFIG_TXT="/boot/firmware/config.txt"
    [ -f "${CONFIG_TXT}" ] || CONFIG_TXT="/boot/config.txt"
    if [ ! -f "${CONFIG_TXT}" ]; then
        echo "    WARNING: no raspi-config and no config.txt found -- enable SPI manually." >&2
    elif sudo grep -qE '^[[:space:]]*dtparam=spi=on[[:space:]]*$' "${CONFIG_TXT}"; then
        echo "    SPI already enabled in ${CONFIG_TXT}."
    else
        if sudo grep -qE '^[[:space:]]*#[[:space:]]*dtparam=spi=on[[:space:]]*$' "${CONFIG_TXT}"; then
            sudo sed -i -E 's/^[[:space:]]*#[[:space:]]*dtparam=spi=on[[:space:]]*$/dtparam=spi=on/' "${CONFIG_TXT}"
        else
            printf '\ndtparam=spi=on\n' | sudo tee -a "${CONFIG_TXT}" >/dev/null
        fi
        echo "    Added 'dtparam=spi=on' to ${CONFIG_TXT} -- a reboot is needed before it takes effect."
        SPI_NEEDS_REBOOT=1
    fi
fi

echo "==> [3/10] Configuring static IP (host .5 on the server's own subnet) if not already done..."
# The server is always host .5 on whatever subnet it's plugged into -- this is
# the same convention the ESP32 client firmware uses to find the server
# without hardcoding an address (SERVER_HOST_BYTE in config.h). We derive the
# actual subnet from the address DHCP handed out the first time this runs,
# then pin it, so this works unattended on any site's router.
#
# Raspberry Pi OS / Raspbian manages networking with dhcpcd by default, and
# dhcpcd is SUPPOSED to be running -- it has its own built-in static-address
# support, so this leaves it installed and active rather than touching it.
# (Only on newer Bookworm-based images, which use NetworkManager instead, do
# we go a different route -- detected below.)
STATIC_MARKER="# Managed by woodshop bootstrap.sh -- static IP, do not hand-edit"

configure_static_ip() {
    local iface cur_cidr gateway cur_ip prefix subnet static_ip dns conn new_ip

    iface="$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')"
    cur_cidr="$(ip -4 -o addr show dev "${iface}" 2>/dev/null | awk '{print $4; exit}')"
    gateway="$(ip -4 route show default 2>/dev/null | awk '{print $3; exit}')"

    if [[ -z "${iface}" || -z "${cur_cidr}" || -z "${gateway}" ]]; then
        echo "    WARNING: could not determine the current interface/address/gateway" >&2
        echo "    -- skipping static IP setup; the machine will keep its DHCP address." >&2
        return
    fi

    cur_ip="${cur_cidr%/*}"
    prefix="${cur_cidr#*/}"
    subnet="${cur_ip%.*}"
    static_ip="${subnet}.5"

    # Keep whatever DNS servers DHCP handed out rather than guessing; fall
    # back to the gateway itself if resolv.conf has nothing usable.
    dns="$(awk '/^nameserver/{print $2}' /etc/resolv.conf 2>/dev/null | paste -sd' ' -)"
    dns="${dns:-${gateway}}"

    echo "    ${iface} is currently ${cur_ip}/${prefix} (DHCP) via gateway ${gateway}."
    echo "    Pinning it to ${static_ip} (DNS: ${dns})."
    echo "    NOTE: if you're on SSH to the DHCP address above, this will drop your"
    echo "          session -- reconnect at ${static_ip} afterwards."

    if command -v nmcli >/dev/null 2>&1 && systemctl is-active --quiet NetworkManager 2>/dev/null; then
        conn="$(nmcli -t -f NAME,DEVICE connection show --active | awk -F: -v d="${iface}" '$2==d{print $1; exit}')"
        if [[ -z "${conn}" ]]; then
            echo "    WARNING: no active NetworkManager connection found for ${iface} -- skipping." >&2
            return
        fi
        sudo nmcli connection modify "${conn}" \
            ipv4.method manual ipv4.addresses "${static_ip}/${prefix}" \
            ipv4.gateway "${gateway}" ipv4.dns "${dns}"
        sudo mkdir -p /etc/woodshop
        echo "${STATIC_MARKER}" | sudo tee /etc/woodshop/static-ip-configured >/dev/null
        sudo nmcli connection up "${conn}"
    elif [ -f /etc/dhcpcd.conf ]; then
        # Strip any pre-existing block for this interface first, rather than
        # appending next to one -- a leftover/duplicate 'interface' block, or
        # 'static ...' lines left outside one, is exactly how a second,
        # dynamic address ends up alongside the static one.
        sudo awk -v iface="${iface}" '
            $1=="interface" && $2==iface { skip=1; next }
            skip && /^[[:space:]]*$/      { skip=0; next }
            skip && $1=="static"          { next }
            { skip=0; print }
        ' /etc/dhcpcd.conf | sudo tee /etc/dhcpcd.conf.new >/dev/null

        sudo tee -a /etc/dhcpcd.conf.new >/dev/null <<EOF

${STATIC_MARKER}
interface ${iface}
static ip_address=${static_ip}/${prefix}
static routers=${gateway}
static domain_name_servers=${dns}
EOF
        sudo mv /etc/dhcpcd.conf.new /etc/dhcpcd.conf
        sudo systemctl restart dhcpcd
    else
        echo "    WARNING: neither NetworkManager nor /etc/dhcpcd.conf found -- configure the static IP manually." >&2
        return
    fi

    sleep 2
    new_ip="$(ip -4 -o addr show dev "${iface}" 2>/dev/null | awk '{print $4; exit}')"
    if [[ "${new_ip%/*}" == "${static_ip}" ]]; then
        echo "    ${iface} is now ${new_ip} (static)."
    else
        echo "    WARNING: expected ${static_ip}, interface reports '${new_ip:-nothing}' -- check manually." >&2
    fi
}

ALREADY_STATIC=0
sudo grep -qF "${STATIC_MARKER}" /etc/dhcpcd.conf 2>/dev/null && ALREADY_STATIC=1
[ -f /etc/woodshop/static-ip-configured ] && ALREADY_STATIC=1

if [[ "${ALREADY_STATIC}" == "1" ]]; then
    echo "    Static IP already configured -- leaving network settings as is."
else
    configure_static_ip
fi

echo "==> [4/10] Ensuring dedicated '${APP_USER}' service account exists..."
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

echo "==> [5/10] Fetching source (${REPO_URL}, branch ${BRANCH})..."
if [ -d "${APP_HOME}/.git" ]; then
    echo "    Existing checkout found -- pulling latest."
    sudo -u "${APP_USER}" git -C "${APP_HOME}" fetch origin "${BRANCH}"
    sudo -u "${APP_USER}" git -C "${APP_HOME}" reset --hard "origin/${BRANCH}"
else
    echo "    No checkout yet -- cloning fresh."
    sudo -u "${APP_USER}" git clone --branch "${BRANCH}" "${REPO_URL}" "${APP_HOME}"
fi

echo "==> [6/10] Building Python venv and installing dependencies..."
sudo -u "${APP_USER}" python3 -m venv "${VENV}"
sudo -u "${APP_USER}" "${VENV}/bin/pip" install --upgrade pip
sudo -u "${APP_USER}" "${VENV}/bin/pip" install -r "${APP_HOME}/requirements.txt"
# Card-reader libraries for the Admin Card page. Optional: warn, never fail.
if [ -f "${APP_HOME}/requirements-card.txt" ]; then
    sudo -u "${APP_USER}" "${VENV}/bin/pip" install -r "${APP_HOME}/requirements-card.txt" \
        || echo "    WARNING: card reader libraries not installed -- the Admin Card page will report an error until they are (SPI must also be enabled)." >&2
fi

echo "==> [7/10] Ensuring runtime data directories exist (not tracked in git)..."
sudo -u "${APP_USER}" mkdir -p "${APP_HOME}/data/diag" "${APP_HOME}/firmware"

echo "==> [8/10] Configuring authbind so app.py can bind :80 as ${APP_USER}..."
sudo touch /etc/authbind/byport/80
sudo chown "${APP_USER}" /etc/authbind/byport/80
sudo chmod 500 /etc/authbind/byport/80

echo "==> [9/10] Installing systemd units and (re)starting services..."
sudo cp "${APP_HOME}/deploy/woodshop.service"     /etc/systemd/system/woodshop.service
sudo cp "${APP_HOME}/deploy/woodshop-tcp.service" /etc/systemd/system/woodshop-tcp.service
sudo systemctl daemon-reload
sudo systemctl enable woodshop woodshop-tcp
sudo systemctl restart woodshop woodshop-tcp

# ---------------------------------------------------------------------------
# Step 10: reference copies (client source + docs). Failure here is reported
# but never stops the install -- the running server does not depend on them.
# ---------------------------------------------------------------------------
echo "==> [10/10] Updating reference copies (client source, documentation)..."
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

if [[ "${SPI_NEEDS_REBOOT:-0}" == "1" ]]; then
    echo
    echo "==> IMPORTANT: SPI was just enabled for the first time."
    echo "    The Admin Card page / rfid_admin_card.py will report 'Failed to"
    echo "    detect the PN532' until you reboot: sudo reboot"
fi
