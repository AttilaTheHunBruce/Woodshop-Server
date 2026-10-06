#!/usr/bin/env python3
"""
set_ota.py  —  Set the UPDATE_AVAILABLE flag in master_server.py
               and restart the woodshop-tcp service.

Usage:
    python3 set_ota.py true    # enable OTA — nodes will download on next reboot
    python3 set_ota.py false   # disable OTA — nodes will skip download
    python3 set_ota.py status  # show current setting

Run with sudo if systemctl restart requires it.
"""

import sys
import os
import re
import subprocess

MASTER_SERVER = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "master_server.py")
SERVICE = "woodshop-tcp"


def get_current(text):
    m = re.search(r'^UPDATE_AVAILABLE\s*=\s*(True|False)', text, re.MULTILINE)
    return m.group(1) if m else None


def set_flag(text, value):
    new_line = "UPDATE_AVAILABLE = {}".format(value)
    result, count = re.subn(
        r'^UPDATE_AVAILABLE\s*=\s*(True|False)',
        new_line,
        text,
        flags=re.MULTILINE
    )
    if count == 0:
        raise ValueError("UPDATE_AVAILABLE not found in master_server.py")
    return result


def restart_service():
    result = subprocess.run(
        ["sudo", "systemctl", "restart", SERVICE],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print("WARNING: systemctl restart failed: {}".format(result.stderr.strip()))
        return False
    # Kill any stale process still holding the port
    port_result = subprocess.run(
        ["sudo", "ss", "-tlnp"],
        capture_output=True, text=True
    )
    for line in port_result.stdout.splitlines():
        if "35487" in line:
            m = re.search(r'pid=(\d+)', line)
            if m:
                pid = m.group(1)
                subprocess.run(["sudo", "kill", pid], capture_output=True)
                print("Killed stale process pid={}".format(pid))
    return True


def main():
    if len(sys.argv) != 2 or sys.argv[1].lower() in ("-h", "--help", "help"):
        print(__doc__)
        sys.exit(0)

    arg = sys.argv[1].lower()

    with open(MASTER_SERVER, "r") as f:
        text = f.read()

    current = get_current(text)

    if arg == "status":
        print("UPDATE_AVAILABLE = {}".format(current or "not found"))
        sys.exit(0)

    if arg in ("true", "1", "yes", "on"):
        new_value = "True"
    elif arg in ("false", "0", "no", "off"):
        new_value = "False"
    else:
        print("Error: argument must be true or false (got '{}')".format(sys.argv[1]))
        sys.exit(1)

    if current == new_value:
        print("UPDATE_AVAILABLE is already {}, no change needed.".format(new_value))
        sys.exit(0)

    updated = set_flag(text, new_value)
    with open(MASTER_SERVER, "w") as f:
        f.write(updated)
    print("UPDATE_AVAILABLE set to {}.".format(new_value))

    print("Restarting {}...".format(SERVICE))
    if restart_service():
        print("Done. Service restarted successfully.")
    else:
        print("Service restart had issues — check 'sudo systemctl status {}'.".format(SERVICE))


if __name__ == "__main__":
    main()
