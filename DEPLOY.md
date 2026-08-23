# Deploying the Woodshop server to DietPi (Raspberry Pi 2B)

## What changed from the last working version

**Path portability.** The server used to hardcode `/home/pi/woodshop` in
several places (`app.py`'s `MASTER_LOG_FILE`, `master_server.py`'s log
handler, `USERS_FILE`, `CSV_LOG_FILE`, and `Database`'s default
`db_path`). DietPi's default account is `dietpi`, not `pi`, so those paths
would have pointed nowhere. They're now derived from `BASE_DIR`
(`os.path.dirname(os.path.abspath(__file__))`), same pattern the rest of
`app.py` already used. The two `.service` files match: `User=dietpi`,
`WorkingDirectory=/home/dietpi/woodshop`.

**No more card reading/writing on the server.** The server used to run a
PN532 NFC reader over SPI to write signed "config cards" (`/admin/config-
card`, `_run_config_card_write`, `server_card_writer.py`, Ed25519 signing).
That's all gone now — the server doesn't touch RFID/NFC hardware at all.
Member cards are written entirely on Lee's machine with `WriteNTAG215.py`
(plaintext NTAG215 layout via an ACR122U reader, no signing, not part of
this project). `cryptography` is no longer a dependency.

**Delete these three files before you push to your repo** — they're
leftover stubs from files this cleanup made obsolete (left behind, marked
`DEPRECATED`, since Claude's output folder can't delete files it already
wrote):
- `server_card_writer.py`
- `requirements-nfc.txt`
- `deploy/gen_key.py`

**Login/logout and access control — already correct, no change needed.**
`master_server.py`'s `LoginListener` on port 45432 already matches the
spec exactly: fixed 52-byte ASCII message (`messageType` 1 char +
`timestamp` 15 chars `YYYYMMDD HHMMSS` + `memberID` 4 chars + `firstName`
16 chars + `lastName` 16 chars), `'0'` = login / `'1'` = logout. Login
inserts/replaces a row in the `active_members` SQLite table (with
permissions snapshotted from `users.json` at login time); logout deletes
it. `Database.is_authorized()` is the sole gate a machine-controller
INSERT event checks (unless the physical override switch is set) — no
active row, or a permission bit of `0`, means denied, exactly as before.
SQLite gives this write-through durability across a power outage for
free.

**Boot/restart diagnostics — already correct, no change needed.** Each
ESP32 node's ring-buffer of boot/reset codes POSTs to `/diag/report`,
which appends a `BOOT/RESTART ...` line to `master.log` (the same file
`master_server.py`'s own logger writes to, so it interleaves
chronologically) and also keeps a capped JSONL file per machine under
`data/diag/`. It's shown only on its own `/admin/diag` page — not on the
dashboard — so it's already "there when you go looking for it" rather
than always in view.

**No RTC/timekeeping hardware.** There was never any WWVB/DS3231 code in
`app.py` or `master_server.py` to remove — Login supplies the timestamp
for every login/logout message, and the server has no independent clock
dependency. Nothing to do here.

## One-time setup, first Pi

1. **Delete the three deprecated files** listed above, then push this
   tree to your git repo (the one `deploy/bootstrap.sh` pulls from). Edit
   `deploy/bootstrap.sh` and set `REPO_URL` to your repo's clone URL, or
   export `WOODSHOP_REPO_URL` before running it.

2. **On the Pi**, confirm SSH works, then run the bootstrap script:

   ```bash
   curl -fsSL https://raw.githubusercontent.com/YOUR_USER/YOUR_REPO/main/deploy/bootstrap.sh | bash
   ```

   Same command for first install and every later "rebuild the whole
   server program." It:

   - installs `git`, `python3-venv`, `authbind`, `sqlite3`
   - clones (or `fetch` + `reset --hard`s) the repo into `/home/dietpi/woodshop`
   - builds/rebuilds the venv and installs `requirements.txt` (just Flask now)
   - creates `data/` and `firmware/` if missing (never overwrites them)
   - sets up `authbind` so `app.py` can bind port 80 as a non-root user
   - installs the two systemd units and restarts both services

3. **Check it's up:**

   ```bash
   sudo systemctl status woodshop woodshop-tcp
   curl http://localhost/          # web admin UI
   ```

   Default admin login is created on first run of `app.py`:
   `admin` / `woodshop` — **change this immediately** from
   `/admin/password` once you're in.

## Rebuilding after code changes

Same command, any time:

```bash
curl -fsSL https://raw.githubusercontent.com/YOUR_USER/YOUR_REPO/main/deploy/bootstrap.sh | bash
```

Idempotent — pulls latest `main`, reinstalls dependencies, restarts
services. Nothing under `data/`, the sqlite db, or `master.log` is
touched (all git-ignored, see `.gitignore`).

If you only changed Python and don't need the full apt/venv pass:

```bash
cd /home/dietpi/woodshop
git pull
sudo systemctl restart woodshop woodshop-tcp
```

## Things that stay outside git (per-Pi, not part of a "rebuild")

- `data/users.json`, `data/machines.json`, `data/admin_creds.json`,
  `data/active_sessions.json`, `data/diag/` — runtime state
- `access_log.csv`, `master.log`, `woodshop.db`
- `firmware/firmware.bin` + `firmware/version.txt` — staged separately
  per the OTA workflow documented at the top of the "OTA Firmware
  endpoints" section in `app.py`.

## Member RFID cards

Not the server's job. Lee writes/updates member cards with
`WriteNTAG215.py` on his own machine (ACR122U reader, plaintext NTAG215
layout: MemberID, per-machine auth bitmask, first/last name — no
signing). That tool and `members.csv` live outside this repo.

One thing worth flagging, not fixed here since it's a live protocol
question rather than a bug: `WriteNTAG215.py`'s machine-auth bitmask is
1-based (bit 0 of page 5 = "Machine 1"), while `master_server.py`'s
`MACHINES` dict and `is_authorized()` are 0-based (`0: "Table Saw"`,
indexing straight into the permission string by `machine_number`). As
long as access is decided purely from the `active_members` permission
string set by Login (which is what `is_authorized()` actually checks —
the card's own bitmask isn't read by the server at all anymore), this
mismatch is harmless. It'd only matter if something ever went back to
reading the card's bitmask directly.

## Flipping OTA for the ESP32 nodes

Unchanged — `set_ota.py` still edits the `UPDATE_AVAILABLE` flag in
`master_server.py` and restarts `woodshop-tcp`:

```bash
cd /home/dietpi/woodshop
sudo venv/bin/python set_ota.py true    # or false / status
```
