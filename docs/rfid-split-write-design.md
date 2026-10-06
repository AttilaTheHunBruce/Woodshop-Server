# Woodshop RFID / Login-Server design (current, as-built)

Status: implemented and deployed. Supersedes the earlier signed-two-section
RFID design (kept below for history) — that design was paused before any
code was written and was **not** what got built. This reflects the actual
`app.py` / `master_server.py` as they stand in this repo, cross-checked
against `DEPLOY.md`.

## System overview

Two physically separate machines, connected via Ethernet, plus one ESP32
node per shop machine:

- **Server** (this repo, deployed to a Raspberry Pi 2B running DietPi):
  runs the machine-access TCP listener (`master_server.py`, port 35487)
  and the web admin app (`app.py`, Flask, port 80 via `authbind`). Holds
  `users.json` (memberID + permissions + metadata) purely as data — it no
  longer reads or writes RFID cards at all. No RTC/WWVB hardware, no
  independent time source; there never was any WWVB/DS3231 code in this
  repo to remove.
- **Login** (Lee's Raspberry Pi 5, separate hardware/codebase, not in this
  repo): the shop-door entry/exit terminal. Sends a login message on
  badge-in and a logout message on badge-out to Server over Ethernet, port
  45432. Also where member cards are written — see below.
- **Machine nodes** (ESP32, one per machine): unchanged 16-byte binary
  protocol to Server on port 35487 for authorization decisions. Also POST
  boot/reset diagnostics to `/diag/report`.

## RFID cards — no longer part of this system's trust model

The earlier two-section signed-card design (Ed25519 signatures, split
access/identity sections, memberID cross-check) was never built. What
actually shipped:

- Cards are **plaintext NTAG215**, written by Lee on his own machine using
  `WriteNTAG215.py` (ACR122U reader) — a separate tool, not part of this
  repo, driven from his own `members.csv`. No signing, no `cryptography`
  dependency anywhere in this codebase.
- Card layout: MemberID, a per-machine auth bitmask, first/last name.
- **The server never reads the card's bitmask.** Authorization is decided
  entirely from the `active_members` table (below), populated by Login's
  port-45432 messages and the permissions on file in `users.json` — the
  card's own bitmask is not consulted at runtime.
- Known-harmless mismatch: `WriteNTAG215.py`'s bitmask is 1-based (bit 0 =
  "Machine 1"), while `master_server.py`'s `MACHINES` dict and
  `is_authorized()` are 0-based. Since the server doesn't read the card
  bitmask, this only matters if something later goes back to reading it
  directly.
- `server_card_writer.py` (PN532/SPI card writer, `/admin/config-card`,
  Ed25519 signing) is gone from the server. `app.py` line ~534 marks this
  explicitly: *"Aug 2026: member-card RFID read/write/erase removed."*

## Login -> Server network message (as-built)

`LoginListener` in `master_server.py`, port 45432, one TCP connection per
message. **Plain ASCII, 52 bytes** (the design doc's original proposal was
a 54-byte binary struct with a `memberStatus` field — not what got built):

    messageType : 1 char   '0' = login, '1' = logout
    timestamp   : 15 chars 'YYYYMMDD HHMMSS'  (Login's own clock)
    memberID    : 4 chars  decimal, e.g. '1023'
    firstName   : 16 chars space-padded
    lastName    : 16 chars space-padded

No `memberStatus` field — eligibility is implicit in whether the member
has permissions on file.

On receipt:
- **Login** (`'0'`): `member_permissions(member_id)` looks up the current
  permission string fresh from `users.json`, then `INSERT OR REPLACE`s a
  row into `active_members` (member_id, first_name, last_name, login_time,
  permissions). `login_time` is parsed directly from the message's own
  timestamp — Server has no clock of its own to fall back to except
  `datetime.now()` if the timestamp fails to parse.
- **Logout** (`'1'`): `DELETE FROM active_members WHERE member_id = ?`.

## Server-side clock

Doesn't exist, and was never needed. `LoginListener`'s own docstring says
so: *"No clock-sync/SyncedClock step — Server doesn't need one for this."*
Every login/logout timestamp comes from Login's message, not from any
Server-side clock.

**Gap vs. the earlier design:** the original doc's midnight-reset job for
`active_members` (clearing stale rows at end of day) does not appear to
exist anywhere in `master_server.py` or `app.py` — there is no scheduled
job, timer thread, or cron reference. `active_members` rows are only
removed by an explicit logout message. Worth deciding whether that's
intentional (e.g. Login always sends logout messages, even at close) or a
real gap.

## Server-side data (as-built)

All paths are `BASE_DIR`-relative, where `BASE_DIR =
os.path.dirname(os.path.abspath(__file__))` in both `app.py` and
`master_server.py` independently (they happen to agree since both files
live in the same directory).

- `master.log` — process log (`app.py`'s `MASTER_LOG_FILE` /
  `master_server.py`'s `logging.FileHandler`). Also receives
  `BOOT/RESTART ...` lines from ESP32 diagnostic POSTs, interleaved
  chronologically with the rest of the log.
- `data/users.json` — member DB: memberID, permissions string, metadata
  (name, email, rfid UID, expiry, active flag, etc.). Still the source of
  truth for permissions; no longer used to drive card writing.
- `data/machines.json` — machine number -> name table.
- `data/access_log.csv` — CSV of machine-use events (`CSV_LOG_FILE` /
  `LOG_FILE`), written by `master_server.py`.
- `data/active_sessions.json` — used by `app.py`.
- `data/admin_creds.json` — web admin login credentials (default
  `admin`/`woodshop` on first run — change via `/admin/password`).
- `data/diag/diag_machine_N.jsonl` — capped per-machine JSONL diagnostic
  ring buffer, fed by `/diag/report`, surfaced on `/admin/diag`.
- `woodshop.db` — SQLite (`Database.db_path`, default
  `BASE_DIR/woodshop.db`). Tables: `sessions`, `machines`,
  `active_members` (member_id PK, first_name, last_name, login_time,
  permissions TEXT — a plain per-machine '0'/'1' string, not a packed
  bitmap; `is_authorized()` indexes it directly by `machine_number`).
  Write-through: every login/logout commits immediately, no periodic
  snapshotting.
- `firmware/` — OTA staging (`firmware.bin` + `version.txt`), toggled via
  `set_ota.py` (`UPDATE_AVAILABLE` flag in `master_server.py`, restarts
  `woodshop-tcp`).

Per `DEPLOY.md`, everything under `data/`, the sqlite db, `master.log`,
and `firmware/` is git-ignored — per-Pi runtime state, not part of a code
rebuild.

## Permissions model (as-built, simpler than the original design)

No 256-bit packed bitmap. `active_members.permissions` is a plain text
string of `'0'`/`'1'` characters snapshotted from `users.json` at login
time; `Database.is_authorized(member_id, machine_number)` does
`permissions[machine_number] == '1'`, 0-based, direct character indexing.
This is also the **sole runtime gate** for machine access — no active row,
or a `'0'` at that index, means denied (unless the physical override
switch is set).

## Effort / scope — status

- `server_card_writer.py` — deleted (was a leftover DEPRECATED stub;
  `DEPLOY.md` calls out deleting it, `requirements-nfc.txt`, and
  `deploy/gen_key.py` before pushing).
- `app.py` — user-management UI already reduced; no RFID read/write/erase
  UI remains.
- `master_server.py` — `active_members` table, port 45432
  `LoginListener`, write-through persistence, `is_authorized()` gate: all
  implemented and, per `DEPLOY.md`, confirmed correct with "no change
  needed."
- Login (Lee's Pi 5) — separate repo/hardware, not tracked here. Writes
  cards via `WriteNTAG215.py` (plaintext, ACR122U), runs the day-to-day
  login/logout reader, sends the 52-byte ASCII messages.
- ESP32 node firmware — unchanged binary protocol on port 35487; OTA
  flagging via `set_ota.py` unchanged.

## Open questions

- Is there supposed to be a midnight/end-of-day reset for stale
  `active_members` rows, or does Login's logout message always cover it?
  No such job exists in the current code.
- The 1-based (card bitmask) vs. 0-based (`is_authorized()`) mismatch is
  currently harmless because the card bitmask is never read server-side —
  flag if that ever changes.
- `members.csv` and `WriteNTAG215.py` live outside this repo on Lee's
  machine; no visibility here into their current field layout beyond what
  `DEPLOY.md` describes.
