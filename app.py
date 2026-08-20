#!/usr/bin/env python3
"""
Woodshop Access Control - Web Backend
Runs on Raspberry Pi, accessible via browser on tablet/phone over WiFi.

Usage:
    python3 app.py

Then browse to http://<pi-ip> from any device on the same WiFi.
"""
__version__ = "1.0.0"

import os
import json
import csv
import hashlib
import secrets
import socket
import struct
import subprocess
import threading
from datetime import datetime, timedelta
from functools import wraps
from flask import (Flask, render_template_string, request, redirect,
                   url_for, session, jsonify, flash, make_response)

# ── Configuration ─────────────────────────────────────────────────────────────

BASE_DIR       = os.path.dirname(os.path.abspath(__file__))
LOG_FILE       = os.path.join(BASE_DIR, "data", "access_log.csv")
USERS_FILE     = os.path.join(BASE_DIR, "data", "users.json")
MACHINES_FILE  = os.path.join(BASE_DIR, "data", "machines.json")
ACTIVE_FILE    = os.path.join(BASE_DIR, "data", "active_sessions.json")
ADMIN_CREDS    = os.path.join(BASE_DIR, "data", "admin_creds.json")

# ── Membership settings ───────────────────────────────────────────────────────
MEMBERSHIP_GRACE_DAYS   = 90   # Days after Dec 31 before access is cut off (default: 90 = April 1)
MEMBERSHIP_YEAR_END_MON = 12   # Month membership year ends
MEMBERSHIP_YEAR_END_DAY = 31   # Day membership year ends

def membership_expiry_for_year(year: int) -> 'datetime':
    """Return the effective card expiry (year-end + grace) for a given membership year."""
    from datetime import date
    year_end = datetime(year, MEMBERSHIP_YEAR_END_MON, MEMBERSHIP_YEAR_END_DAY)
    return year_end + timedelta(days=MEMBERSHIP_GRACE_DAYS)

def default_expiry_date() -> str:
    """Return Dec 31 of current year as YYYY-MM-DD string."""
    return datetime.now().strftime(f"%Y-{MEMBERSHIP_YEAR_END_MON:02d}-{MEMBERSHIP_YEAR_END_DAY:02d}")

def is_membership_current(user: dict) -> bool:
    """True if user is active AND membership has not lapsed past the grace period."""
    if not user.get('active', True):
        return False
    expiry_str = user.get('expiry', '')
    if not expiry_str:
        return True   # no expiry set → assume current
    try:
        expiry = datetime.strptime(expiry_str, '%Y-%m-%d')
        effective = expiry + timedelta(days=MEMBERSHIP_GRACE_DAYS)
        return datetime.now() <= effective
    except ValueError:
        return True

# Log CSV columns — must match master_server.py log_csv_remove() header
LOG_COLS = [
    "timestamp", "member_id", "member_name",
    "machine_number", "machine_name",
    "start_time", "stop_time",
    "connect_time_s", "machine_on_s",
    "avg_current_A", "starts"
]
# Legacy 6-column format (IN/OUT events written by older firmware)
LOG_COLS_LEGACY = ["timestamp", "user_id", "user_name", "machine_id", "machine_name", "event"]

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)   # regenerates on restart; fine for a local tool

# ── Helpers ───────────────────────────────────────────────────────────────────

def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def load_json(path: str, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default

def save_json(path: str, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def read_log() -> list[dict]:
    rows = []
    try:
        with open(LOG_FILE, newline="") as f:
            reader = csv.reader(f)
            for raw in reader:
                if not raw:
                    continue
                # Skip header rows written by master_server.py
                if raw[0].strip().lower() in ("timestamp", "date"):
                    continue
                if len(raw) >= len(LOG_COLS):
                    # New 11-column format
                    row = dict(zip(LOG_COLS, raw))
                    # Aliases for backwards-compat with filter/display code
                    row.setdefault("user_id",   row.get("member_id", ""))
                    row.setdefault("user_name", row.get("member_name", ""))
                    row.setdefault("machine_id",row.get("machine_number", ""))
                    row.setdefault("event",     "SESSION")
                elif len(raw) >= len(LOG_COLS_LEGACY):
                    # Old 6-column IN/OUT format
                    row = dict(zip(LOG_COLS_LEGACY, raw))
                    row.setdefault("user_id",    row.get("user_id", ""))
                    row.setdefault("member_id",  row.get("user_id", ""))
                    row.setdefault("member_name",row.get("user_name", ""))
                    row.setdefault("machine_number", row.get("machine_id", ""))
                    row.setdefault("start_time", row.get("timestamp", ""))
                    row.setdefault("stop_time",  "")
                    row.setdefault("connect_time_s", "")
                    row.setdefault("machine_on_s",   "")
                    row.setdefault("avg_current_A",  "")
                    row.setdefault("starts",         "")
                else:
                    continue
                rows.append(row)
    except FileNotFoundError:
        pass
    return rows

def filter_log(rows, machine=None, user=None,
               date_from=None, date_to=None, last_n=None) -> list[dict]:
    """Apply filters to log rows. All params are optional."""
    if machine:
        machine_lc = machine.lower()
        rows = [r for r in rows
                if machine_lc in r.get("machine_name", "").lower()
                or machine_lc in r.get("machine_number", r.get("machine_id", "")).lower()]
    if user:
        user_lc = user.lower()
        rows = [r for r in rows
                if user_lc in r.get("member_name", r.get("user_name", "")).lower()
                or user_lc in str(r.get("member_id", r.get("user_id", ""))).lower()]
    if date_from:
        rows = [r for r in rows if r["timestamp"] >= date_from]
    if date_to:
        # Include the full end day
        end = date_to + " 23:59:59"
        rows = [r for r in rows if r["timestamp"] <= end]
    if last_n:
        try:
            rows = rows[-int(last_n):]
        except ValueError:
            pass
    return rows

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated

def check_admin(username: str, password: str) -> bool:
    creds = load_json(ADMIN_CREDS, {})
    return (creds.get("username") == username and
            creds.get("password_hash") == hash_password(password))

# ── Seed demo data if files don't exist ───────────────────────────────────────

def seed_demo_data():
    os.makedirs(os.path.join(BASE_DIR, "data"), exist_ok=True)

    if not os.path.exists(ADMIN_CREDS):
        save_json(ADMIN_CREDS, {
            "username": "admin",
            "password_hash": hash_password("woodshop")
        })
        print("Created admin_creds.json  →  user: admin  password: woodshop")

    if not os.path.exists(USERS_FILE):
        this_year_expiry = default_expiry_date()
        save_json(USERS_FILE, [
            {"id": 1001, "first_name": "Alice",   "last_name": "Smith",
             "email": "alice@example.com",  "phone": "555-1001",
             "rfid": "AABBCCDD", "active": True,
             "joined": "2024-01-01", "expiry": this_year_expiry,
             "permissions": "11000000" + "0"*120},
            {"id": 1002, "first_name": "Bob",     "last_name": "Jones",
             "email": "bob@example.com",    "phone": "555-1002",
             "rfid": "11223344", "active": True,
             "joined": "2024-03-15", "expiry": this_year_expiry,
             "permissions": "10000000" + "0"*120},
            {"id": 1003, "first_name": "Charlie", "last_name": "Brown",
             "email": "", "phone": "555-1003",
             "rfid": "DEADBEEF", "active": False,
             "joined": "2023-06-01", "expiry": "2024-12-31",
             "permissions": "0"*128}
        ])

    if not os.path.exists(MACHINES_FILE):
        save_json(MACHINES_FILE, [
            {"id": "1",  "name": "Table Saw",    "location": "Center Bay",  "enabled": True},
            {"id": "2",  "name": "Band Saw",     "location": "North Wall",  "enabled": True},
            {"id": "3",  "name": "Drill Press",  "location": "South Wall",  "enabled": True},
            {"id": "4",  "name": "Jointer",      "location": "East Bay",    "enabled": True},
            {"id": "5",  "name": "Planer",       "location": "East Bay",    "enabled": True},
            {"id": "6",  "name": "Lathe",        "location": "West Bay",    "enabled": True},
            {"id": "7",  "name": "Router Table", "location": "Center Bay",  "enabled": True},
            {"id": "8",  "name": "Scroll Saw",   "location": "South Wall",  "enabled": True},
        ])

    if not os.path.exists(LOG_FILE):
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        sample_rows = [
            ["2025-02-20 08:00:00","1001","Alice Smith","1","Table Saw","IN"],
            ["2025-02-20 08:45:00","1002","Bob Jones",  "2","Band Saw","IN"],
            ["2025-02-20 10:30:00","1001","Alice Smith","1","Table Saw","OUT"],
            ["2025-02-20 11:00:00","1001","Alice Smith","2","Band Saw","IN"],
            ["2025-02-20 14:00:00","1002","Bob Jones",  "2","Band Saw","OUT"],
            ["2025-02-21 09:00:00","1003","Charlie Brown","3","Drill Press","IN"],
            ["2025-02-21 09:45:00","1003","Charlie Brown","3","Drill Press","OUT"],
        ]
        with open(LOG_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerows(sample_rows)

    if not os.path.exists(ACTIVE_FILE):
        save_json(ACTIVE_FILE, [])

# ── Common CSS / JS (inlined so it's single-file deployment) ─────────────────

COMMON_STYLE = """
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  :root{--bg:#1a1a1a;--panel:#252525;--border:#333;--accent:#e07b00;
        --text:#e0e0e0;--muted:#888;--danger:#c0392b;--ok:#27ae60}
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:system-ui,sans-serif;background:var(--bg);color:var(--text);
       min-height:100vh}
  a{color:var(--accent);text-decoration:none}
  a:hover{text-decoration:underline}
  .topbar{background:var(--panel);border-bottom:1px solid var(--border);
          padding:.75rem 1rem;display:flex;align-items:center;gap:1rem;
          flex-wrap:wrap}
  .topbar h1{font-size:1.1rem;color:var(--accent);flex:1}
  .topbar nav a{color:var(--text);margin-left:.5rem;font-size:.9rem}
  .topbar nav a:hover{color:var(--accent)}
  .container{max-width:960px;margin:1.5rem auto;padding:0 1rem}
  .card{background:var(--panel);border:1px solid var(--border);border-radius:6px;
        padding:1rem;margin-bottom:1rem}
  .card h2{font-size:1rem;color:var(--accent);margin-bottom:.75rem}
  label{display:block;font-size:.8rem;color:var(--muted);margin-bottom:.2rem}
  input,select,textarea{width:100%;padding:.45rem .6rem;background:#1e1e1e;
    border:1px solid var(--border);border-radius:4px;color:var(--text);
    font-size:.9rem;margin-bottom:.75rem}
  textarea{resize:vertical;min-height:300px;font-family:monospace;font-size:.82rem}
  button,.btn{padding:.5rem 1.1rem;border:none;border-radius:4px;cursor:pointer;
              font-size:.9rem;background:var(--accent);color:#000;font-weight:600}
  button:hover,.btn:hover{opacity:.85}
  .btn-danger{background:var(--danger);color:#fff}
  .btn-sm{padding:.3rem .7rem;font-size:.8rem}
  .filter-row{display:flex;flex-wrap:wrap;gap:.6rem;align-items:flex-end;
              margin-bottom:.8rem}
  .filter-row>div{flex:1;min-width:130px}
  .filter-row button{height:2.1rem;flex-shrink:0}
  table{width:100%;border-collapse:collapse;font-size:.85rem}
  th{background:#1e1e1e;text-align:left;padding:.4rem .6rem;
     border-bottom:1px solid var(--border);color:var(--muted);font-weight:600}
  td{padding:.4rem .6rem;border-bottom:1px solid #2a2a2a}
  tr:last-child td{border-bottom:none}
  .badge{display:inline-block;padding:.1rem .5rem;border-radius:3px;
         font-size:.75rem;font-weight:600}
  .badge-in {background:#1a4a2e;color:#4caf50}
  .badge-out{background:#3a1a1a;color:#ef9a9a}
  .badge-on {background:#1a4a2e;color:#4caf50}
  .badge-off{background:#3a2a0a;color:#f9a825}
  .flash{background:#2d1f00;border:1px solid var(--accent);border-radius:4px;
         padding:.5rem .8rem;margin-bottom:.8rem;font-size:.9rem}
  .flash.error{background:#2d0000;border-color:var(--danger)}
  .empty{color:var(--muted);font-size:.9rem;padding:.5rem 0}
  @media(max-width:600px){.filter-row>div{min-width:100%}}
</style>
"""

NAV_AUTH = """
<div class="topbar">
  <h1>🪵 Woodshop Control</h1>
  <span style="font-size:.75rem;color:var(--muted)">v{app_version}</span>
  <nav>
    <a href="/logs">Logs</a>
    <a href="/active">Active</a>
    <a href="/admin/users">Users</a>
    <a href="/admin/machines">Machines</a>
    <a href="/admin/renew">Renew</a>
    <a href="/admin/ntp">NTP Sync</a>
    <a href="/admin/config-card">Config Card</a>
    <a href="/logout">Logout</a>
  </nav>
</div>"""

NAV_ANON = """
<div class="topbar">
  <h1>🪵 Woodshop Control</h1>
  <nav><a href="/login">Login</a></nav>
</div>"""

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    if session.get("logged_in"):
        return redirect(url_for("active"))
    return redirect(url_for("login"))

# ── Login / Logout ────────────────────────────────────────────────────────────

LOGIN_PAGE = """<!doctype html><html><head><title>Login – Woodshop</title>
{style}</head><body>
{nav}
<div class="container" style="max-width:380px">
  <div class="card" style="margin-top:3rem">
    <h2>Admin Login</h2>
    {flash}
    <form method="POST">
      <label>Username</label>
      <input name="username" autocomplete="username" required>
      <label>Password</label>
      <input name="password" type="password" autocomplete="current-password" required>
      <button type="submit" style="width:100%">Log In</button>
    </form>
  </div>
</div></body></html>"""

@app.route("/login", methods=["GET","POST"])
def login():
    flash_html = ""
    if request.method == "POST":
        u = request.form.get("username","").strip()
        p = request.form.get("password","")
        if check_admin(u, p):
            session["logged_in"] = True
            session["username"]  = u
            next_url = request.args.get("next", url_for("active"))
            return redirect(next_url)
        flash_html = '<div class="flash error">Invalid credentials.</div>'
    return LOGIN_PAGE.format(style=COMMON_STYLE, nav=NAV_ANON, flash=flash_html)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ── Active Sessions ───────────────────────────────────────────────────────────

ACTIVE_PAGE = """<!doctype html><html><head><title>Active – Woodshop</title>
{style}</head><body>
{nav}
<div class="container">
  <div class="card">
    <h2>Currently Active in Shop</h2>
    {content}
  </div>
</div>
<script>setTimeout(()=>location.reload(),30000);</script>
</body></html>"""

@app.route("/active")
@login_required
def active():
    sessions = load_json(ACTIVE_FILE, [])
    if sessions:
        rows = "".join(
            f"<tr><td>{s.get('user_name','?')}</td>"
            f"<td>{s.get('machine_name','?')}</td>"
            f"<td>{s.get('since','?')}</td></tr>"
            for s in sessions
        )
        content = f"""<table>
          <thead><tr><th>User</th><th>Machine</th><th>Since</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>
        <p style="font-size:.8rem;color:var(--muted);margin-top:.6rem">
          Auto-refreshes every 30 s</p>"""
    else:
        content = '<p class="empty">No one is currently active in the shop.</p>'
    return ACTIVE_PAGE.format(style=COMMON_STYLE, nav=NAV_AUTH.format(app_version=__version__), content=content)

# ── Log Viewer ────────────────────────────────────────────────────────────────

LOG_PAGE = """<!doctype html><html><head><title>Logs – Woodshop</title>
{style}</head><body>
{nav}
<div class="container">
  <div class="card">
    <h2>Access Log</h2>
    <form method="GET" action="/logs">
      <div class="filter-row">
        <div><label>Machine</label>
          <input name="machine" value="{f_machine}" placeholder="any"></div>
        <div><label>User</label>
          <input name="user" value="{f_user}" placeholder="any"></div>
        <div><label>From (YYYY-MM-DD)</label>
          <input name="date_from" value="{f_from}" placeholder="2025-01-01"></div>
        <div><label>To (YYYY-MM-DD)</label>
          <input name="date_to" value="{f_to}" placeholder="today"></div>
        <div><label>Last N entries</label>
          <input name="last_n" value="{f_n}" placeholder="e.g. 50" style="width:100px"></div>
        <button type="submit">Filter</button>
        <a href="/logs" class="btn btn-sm" style="line-height:1.8">Clear</a>
      </div>
    </form>
    <p style="font-size:.8rem;color:var(--muted);margin-bottom:.5rem">
      Showing {count} entries</p>
    {table}
  </div>
</div></body></html>"""

@app.route("/logs")
@login_required
def logs():
    machine   = request.args.get("machine","").strip()
    user      = request.args.get("user","").strip()
    date_from = request.args.get("date_from","").strip()
    date_to   = request.args.get("date_to","").strip()
    last_n    = request.args.get("last_n","").strip()

    rows = read_log()
    rows = filter_log(rows,
                      machine   = machine   or None,
                      user      = user      or None,
                      date_from = date_from or None,
                      date_to   = date_to   or None,
                      last_n    = last_n    or None)

    if rows:
        def _fmt_duration(s):
            """Format seconds as Xh Ym Zs or just Ym Zs / Zs."""
            try:
                s = int(float(s))
            except (TypeError, ValueError):
                return s or "—"
            if s < 0:
                return "—"
            h, rem = divmod(s, 3600)
            m, sec = divmod(rem, 60)
            if h:
                return f"{h}h {m}m {sec}s"
            if m:
                return f"{m}m {sec}s"
            return f"{sec}s"

        def _fmt_current(a):
            try:
                return f"{float(a):.2f} A"
            except (TypeError, ValueError):
                return a or "—"

        def _fmt_event(r):
            ev = r.get("event", "SESSION")
            cls = {"IN": "badge-in", "OUT": "badge-out", "SESSION": "badge-in"}.get(ev, "badge-out")
            return f"<span class='badge {cls}'>{ev}</span>"

        body = "".join(
            f"<tr>"
            f"<td style='white-space:nowrap'>{r.get('stop_time') or r.get('timestamp','')}</td>"
            f"<td style='white-space:nowrap'>{r.get('start_time','') or '—'}</td>"
            f"<td>{r.get('member_name') or r.get('user_name','?')} "
            f"<span style='color:var(--muted);font-size:.75rem'>({r.get('member_id') or r.get('user_id','')})</span></td>"
            f"<td>{r.get('machine_name','?')} "
            f"<span style='color:var(--muted);font-size:.75rem'>({r.get('machine_number') or r.get('machine_id','')})</span></td>"
            f"<td style='text-align:right'>{_fmt_duration(r.get('machine_on_s',''))}</td>"
            f"<td style='text-align:right'>{_fmt_duration(r.get('connect_time_s',''))}</td>"
            f"<td style='text-align:right'>{_fmt_current(r.get('avg_current_A',''))}</td>"
            f"<td style='text-align:right'>{r.get('starts','') or '—'}</td>"
            f"<td>{_fmt_event(r)}</td>"
            f"</tr>"
            for r in reversed(rows)          # newest first
        )
        table = f"""<div style="overflow-x:auto"><table>
          <thead><tr>
            <th>Stop Time</th>
            <th>Start Time</th>
            <th>Member</th>
            <th>Machine</th>
            <th style='text-align:right'>Machine On</th>
            <th style='text-align:right'>Connect Time</th>
            <th style='text-align:right'>Avg Current</th>
            <th style='text-align:right'>Starts</th>
            <th>Event</th>
          </tr></thead>
          <tbody>{body}</tbody></table></div>"""
    else:
        table = '<p class="empty">No log entries match the current filters.</p>'

    resp = make_response(LOG_PAGE.format(
        style=COMMON_STYLE, nav=NAV_AUTH.format(app_version=__version__), table=table,
        f_machine=machine, f_user=user, f_from=date_from,
        f_to=date_to, f_n=last_n, count=len(rows)
    ))
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    resp.headers['Pragma'] = 'no-cache'
    return resp

# ── JSON API endpoint for log (for programmatic access) ──────────────────────

@app.route("/api/logs")
@login_required
def api_logs():
    machine   = request.args.get("machine")
    user      = request.args.get("user")
    date_from = request.args.get("date_from")
    date_to   = request.args.get("date_to")
    last_n    = request.args.get("last_n")
    rows = filter_log(read_log(), machine, user, date_from, date_to, last_n)
    return jsonify(rows)

@app.route("/api/active")
@login_required
def api_active():
    return jsonify(load_json(ACTIVE_FILE, []))

# ── Admin: Users — full management flow ───────────────────────────────────────
#
# Step 1:  /admin/users          — choose: Scan Card  OR  Search by name/ID
# Step 2a: /admin/users/scan     — page polls /api/card_scan until master posts
# Step 2b: /admin/users/search   — search form → results list
# Step 3:  /admin/users/edit     — full edit form with permissions grid
# Step 4:  POST /admin/users/save — write back to users.json
#
# Card scan relay:
#   The master Pico POSTs to  /api/card_present  when a card is scanned
#   while the web UI is waiting.  The web UI polls /api/card_scan to pick it up.
# ─────────────────────────────────────────────────────────────────────────────

# Volatile slot — holds the most-recently scanned card (one at a time)
_pending_card: dict | None = None
_pending_card_lock = threading.Lock()

NUM_MACHINES     = 40   # number of machines shown in the permissions grid
NUM_PERMS_STORED = 128  # full permission string length kept in storage

def _perms_to_list(perm_str: str) -> list[int]:
    """'10110...' -> list of ints, padded/truncated to NUM_PERMS_STORED"""
    s = (perm_str or "").strip()
    bits = [int(c) if c in "01" else 0 for c in s]
    bits = bits[:NUM_PERMS_STORED] + [0] * max(0, NUM_PERMS_STORED - len(bits))
    return bits

def _list_to_perms(bits: list[int]) -> str:
    """Rebuild full 128-char string from bits list."""
    return "".join(str(b) for b in bits)

def _find_user(uid: str) -> dict | None:
    """Lookup by id (OTOW# / member ID)."""
    users = load_json(USERS_FILE, [])
    uid = uid.strip()
    for u in users:
        if str(u.get("id","")).strip() == uid:
            return u
    return None

def _search_users(q: str) -> list[dict]:
    q = q.lower().strip()
    users = load_json(USERS_FILE, [])
    results = []
    for u in users:
        haystack = " ".join([
            str(u.get("id","")),
            u.get("first_name",""),
            u.get("last_name",""),
        ]).lower()
        if q in haystack:
            results.append(u)
    return results

# ── Step 1: landing ───────────────────────────────────────────────────────────

USERS_LANDING = """<!doctype html><html><head><title>Users – Woodshop</title>
{style}</head><body>
{nav}
<div class="container" style="max-width:560px">
  {flash}

  <!-- Database Functions -->
  <div class="card">
    <h2>👥 User Database</h2>
    <div style="display:flex;gap:.8rem;flex-wrap:wrap;margin-bottom:.8rem">
      <a href="/admin/users/list" class="btn"
         style="flex:1;text-align:center;padding:.75rem;font-size:.95rem">
        📋 List All Users</a>
      <a href="/admin/users/edit?mode=new" class="btn"
         style="flex:1;text-align:center;padding:.75rem;font-size:.95rem;
                background:#333;color:var(--text)">
        ➕ Add New User</a>
    </div>
    <div style="display:flex;gap:.8rem;flex-wrap:wrap">
      <button onclick="document.getElementById('sbox').style.display='block';
                       this.style.display='none'"
              class="btn btn-sm" style="background:#333;color:var(--text)">
        🔍 Search Users</button>
      <a href="/api/users/export.csv" class="btn btn-sm"
         style="background:#333;color:var(--text)">⬇ Users CSV</a>
      <label class="btn btn-sm" style="background:#333;color:var(--text);cursor:pointer">
        ⬆ Import Users CSV
        <input type="file" accept=".csv" style="display:none"
               onchange="importUsersCSV(this)">
      </label>
    </div>
    <div style="display:flex;gap:.8rem;flex-wrap:wrap;margin-top:.5rem">
      <a href="/api/machines/export.csv" class="btn btn-sm"
         style="background:#333;color:var(--text)">⬇ Machines CSV</a>
      <label class="btn btn-sm" style="background:#333;color:var(--text);cursor:pointer">
        ⬆ Import Machines CSV
        <input type="file" accept=".csv" style="display:none"
               onchange="importMachinesCSV(this)">
      </label>
      <a href="/api/log/export.csv" class="btn btn-sm"
         style="background:#333;color:var(--text)">⬇ Log CSV</a>
    </div>
    <div id="sbox" style="display:none;margin-top:.8rem">
      <form method="GET" action="/admin/users/search">
        <label>Search by name or member ID</label>
        <div style="display:flex;gap:.5rem">
          <input name="q" placeholder="e.g. Alice  or  1234" style="margin:0">
          <button type="submit" style="flex-shrink:0">Search</button>
        </div>
      </form>
    </div>
  </div>
  <script>
  function importUsersCSV(input) {{
    const file = input.files[0];
    if (!file) return;
    const form = new FormData();
    form.append('file', file);
    fetch('/api/users/import.csv', {{ method: 'POST', body: form }})
      .then(r => r.json())
      .then(d => {{
        if (d.ok) {{ alert(d.message); location.reload(); }}
        else alert('Import failed: ' + (d.error || 'unknown'));
      }});
  }}
  function importMachinesCSV(input) {{
    const file = input.files[0];
    if (!file) return;
    const form = new FormData();
    form.append('file', file);
    fetch('/api/machines/import.csv', {{ method: 'POST', body: form }})
      .then(r => r.json())
      .then(d => {{
        if (d.ok) {{ alert(d.message); location.reload(); }}
        else alert('Import failed: ' + (d.error || 'unknown'));
      }});
  }}
  </script>

  <!-- RFID Card Functions -->
  <div class="card">
    <h2>📡 RFID Card Functions</h2>
    <div style="display:flex;gap:.8rem;flex-wrap:wrap">
      <a href="/admin/users/scan" class="btn"
         style="flex:1;text-align:center;padding:.75rem;font-size:.95rem">
        📖 Read Card</a>
      <a href="/admin/users/card-write" class="btn"
         style="flex:1;text-align:center;padding:.75rem;font-size:.95rem;
                background:#333;color:var(--text)">
        ✍ Write Card</a>
      <a href="/admin/users/card-erase" class="btn"
         style="flex:1;text-align:center;padding:.75rem;font-size:.95rem;
                background:#5a1a1a;color:#ef9a9a">
        🗑 Erase Card</a>
    </div>
    <div style="display:flex;gap:.8rem;flex-wrap:wrap;margin-top:.5rem">
      <a href="/admin/config-card" class="btn"
         style="flex:1;text-align:center;padding:.75rem;font-size:.95rem;
                background:#1a3a5a;color:#90caf9">
        ⚙ Write Config Card</a>
    </div>
    <p style="font-size:.8rem;color:var(--muted);margin-top:.6rem">
      Read: scan any card to view/edit the matched user record.<br>
      Write: choose a user from the database and program a card.<br>
      Erase: wipe all user data from a card.<br>
      Config Card: program a node's machine number and blast gate delay.
    </p>
  </div>

</div></body></html>"""

@app.route("/admin/users", methods=["GET"])
@login_required
def admin_users():
    flash_html = ""
    msg = request.args.get("msg","")
    if msg:
        kind = "error" if request.args.get("err") else ""
        flash_html = f'<div class="flash {kind}">{msg}</div>'
    return USERS_LANDING.format(style=COMMON_STYLE, nav=NAV_AUTH.format(app_version=__version__), flash=flash_html)

# ── User list ──────────────────────────────────────────────────────────────────

USERS_LIST_PAGE = """<!doctype html><html><head><title>All Users – Woodshop</title>
{style}
<style>
  .status-active  {{color:#4caf50;font-weight:600}}
  .status-grace   {{color:#f9a825;font-weight:600}}
  .status-lapsed  {{color:#ef9a9a;font-weight:600}}
  .status-inactive{{color:var(--muted);font-style:italic}}
</style>
</head><body>
{nav}
<div class="container">
  <div class="card">
    <div style="display:flex;align-items:center;justify-content:space-between;
                flex-wrap:wrap;gap:.5rem;margin-bottom:.8rem">
      <h2 style="margin:0">All Users
        <span style="color:var(--muted);font-size:.8rem;font-weight:400">
          ({count} members)</span></h2>
      <div style="display:flex;gap:.5rem;flex-wrap:wrap">
        <a href="/admin/users/edit?mode=new" class="btn btn-sm">➕ Add New</a>
        <a href="/api/users/export.csv" class="btn btn-sm"
           style="background:#333;color:var(--text)">⬇ CSV</a>
        <label class="btn btn-sm" style="background:#333;color:var(--text);cursor:pointer">
          ⬆ Import CSV
          <input type="file" accept=".csv" style="display:none"
                 onchange="importCSV(this,'users')">
        </label>
        <a href="/admin/users" class="btn btn-sm"
           style="background:#333;color:var(--text)">← Back</a>
      </div>
    </div>
    <div style="display:flex;gap:.5rem;margin-bottom:.8rem;flex-wrap:wrap">
      <input id="filterInput" placeholder="Filter by name, ID, RFID…"
             oninput="filterTable(this.value)"
             style="flex:1;min-width:180px;margin:0">
      <select id="statusFilter"
              onchange="filterTable(document.getElementById('filterInput').value)"
              style="width:auto;margin:0">
        <option value="">All statuses</option>
        <option value="active">Active</option>
        <option value="grace">Grace period</option>
        <option value="lapsed">Lapsed</option>
        <option value="inactive">Inactive</option>
      </select>
    </div>
    <div style="overflow-x:auto">
      <table id="userTable">
        <thead><tr>
          <th><a class="sort-link" onclick="sortTable(0)">ID ⇅</a></th>
          <th><a class="sort-link" onclick="sortTable(1)">Name ⇅</a></th>
          <th>Email</th>
          <th>RFID</th>
          <th><a class="sort-link" onclick="sortTable(4)">Expiry ⇅</a></th>
          <th>Status</th>
          <th></th>
        </tr></thead>
        <tbody>{rows}</tbody>
      </table>
      <p id="noResults" style="display:none" class="empty">No matching users.</p>
    </div>
  </div>
</div>
<style>
  .sort-link{{color:var(--accent);cursor:pointer;font-size:.8rem;text-decoration:none}}
  .sort-link:hover{{opacity:.7}}
</style>
<script>
function filterTable(q) {{
  q = q.toLowerCase();
  const sf = document.getElementById('statusFilter').value;
  let vis = 0;
  document.querySelectorAll('#userTable tbody tr').forEach(row => {{
    const show = (!q || row.textContent.toLowerCase().includes(q))
              && (!sf  || row.dataset.status === sf);
    row.style.display = show ? '' : 'none';
    if (show) vis++;
  }});
  document.getElementById('noResults').style.display = vis ? 'none' : 'block';
}}
let _sortDir = {{}};
function sortTable(col) {{
  const tbody = document.querySelector('#userTable tbody');
  const rows  = Array.from(tbody.querySelectorAll('tr'));
  const asc   = !_sortDir[col];
  _sortDir = {{[col]: asc}};
  rows.sort((a,b) => {{
    const av = a.cells[col]?.textContent.trim()||'';
    const bv = b.cells[col]?.textContent.trim()||'';
    const an = parseFloat(av), bn = parseFloat(bv);
    if (!isNaN(an)&&!isNaN(bn)) return asc?an-bn:bn-an;
    return asc?av.localeCompare(bv):bv.localeCompare(av);
  }});
  rows.forEach(r=>tbody.appendChild(r));
}}
function deleteUser(uid, name) {{
  if (!confirm('Delete user ' + name + ' (ID ' + uid + ')? This cannot be undone.')) return;
  fetch('/admin/users/delete', {{
    method: 'POST',
    headers: {{'Content-Type':'application/x-www-form-urlencoded'}},
    body: 'id=' + encodeURIComponent(uid)
  }}).then(r => r.json()).then(d => {{
    if (d.ok) {{
      document.querySelectorAll('#userTable tbody tr').forEach(r => {{
        if (r.cells[0].textContent.trim() == uid) r.remove();
      }});
    }} else alert('Delete failed: ' + (d.error || 'unknown error'));
  }});
}}
function importCSV(input, type) {{
  const file = input.files[0];
  if (!file) return;
  const form = new FormData();
  form.append('file', file);
  fetch('/api/' + type + '/import.csv', {{ method: 'POST', body: form }})
    .then(r => r.json())
    .then(d => {{
      if (d.ok) {{ alert(d.message); location.reload(); }}
      else alert('Import failed: ' + (d.error || 'unknown'));
    }});
}}
</script>
</body></html>"""

@app.route("/admin/users/list")
@login_required
def admin_users_list():
    users = load_json(USERS_FILE, [])
    users_sorted = sorted(users, key=lambda u: (
        u.get('last_name','').lower(), u.get('first_name','').lower()
    ))
    rows_html = ""
    for u in users_sorted:
        uid    = u.get('id','')
        name   = f"{u.get('first_name','')} {u.get('last_name','')}".strip()
        email  = u.get('email','')
        rfid   = u.get('rfid','')
        expiry = u.get('expiry','')
        css, label = _renew_status(u)
        rows_html += (
            f'<tr data-status="{css}">'
            f'<td>{uid}</td>'
            f'<td>{name}</td>'
            f'<td style="font-size:.8rem">{email}</td>'
            f'<td style="font-family:monospace;font-size:.8rem">{rfid}</td>'
            f'<td style="font-size:.8rem">{expiry}</td>'
            f'<td><span class="status-{css}">{label}</span></td>'
            f'<td style="white-space:nowrap">'
            f'<a href="/admin/users/edit?uid={uid}" class="btn btn-sm">Edit</a> '
            f'<a href="/admin/users/card-write?uid={uid}" class="btn btn-sm"'
            f'   style="background:#333;color:var(--text)">Write Card</a> '
            f'<button class="btn btn-sm btn-danger"'
            f'  onclick="deleteUser(\'{uid}\',\'{name}\')">Delete</button>'
            f'</td>'
            f'</tr>'
        )
    return USERS_LIST_PAGE.format(
        style=COMMON_STYLE, nav=NAV_AUTH.format(app_version=__version__), count=len(users), rows=rows_html
    )

# ── CSV export ─────────────────────────────────────────────────────────────────

@app.route("/api/users/export.csv")
@login_required
def api_users_export():
    import io
    from flask import Response
    users = load_json(USERS_FILE, [])
    users_sorted = sorted(users, key=lambda u: (
        u.get('last_name','').lower(), u.get('first_name','').lower()
    ))
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["member_id","first_name","last_name","email","phone",
                     "rfid","joined","expiry","active","permissions"])
    for u in users_sorted:
        writer.writerow([
            u.get('id',''), u.get('first_name',''), u.get('last_name',''),
            u.get('email',''), u.get('phone',''), u.get('rfid',''),
            u.get('joined',''), u.get('expiry',''), u.get('active',''),
            u.get('permissions',''),
        ])
    return Response(output.getvalue(), mimetype='text/csv',
        headers={"Content-Disposition": "attachment; filename=woodshop_users.csv"})

# ── RFID card write/erase (Pi-local PN532 via server_card_writer) ─────────────
#
# Architecture: write/erase runs in a background thread on the Pi using the
# same PN532 hardware and server_card_writer module as rfid_writer.py.
# The web UI starts the job, then polls /api/card_op_status for completion.
#
# /admin/users/card-write?uid=NNN  — confirm page for a specific user, or
# /admin/users/card-write           — search page to pick a user
# /admin/users/card-erase           — erase confirmation page
# POST /api/card_op_start           — starts background write or erase thread
# GET  /api/card_op_status          — polled by UI: idle|waiting|writing|done|error

_card_op_status = {"state": "idle", "message": ""}
_card_op_lock   = threading.Lock()

def _card_op_set(state, message=""):
    with _card_op_lock:
        _card_op_status["state"]   = state
        _card_op_status["message"] = message

def _run_card_write(uid_int, p0, p1, p2, p3, firstname, lastname):
    """Background thread: write card data using PN532 on the Pi."""
    try:
        from server_card_writer import create_card_data, CARD_LEN
        import board, busio, digitalio
        from adafruit_pn532.spi import PN532_SPI

        private_key = _load_card_private_key()
        if private_key is None:
            _card_op_set("error", "Private key not found")
            return

        spi   = busio.SPI(board.SCK, board.MOSI, board.MISO)
        cs    = digitalio.DigitalInOut(board.CE0)
        pn532 = PN532_SPI(spi, cs, debug=False)
        pn532.SAM_configuration()

        card_bytes = create_card_data(uid_int, p0, p1, p2, p3, firstname, lastname, private_key)
        _card_op_set("waiting", "Place card on reader…")

        # Wait up to 60s for a card
        import time
        deadline = time.time() + 60
        card_uid = None
        while time.time() < deadline:
            card_uid = pn532.read_passive_target(timeout=0.5)
            if card_uid:
                break
        if not card_uid:
            _card_op_set("error", "Timed out waiting for card (60s)")
            return

        _card_op_set("writing", "Writing…")
        pages = CARD_LEN // 4
        for i in range(pages):
            page = 4 + i   # PAGE_DATA_START = 4
            pn532.ntag2xx_write_block(page, card_bytes[i*4:(i+1)*4])
            time.sleep(0.01)

        _card_op_set("done", f"Card written for member {uid_int}")

    except Exception as e:
        _card_op_set("error", str(e))

def _run_card_erase():
    """Background thread: erase card data using PN532 on the Pi."""
    try:
        import board, busio, digitalio
        from adafruit_pn532.spi import PN532_SPI
        import time

        spi   = busio.SPI(board.SCK, board.MOSI, board.MISO)
        cs    = digitalio.DigitalInOut(board.CE0)
        pn532 = PN532_SPI(spi, cs, debug=False)
        pn532.SAM_configuration()

        _card_op_set("waiting", "Place card on reader…")
        deadline = time.time() + 60
        card_uid = None
        while time.time() < deadline:
            card_uid = pn532.read_passive_target(timeout=0.5)
            if card_uid:
                break
        if not card_uid:
            _card_op_set("error", "Timed out waiting for card (60s)")
            return

        _card_op_set("writing", "Erasing…")
        # Erase 29 pages (116 bytes) starting at page 4
        from server_card_writer import CARD_LEN
        pages = CARD_LEN // 4
        for page in range(4, 4 + pages):
            pn532.ntag2xx_write_block(page, b'\x00\x00\x00\x00')
            time.sleep(0.01)

        _card_op_set("done", "Card erased")

    except Exception as e:
        _card_op_set("error", str(e))

PRIVATE_KEY_PATH = '/home/pi/woodshop/server_private.pem'

def _load_card_private_key():
    try:
        from server_card_writer import load_private_key
        return load_private_key(PRIVATE_KEY_PATH)
    except Exception:
        return None

# ── Card write: confirm page ───────────────────────────────────────────────────

CARD_WRITE_SEARCH_PAGE = """<!doctype html><html><head>
<title>Write RFID Card – Woodshop</title>{style}</head><body>
{nav}
<div class="container" style="max-width:540px">
  <div class="card">
    <h2>✍ Write RFID Card</h2>
    <p style="color:var(--muted);font-size:.85rem;margin-bottom:.8rem">
      Search for the user whose data you want to write to a card.</p>
    <form method="GET" action="/admin/users/card-write">
      <label>Search by name or member ID</label>
      <div style="display:flex;gap:.5rem">
        <input name="q" value="{q}" placeholder="e.g. Alice  or  1234" style="margin:0">
        <button type="submit" style="flex-shrink:0">Search</button>
      </div>
    </form>
    {results}
  </div>
  <a href="/admin/users" class="btn btn-sm"
     style="background:#333;color:var(--text)">← Back</a>
</div></body></html>"""

CARD_WRITE_CONFIRM_PAGE = """<!doctype html><html><head>
<title>Write RFID Card – Woodshop</title>{style}</head><body>
{nav}
<div class="container" style="max-width:500px">
  <div class="card">
    <h2>✍ Write Card — {name}</h2>
    <p style="color:var(--muted);font-size:.85rem;margin-bottom:.8rem">
      Data to be written to card:</p>
    <table style="margin-bottom:.8rem">
      <tr><th style="width:40%">Member ID</th><td>{uid}</td></tr>
      <tr><th>Name</th><td>{name}</td></tr>
      <tr><th>Expiry</th><td>{expiry}</td></tr>
      <tr><th>Machines enabled</th><td>{enabled} of {total}</td></tr>
      <tr><th>Permissions</th>
          <td style="font-family:monospace;font-size:.72rem;word-break:break-all">
            {perms_display}</td></tr>
    </table>

    <div id="opStatus" style="display:none;text-align:center;padding:1rem 0">
      <div id="opIcon" style="font-size:2.5rem">⏳</div>
      <div id="opMsg"  style="color:var(--muted);margin-top:.4rem;font-size:.9rem">
        Starting…</div>
    </div>

    <div id="opActions" style="display:flex;gap:.5rem;flex-wrap:wrap">
      <button id="startBtn" onclick="startOp()">📡 Start — Place Card on Reader</button>
      <a href="/admin/users/card-write" class="btn"
         style="background:#333;color:var(--text)">Cancel</a>
    </div>
  </div>
</div>
<script>
function setUI(icon, msg) {{
  document.getElementById('opIcon').textContent = icon;
  document.getElementById('opMsg').textContent  = msg;
}}
function startOp() {{
  document.getElementById('startBtn').disabled = true;
  document.getElementById('opStatus').style.display = 'block';
  setUI('⏳', 'Starting…');
  fetch('/api/card_op_start', {{
    method: 'POST',
    headers: {{'Content-Type':'application/json'}},
    body: JSON.stringify({{op:'write', uid:'{uid}'}})
  }}).then(r=>r.json()).then(d=>{{
    if (d.ok) poll();
    else setUI('❌', 'Error: '+(d.error||'unknown'));
  }}).catch(()=>setUI('❌','Network error'));
}}
async function poll() {{
  try {{
    const d = await (await fetch('/api/card_op_status')).json();
    if (d.state==='waiting') {{ setUI('📡', d.message); setTimeout(poll,800); }}
    else if (d.state==='writing') {{ setUI('✏️', d.message); setTimeout(poll,600); }}
    else if (d.state==='done') {{
      setUI('✅', d.message);
      document.getElementById('opActions').innerHTML =
        '<a href="/admin/users/list" class="btn">Done</a>'
        +'<a href="/admin/users/card-write" class="btn" style="background:#333;color:var(--text)">Write Another</a>';
    }} else if (d.state==='error') {{
      setUI('❌', 'Error: '+d.message);
      document.getElementById('startBtn').disabled=false;
    }} else {{ setTimeout(poll,1000); }}
  }} catch(e) {{ setTimeout(poll,1200); }}
}}
</script>
</body></html>"""

CARD_ERASE_PAGE = """<!doctype html><html><head>
<title>Erase RFID Card – Woodshop</title>{style}</head><body>
{nav}
<div class="container" style="max-width:500px">
  <div class="card">
    <h2>🗑 Erase RFID Card</h2>
    <p style="color:#ef9a9a;font-size:.9rem;margin-bottom:1rem">
      ⚠ This will permanently wipe all user data from the card.</p>

    <div id="opStatus" style="display:none;text-align:center;padding:1rem 0">
      <div id="opIcon" style="font-size:2.5rem">⏳</div>
      <div id="opMsg"  style="color:var(--muted);margin-top:.4rem;font-size:.9rem">
        Starting…</div>
    </div>

    <div id="opActions" style="display:flex;gap:.5rem;flex-wrap:wrap">
      <button id="startBtn" class="btn btn-danger" onclick="startOp()">
        🗑 Erase — Place Card on Reader</button>
      <a href="/admin/users" class="btn"
         style="background:#333;color:var(--text)">Cancel</a>
    </div>
  </div>
</div>
<script>
function setUI(icon,msg){{
  document.getElementById('opIcon').textContent=icon;
  document.getElementById('opMsg').textContent=msg;
}}
function startOp(){{
  document.getElementById('startBtn').disabled=true;
  document.getElementById('opStatus').style.display='block';
  setUI('⏳','Starting…');
  fetch('/api/card_op_start',{{
    method:'POST',
    headers:{{'Content-Type':'application/json'}},
    body:JSON.stringify({{op:'erase'}})
  }}).then(r=>r.json()).then(d=>{{
    if(d.ok) poll();
    else setUI('❌','Error: '+(d.error||'unknown'));
  }}).catch(()=>setUI('❌','Network error'));
}}
async function poll(){{
  try{{
    const d=await(await fetch('/api/card_op_status')).json();
    if(d.state==='waiting'){{setUI('📡',d.message);setTimeout(poll,800);}}
    else if(d.state==='writing'){{setUI('✏️',d.message);setTimeout(poll,600);}}
    else if(d.state==='done'){{
      setUI('✅',d.message);
      document.getElementById('opActions').innerHTML=
        '<a href="/admin/users" class="btn">Done</a>'
        +'<a href="/admin/users/card-erase" class="btn" style="background:#333;color:var(--text)">Erase Another</a>';
    }}else if(d.state==='error'){{
      setUI('❌','Error: '+d.message);
      document.getElementById('startBtn').disabled=false;
    }}else{{setTimeout(poll,1000);}}
  }}catch(e){{setTimeout(poll,1200);}}
}}
</script>
</body></html>"""

@app.route("/admin/users/card-write")
@login_required
def admin_card_write():
    uid = request.args.get("uid","").strip()
    q   = request.args.get("q","").strip()

    # Direct link with uid (e.g. from user list) — show confirm page immediately
    if uid:
        user = _find_user(uid)
        if not user:
            return redirect(url_for('admin_card_write', msg="User not found"))
        return _card_write_confirm(user)

    # Search results
    results_html = ""
    if q:
        hits = _search_users(q)
        if hits:
            rows = "".join(
                "<tr>"
                f"<td>{u.get('id','')}</td>"
                f"<td>{u.get('first_name','')} {u.get('last_name','')}</td>"
                f"<td><a href='/admin/users/card-write?uid={u.get('id','')}'"
                "   class='btn btn-sm'>Select</a></td>"
                "</tr>"
                for u in hits
            )
            results_html = (
                '<div style="margin-top:.8rem"><table>'
                '<thead><tr><th>ID</th><th>Name</th><th></th></tr></thead>'
                f'<tbody>{rows}</tbody></table></div>'
            )
        else:
            results_html = f'<p class="empty" style="margin-top:.6rem">No users match "{q}".</p>'

    return CARD_WRITE_SEARCH_PAGE.format(
        style=COMMON_STYLE, nav=NAV_AUTH.format(app_version=__version__), q=q, results=results_html
    )

def _card_write_confirm(user):
    """Render the write confirmation page for a given user dict."""
    from server_card_writer import perms_str_to_words, perms_to_machines
    uid    = user.get('id','')
    name   = f"{user.get('first_name','')} {user.get('last_name','')}".strip()
    expiry = user.get('expiry', default_expiry_date())
    perms  = user.get('permissions','0'*128)
    try:
        p0, p1, p2, p3 = perms_str_to_words(perms)
        machines        = perms_to_machines(p0, p1, p2, p3)
        enabled         = len(machines)
    except Exception:
        enabled = sum(1 for c in perms if c == '1')
    perms_short = perms[:40] + ('…' if len(perms) > 40 else '')
    return CARD_WRITE_CONFIRM_PAGE.format(
        style=COMMON_STYLE, nav=NAV_AUTH.format(app_version=__version__),
        uid=uid, name=name, expiry=expiry,
        perms_display=perms_short,
        enabled=enabled, total=NUM_MACHINES
    )

@app.route("/admin/users/card-erase")
@login_required
def admin_card_erase():
    return CARD_ERASE_PAGE.format(style=COMMON_STYLE, nav=NAV_AUTH.format(app_version=__version__))

@app.route("/api/card_op_start", methods=["POST"])
@login_required
def api_card_op_start():
    """Start a background card write or erase operation."""
    global _card_op_status
    with _card_op_lock:
        if _card_op_status["state"] in ("waiting","writing"):
            return jsonify({"error": "operation already in progress"}), 409

    data = request.get_json(silent=True) or {}
    op   = data.get("op","")

    if op == "write":
        uid_str = str(data.get("uid","")).strip()
        user    = _find_user(uid_str)
        if not user:
            return jsonify({"error": "user not found"}), 404
        try:
            from server_card_writer import perms_str_to_words
            perms = user.get('permissions','0'*128)
            p0, p1, p2, p3 = perms_str_to_words(perms)
        except Exception as e:
            return jsonify({"error": f"permissions error: {e}"}), 400
        uid_int   = int(user.get('id', 0))
        firstname = user.get('first_name', '').strip()
        lastname  = user.get('last_name',  '').strip()
        _card_op_set("starting", "")
        t = threading.Thread(target=_run_card_write,
                             args=(uid_int, p0, p1, p2, p3, firstname, lastname), daemon=True)
        t.start()
        return jsonify({"ok": True})

    elif op == "erase":
        _card_op_set("starting", "")
        t = threading.Thread(target=_run_card_erase, daemon=True)
        t.start()
        return jsonify({"ok": True})

    return jsonify({"error": "unknown op"}), 400

@app.route("/api/card_op_status")
@login_required
def api_card_op_status():
    with _card_op_lock:
        return jsonify(dict(_card_op_status))

# ── Step 2a: scan card (local PN532) ─────────────────────────────────────────

SCAN_PAGE = """<!doctype html><html><head><title>Read Card – Woodshop</title>
{style}</head><body>
{nav}
<div class="container" style="max-width:420px">
  <div class="card" style="margin-top:2rem;text-align:center">
    <h2>📡 Read RFID Card</h2>
    <p style="color:var(--muted);font-size:.9rem;margin:.6rem 0 1.2rem">
      Place the card on the Pi's PN532 reader.</p>
    <div id="spinner" style="font-size:2.5rem;margin:1rem 0">📡</div>
    <div id="status" style="color:var(--muted);font-size:.9rem">Waiting for card…</div>
    <div style="margin-top:1.2rem">
      <a href="/admin/users" class="btn btn-sm"
         style="background:#333;color:var(--text)">Cancel</a>
    </div>
  </div>
</div>
<script>
async function poll() {{
  try {{
    const r = await fetch('/api/card_scan');
    const d = await r.json();
    if (d.state === 'done' && d.uid) {{
      document.getElementById('spinner').textContent = '✔';
      document.getElementById('status').textContent = d.message;
      if (d.card_type === 'config') {{
        // Config card — just show the result, no redirect
        document.getElementById('spinner').textContent = '⚙';
      }} else if (d.member_id) {{
        window.location = '/admin/users/edit?uid=' + encodeURIComponent(d.member_id) + '&mode=db';
      }} else {{
        window.location = '/admin/users/edit?rfid=' + encodeURIComponent(d.uid) + '&mode=card';
      }}
      return;
    }} else if (d.state === 'error') {{
      document.getElementById('spinner').textContent = '❌';
      document.getElementById('status').textContent = 'Error: ' + d.message;
      return;
    }}
  }} catch(e) {{}}
  setTimeout(poll, 800);
}}
poll();
</script>
</body></html>"""

# ── Local PN532 scan state ────────────────────────────────────────────────────

_scan_status  = {"state": "idle", "message": "", "uid": "", "member_id": "", "card_type": ""}
_scan_lock    = threading.Lock()
_scan_running = False

def _scan_op_set(state, message="", uid="", member_id="", card_type=""):
    with _scan_lock:
        _scan_status["state"]     = state
        _scan_status["message"]   = message
        _scan_status["uid"]       = uid
        _scan_status["member_id"] = member_id
        _scan_status["card_type"] = card_type

def _run_card_scan():
    """Background thread: read a card from the Pi's local PN532 and decode it."""
    global _scan_running
    try:
        import board, busio, digitalio, time, struct
        from adafruit_pn532.spi import PN532_SPI
        from server_card_writer import PAYLOAD_FORMAT, PAYLOAD_LEN, CARD_LEN

        spi   = busio.SPI(board.SCK, board.MOSI, board.MISO)
        cs    = digitalio.DigitalInOut(board.CE0)
        pn532 = PN532_SPI(spi, cs, debug=False)
        pn532.SAM_configuration()

        _scan_op_set("waiting", "Place card on reader…")

        deadline = time.time() + 60
        raw_uid  = None
        while time.time() < deadline:
            raw_uid = pn532.read_passive_target(timeout=0.5)
            if raw_uid:
                break
        if not raw_uid:
            _scan_op_set("error", "Timed out waiting for card (60s)")
            return

        uid_hex = raw_uid.hex().upper()

        data = bytearray()
        for i in range(CARD_LEN // 4):
            page  = 4 + i
            chunk = None
            for _ in range(3):
                try:
                    chunk = pn532.ntag2xx_read_block(page)
                    if chunk is not None:
                        break
                except Exception:
                    pass
                time.sleep(0.02)
            if chunk is None:
                _scan_op_set("error", f"Read failed on page {page}")
                return
            data.extend(chunk[:4])
            time.sleep(0.01)

        card_bytes = bytes(data)

        if all(b == 0 for b in card_bytes):
            _scan_op_set("done", "Blank card", uid=uid_hex, member_id="")
            return

        try:
            card_type = card_bytes[0]
            card_ver  = card_bytes[1]

            if card_type == 0x02:
                # Config card — decode the 5-byte signed payload
                machine_num = card_bytes[2]
                blast_raw   = card_bytes[3] & 0x0F
                _scan_op_set("done",
                             f"Config card v{card_ver}: machine={machine_num}, "
                             f"blast gate={blast_raw * 10}s",
                             uid=uid_hex, member_id="", card_type="config")
                return

            if card_type == 0x01:
                # Member card — decode using server_card_writer format
                from server_card_writer import PAYLOAD_FORMAT, PAYLOAD_LEN
                payload = card_bytes[:PAYLOAD_LEN]
                card_type, version, member_id, p0, p1, p2, p3, fn_raw, ln_raw = \
                    struct.unpack(PAYLOAD_FORMAT, payload)
                if version != 0x01:
                    _scan_op_set("done",
                                 f"Unsupported member card version (v{version})",
                                 uid=uid_hex, member_id="", card_type="member")
                    return
                def _dn(b):
                    try: b = b[:b.index(0)]
                    except ValueError: pass
                    return b.decode("utf-8", errors="replace")
                firstname = _dn(fn_raw)
                lastname  = _dn(ln_raw)
                _scan_op_set("done",
                             f"Member {member_id}: {firstname} {lastname}",
                             uid=uid_hex,
                             member_id=str(member_id),
                             card_type="member")
                return

            # Unknown card type
            _scan_op_set("done",
                         f"Unknown card type 0x{card_type:02X}",
                         uid=uid_hex, member_id="", card_type="unknown")

        except Exception as e:
            _scan_op_set("done", f"Could not decode: {e}", uid=uid_hex, member_id="")

    except Exception as e:
        _scan_op_set("error", str(e))
    finally:
        _scan_running = False


@app.route("/admin/users/scan")
@login_required
def admin_users_scan():
    global _scan_running, _scan_status
    with _scan_lock:
        _scan_status  = {"state": "starting", "message": "", "uid": "", "member_id": ""}
        _scan_running = True
    t = threading.Thread(target=_run_card_scan, daemon=True)
    t.start()
    return SCAN_PAGE.format(style=COMMON_STYLE, nav=NAV_AUTH.format(app_version=__version__))


@app.route("/api/card_scan")
@login_required
def api_card_scan():
    """Polled by the scan page. Returns current scan state."""
    with _scan_lock:
        return jsonify(dict(_scan_status))


# ESP32 machines may post card UIDs here (kept for future use)
@app.route("/api/card_present", methods=["POST"])
def api_card_present():
    """Called by ESP32 when a card is scanned. No login required."""
    data = request.get_json(silent=True) or request.form
    rfid = str(data.get("rfid", "")).strip().upper()
    if not rfid:
        return jsonify({"error": "no rfid"}), 400
    return jsonify({"ok": True})

# ── Step 2b: search ───────────────────────────────────────────────────────────

SEARCH_PAGE = """<!doctype html><html><head><title>Search Users – Woodshop</title>
{style}</head><body>
{nav}
<div class="container" style="max-width:600px">
  <div class="card">
    <h2>Search Users</h2>
    <form method="GET" action="/admin/users/search" style="display:flex;gap:.5rem;margin-bottom:.8rem">
      <input name="q" value="{q}" placeholder="name or member ID" style="margin:0">
      <button type="submit" style="flex-shrink:0">Search</button>
    </form>
    {results}
  </div>
</div></body></html>"""

@app.route("/admin/users/search")
@login_required
def admin_users_search():
    q = request.args.get("q","").strip()
    results_html = ""
    if q:
        hits = _search_users(q)
        if hits:
            rows = "".join(
                f"<tr>"
                f"<td>{u.get('id','')}</td>"
                f"<td>{u.get('first_name','')} {u.get('last_name','')}</td>"
                f"<td><a href='/admin/users/edit?uid={u.get('id','')}' class='btn btn-sm'>Edit</a></td>"
                f"</tr>"
                for u in hits
            )
            results_html = f"""<table>
              <thead><tr><th>Member ID</th><th>Name</th><th></th></tr></thead>
              <tbody>{rows}</tbody></table>"""
        else:
            results_html = f'<p class="empty">No users match "{q}".</p>'
    return SEARCH_PAGE.format(style=COMMON_STYLE, nav=NAV_AUTH.format(app_version=__version__),
                              q=q, results=results_html)

# ── Step 3: edit form ─────────────────────────────────────────────────────────

def _build_edit_page(user: dict, machines: list[dict],
                     mode: str, rfid: str, flash_html: str) -> str:
    """
    Render the full user edit form with the 128-machine permissions grid.
    mode: 'new' | 'card' | 'db'
    """
    perms = _perms_to_list(user.get("permissions",""))
    NAV_AUTH_V = NAV_AUTH.format(app_version=__version__)

    # Build machine lookup: index (0-based) → name
    mname = {}
    for m in machines:
        try:
            idx = int(m.get("id", m.get("machine_num", -1))) - 1  # 1-based → 0-based
            if 0 <= idx < NUM_MACHINES:
                mname[idx] = m.get("name", m.get("machine_name", ""))
        except (ValueError, TypeError):
            pass

    # Build the permissions grid: rows of 8, only first NUM_MACHINES slots
    COLS = 8
    grid_rows = ""
    for row_start in range(0, NUM_MACHINES, COLS):
        cells = ""
        for i in range(row_start, min(row_start + COLS, NUM_MACHINES)):
            name  = mname.get(i, "")
            label = name if name else f"M{i+1}"
            dim   = "" if name else "opacity:.4;"
            chk   = "checked" if perms[i] else ""
            cells += f"""
              <div class="pcell" title="Machine {i+1}{': ' + name if name else ''}">
                <label>
                  <input type="checkbox" name="perm_{i}" value="1" {chk}
                         class="pchk" data-idx="{i}">
                  <span class="plabel" style="{dim}">{label}</span>
                </label>
              </div>"""
        grid_rows += f'<div class="prow">{cells}</div>'

    # Determine source note
    source_note = {
        "card": "Data loaded from RFID card",
        "new":  "New user",
        "db":   "Data loaded from database"
    }.get(mode, "")

    return f"""<!doctype html><html><head>
<title>Edit User – Woodshop</title>
{COMMON_STYLE}
<style>
  .prow{{display:flex;flex-wrap:wrap;gap:2px;margin-bottom:2px}}
  .pcell{{background:#1e1e1e;border:1px solid var(--border);border-radius:3px;
          padding:.25rem .35rem;min-width:70px;flex:1}}
  .pcell label{{display:flex;flex-direction:column;align-items:center;
               gap:.15rem;cursor:pointer;margin:0}}
  .pcell input[type=checkbox]{{width:auto;margin:0;cursor:pointer}}
  .plabel{{font-size:.7rem;color:var(--muted);text-align:center;
           word-break:break-all;line-height:1.1}}
  .pcell:has(input:checked){{background:#1a3a1a;border-color:#2d6a2d}}
  .pcell:has(input:checked) .plabel{{color:#8bc34a}}
  .filter-bar{{display:flex;gap:.5rem;margin-bottom:.5rem;flex-wrap:wrap}}
  .filter-bar input{{margin:0;flex:1;min-width:120px}}
  .perm-summary{{font-size:.8rem;color:var(--muted);margin-bottom:.4rem}}
</style>
</head><body>
{NAV_AUTH_V}
<div class="container" style="max-width:760px">
  {flash_html}
  <div class="card">
    <h2>{'New User' if mode == 'new' else 'Edit User'}</h2>
    {f'<p style="font-size:.8rem;color:var(--muted);margin-bottom:.6rem">{source_note}</p>' if source_note else ''}

    <form method="POST" action="/admin/users/save" id="editForm">
      <input type="hidden" name="original_id" value="{user.get('id','')}">
      <input type="hidden" name="mode" value="{mode}">

      <div style="display:flex;gap:.8rem;flex-wrap:wrap">
        <div style="flex:1;min-width:140px">
          <label>Member ID</label>
          <input name="id" value="{user.get('id','')}" required>
        </div>
        <div style="flex:1;min-width:140px">
          <label>First Name</label>
          <input name="first_name" value="{user.get('first_name','')}">
        </div>
        <div style="flex:1;min-width:140px">
          <label>Last Name</label>
          <input name="last_name" value="{user.get('last_name','')}">
        </div>
      </div>

      <div style="display:flex;gap:.8rem;flex-wrap:wrap">
        <div style="flex:1;min-width:160px">
          <label>Email</label>
          <input name="email" value="{user.get('email','')}" placeholder="member@example.com">
        </div>
        <div style="flex:1;min-width:160px">
          <label>Phone</label>
          <input name="phone" value="{user.get('phone','')}">
        </div>
      </div>

      <div style="display:flex;gap:.8rem;flex-wrap:wrap">
        <div style="flex:1;min-width:160px">
          <label>RFID UID (hex)</label>
          <input name="rfid" value="{user.get('rfid', rfid)}" placeholder="04994E2A737A80">
        </div>
        <div style="flex:1;min-width:120px">
          <label>Joined (YYYY-MM-DD)</label>
          <input name="joined" value="{user.get('joined','')}" placeholder="2026-01-01">
        </div>
        <div style="flex:1;min-width:120px">
          <label>Expiry (YYYY-MM-DD)</label>
          <input name="expiry" value="{user.get('expiry', default_expiry_date())}" placeholder="2026-12-31">
        </div>
        <div style="flex:0;min-width:100px">
          <label>Active</label>
          <select name="active" style="width:auto">
            <option value="true"  {'selected' if user.get('active', True) else ''}>Yes</option>
            <option value="false" {'selected' if not user.get('active', True) else ''}>No</option>
          </select>
        </div>
      </div>

      <!-- Permissions grid -->
      <div style="margin-top:.8rem">
        <div style="display:flex;align-items:center;justify-content:space-between;
                    margin-bottom:.4rem;flex-wrap:wrap;gap:.4rem">
          <h2 style="margin:0">Machine Permissions</h2>
          <div style="display:flex;gap:.5rem">
            <button type="button" class="btn btn-sm" onclick="setAll(true)">All On</button>
            <button type="button" class="btn btn-sm btn-danger" onclick="setAll(false)">All Off</button>
          </div>
        </div>
        <div class="filter-bar">
          <input id="permSearch" placeholder="Filter machines by name …"
                 oninput="filterMachines(this.value)" style="flex:1">
          <span class="perm-summary" id="permCount"></span>
        </div>
        <div id="permGrid">
          {grid_rows}
        </div>
      </div>

      <div style="margin-top:.8rem;display:flex;gap:.5rem;flex-wrap:wrap">
        <button type="submit">💾 Save User</button>
        <a href="/admin/users" class="btn" style="background:#333;color:var(--text)">Cancel</a>
        {'<button type="button" class="btn btn-danger" onclick="deleteUser()" style="margin-left:auto">🗑 Delete</button>' if mode != 'new' else ''}
      </div>
    </form>
  </div>
</div>

<script>
function updateCount() {{
  const total = document.querySelectorAll('.pchk').length;
  const on    = document.querySelectorAll('.pchk:checked').length;
  document.getElementById('permCount').textContent = on + ' of ' + total + ' machines enabled';
}}
function setAll(val) {{
  document.querySelectorAll('.pchk:not([data-hidden])').forEach(c => c.checked = val);
  updateCount();
}}
function filterMachines(q) {{
  q = q.toLowerCase();
  document.querySelectorAll('.pcell').forEach(cell => {{
    const label = cell.querySelector('.plabel').textContent.toLowerCase();
    const title = (cell.title || '').toLowerCase();
    const show  = !q || label.includes(q) || title.includes(q);
    cell.style.display = show ? '' : 'none';
    const chk = cell.querySelector('input');
    if (show) chk.removeAttribute('data-hidden');
    else chk.setAttribute('data-hidden','1');
  }});
}}
document.querySelectorAll('.pchk').forEach(c =>
  c.addEventListener('change', updateCount));
updateCount();

function deleteUser() {{
  if (!confirm('Delete this user? This cannot be undone.')) return;
  fetch('/admin/users/delete', {{
    method: 'POST',
    headers: {{'Content-Type':'application/x-www-form-urlencoded'}},
    body: 'id=' + encodeURIComponent(document.querySelector('[name=original_id]').value)
  }}).then(() => window.location = '/admin/users?msg=User+deleted');
}}
</script>
</body></html>"""

@app.route("/admin/users/edit")
@login_required
def admin_users_edit():
    mode = request.args.get("mode", "db")   # new | card | db
    rfid = request.args.get("rfid", "").strip().upper()
    uid  = request.args.get("uid", "").strip()
    machines = load_json(MACHINES_FILE, [])

    user = {}
    flash_html = ""

    if mode == "card" and rfid:
        # Try to find user in DB by RFID UID
        users = load_json(USERS_FILE, [])
        matched = next((u for u in users
                        if str(u.get("rfid","")).upper() == rfid), None)
        if matched:
            user = matched
            flash_html = f'<div class="flash">Card {rfid} matched to {user.get("first_name","")} {user.get("last_name","")}. Editing existing record.</div>'
            mode = "db"
        else:
            # New card not in database
            user = {"rfid": rfid, "active": True, "permissions": "0" * NUM_MACHINES}
            flash_html = f'<div class="flash">Card {rfid} not found in database — creating new user.</div>'
            mode = "new"
    elif uid:
        user = _find_user(uid) or {}
        if not user:
            flash_html = '<div class="flash error">User not found.</div>'

    if mode == "new" and not user:
        user = {"active": True, "permissions": "0" * NUM_MACHINES}

    return _build_edit_page(user, machines, mode, rfid, flash_html)

# ── Step 4: save ──────────────────────────────────────────────────────────────

@app.route("/admin/users/save", methods=["POST"])
@login_required
def admin_users_save():
    f = request.form
    uid         = f.get("id","").strip()
    original_id = f.get("original_id","").strip()
    mode        = f.get("mode","db")

    if not uid:
        return redirect(url_for("admin_users",
                                msg="Member ID is required", err=1))

    # Rebuild permission string from checkboxes (first NUM_MACHINES bits only).
    # Preserve bits NUM_MACHINES..NUM_PERMS_STORED-1 from the existing record
    # so we never clobber data for machines 41-128.
    existing = _find_user(original_id) if original_id else None
    existing_bits = _perms_to_list(existing.get("permissions","") if existing else "")

    bits = []
    for i in range(NUM_MACHINES):
        bits.append(1 if f.get(f"perm_{i}") == "1" else 0)
    # append preserved upper bits unchanged
    bits.extend(existing_bits[NUM_MACHINES:NUM_PERMS_STORED])
    perms = _list_to_perms(bits)

    # Parse id as int if possible
    try:
        uid_val = int(uid)
    except ValueError:
        uid_val = uid

    new_rec = {
        "id":          uid_val,
        "first_name":  f.get("first_name","").strip(),
        "last_name":   f.get("last_name","").strip(),
        "email":       f.get("email","").strip(),
        "phone":       f.get("phone","").strip(),
        "rfid":        f.get("rfid","").strip().upper(),
        "joined":      f.get("joined","").strip(),
        "expiry":      f.get("expiry","").strip(),
        "active":      f.get("active","true") == "true",
        "permissions": perms,
    }

    users = load_json(USERS_FILE, [])

    # Replace or append
    idx = next((i for i,u in enumerate(users)
                if str(u.get("id","")) == original_id), None)
    if idx is not None:
        users[idx] = new_rec
    else:
        users.append(new_rec)

    # Re-sort by id after save
    try:
        users.sort(key=lambda u: int(u.get('id', 0)))
    except (ValueError, TypeError):
        pass
    save_json(USERS_FILE, users)
    enabled = sum(bits[:NUM_MACHINES])
    return redirect(url_for("admin_users",
                            msg=f"Saved {new_rec['first_name']} {new_rec['last_name']} — {enabled} of {NUM_MACHINES} machine permissions enabled"))

@app.route("/admin/users/delete", methods=["POST"])
@login_required
def admin_users_delete():
    uid   = request.form.get("id","").strip()
    users = load_json(USERS_FILE, [])
    users = [u for u in users if str(u.get("id","")) != uid]
    save_json(USERS_FILE, users)
    return jsonify({"ok": True})


# ── Admin: Bulk Membership Renewal ───────────────────────────────────────────

RENEW_PAGE = """<!doctype html><html><head><title>Renew Members – Woodshop</title>
{style}
<style>
  .member-row{{display:flex;align-items:center;gap:.8rem;padding:.45rem .6rem;
              border-bottom:1px solid #2a2a2a;font-size:.9rem}}
  .member-row:last-child{{border-bottom:none}}
  .member-row input[type=checkbox]{{width:auto;margin:0;cursor:pointer;
                                   width:1.1rem;height:1.1rem}}
  .member-name{{flex:1;font-weight:500}}
  .member-meta{{color:var(--muted);font-size:.8rem;min-width:200px;text-align:right}}
  .lapsed{{color:#ef9a9a}}
  .grace{{color:#f9a825}}
  .current{{color:#4caf50}}
  .inactive{{color:var(--muted);font-style:italic}}
  .bulk-actions{{display:flex;gap:.6rem;align-items:center;flex-wrap:wrap;
                margin-bottom:.8rem}}
  .renew-year{{background:#1e1e1e;border:1px solid var(--border);border-radius:4px;
               padding:.45rem .6rem;color:var(--text);font-size:.9rem;width:90px}}
</style>
</head><body>
{nav}
<div class="container" style="max-width:700px">
  {flash}
  <div class="card">
    <h2>Bulk Membership Renewal</h2>
    <p style="font-size:.83rem;color:var(--muted);margin-bottom:.8rem">
      Check members who have paid dues, then click Renew.
      Unchecked members will not be updated.
      Grace period: <strong>{grace} days</strong> after Dec 31.
    </p>

    <form method="POST" action="/admin/renew">
      <div class="bulk-actions">
        <button type="button" class="btn btn-sm" onclick="setAll(true)">✔ Check All</button>
        <button type="button" class="btn btn-sm" style="background:#333;color:var(--text)"
                onclick="setAll(false)">✗ Uncheck All</button>
        <label style="font-size:.85rem;color:var(--muted);margin:0">
          Renew through Dec 31,&nbsp;
          <input type="number" name="renew_year" value="{renew_year}" min="2020" max="2099"
                 class="renew-year">
        </label>
        <button type="submit" class="btn" style="margin-left:auto">💾 Renew Checked</button>
      </div>

      <div id="memberList">
        {rows}
      </div>
    </form>
  </div>
</div>
<script>
function setAll(val) {{
  document.querySelectorAll('input[name="renew_ids"]').forEach(c => c.checked = val);
}}
</script>
</body></html>"""

def _renew_status(user: dict) -> tuple:
    """Returns (css_class, status_label) for a user."""
    if not user.get('active', True):
        return 'inactive', 'Inactive'
    expiry_str = user.get('expiry', '')
    if not expiry_str:
        return 'current', 'No expiry'
    try:
        expiry = datetime.strptime(expiry_str, '%Y-%m-%d')
        effective = expiry + timedelta(days=MEMBERSHIP_GRACE_DAYS)
        now = datetime.now()
        if now > effective:
            return 'lapsed', f'Lapsed {expiry_str}'
        elif now > expiry:
            return 'grace', f'Grace until {effective.strftime("%Y-%m-%d")}'
        else:
            return 'current', f'Current through {expiry_str}'
    except ValueError:
        return 'current', expiry_str


@app.route("/admin/renew", methods=["GET"])
@login_required
def admin_renew():
    users = load_json(USERS_FILE, [])
    renew_year = datetime.now().year

    rows_html = ""
    for u in sorted(users, key=lambda x: (x.get('last_name',''), x.get('first_name',''))):
        uid   = u.get('id', '')
        name  = f"{u.get('first_name','')} {u.get('last_name','')}".strip() or str(uid)
        css, label = _renew_status(u)
        # Default: check active+current/grace members, uncheck lapsed/inactive
        checked = 'checked' if css in ('current', 'grace') else ''
        rows_html += f"""
        <div class="member-row">
          <input type="checkbox" name="renew_ids" value="{uid}" {checked}>
          <span class="member-name">{name}</span>
          <span class="member-meta {css}">{label}</span>
        </div>"""

    flash_html = ""
    msg = request.args.get("msg", "")
    if msg:
        flash_html = f'<div class="flash">{msg}</div>'

    return RENEW_PAGE.format(
        style=COMMON_STYLE, nav=NAV_AUTH.format(app_version=__version__), flash=flash_html,
        grace=MEMBERSHIP_GRACE_DAYS, renew_year=renew_year, rows=rows_html
    )


@app.route("/admin/renew", methods=["POST"])
@login_required
def admin_renew_post():
    renew_ids = set(request.form.getlist("renew_ids"))
    try:
        renew_year = int(request.form.get("renew_year", datetime.now().year))
    except ValueError:
        renew_year = datetime.now().year

    new_expiry = f"{renew_year}-{MEMBERSHIP_YEAR_END_MON:02d}-{MEMBERSHIP_YEAR_END_DAY:02d}"

    users = load_json(USERS_FILE, [])
    count = 0
    for u in users:
        if str(u.get('id', '')) in renew_ids:
            u['expiry'] = new_expiry
            count += 1

    save_json(USERS_FILE, users)
    return redirect(url_for('admin_renew',
        msg=f"✔ Renewed {count} member{'s' if count != 1 else ''} through {new_expiry}"))

MACHINES_PAGE = """<!doctype html><html><head><title>Machines – Woodshop</title>
{style}
<style>
  .status-on {{color:#4caf50;font-weight:600}}
  .status-off{{color:#ef9a9a;font-weight:600}}
</style>
</head><body>
{nav}
<div class="container" style="max-width:800px">
  {flash}
  <div class="card">
    <div style="display:flex;align-items:center;justify-content:space-between;
                flex-wrap:wrap;gap:.5rem;margin-bottom:.8rem">
      <h2 style="margin:0">Machines
        <span style="color:var(--muted);font-size:.8rem;font-weight:400">
          ({count} total)</span></h2>
      <div style="display:flex;gap:.5rem;flex-wrap:wrap">
        <a href="/admin/machines/edit?mode=new" class="btn btn-sm">➕ Add Machine</a>
        <a href="/api/machines/export.csv" class="btn btn-sm"
           style="background:#333;color:var(--text)">⬇ CSV</a>
        <label class="btn btn-sm" style="background:#333;color:var(--text);cursor:pointer">
          ⬆ Import CSV
          <input type="file" accept=".csv" style="display:none"
                 onchange="importCSV(this)">
        </label>
      </div>
    </div>
    <div style="overflow-x:auto">
      <table>
        <thead><tr>
          <th>ID</th><th>Name</th><th>Location</th><th>Status</th><th></th>
        </tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </div>
  </div>
</div>
<script>
function deleteMachine(mid, name) {{
  if (!confirm('Delete machine ' + name + ' (ID ' + mid + ')? This cannot be undone.')) return;
  fetch('/admin/machines/delete', {{
    method: 'POST',
    headers: {{'Content-Type':'application/x-www-form-urlencoded'}},
    body: 'id=' + encodeURIComponent(mid)
  }}).then(r => r.json()).then(d => {{
    if (d.ok) location.reload();
    else alert('Delete failed: ' + (d.error || 'unknown'));
  }});
}}
function importCSV(input) {{
  const file = input.files[0];
  if (!file) return;
  const form = new FormData();
  form.append('file', file);
  fetch('/api/machines/import.csv', {{ method: 'POST', body: form }})
    .then(r => r.json())
    .then(d => {{
      if (d.ok) {{ alert(d.message); location.reload(); }}
      else alert('Import failed: ' + (d.error || 'unknown'));
    }});
}}
</script>
</body></html>"""

MACHINE_EDIT_PAGE = """<!doctype html><html><head><title>{page_title} – Woodshop</title>
{style}</head><body>
{nav}
<div class="container" style="max-width:480px">
  {flash}
  <div class="card">
    <h2>{page_title}</h2>
    <form method="POST" action="/admin/machines/save">
      <input type="hidden" name="original_id" value="{original_id}">
      <label>Machine ID (number)</label>
      <input name="id" type="number" min="0" max="255" value="{mid}" required
             {id_readonly}>
      <label>Name</label>
      <input name="name" value="{name}" required>
      <label>Location</label>
      <input name="location" value="{location}">
      <label style="display:flex;align-items:center;gap:.5rem;cursor:pointer">
        <input name="enabled" type="checkbox" value="1" {checked}
               style="width:auto;margin:0">
        Enabled
      </label>
      <div style="display:flex;gap:.5rem;margin-top:.8rem">
        <button type="submit">Save</button>
        <a href="/admin/machines" class="btn"
           style="background:#333;color:var(--text)">Cancel</a>
      </div>
    </form>
  </div>
</div></body></html>"""

@app.route("/admin/machines", methods=["GET"])
@login_required
def admin_machines():
    flash_html = ""
    msg = request.args.get("msg", "")
    if msg:
        kind = "error" if request.args.get("err") else ""
        flash_html = f'<div class="flash {kind}">{msg}</div>'
    machines = load_json(MACHINES_FILE, [])
    machines_sorted = sorted(machines, key=lambda m: (
        int(m.get("id", 0)) if str(m.get("id","")).isdigit() else 0
    ))
    rows_html = ""
    for m in machines_sorted:
        mid      = m.get("id", "")
        name     = m.get("name", "")
        location = m.get("location", "")
        enabled  = m.get("enabled", True)
        status_css   = "on" if enabled else "off"
        status_label = "Enabled" if enabled else "Disabled"
        rows_html += (
            f'<tr>'
            f'<td>{mid}</td>'
            f'<td>{name}</td>'
            f'<td style="font-size:.85rem;color:var(--muted)">{location}</td>'
            f'<td><span class="status-{status_css}">{status_label}</span></td>'
            f'<td style="white-space:nowrap">'
            f'<a href="/admin/machines/edit?id={mid}" class="btn btn-sm">Edit</a> '
            f'<button class="btn btn-sm btn-danger"'
            f'  onclick="deleteMachine(\'{mid}\',\'{name}\')">Delete</button>'
            f'</td>'
            f'</tr>'
        )
    return MACHINES_PAGE.format(
        style=COMMON_STYLE, nav=NAV_AUTH.format(app_version=__version__),
        flash=flash_html, count=len(machines), rows=rows_html
    )

@app.route("/admin/machines/edit", methods=["GET"])
@login_required
def admin_machines_edit():
    mode = request.args.get("mode", "edit")
    mid  = request.args.get("id", "").strip()
    flash_html = ""
    machine = {}
    if mode == "new":
        page_title  = "Add Machine"
        id_readonly = ""
    else:
        machines = load_json(MACHINES_FILE, [])
        machine  = next((m for m in machines if str(m.get("id","")) == mid), {})
        if not machine:
            return redirect(url_for("admin_machines", msg="Machine not found", err=1))
        page_title  = "Edit Machine"
        id_readonly = "readonly style='opacity:.5'"
    return MACHINE_EDIT_PAGE.format(
        style=COMMON_STYLE, nav=NAV_AUTH.format(app_version=__version__),
        flash=flash_html, page_title=page_title,
        original_id=machine.get("id", ""),
        mid=machine.get("id", ""),
        name=machine.get("name", ""),
        location=machine.get("location", ""),
        checked="checked" if machine.get("enabled", True) else "",
        id_readonly=id_readonly,
    )

@app.route("/admin/machines/save", methods=["POST"])
@login_required
def admin_machines_save():
    f           = request.form
    mid         = f.get("id", "").strip()
    original_id = f.get("original_id", "").strip()
    name        = f.get("name", "").strip()
    location    = f.get("location", "").strip()
    enabled     = f.get("enabled") == "1"
    if not mid or not name:
        return redirect(url_for("admin_machines", msg="ID and Name are required", err=1))
    machines = load_json(MACHINES_FILE, [])
    # Remove old entry (handles both new and edit)
    machines = [m for m in machines if str(m.get("id","")) != original_id
                                    and str(m.get("id","")) != mid]
    machines.append({"id": mid, "name": name, "location": location, "enabled": enabled})
    machines.sort(key=lambda m: int(m["id"]) if str(m["id"]).isdigit() else 0)
    save_json(MACHINES_FILE, machines)
    return redirect(url_for("admin_machines", msg=f"Machine {mid} saved."))

@app.route("/admin/machines/delete", methods=["POST"])
@login_required
def admin_machines_delete():
    mid      = request.form.get("id", "").strip()
    machines = load_json(MACHINES_FILE, [])
    machines = [m for m in machines if str(m.get("id", "")) != mid]
    save_json(MACHINES_FILE, machines)
    return jsonify({"ok": True})

# ── Admin: Change password ────────────────────────────────────────────────────

PASSWD_PAGE = """<!doctype html><html><head><title>Change Password – Woodshop</title>
{style}</head><body>
{nav}
<div class="container" style="max-width:400px">
  <div class="card" style="margin-top:2rem">
    <h2>Change Admin Password</h2>
    {flash}
    <form method="POST">
      <label>Current password</label>
      <input name="current" type="password" required>
      <label>New password</label>
      <input name="new1" type="password" required>
      <label>Confirm new password</label>
      <input name="new2" type="password" required>
      <button type="submit">Update Password</button>
    </form>
  </div>
</div></body></html>"""

@app.route("/admin/password", methods=["GET","POST"])
@login_required
def admin_password():
    flash_html = ""
    if request.method == "POST":
        current = request.form.get("current","")
        new1    = request.form.get("new1","")
        new2    = request.form.get("new2","")
        creds   = load_json(ADMIN_CREDS, {})
        if creds.get("password_hash") != hash_password(current):
            flash_html = '<div class="flash error">Current password incorrect.</div>'
        elif new1 != new2:
            flash_html = '<div class="flash error">New passwords do not match.</div>'
        elif len(new1) < 6:
            flash_html = '<div class="flash error">Password must be at least 6 characters.</div>'
        else:
            creds["password_hash"] = hash_password(new1)
            save_json(ADMIN_CREDS, creds)
            flash_html = '<div class="flash">✔ Password updated.</div>'
    return PASSWD_PAGE.format(style=COMMON_STYLE, nav=NAV_AUTH.format(app_version=__version__), flash=flash_html)

# ── Admin: NTP Sync ───────────────────────────────────────────────────────────
#
# Workflow:
#   1. User connects phone/tablet hotspot → Pi joins it (wpa_supplicant call)
#   2. Pi queries pool.ntp.org for current UTC time
#   3. Python writes the time to the DS3231 via I2C (smbus2)
#   4. Result displayed on-screen with before/after timestamps
#
# DS3231 I2C address is 0x68; we write directly with smbus2 so there's
# no Arduino dependency.  Install with: pip install smbus2
#
# All long operations (WiFi join, NTP query, RTC write) run in a background
# thread and stream status via the /admin/ntp/status JSON endpoint so the
# page can poll without timing out.
# ─────────────────────────────────────────────────────────────────────────────

# Thread-safe status log for the NTP operation
_ntp_log: list[str] = []
_ntp_running = False
_ntp_lock    = threading.Lock()

DS3231_I2C_BUS  = 1      # /dev/i2c-1 on Pi (change to 0 for older Pi rev)
DS3231_ADDRESS  = 0x68
UTC_OFFSET_FILE = os.path.join(BASE_DIR, "data", "utc_offset.json")  # persists TZ choice

def _log(msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    with _ntp_lock:
        _ntp_log.append(f"[{ts}] {msg}")

def _bcd(n: int) -> int:
    return (n // 10) << 4 | (n % 10)

def _write_ds3231(dt: datetime):
    """Write datetime to DS3231 over I2C using smbus2."""
    try:
        import smbus2
        bus = smbus2.SMBus(DS3231_I2C_BUS)
        # Registers 0x00–0x06: sec, min, hr, dow, date, mon, yr (all BCD)
        bus.write_i2c_block_data(DS3231_ADDRESS, 0x00, [
            _bcd(dt.second),
            _bcd(dt.minute),
            _bcd(dt.hour),
            _bcd(dt.weekday() + 1),   # DS3231 day-of-week 1–7
            _bcd(dt.day),
            _bcd(dt.month),
            _bcd(dt.year % 100)
        ])
        bus.close()
        return True, None
    except ImportError:
        return False, "smbus2 not installed (pip install smbus2)"
    except Exception as e:
        return False, str(e)

def _get_ntp_time(server: str = "pool.ntp.org") -> float | None:
    """Raw NTP query — no external library needed."""
    packet = b'\x1b' + 47 * b'\0'
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(10)
            s.sendto(packet, (server, 123))
            data, _ = s.recvfrom(1024)
        ts = struct.unpack('!I', data[40:44])[0]
        return ts - 2208988800  # NTP epoch → Unix epoch
    except Exception as e:
        _log(f"NTP query failed: {e}")
        return None

# Name of the main shop WiFi connection to restore after hotspot sync
SHOP_CONNECTION = "netplan-wlan0-BigHippo"

def _join_wifi(ssid: str, password: str) -> bool:
    """
    Connect to a WiFi hotspot using nmcli (Pi OS Bookworm/NetworkManager).
    Creates a fresh connection profile with explicit WPA-PSK security.
    Requires root privileges (service runs as root).
    """
    try:
        # Delete any stale profile with same name
        subprocess.run(["nmcli", "connection", "delete", ssid],
                       capture_output=True, timeout=10)
        # Create fresh profile with explicit WPA-PSK
        r = subprocess.run(
            ["nmcli", "connection", "add",
             "type", "wifi",
             "con-name", ssid,
             "ssid", ssid,
             "wifi-sec.key-mgmt", "wpa-psk",
             "wifi-sec.psk", password],
            capture_output=True, text=True, timeout=30
        )
        if r.returncode != 0:
            _log(f"nmcli add failed: {r.stderr.strip()}")
            return False
        r2 = subprocess.run(
            ["nmcli", "connection", "up", ssid],
            capture_output=True, text=True, timeout=30
        )
        if r2.returncode == 0:
            _log(f"nmcli: connected to '{ssid}'")
            return True
        _log(f"nmcli connect failed: {r2.stderr.strip()}")
        return False
    except Exception as e:
        _log(f"nmcli error: {e}")
        return False

def _restore_wifi() -> None:
    """Reconnect to the main shop WiFi after hotspot sync."""
    import time
    _log(f"Reconnecting to shop WiFi ({SHOP_CONNECTION}) …")
    # Delete the temporary hotspot profile
    subprocess.run(["nmcli", "connection", "delete", "hotspot-ntp-temp"],
                   capture_output=True, timeout=10)
    time.sleep(2)
    r = subprocess.run(
        ["nmcli", "connection", "up", SHOP_CONNECTION],
        capture_output=True, text=True, timeout=30
    )
    if r.returncode == 0:
        _log("✔ Reconnected to shop WiFi")
    else:
        _log(f"WARNING: Could not reconnect to shop WiFi: {r.stderr.strip()}")

def _ntp_sync_worker(ssid: str, password: str, utc_offset: int,
                     ntp_server: str, skip_wifi: bool):
    global _ntp_running
    hotspot_connected = False
    try:
        _log("── NTP sync started ──")

        if not skip_wifi:
            _log(f"Connecting to hotspot '{ssid}' …")
            if not _join_wifi(ssid, password):
                _log("ERROR: Could not connect to hotspot. Aborting.")
                return
            hotspot_connected = True
            import time; time.sleep(3)
            _log("WiFi connected. Waiting for DHCP …")
            time.sleep(2)
        else:
            _log("Skipping WiFi step (already connected).")

        _log(f"Querying {ntp_server} …")
        unix_ts = _get_ntp_time(ntp_server)
        if unix_ts is None:
            _log("ERROR: NTP query returned no result.")
            return

        utc_dt = datetime.utcfromtimestamp(unix_ts)
        local_dt = datetime.fromtimestamp(unix_ts + utc_offset * 3600)
        _log(f"NTP UTC time : {utc_dt.strftime('%Y-%m-%d %H:%M:%S')}")
        _log(f"Local time   : {local_dt.strftime('%Y-%m-%d %H:%M:%S')} "
             f"(UTC{utc_offset:+d})")

        _log("Writing to DS3231 …")
        ok, err = _write_ds3231(local_dt)
        if ok:
            _log(f"✔ DS3231 updated to {local_dt.strftime('%Y-%m-%d %H:%M:%S')}")
        else:
            _log(f"ERROR writing DS3231: {err}")

        # Persist UTC offset so next open of the page pre-fills it
        save_json(UTC_OFFSET_FILE, {"utc_offset": utc_offset})

    except Exception as e:
        _log(f"Unexpected error: {e}")
    finally:
        # Always reconnect to shop WiFi if we switched away
        if hotspot_connected:
            _restore_wifi()
        _ntp_running = False
        _log("── Done ──")

NTP_PAGE = """<!doctype html><html><head><title>NTP Sync – Woodshop</title>
{style}
<style>
  #log-box{{background:#111;border:1px solid var(--border);border-radius:4px;
            padding:.6rem;font-family:monospace;font-size:.82rem;min-height:80px;
            max-height:260px;overflow-y:auto;color:#8bc34a;margin-top:.6rem}}
  .row2{{display:flex;gap:.6rem}}
  .row2>div{{flex:1}}
</style>
</head><body>
{nav}
<div class="container" style="max-width:500px">
  <div class="card">
    <h2>📡 NTP Time Sync → DS3231</h2>
    <p style="font-size:.83rem;color:var(--muted);margin-bottom:.8rem">
      Connect the Pi to your phone/tablet hotspot, then sync the RTC from the
      internet. The hotspot must have internet access.
    </p>
    {flash}
    <form id="syncForm">
      <label>Hotspot SSID</label>
      <input id="ssid" name="ssid" placeholder="MyPhone" value="{last_ssid}">
      <label>Hotspot Password</label>
      <input id="pw" name="password" type="password" placeholder="hotspot password">
      <label>NTP Server</label>
      <input id="ntp" name="ntp_server" value="pool.ntp.org">
      <div class="row2">
        <div>
          <label>UTC Offset (hours)</label>
          <input id="utc" name="utc_offset" type="number" min="-12" max="14"
                 value="{utc_offset}" style="width:80px">
        </div>
        <div style="display:flex;align-items:flex-end;padding-bottom:.75rem">
          <label style="display:flex;gap:.4rem;align-items:center;margin:0">
            <input type="checkbox" id="skipWifi" name="skip_wifi" style="width:auto;margin:0">
            Already on correct WiFi
          </label>
        </div>
      </div>
      <button type="submit" id="syncBtn">🔄 Sync Now</button>
    </form>
    <div id="log-box">Ready.</div>
  </div>
</div>

<script>
const form = document.getElementById('syncForm');
const btn  = document.getElementById('syncBtn');
const log  = document.getElementById('log-box');
let polling = false;

async function pollStatus() {{
  try {{
    const r = await fetch('/admin/ntp/status');
    const d = await r.json();
    log.textContent = d.log.join('\\n');
    log.scrollTop = log.scrollHeight;
    if (d.running) {{
      setTimeout(pollStatus, 1000);
    }} else {{
      btn.disabled = false;
      btn.textContent = '🔄 Sync Now';
      polling = false;
    }}
  }} catch(e) {{
    setTimeout(pollStatus, 2000);
  }}
}}

form.addEventListener('submit', async (e) => {{
  e.preventDefault();
  if (polling) return;
  btn.disabled = true;
  btn.textContent = 'Syncing …';
  log.textContent = 'Starting …';
  polling = true;

  const body = new URLSearchParams({{
    ssid:       document.getElementById('ssid').value,
    password:   document.getElementById('pw').value,
    ntp_server: document.getElementById('ntp').value,
    utc_offset: document.getElementById('utc').value,
    skip_wifi:  document.getElementById('skipWifi').checked ? '1' : '0'
  }});

  try {{
    await fetch('/admin/ntp/run', {{method:'POST', body}});
  }} catch(e) {{}}  // response may not arrive if WiFi drops
  setTimeout(pollStatus, 1500);
}});
</script>
</body></html>"""

@app.route("/admin/ntp", methods=["GET"])
@login_required
def admin_ntp():
    saved = load_json(UTC_OFFSET_FILE, {})
    return NTP_PAGE.format(
        style    = COMMON_STYLE,
        nav      = NAV_AUTH.format(app_version=__version__),
        flash    = "",
        last_ssid= "",
        utc_offset = saved.get("utc_offset", -5)
    )

@app.route("/admin/ntp/run", methods=["POST"])
@login_required
def admin_ntp_run():
    global _ntp_running, _ntp_log
    if _ntp_running:
        return jsonify({"status": "already running"})

    ssid       = request.form.get("ssid", "").strip()
    password   = request.form.get("password", "")
    ntp_server = request.form.get("ntp_server", "pool.ntp.org").strip()
    skip_wifi  = request.form.get("skip_wifi", "0") == "1"
    try:
        utc_offset = int(request.form.get("utc_offset", -5))
    except ValueError:
        utc_offset = -5

    with _ntp_lock:
        _ntp_log = []
        _ntp_running = True

    t = threading.Thread(
        target=_ntp_sync_worker,
        args=(ssid, password, utc_offset, ntp_server, skip_wifi),
        daemon=True
    )
    t.start()
    return jsonify({"status": "started"})

@app.route("/admin/ntp/status")
@login_required
def admin_ntp_status():
    with _ntp_lock:
        return jsonify({"running": _ntp_running, "log": list(_ntp_log)})

# ── Admin: Config Card ────────────────────────────────────────────────────────
#
# Writes a signed config card (type 0x02) to an NTAG215 containing:
#   Byte 0: Card type (0x02)
#   Byte 1: Card version (0x01)
#   Byte 2: Machine number (0-255)
#   Byte 3: Blast gate delay (0-15, ×10 seconds)
#   Byte 4: Reserved
#   Bytes 5-68: Ed25519 signature over bytes 0-4
#
# The ESP32 node reads this card at boot, stores config in NVS flash,
# and does not require the card again unless NVS is explicitly cleared.
#
# Card types:
#   0x01 = member card
#   0x02 = config card
#   0x03 = erase-config card (future use)
# ─────────────────────────────────────────────────────────────────────────────

CONFIG_CARD_TYPE    = 0x02
CONFIG_CARD_VERSION = 0x01
CONFIG_PAYLOAD_LEN  = 5     # bytes 0-4 are signed
CONFIG_CARD_LEN     = 72    # 5 payload + 64 sig + 3 pad to 4-byte boundary = 72

CONFIG_CARD_PAGE = """<!doctype html><html><head>
<title>Write Config Card – Woodshop</title>{style}</head><body>
{nav}
<div class="container" style="max-width:500px">
  <div class="card">
    <h2>⚙ Write Config Card</h2>
    <p style="color:var(--muted);font-size:.85rem;margin-bottom:.8rem">
      Programs a node's machine number and blast gate delay into an NTAG215
      card. The node reads this card once at boot and caches the config in
      NVS flash — the card is not needed again unless the node is re-flashed
      or config is explicitly cleared.</p>

    {flash}

    <table style="margin-bottom:.8rem;font-size:.85rem">
      <tr><th style="width:50%;padding-right:1rem">Machine number</th>
          <td>0–255 (8-bit node ID)</td></tr>
      <tr><th>Blast gate delay</th>
          <td>0–150 s in 10 s steps (4-bit value × 10)</td></tr>
    </table>

    <div id="opStatus" style="display:none;text-align:center;padding:1rem 0">
      <div id="opIcon" style="font-size:2.5rem">⏳</div>
      <div id="opMsg"  style="color:var(--muted);margin-top:.4rem;font-size:.9rem">
        Starting…</div>
    </div>

    <div id="opForm">
      <label>Machine Number (0–255)</label>
      <input id="machNum" type="number" min="0" max="255" value="0"
             style="width:120px">

      <label>Blast Gate Delay</label>
      <select id="blastDelay" style="width:auto">
        <option value="0">0 s (off)</option>
        <option value="1">10 s</option>
        <option value="2">20 s</option>
        <option value="3">30 s</option>
        <option value="4">40 s</option>
        <option value="5">50 s</option>
        <option value="6">60 s</option>
        <option value="7">70 s</option>
        <option value="8">80 s</option>
        <option value="9">90 s</option>
        <option value="10">100 s</option>
        <option value="11">110 s</option>
        <option value="12">120 s</option>
        <option value="13">130 s</option>
        <option value="14">140 s</option>
        <option value="15">150 s (always on)</option>
      </select>

      <div style="display:flex;gap:.5rem;flex-wrap:wrap;margin-top:.8rem"
           id="opActions">
        <button id="startBtn" onclick="startOp()">
          📡 Start — Place Card on Reader</button>
        <a href="/admin/users" class="btn"
           style="background:#333;color:var(--text)">Cancel</a>
      </div>
    </div>
  </div>
</div>
<script>
function setUI(icon, msg) {{
  document.getElementById('opIcon').textContent = icon;
  document.getElementById('opMsg').textContent  = msg;
}}
function startOp() {{
  const machNum    = parseInt(document.getElementById('machNum').value);
  const blastDelay = parseInt(document.getElementById('blastDelay').value);
  if (isNaN(machNum) || machNum < 0 || machNum > 255) {{
    alert('Machine number must be 0–255'); return;
  }}
  document.getElementById('startBtn').disabled = true;
  document.getElementById('opStatus').style.display = 'block';
  setUI('⏳', 'Starting…');
  fetch('/api/config_card_start', {{
    method: 'POST',
    headers: {{'Content-Type':'application/json'}},
    body: JSON.stringify({{machine_num: machNum, blast_delay: blastDelay}})
  }}).then(r=>r.json()).then(d=>{{
    if (d.ok) poll();
    else setUI('❌', 'Error: '+(d.error||'unknown'));
  }}).catch(()=>setUI('❌','Network error'));
}}
async function poll() {{
  try {{
    const d = await (await fetch('/api/card_op_status')).json();
    if (d.state==='waiting')  {{ setUI('📡', d.message); setTimeout(poll,800); }}
    else if (d.state==='writing') {{ setUI('✏️', d.message); setTimeout(poll,600); }}
    else if (d.state==='done') {{
      setUI('✅', d.message);
      document.getElementById('opActions').innerHTML =
        '<a href="/admin/config-card" class="btn">Write Another</a>'
        +'<a href="/admin/users" class="btn" style="background:#333;color:var(--text)">Done</a>';
    }} else if (d.state==='error') {{
      setUI('❌', 'Error: '+d.message);
      document.getElementById('startBtn').disabled=false;
    }} else {{ setTimeout(poll,1000); }}
  }} catch(e) {{ setTimeout(poll,1200); }}
}}
</script>
</body></html>"""


def _run_config_card_write(machine_num, blast_delay):
    """Background thread: write a signed config card via Pi's local PN532."""
    try:
        import struct, time
        import board, busio, digitalio
        from adafruit_pn532.spi import PN532_SPI

        private_key = _load_card_private_key()
        if private_key is None:
            _card_op_set("error", "Private key not found")
            return

        spi   = busio.SPI(board.SCK, board.MOSI, board.MISO)
        cs    = digitalio.DigitalInOut(board.CE0)
        pn532 = PN532_SPI(spi, cs, debug=False)
        pn532.SAM_configuration()

        # Build 5-byte payload and sign it
        payload = struct.pack('5B',
            CONFIG_CARD_TYPE,
            CONFIG_CARD_VERSION,
            machine_num & 0xFF,
            blast_delay & 0x0F,
            0x00               # reserved
        )
        signature  = private_key.sign(payload)   # 64 bytes Ed25519
        card_bytes = payload + signature          # 69 bytes

        # Pad to 4-byte page boundary → 72 bytes
        card_bytes += b'\x00' * (CONFIG_CARD_LEN - len(card_bytes))

        _card_op_set("waiting", "Place config card on reader…")

        deadline = time.time() + 60
        card_uid = None
        while time.time() < deadline:
            card_uid = pn532.read_passive_target(timeout=0.5)
            if card_uid:
                break
        if not card_uid:
            _card_op_set("error", "Timed out waiting for card (60 s)")
            return

        _card_op_set("writing", "Writing config card…")
        pages = CONFIG_CARD_LEN // 4
        for i in range(pages):
            page = 4 + i
            pn532.ntag2xx_write_block(page, card_bytes[i*4:(i+1)*4])
            time.sleep(0.01)

        _card_op_set("done",
            f"Config card written: machine {machine_num}, "
            f"blast gate delay {blast_delay * 10} s")

    except Exception as e:
        _card_op_set("error", str(e))


@app.route("/admin/config-card")
@login_required
def admin_config_card():
    flash_html = ""
    msg = request.args.get("msg", "")
    if msg:
        kind = "error" if request.args.get("err") else ""
        flash_html = f'<div class="flash {kind}">{msg}</div>'
    return CONFIG_CARD_PAGE.format(
        style=COMMON_STYLE, nav=NAV_AUTH.format(app_version=__version__), flash=flash_html
    )


@app.route("/api/config_card_start", methods=["POST"])
@login_required
def api_config_card_start():
    """Start a background config card write operation."""
    with _card_op_lock:
        if _card_op_status["state"] in ("waiting", "writing"):
            return jsonify({"error": "operation already in progress"}), 409

    data = request.get_json(silent=True) or {}
    try:
        machine_num  = int(data.get("machine_num", 0))
        blast_delay  = int(data.get("blast_delay", 0))
    except (ValueError, TypeError):
        return jsonify({"error": "invalid parameters"}), 400

    if not (0 <= machine_num <= 255):
        return jsonify({"error": "machine_num out of range 0-255"}), 400
    if not (0 <= blast_delay <= 15):
        return jsonify({"error": "blast_delay out of range 0-15"}), 400

    _card_op_set("starting", "")
    t = threading.Thread(
        target=_run_config_card_write,
        args=(machine_num, blast_delay),
        daemon=True
    )
    t.start()
    return jsonify({"ok": True})


FIRMWARE_DIR = os.path.join(BASE_DIR, "firmware")


# ── OTA Firmware endpoints ────────────────────────────────────────────────────

@app.route("/firmware/version")
def firmware_version():
    """Return current firmware version string."""
    try:
        with open(os.path.join(FIRMWARE_DIR, "version.txt")) as f:
            return f.read().strip()
    except OSError:
        return "0.0.0"


@app.route("/firmware/manifest.json")
def firmware_manifest():
    """Return JSON list of {file, md5} for all .py files in firmware dir."""
    entries = []
    try:
        for fname in sorted(os.listdir(FIRMWARE_DIR)):
            if not fname.endswith(".py") or fname == "__init__.py":
                continue
            path = os.path.join(FIRMWARE_DIR, fname)
            md5  = hashlib.md5(open(path, "rb").read()).hexdigest()
            entries.append({"file": fname, "md5": md5})
    except OSError:
        pass
    from flask import jsonify as _jsonify
    return _jsonify(entries)


@app.route("/firmware/<path:filename>")
def firmware_file(filename):
    """Serve a firmware file for OTA download."""
    from flask import send_from_directory, abort
    # Prevent path traversal
    if ".." in filename or filename.startswith("/"):
        abort(400)
    return send_from_directory(FIRMWARE_DIR, filename)


# ── Machines CSV export ────────────────────────────────────────────────────────

@app.route("/api/machines/export.csv")
@login_required
def api_machines_export():
    import io
    from flask import Response
    machines = load_json(MACHINES_FILE, [])
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "name", "location", "enabled"])
    for m in machines:
        writer.writerow([
            m.get("id", ""), m.get("name", ""),
            m.get("location", ""), m.get("enabled", True),
        ])
    return Response(output.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=woodshop_machines.csv"})


# ── Log CSV export ─────────────────────────────────────────────────────────────

@app.route("/api/log/export.csv")
@login_required
def api_log_export():
    from flask import Response
    try:
        with open(LOG_FILE, "r", newline="") as f:
            data = f.read()
    except FileNotFoundError:
        data = ""
    return Response(data, mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=woodshop_access_log.csv"})


# ── Users CSV import ───────────────────────────────────────────────────────────

@app.route("/api/users/import.csv", methods=["POST"])
@login_required
def api_users_import():
    from flask import jsonify as _j
    f = request.files.get("file")
    if not f:
        return _j({"ok": False, "error": "No file uploaded"})
    try:
        text    = f.read().decode("utf-8-sig")   # strip BOM if present
        reader  = csv.DictReader(text.splitlines())
        # Accept either 'member_id' or 'id' as the ID column
        new_users = []
        for row in reader:
            uid = row.get("member_id") or row.get("id", "")
            if not uid:
                continue
            try:
                uid = int(uid)
            except ValueError:
                pass
            active_raw = str(row.get("active", "True")).strip().lower()
            active = active_raw not in ("false", "0", "no")
            new_users.append({
                "id":           uid,
                "first_name":   row.get("first_name", "").strip(),
                "last_name":    row.get("last_name", "").strip(),
                "email":        row.get("email", "").strip(),
                "phone":        row.get("phone", "").strip(),
                "rfid":         row.get("rfid", "").strip().upper(),
                "joined":       row.get("joined", "").strip(),
                "expiry":       row.get("expiry", "").strip(),
                "active":       active,
                "permissions":  row.get("permissions", "0" * 128).strip(),
            })
        if not new_users:
            return _j({"ok": False, "error": "No valid rows found in CSV"})
        # Merge: existing records not in CSV are preserved; CSV records overwrite by ID
        existing = load_json(USERS_FILE, [])
        existing_by_id = {str(u.get("id", "")): u for u in existing}
        for u in new_users:
            existing_by_id[str(u["id"])] = u
        save_json(USERS_FILE, list(existing_by_id.values()))
        return _j({"ok": True, "message": f"Imported {len(new_users)} user(s) successfully."})
    except Exception as e:
        return _j({"ok": False, "error": str(e)})


# ── Machines CSV import ────────────────────────────────────────────────────────

@app.route("/api/machines/import.csv", methods=["POST"])
@login_required
def api_machines_import():
    from flask import jsonify as _j
    f = request.files.get("file")
    if not f:
        return _j({"ok": False, "error": "No file uploaded"})
    try:
        text   = f.read().decode("utf-8-sig")
        reader = csv.DictReader(text.splitlines())
        new_machines = []
        for row in reader:
            mid = row.get("id", "").strip()
            if not mid:
                continue
            enabled_raw = str(row.get("enabled", "True")).strip().lower()
            enabled = enabled_raw not in ("false", "0", "no")
            new_machines.append({
                "id":       mid,
                "name":     row.get("name", "").strip(),
                "location": row.get("location", "").strip(),
                "enabled":  enabled,
            })
        if not new_machines:
            return _j({"ok": False, "error": "No valid rows found in CSV"})
        # Merge by machine id
        existing = load_json(MACHINES_FILE, [])
        existing_by_id = {str(m.get("id", "")): m for m in existing}
        for m in new_machines:
            existing_by_id[str(m["id"])] = m
        save_json(MACHINES_FILE, list(existing_by_id.values()))
        return _j({"ok": True, "message": f"Imported {len(new_machines)} machine(s) successfully."})
    except Exception as e:
        return _j({"ok": False, "error": str(e)})


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    seed_demo_data()
    print("\nWoodshop web server starting...")
    print("Browse to http://<pi-ip>  (port 80)")
    print("Default login:  admin / woodshop\n")
    app.run(host="0.0.0.0", port=80, debug=False)
