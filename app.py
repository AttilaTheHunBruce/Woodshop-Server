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
    <a href="/admin/diag">Diagnostics</a>
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
# Step 1: /admin/users           — choose: List All  OR  Search by name/ID
# Step 2: /admin/users/search    — search form → results list
# Step 3: /admin/users/edit      — full edit form with permissions grid
# Step 4: POST /admin/users/save — write back to users.json
#
# Aug 2026: member-card RFID read/write/erase removed. Login/logout is now
# handled entirely by Lee's system over the network (port 45432) — Server
# no longer reads or writes member cards at all. The permissions grid here
# still edits the reduced member file (memberID + machine access bits),
# which is what gets looked up when a member logs in.
# ─────────────────────────────────────────────────────────────────────────────

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
    mode = request.args.get("mode", "db")   # new | db
    rfid = request.args.get("rfid", "").strip().upper()
    uid  = request.args.get("uid", "").strip()
    machines = load_json(MACHINES_FILE, [])

    user = {}
    flash_html = ""

    if uid:
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

FIRMWARE_DIR = os.path.join(BASE_DIR, "firmware")
FIRMWARE_BIN = "firmware.bin"   # single compiled image; see /firmware/manifest.json


# ── OTA Firmware endpoints ────────────────────────────────────────────────────
# Aug 2026: the client rewrote from ESP32-C3/MicroPython (many loose .py
# source files, patched individually) to ESP32/C (one compiled binary,
# flashed as a whole into the inactive OTA partition — see the client's
# ota_task.cpp for the full explanation). The manifest below changed to
# match: one firmware.bin, not a list of source files. version.txt and the
# generic /firmware/<filename> file server both still work exactly as
# before — only firmware_manifest() below actually changed.
#
# To ship an update:
#   1. Arduino IDE: Sketch > Export Compiled Binary (produces .ino.bin next
#      to the sketch). Copy it to FIRMWARE_DIR as "firmware.bin".
#   2. Bump the version string in FIRMWARE_DIR/version.txt to match the new
#      FW_VERSION you set in the client's config.h.
#   3. set_ota.py true   (flips UPDATE_AVAILABLE in master_server.py and
#      restarts woodshop-tcp — unchanged from before)
#   4. Each node picks up update_available=1 on its next card event (fast
#      path) or its next periodic self-check (idle nodes, every 10 min —
#      see OTA_CHECK_INTERVAL_MS), downloads+flashes in the background, and
#      reboots into it once no card session is open. Nodes already running
#      the new version see their own version match FIRMWARE_DIR/version.txt
#      and skip re-flashing, so UPDATE_AVAILABLE can safely stay True for
#      the whole rollout — no more need to rush set_ota.py false the moment
#      the last node updates (still worth doing eventually, just not urgent).

@app.route("/firmware/version")
def firmware_version():
    """Return current firmware version string (human/admin convenience;
    the client itself reads the "version" field of manifest.json below)."""
    try:
        with open(os.path.join(FIRMWARE_DIR, "version.txt")) as f:
            return f.read().strip()
    except OSError:
        return "0.0.0"


@app.route("/firmware/manifest.json")
def firmware_manifest():
    """Return {file, version, md5, size} describing the one firmware.bin,
    or {} if no image has been staged in FIRMWARE_DIR yet."""
    from flask import jsonify as _jsonify

    path = os.path.join(FIRMWARE_DIR, FIRMWARE_BIN)
    if not os.path.isfile(path):
        return _jsonify({})

    try:
        with open(os.path.join(FIRMWARE_DIR, "version.txt")) as f:
            version = f.read().strip()
    except OSError:
        version = "0.0.0"

    data = open(path, "rb").read()
    return _jsonify({
        "file":    FIRMWARE_BIN,
        "version": version,
        "md5":     hashlib.md5(data).hexdigest(),
        "size":    len(data),
    })


@app.route("/firmware/<path:filename>")
def firmware_file(filename):
    """Serve a firmware file for OTA download (firmware.bin, in practice)."""
    from flask import send_from_directory, abort
    # Prevent path traversal
    if ".." in filename or filename.startswith("/"):
        abort(400)
    return send_from_directory(FIRMWARE_DIR, filename)


# ── Diagnostics (diag.h / diag.cpp on the client, Aug 2026) ──────────────────
# Units installed in the field were rebooting several times in rapid
# succession with no discernible pattern and no way to have a laptop on
# Serial when it happened. The client firmware captures why each boot
# happened (esp_reset_reason + a breadcrumb of what the firmware was doing
# right before the reset) and POSTs it here once WiFi comes up after any
# boot that has a report pending. See claude/diag-server-endpoint-spec.md
# in the Woodshop Client project for the full field-by-field description.
#
# No login required here, same trust model as the /firmware/* endpoints
# above: nodes on the shop LAN post directly, no browser session involved.
#
# Storage: one JSONL file per machine number under data/diag/, trimmed to
# the most recent DIAG_KEEP_PER_MACHINE lines on every write so this can't
# grow unbounded even if a node reboot-loops for hours. Each accepted
# report is also appended to the main text logfile (master.log, the same
# file master_server.py's logger writes to) so bootup/restart codes show
# up there too, not just on the /admin/diag page.
#
# Aug 2026 update: the client's on-device NVS ring buffer (16 entries) is
# no longer just a last-resort fallback for a report that never arrived --
# after being offline it now forwards the whole backlog in one POST, so
# this endpoint accepts either a single report object (the normal case)
# or a JSON array of report objects (a ring-buffer backlog). Each entry in
# a batch is stored and logged exactly like a single report would be.

DIAG_DIR              = os.path.join(BASE_DIR, "data", "diag")
DIAG_KEEP_PER_MACHINE  = 200
MASTER_LOG_FILE        = os.path.join(BASE_DIR, 'master.log')

def _diag_log_path(machine_num) -> str:
    return os.path.join(DIAG_DIR, f"diag_machine_{machine_num}.jsonl")

# Separate named logger (not Flask's own) that appends to the same
# master.log file master_server.py writes to, in the same format, so boot
# reports interleave chronologically with everything else in that file.
import logging as _logging
diag_logger = _logging.getLogger("woodshop.diag")
diag_logger.setLevel(_logging.INFO)
if not diag_logger.handlers:
    _diag_handler = _logging.FileHandler(MASTER_LOG_FILE)
    _diag_handler.setFormatter(_logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    diag_logger.addHandler(_diag_handler)
    diag_logger.propagate = False

def _ingest_one_diag_report(data: dict) -> bool:
    """Validate, store (JSONL), and logfile one report. Returns True if accepted."""
    if not isinstance(data, dict) or "machine" not in data:
        return False
    try:
        machine = int(data["machine"])
    except (TypeError, ValueError):
        return False

    data["_received_at"] = datetime.now().isoformat(timespec="seconds")

    os.makedirs(DIAG_DIR, exist_ok=True)
    path = _diag_log_path(machine)
    lines = []
    if os.path.exists(path):
        try:
            with open(path) as f:
                lines = f.readlines()
        except OSError:
            lines = []
    lines.append(json.dumps(data) + "\n")
    lines = lines[-DIAG_KEEP_PER_MACHINE:]
    with open(path, "w") as f:
        f.writelines(lines)

    summary = (f"machine={machine} boot={data.get('boot_num','?')} "
               f"reset_reason={data.get('reset_reason','?')} "
               f"last_mark={data.get('last_mark','?')}")
    print(f"[diag] {summary}")
    diag_logger.info(f"BOOT/RESTART {summary} "
                      f"fw={data.get('fw_version','?')} "
                      f"rtc_cpu0={data.get('rtc_reason_cpu0','?')} "
                      f"rtc_cpu1={data.get('rtc_reason_cpu1','?')} "
                      f"heartbeats={data.get('heartbeat_count','?')} "
                      f"heap_last={data.get('free_heap_last','?')} "
                      f"heap_min={data.get('free_heap_min','?')}")
    return True

@app.route("/diag/report", methods=["POST"])
def diag_report():
    """Ingest one boot's diagnostic report, or a backlog batch (ring-buffer
    array), from a client node."""
    payload = request.get_json(silent=True, force=True)
    if not payload:
        return jsonify({"error": "bad request"}), 400

    reports = payload if isinstance(payload, list) else [payload]
    accepted = sum(1 for r in reports if _ingest_one_diag_report(r))

    if accepted == 0:
        return jsonify({"error": "no valid reports in payload"}), 400

    return "", 204

# Reset reasons that mean "something went wrong" rather than a deliberate
# restart or a normal cold boot — used to highlight rows red in the viewer.
_DIAG_BAD_REASONS = {"BROWNOUT", "PANIC", "TASK_WDT", "INTERRUPT_WDT", "OTHER_WDT"}

DIAG_PAGE = """<!doctype html><html><head><title>Diagnostics – Woodshop</title>
{style}</head><body>
{nav}
<div class="container">
  <div class="card">
    <h2>Node Reboot Diagnostics</h2>
    <p style="font-size:.8rem;color:var(--muted);margin-bottom:.5rem">
      Showing {count} most recent reports across all machines, newest first.
      Each node POSTs one report per boot once WiFi comes up. Red "Reset
      Reason" means a brownout, panic, or watchdog fired; green means a
      deliberate restart (OTA, node giving up init after retries) or a
      normal power-on. "Breadcrumb Valid" = NO means the RTC memory that
      carries Last Mark/Heartbeats/Heap didn't survive the reset — either a
      cold power-on or a brownout deep enough to reset the RTC domain too,
      which by itself points at the supply rail rather than firmware logic.
      Auto-refreshes every 60s.</p>
    {table}
  </div>
</div>
<script>setTimeout(()=>location.reload(),60000);</script>
</body></html>"""

@app.route("/admin/diag")
@login_required
def admin_diag():
    machines = load_json(MACHINES_FILE, [])
    mnames = {str(m.get("id", "")): m.get("name", "") for m in machines}

    reports = []
    if os.path.isdir(DIAG_DIR):
        for fname in os.listdir(DIAG_DIR):
            if not (fname.startswith("diag_machine_") and fname.endswith(".jsonl")):
                continue
            try:
                with open(os.path.join(DIAG_DIR, fname)) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            reports.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
            except OSError:
                continue

    reports.sort(key=lambda r: r.get("_received_at", ""), reverse=True)
    reports = reports[:300]   # cap what we render in one page

    def _badge(reason):
        return "badge-out" if reason in _DIAG_BAD_REASONS else "badge-in"

    rows_html = "".join(
        "<tr>"
        f"<td style='white-space:nowrap'>{r.get('_received_at','')}</td>"
        f"<td>{r.get('machine','?')} "
        f"<span style='color:var(--muted);font-size:.75rem'>"
        f"({mnames.get(str(r.get('machine','')), '?')})</span></td>"
        f"<td>{r.get('fw_version','?')}</td>"
        f"<td style='text-align:right'>{r.get('boot_num','?')}</td>"
        f"<td><span class='badge {_badge(r.get('reset_reason',''))}'>"
        f"{r.get('reset_reason','?')}</span></td>"
        f"<td style='font-size:.75rem'>{r.get('rtc_reason_cpu0','')} / "
        f"{r.get('rtc_reason_cpu1','')}</td>"
        f"<td>{'yes' if r.get('prev_run_valid') else 'NO'}</td>"
        f"<td>{r.get('last_mark','?')}</td>"
        f"<td style='text-align:right'>{r.get('heartbeat_count','?')}</td>"
        f"<td style='text-align:right'>{r.get('free_heap_last','?')}</td>"
        f"<td style='text-align:right'>{r.get('free_heap_min','?')}</td>"
        "</tr>"
        for r in reports
    )
    if rows_html:
        table = f"""<div style="overflow-x:auto"><table>
          <thead><tr>
            <th>Received</th><th>Machine</th><th>FW</th>
            <th style='text-align:right'>Boot#</th>
            <th>Reset Reason</th><th>RTC cpu0 / cpu1</th>
            <th>Breadcrumb Valid</th><th>Last Mark</th>
            <th style='text-align:right'>Heartbeats</th>
            <th style='text-align:right'>Heap Last</th>
            <th style='text-align:right'>Heap Min</th>
          </tr></thead>
          <tbody>{rows_html}</tbody></table></div>"""
    else:
        table = '<p class="empty">No diagnostic reports received yet.</p>'

    return DIAG_PAGE.format(
        style=COMMON_STYLE, nav=NAV_AUTH.format(app_version=__version__),
        table=table, count=len(reports)
    )


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