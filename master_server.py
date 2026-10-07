UPDATE_AVAILABLE = True
"""
Woodshop Master Server
Runs on Raspberry Pi
Receives binary data from woodshop machine controllers via WiFi

Client to Server Message Format (16 bytes total):
    1. Machine#:        1 byte  (uint8)  - Machine number (0-255, from DIP switches)
    2. MemberID:        4 bytes (uint32) - Member ID from RFID card
    3. Duration (secs): 2 bytes (uint16) - Machine runtime in seconds
    4. Current (0.01A): 2 bytes (uint16) - Average current in 0.01A units
    5. ConnectTime:     4 bytes (uint32) - Total time card present (seconds)
    6. Override:        1 byte  (uint8)  - Override/status bits
    7. EventType:       1 byte  (uint8)  - 0=INSERT, 1=REMOVE, 2=OVERRIDE
    8. AuthStatus:      1 byte  (uint8)  - 0=AUTHORIZED, 1=NOT_AUTHORIZED, 2=UNKNOWN, 3=READ_ERROR

Override Byte Bits:
    Bit 0: Override mode (1=bypass, no card required)
    Bit 1: Emergency stop
    Bit 2: Maintenance mode
    Bit 3: Training mode

Server to Client Response Format (8 bytes total):
    1. Machine#:        1 byte  (uint8)  - Echo back machine number
    2. MemberID:        4 bytes (uint32) - Echo back member ID
    3. Status:          2 bytes (uint16) - Server status code
    4. UpdateAvailable: 1 byte  (uint8)  - 0=none, 1=update ready for download

Status Codes:
    0x0000: OK - Message received and processed
    0x0001: ERROR - Generic error
    0x0002: MEMBER_NOT_FOUND - Member ID not in database
    0x0003: MACHINE_DISABLED - Machine is disabled
    0x0004: MEMBER_NOT_AUTHORIZED - Member not authorized for this machine
    0x0005: INVALID_MESSAGE - Message format error
"""
import csv
import os
import socket
import threading
import json
import struct
import time
import sqlite3
import signal
import sys
from datetime import datetime, timedelta
import logging

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(BASE_DIR, 'master.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# ── Status LEDs ────────────────────────────────────────────────────────────
# Wired through a driver board on the Pi's GPIO header:
#   GPIO25 (red) - lit while the server is inoperable
#   GPIO20 (grn) - lit while the server is running normally
#   GPIO5  (blu) - flashes 1s on a message from Lee's machine (port 45432)
#                  (moved off GPIO24 2026-08-26 to test whether dimming on
#                  the yellow channel is tied to that specific ULN2803
#                  channel pairing -- see master.log discussion)
#   GPIO26 (yel) - flashes 1s on a message from a machine controller (port 35487)
#   GPIO27 (wht) - lit while a node is downloading firmware.bin; owned and
#                  driven by app.py (woodshop.service), not this file —
#                  see FIRMWARE_DIR / firmware_file() there
#
# LED setup is defensive: if gpiozero or its pin backend isn't available
# (e.g. missing python3-lgpio, or a udev permission issue), the server logs
# a warning and keeps running with the LEDs disabled rather than crashing.
class _NullLED:
    def on(self):  pass
    def off(self): pass


def _make_led(pin):
    try:
        from gpiozero import LED
        led = LED(pin)
        logger.info(f"Status LED on GPIO{pin} initialized OK")
        return led
    except Exception as e:
        logger.warning(f"Status LED on GPIO{pin} unavailable ({e}); running without it")
        return _NullLED()


led_red = _make_led(25)
led_grn = _make_led(20)
led_blu = _make_led(5)
led_yel = _make_led(26)


class _Flasher:
    """Turns an LED on, then off again after a fixed delay.

    Calling trigger() again before the delay elapses just restarts the
    timer, so back-to-back messages keep the LED lit instead of flickering.
    """

    def __init__(self, led, seconds=2.0, name=""):
        self.led = led
        self.seconds = seconds
        self.name = name or "led"
        self._timer = None
        self._lock = threading.Lock()

    def trigger(self):
        with self._lock:
            logger.info(f"[LED] {self.name} ON for {self.seconds}s")
            self.led.on()
            if self._timer is not None:
                self._timer.cancel()
            self._timer = threading.Timer(self.seconds, self._off)
            self._timer.daemon = True
            self._timer.start()

    def _off(self):
        self.led.off()


blu_flasher = _Flasher(led_blu, seconds=1.0, name="blue/Lee(45432)")
yel_flasher = _Flasher(led_yel, seconds=1.0, name="yellow/client(35487)")


def mark_failed(reason=""):
    led_grn.off()
    led_red.on()
    logger.error(f"[STATUS] server marked FAILED: {reason}")


def mark_ok():
    led_red.off()
    led_grn.on()


# ── Crash / hang diagnostics ──────────────────────────────────────────────
# Anything that escapes normal handling (main thread or a background
# thread) gets a full traceback written to master.log, plus the red LED,
# instead of vanishing into stderr with no record.

def _log_uncaught_main(exc_type, exc_value, exc_tb):
    logger.error("UNCAUGHT EXCEPTION (main thread)", exc_info=(exc_type, exc_value, exc_tb))
    mark_failed(f"uncaught exception: {exc_value}")


sys.excepthook = _log_uncaught_main


def _log_uncaught_thread(args):
    logger.error(
        f"UNCAUGHT EXCEPTION in thread '{args.thread.name}'",
        exc_info=(args.exc_type, args.exc_value, args.exc_traceback)
    )
    mark_failed(f"exception in thread {args.thread.name}: {args.exc_value}")


threading.excepthook = _log_uncaught_thread


# Status codes
STATUS_OK                  = 0x0000
STATUS_ERROR               = 0x0001
STATUS_MEMBER_NOT_FOUND    = 0x0002
STATUS_MACHINE_DISABLED    = 0x0003
STATUS_MEMBER_NOT_AUTHORIZED = 0x0004
STATUS_INVALID_MESSAGE     = 0x0005

# ── OTA update flag ───────────────────────────────────────────────────────────
# Set True to signal all nodes a software update is available. Nodes are
# ESP32/C (compiled binary, flashed into the inactive OTA partition) as of
# Aug 2026 — see app.py's "OTA Firmware endpoints" comment block for the
# full explanation and the firmware.bin/manifest.json side of this.
# Workflow:
#   1. Stage firmware.bin + version.txt in the woodshop firmware/ directory
#      (see app.py's OTA Firmware endpoints section for exact steps)
#   2. python3 set_ota.py true   (sets UPDATE_AVAILABLE = True below and
#      restarts woodshop-tcp for you)
#   3. Each node picks up update_available=1 on its next card event (fast
#      path) or its next periodic self-check (idle nodes, every 10 min —
#      see OTA_CHECK_INTERVAL_MS on the client)
#   4. Node fetches manifest.json, compares versions, downloads+flashes in
#      the background if different, and reboots once no card session is
#      open. Nodes already on the new version compare equal and skip
#      re-flashing, so this flag can safely stay True through a rollout.
#   5. python3 set_ota.py false once all nodes have updated (not urgent)
#UPDATE_AVAILABLE = False   <-- placed at top of file



# Machine number -> name. Names come from data/machines.json (the list edited
# on the web app's Machines page and used by the Admin Card page), looked up by
# machine number = the "id" there. Machine numbers are 1-based, the same
# numbering as the permission bits (bit 0 = machine 1) and the admin card.
# A number with no entry shows as "Machine N". The file is re-read whenever it
# changes, so renaming a machine on the web page takes effect immediately.
MACHINES_FILE = os.path.join(BASE_DIR, 'data', 'machines.json')
_machine_names = {}
_machine_names_mtime = None


def machine_name(num):
    global _machine_names, _machine_names_mtime
    try:
        mtime = os.path.getmtime(MACHINES_FILE)
    except OSError:
        mtime = None
    if mtime != _machine_names_mtime:
        names = {}
        try:
            with open(MACHINES_FILE) as f:
                for m in json.load(f):
                    try:
                        names[int(m.get('id'))] = str(m.get('name', '')).strip()
                    except (TypeError, ValueError):
                        pass
        except (OSError, ValueError):
            pass
        _machine_names, _machine_names_mtime = names, mtime
    return _machine_names.get(num) or f"Machine {num}"


USERS_FILE   = os.path.join(BASE_DIR, 'data', 'users.json')
CSV_LOG_FILE = os.path.join(BASE_DIR, 'data', 'access_log.csv')

def member_name(member_id):
    """Look up member name from users.json by member ID."""
    try:
        with open(USERS_FILE) as f:
            users = json.load(f)
        mid = str(member_id)
        for u in users:
            if str(u.get('id', '')) == mid:
                first = u.get('first_name', '')
                last  = u.get('last_name', '')
                name  = f"{first} {last}".strip()
                return name if name else f"Member {member_id}"
    except Exception:
        pass
    return f"Member {member_id}"


def _membership_current(user):
    """Eligibility is decided by Login (Lee's kiosk): it only sends a message
    for a member who is entitled to be in the shop, so no expiry / grace-period
    test is done here. The only local rule is the optional admin block: a
    record whose 'active' flag was explicitly set to False on the Users page
    gets no machine permissions."""
    return user.get('active', True) is not False


NEW_MEMBER_PERMISSIONS = '1' * 128     # full access, all 128 machine positions
_users_lock = threading.Lock()


def ensure_member(member_id, first_name, last_name):
    """
    Every message from Login is assumed to be for a valid member. If
    member_id is not in users.json, append a record with the names from the
    message and FULL access to all 128 machines (permission string of 128 '1').
    An existing record is never modified (so permissions limited on the web
    page are kept). Returns True if a record was added.

    Safety: a missing file starts a new list, but a file that exists and
    cannot be parsed is left alone (logged, nothing written) so a bad read
    can never wipe the member list. The write is atomic (temp file +
    os.replace).
    """
    if not member_id:
        return False
    mid = str(member_id)
    with _users_lock:
        try:
            if os.path.exists(USERS_FILE):
                with open(USERS_FILE) as f:
                    users = json.load(f)
                if not isinstance(users, list):
                    raise ValueError("users.json is not a list")
            else:
                users = []
        except Exception as e:
            logger.error(f"[ENROLL] cannot read {USERS_FILE} ({e}); "
                         f"member {member_id} NOT added")
            return False
        if any(str(u.get('id', '')) == mid for u in users):
            return False
        users.append({
            'id':          member_id,
            'first_name':  first_name,
            'last_name':   last_name,
            'email':       '',
            'phone':       '',
            'rfid':        '',
            'joined':      datetime.now().strftime('%Y-%m-%d'),
            'expiry':      '',
            'active':      True,
            'permissions': NEW_MEMBER_PERMISSIONS,
        })
        try:
            os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
            tmp = USERS_FILE + '.tmp'
            with open(tmp, 'w') as f:
                json.dump(users, f, indent=2)
            os.replace(tmp, USERS_FILE)
        except Exception as e:
            logger.error(f"[ENROLL] could not write {USERS_FILE}: {e}")
            return False
    logger.info(f"[ENROLL] new member {member_id} ({first_name} {last_name}) "
                f"added to users.json with full access (128 machines)")
    return True


def member_permissions(member_id):
    """
    Look up a member's machine-access permission string from users.json by
    member ID. Returns '' if the member isn't found or has no permissions
    set. This is the "member file" referenced by the active_members table --
    read once at login time and snapshotted into the row, per the Aug 2026
    Login/logout redesign (Server itself no longer decides eligibility;
    Login does, and just tells us who's currently signed in).
    """
    try:
        with open(USERS_FILE) as f:
            users = json.load(f)
        mid = str(member_id)
        for u in users:
            if str(u.get('id', '')) == mid:
                if not _membership_current(u):
                    logger.warning(f"Member {member_id} is blocked (active=False) -- "
                                   f"granting NO machine permissions")
                    return ''
                return u.get('permissions', '') or ''
    except Exception:
        pass
    return ''


class BinaryMessage:
    """Binary message parser and formatter"""

    # Client to Server format: >B I H H I B B B
    # > = big-endian
    # B = uint8  (1 byte)
    # I = uint32 (4 bytes)
    # H = uint16 (2 bytes)
    FORMAT = '>BIHHIBBB'
    SIZE   = 16  # Total bytes

    # EventType constants
    EVENT_INSERT   = 0
    EVENT_REMOVE   = 1
    EVENT_OVERRIDE = 2
    EVENT_FAULT    = 3    # WDT reset fault report (member_id=0, WDT_FAULT_BIT set)

    # AuthStatus constants
    AUTH_AUTHORIZED     = 0
    AUTH_NOT_AUTHORIZED = 1
    AUTH_UNKNOWN        = 2
    AUTH_READ_ERROR     = 3

    # Server to Client response format: >B I H B
    # Byte 0:   Machine#         (uint8)
    # Byte 1-4: MemberID         (uint32)
    # Byte 5-6: Status           (uint16)
    # Byte 7:   update_available (uint8)  0=none, 1=update ready
    RESPONSE_FORMAT = '>BIHB'
    RESPONSE_SIZE   = 8  # Total bytes

    def __init__(self, machine_number=0, member_id=0, duration=0, current=0,
                 connect_time=0, override=0, event_type=0, auth_status=0,
                 starts=0, stops=0):
        self.machine_number = machine_number
        self.member_id      = member_id
        self.duration       = duration
        self.current_raw    = current   # In 0.01A units
        self.connect_time   = connect_time
        self.override       = override
        self.event_type     = event_type
        self.auth_status    = auth_status
        self.starts         = starts
        self.stops          = stops

    @property
    def current_amps(self):
        return self.current_raw * 0.001

    @property
    def member_id_hex(self):
        return f"{self.member_id:08X}"

    @property
    def member_id_dec(self):
        return str(self.member_id)

    # EventType helpers
    @property
    def is_insert(self):
        return self.event_type == self.EVENT_INSERT

    @property
    def is_remove(self):
        return self.event_type == self.EVENT_REMOVE

    @property
    def is_override(self):
        return self.event_type == self.EVENT_OVERRIDE

    @property
    def is_fault(self):
        return self.event_type == self.EVENT_FAULT

    # Override byte bit flags
    @property
    def is_override_mode(self):
        return (self.override & 0x01) != 0

    @property
    def is_emergency_stop(self):
        return (self.override & 0x02) != 0

    @property
    def is_maintenance_mode(self):
        return (self.override & 0x04) != 0

    @property
    def is_training_mode(self):
        return (self.override & 0x08) != 0

    @property
    def is_blast_gate(self):
        return (self.override & 0x10) != 0

    @property
    def is_wdt_fault(self):
        return (self.override & 0x40) != 0

    # AuthStatus helpers
    @property
    def is_authorized(self):
        return self.auth_status == self.AUTH_AUTHORIZED

    @property
    def auth_status_str(self):
        return {
            self.AUTH_AUTHORIZED:     'AUTHORIZED',
            self.AUTH_NOT_AUTHORIZED: 'NOT_AUTHORIZED',
            self.AUTH_UNKNOWN:        'UNKNOWN',
            self.AUTH_READ_ERROR:     'READ_ERROR',
        }.get(self.auth_status, f'0x{self.auth_status:02x}')

    @classmethod
    def from_bytes(cls, data):
        if len(data) != cls.SIZE:
            raise ValueError(f"Expected {cls.SIZE} bytes, got {len(data)}")
        machine_number, member_id, duration, current, connect_time, override, starts, stops = \
            struct.unpack(cls.FORMAT, data)
        # Determine event type:
        #   FAULT:  WDT_FAULT_BIT (0x40) set in override byte
        #   REMOVE: duration or connect_time > 0, OR starts/stops > 0
        #           (catches very short sessions where connect_time rounds to 0)
        #   INSERT: everything else (duration=0, connect_time=0, starts=0, stops=0)
        WDT_FAULT_BIT = 0x40
        if override & WDT_FAULT_BIT:
            event_type = cls.EVENT_FAULT
        elif duration > 0 or connect_time > 0 or starts > 0 or stops > 0:
            event_type = cls.EVENT_REMOVE
        else:
            event_type = cls.EVENT_INSERT
        auth_status = cls.AUTH_AUTHORIZED
        return cls(machine_number, member_id, duration, current,
                   connect_time, override, event_type, auth_status,
                   starts=starts, stops=stops)

    def to_bytes(self):
        return struct.pack(self.FORMAT,
                           self.machine_number, self.member_id,
                           self.duration, self.current_raw,
                           self.connect_time, self.override,
                           self.event_type, self.auth_status)

    @staticmethod
    def create_response(machine_number, member_id, status_code, update_available=False):
        return struct.pack(BinaryMessage.RESPONSE_FORMAT,
                           machine_number, member_id, status_code,
                           1 if update_available else 0)

    def get_override_flags_string(self):
        flags = []
        if self.is_override_mode:    flags.append("SYS-OVERRIDE")
        if self.is_emergency_stop:   flags.append("E-STOP")
        if self.is_maintenance_mode: flags.append("MAINT")
        if self.is_training_mode:    flags.append("TRAIN")
        if self.is_blast_gate:       flags.append("BLAST-GATE")
        return " | ".join(flags) if flags else "NORMAL"

    def __str__(self):
        event = {self.EVENT_INSERT:   "INSERT",
                 self.EVENT_REMOVE:   "REMOVE",
                 self.EVENT_OVERRIDE: "OVERRIDE",
                 self.EVENT_FAULT:    "FAULT"}.get(self.event_type, "UNKNOWN")
        return (f"{event}: Machine={self.machine_number} ({machine_name(self.machine_number)}), "
                f"Member={self.member_id_dec}, Auth={self.auth_status_str}, "
                f"Duration={self.duration}s, Current={self.current_amps:.1f}A, "
                f"ConnectTime={self.connect_time}s, Flags=[{self.get_override_flags_string()}]")


class Database:
    """SQLite database for storing woodshop session data"""

    def __init__(self, db_path=None):
        self.db_path = db_path or os.path.join(BASE_DIR, 'woodshop.db')
        self.init_database()

    def init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                member_id TEXT NOT NULL,
                machine_number INTEGER,
                duration_seconds INTEGER,
                current_amps REAL,
                connect_time_seconds INTEGER,
                override INTEGER,
                auth_status INTEGER DEFAULT 0,
                insert_time TIMESTAMP,
                remove_time TIMESTAMP,
                received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS raw_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                member_id TEXT,
                machine_number INTEGER,
                event_type INTEGER,
                auth_status INTEGER,
                duration INTEGER,
                current_raw INTEGER,
                connect_time INTEGER,
                override INTEGER,
                received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                message_hex TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS machines (
                machine_number INTEGER PRIMARY KEY,
                current_member_id TEXT,
                session_start TIMESTAMP,
                last_seen TIMESTAMP,
                status TEXT DEFAULT 'idle'
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS members (
                member_id TEXT PRIMARY KEY,
                first_name TEXT,
                last_name TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Aug 2026 redesign: who's currently signed in at Login's door
        # reader. A row is inserted (or replaced) when Login sends a login
        # message on port 45432, and deleted when Login sends the matching
        # logout message. Someone with no row here cannot use any machine --
        # this is the sole runtime gate for machine access now (replacing
        # the old RFID-card-carries-its-own-permissions model). SQLite
        # gives us write-through persistence across a power outage for
        # free, same as the sessions/machines tables above.
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS active_members (
                member_id   INTEGER PRIMARY KEY,
                first_name  TEXT,
                last_name   TEXT,
                login_time  TIMESTAMP,
                permissions TEXT
            )
        ''')

        conn.commit()
        conn.close()
        logger.info("Database initialized")

    # ── active_members: who's currently signed in ──────────────────────────

    def login_member(self, member_id, first_name, last_name, login_time, permissions):
        """
        Insert or replace the active_members row for member_id. Called on a
        LOGIN message from Login (port 45432). permissions is the raw
        '0'/'1' bit string snapshotted from the reduced member file at
        login time -- see member_permissions() above.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO active_members
            (member_id, first_name, last_name, login_time, permissions)
            VALUES (?, ?, ?, ?, ?)
        ''', (member_id, first_name, last_name, login_time, permissions))
        conn.commit()
        conn.close()

    def logout_member(self, member_id):
        """Delete the active_members row for member_id. Called on a LOGOUT
        message from Login (port 45432)."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM active_members WHERE member_id = ?', (member_id,))
        conn.commit()
        conn.close()

    def get_active_member(self, member_id):
        """Return (member_id, first_name, last_name, login_time, permissions)
        for a currently signed-in member, or None if they're not signed in."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT member_id, first_name, last_name, login_time, permissions
            FROM active_members WHERE member_id = ?
        ''', (member_id,))
        row = cursor.fetchone()
        conn.close()
        return row

    def is_authorized(self, member_id, machine_number):
        """
        True if member_id is currently signed in (present in
        active_members) AND their snapshotted permission string grants
        access to machine_number.

        Bit convention: bit 0 (first character of the permission string) =
        machine 1, i.e. index = machine_number - 1. Same as the RFID card
        layout (rfid_write.py) and the users CSV template. Machine 0 and
        anything outside 1..len(permissions) is never authorized.
        """
        row = self.get_active_member(member_id)
        if row is None:
            return False            # not signed in at the kiosk
        # Live lookup in the member file on every request (so permission,
        # permission and block (active=False) changes take effect immediately, not only at
        # the member's next login). member_permissions() returns '' for an
        # unknown or blocked member.
        permissions = member_permissions(member_id)
        if not permissions:
            return False
        idx = machine_number - 1
        if idx < 0 or idx >= len(permissions):
            return False
        return permissions[idx] == '1'

    def log_raw_message(self, msg):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO raw_messages
            (member_id, machine_number, event_type, auth_status,
             duration, current_raw, connect_time, override, message_hex)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (msg.member_id_hex, msg.machine_number, msg.event_type, msg.auth_status,
              msg.duration, msg.current_raw, msg.connect_time, msg.override,
              msg.to_bytes().hex()))
        conn.commit()
        conn.close()

    def record_insert(self, msg):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO sessions
            (member_id, machine_number, insert_time, override, auth_status)
            VALUES (?, ?, ?, ?, ?)
        ''', (msg.member_id_hex, msg.machine_number,
              datetime.now(), msg.override, msg.auth_status))
        session_id = cursor.lastrowid
        cursor.execute('''
            INSERT OR REPLACE INTO machines
            (machine_number, current_member_id, session_start, last_seen, status)
            VALUES (?, ?, ?, ?, 'active')
        ''', (msg.machine_number, msg.member_id_hex, datetime.now(), datetime.now()))
        conn.commit()
        conn.close()
        return session_id

    def record_remove(self, msg):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        if msg.is_override:
            cursor.execute('''
                INSERT INTO sessions
                (member_id, machine_number, duration_seconds, current_amps,
                 connect_time_seconds, override, auth_status, insert_time, remove_time)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (msg.member_id_hex, msg.machine_number, msg.duration, msg.current_amps,
                  msg.connect_time, msg.override, msg.auth_status,
                  datetime.now(), datetime.now()))
        else:
            cursor.execute('''
                SELECT id FROM sessions
                WHERE member_id = ? AND machine_number = ? AND remove_time IS NULL
                ORDER BY insert_time DESC LIMIT 1
            ''', (msg.member_id_hex, msg.machine_number))
            result = cursor.fetchone()
            if result:
                cursor.execute('''
                    UPDATE sessions
                    SET duration_seconds = ?, current_amps = ?,
                        connect_time_seconds = ?, remove_time = ?,
                        override = ?, auth_status = ?
                    WHERE id = ?
                ''', (msg.duration, msg.current_amps, msg.connect_time,
                      datetime.now(), msg.override, msg.auth_status, result[0]))
            else:
                cursor.execute('''
                    INSERT INTO sessions
                    (member_id, machine_number, duration_seconds, current_amps,
                     connect_time_seconds, override, auth_status, insert_time, remove_time)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (msg.member_id_hex, msg.machine_number, msg.duration, msg.current_amps,
                      msg.connect_time, msg.override, msg.auth_status,
                      datetime.now(), datetime.now()))

        cursor.execute('''
            UPDATE machines
            SET current_member_id = NULL, session_start = NULL,
                last_seen = ?, status = 'idle'
            WHERE machine_number = ?
        ''', (datetime.now(), msg.machine_number))

        conn.commit()
        conn.close()

    def get_insert_time(self, msg):
        """Return the insert_time datetime for the open session matching this REMOVE, or None."""
        conn   = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT insert_time FROM sessions
            WHERE member_id = ? AND machine_number = ? AND remove_time IS NULL
            ORDER BY insert_time DESC LIMIT 1
        ''', (msg.member_id_hex, msg.machine_number))
        row = cursor.fetchone()
        conn.close()
        if row and row[0]:
            try:
                return datetime.fromisoformat(str(row[0]))
            except Exception:
                return None
        return None

    def log_csv_remove(self, msg, insert_time):
        """
        Append a completed session row to access_log.csv on REMOVE.
        Columns: timestamp, member_id, member_name, machine_number, machine_name,
                 start_time, stop_time, connect_time_s, machine_on_s,
                 avg_current_A, starts
        """
        now       = datetime.now()
        mid       = str(msg.member_id)
        name      = member_name(msg.member_id)
        mnum      = str(msg.machine_number)
        mname     = machine_name(msg.machine_number)
        start_str = insert_time.strftime("%Y-%m-%d %H:%M:%S") if insert_time else ""
        stop_str  = now.strftime("%Y-%m-%d %H:%M:%S")
        write_header = not os.path.exists(CSV_LOG_FILE)
        logger.info(f"  CSV write: file={CSV_LOG_FILE} exists={os.path.exists(CSV_LOG_FILE)} "
                    f"write_header={write_header}")
        logger.info(f"  CSV row: member={mid} machine={mnum} start='{start_str}' "
                    f"connect={msg.connect_time}s duration={msg.duration}s "
                    f"current={msg.current_amps:.2f}A starts={msg.starts}")
        try:
            with open(CSV_LOG_FILE, "a", newline="") as f:
                writer = csv.writer(f)
                if write_header:
                    writer.writerow([
                        "timestamp", "member_id", "member_name",
                        "machine_number", "machine_name",
                        "start_time", "stop_time",
                        "connect_time_s", "machine_on_s",
                        "avg_current_A", "starts"
                    ])
                writer.writerow([
                    stop_str, mid, name, mnum, mname,
                    start_str, stop_str,
                    msg.connect_time,
                    msg.duration,
                    f"{msg.current_amps:.2f}",
                    msg.starts
                ])
            logger.info(f"  CSV write OK")
        except Exception as e:
            import traceback
            logger.error(f"CSV log error: {e}\n{traceback.format_exc()}")

    def log_csv_session_event(self, member_id, name, event, when):
        """
        Append a kiosk LOGIN / LOGOUT row to access_log.csv so it shows on the
        web page's Logs tab. Uses the 6-column format app.py's read_log()
        already understands:
            timestamp, member_id, member_name, machine_id, machine_name, event
        """
        write_header = not os.path.exists(CSV_LOG_FILE)
        try:
            os.makedirs(os.path.dirname(CSV_LOG_FILE), exist_ok=True)
            with open(CSV_LOG_FILE, "a", newline="") as f:
                writer = csv.writer(f)
                if write_header:
                    writer.writerow([
                        "timestamp", "member_id", "member_name",
                        "machine_number", "machine_name",
                        "start_time", "stop_time",
                        "connect_time_s", "machine_on_s",
                        "avg_current_A", "starts"
                    ])
                writer.writerow([
                    when.strftime("%Y-%m-%d %H:%M:%S"), str(member_id), name,
                    "", "Kiosk", event
                ])
        except Exception as e:
            import traceback
            logger.error(f"CSV session-event log error: {e}\n{traceback.format_exc()}")

    def log_csv_fault(self, msg):
        """
        Append a WDT fault row to access_log.csv.
        Uses member_id=0, member_name='WDT-FAULT', duration/current=0
        so it stands out clearly in the log.
        """
        now       = datetime.now()
        ts        = now.strftime("%Y-%m-%d %H:%M:%S")
        mnum      = str(msg.machine_number)
        mname     = machine_name(msg.machine_number)
        write_header = not os.path.exists(CSV_LOG_FILE)
        try:
            with open(CSV_LOG_FILE, "a", newline="") as f:
                writer = csv.writer(f)
                if write_header:
                    writer.writerow([
                        "timestamp", "member_id", "member_name",
                        "machine_number", "machine_name",
                        "start_time", "stop_time",
                        "connect_time_s", "machine_on_s",
                        "avg_current_A", "starts"
                    ])
                writer.writerow([
                    ts, "0", "WDT-FAULT", mnum, mname,
                    ts, ts,
                    0, 0, "0.00", 0
                ])
        except Exception as e:
            import traceback
            logger.error(f"CSV fault log error: {e}\n{traceback.format_exc()}")

    def get_active_sessions(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT machine_number, current_member_id, session_start
            FROM machines WHERE status = 'active'
        ''')
        sessions = cursor.fetchall()
        conn.close()
        return sessions

    def get_recent_sessions(self, limit=50):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT member_id, machine_number, duration_seconds,
                   current_amps, connect_time_seconds, override,
                   auth_status, insert_time, remove_time
            FROM sessions
            WHERE remove_time IS NOT NULL
            ORDER BY remove_time DESC LIMIT ?
        ''', (limit,))
        sessions = cursor.fetchall()
        conn.close()
        return sessions

    def get_member_stats(self, member_id):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT COUNT(*) as session_count,
                   SUM(duration_seconds) as total_duration,
                   AVG(current_amps) as avg_current,
                   SUM(connect_time_seconds) as total_connect_time
            FROM sessions
            WHERE member_id = ? AND remove_time IS NOT NULL
        ''', (member_id,))
        stats = cursor.fetchone()
        conn.close()
        return stats


class WoodshopServer:
    """TCP server for woodshop machine controllers"""

    def __init__(self, host='0.0.0.0', port=35487):
        self.host     = host
        self.port     = port
        self.database = Database()
        self.running  = False
        self.server_socket = None

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            logger.info(f"Woodshop Master Server started on {self.host}:{self.port}")
            logger.info(f"Expecting {BinaryMessage.SIZE}-byte messages")
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    logger.info(f"Connection from {client_address}")
                    t = threading.Thread(target=self.handle_client,
                                        args=(client_socket, client_address))
                    t.daemon = True
                    t.start()
                except Exception as e:
                    if self.running:
                        logger.error(f"Error accepting connection: {e}")
        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            if self.server_socket:
                self.server_socket.close()

    def handle_client(self, client_socket, client_address):
        try:
            client_socket.settimeout(10.0)  # never block a thread forever on a stalled client
            data = b''
            while len(data) < BinaryMessage.SIZE:
                chunk = client_socket.recv(BinaryMessage.SIZE - len(data))
                if not chunk:
                    break
                data += chunk

            if len(data) == BinaryMessage.SIZE:
                msg = BinaryMessage.from_bytes(data)
                logger.info(f"From {client_address[0]}: {msg}")
                yel_flasher.trigger()
                status_code = self.process_message(msg)
                response = BinaryMessage.create_response(
                    msg.machine_number, msg.member_id, status_code,
                    update_available=UPDATE_AVAILABLE)
                client_socket.send(response)
                logger.info(f"Response: Machine={msg.machine_number}, "
                            f"Member={msg.member_id_dec}, Status=0x{status_code:04X}, "
                            f"UpdateAvailable={UPDATE_AVAILABLE}")
            else:
                logger.warning(f"Incomplete message from {client_address}: "
                               f"{len(data)} bytes (expected {BinaryMessage.SIZE})")
                response = BinaryMessage.create_response(0, 0, STATUS_INVALID_MESSAGE)
                client_socket.send(response)

        except Exception as e:
            logger.error(f"Error handling client {client_address}: {e}")
            try:
                response = BinaryMessage.create_response(0, 0, STATUS_ERROR)
                client_socket.send(response)
            except:
                pass
        finally:
            client_socket.close()

    def process_message(self, msg):
        self.database.log_raw_message(msg)
        logger.info(f"process_message: event_type={msg.event_type} "
                    f"machine={msg.machine_number} member={msg.member_id} "
                    f"duration={msg.duration} connect={msg.connect_time} "
                    f"starts={msg.starts} stops={msg.stops} override=0x{msg.override:02X}")

        if msg.is_insert:
            # Override-mode bypass (admin override switch on the node itself)
            # still works exactly as before, with no active_members check.
            if not msg.is_override_mode:
                if not self.database.is_authorized(msg.member_id, msg.machine_number):
                    logger.warning(
                        f"NOT AUTHORIZED: Member={msg.member_id_dec} "
                        f"({member_name(msg.member_id)}), "
                        f"Machine={msg.machine_number} ({machine_name(msg.machine_number)}) "
                        f"-- not signed in, or no permission for this machine")
                    return STATUS_MEMBER_NOT_AUTHORIZED

            # Aug 2026: the client now retries this exact same INSERT message
            # every 30s whenever it can't reach us, for as long as the card
            # stays in (see wifi_task.cpp's server-confirmation loop) -- the
            # local card grants access immediately and this exchange is only
            # the server's chance to veto that grant, not a one-shot event
            # anymore. is_authorized() above is still re-checked on every
            # retry (that's the point), but record_insert() must NOT run
            # again for a session that's already open: it unconditionally
            # inserts a new `sessions` row with insert_time=now, and
            # record_remove()/get_insert_time() later grab "the most
            # recently opened" row for this member+machine -- so a second
            # (or third, or tenth) row would make the eventual REMOVE report
            # a duration truncated to the last retry interval, and leave
            # every earlier row open and orphaned forever.
            if self.database.get_insert_time(msg) is not None:
                logger.info(f"INSERT (confirmation retry): Member={msg.member_id_dec} "
                            f"({member_name(msg.member_id)}), Machine={msg.machine_number} "
                            f"({machine_name(msg.machine_number)}) -- session already open, "
                            f"not re-recorded")
                return STATUS_OK

            logger.info(f"INSERT: Member={msg.member_id_dec} ({member_name(msg.member_id)}), "
                        f"Machine={msg.machine_number} ({machine_name(msg.machine_number)}), "
                        f"Auth={msg.auth_status_str}")
            logger.info(f" ")
            session_id = self.database.record_insert(msg)
            logger.info(f"  Session ID: {session_id}")
            return STATUS_OK

        elif msg.is_remove:
            logger.info(f"REMOVE: Member={msg.member_id_dec} ({member_name(msg.member_id)}), "
                        f"Machine={msg.machine_number} ({machine_name(msg.machine_number)}), "
                        f"Auth={msg.auth_status_str}")
            logger.info(f"  Duration={msg.duration}s, Current={msg.current_amps:.1f}A, "
                        f"ConnectTime={msg.connect_time}s, Starts={msg.starts}")
            insert_time = self.database.get_insert_time(msg)
            logger.info(f"  CSV: insert_time={insert_time}, starts={msg.starts}, stops={msg.stops}")
            self.database.record_remove(msg)
            self.database.log_csv_remove(msg, insert_time)
            return STATUS_OK

        elif msg.is_override:
            logger.info(f"OVERRIDE: Machine={msg.machine_number} ({machine_name(msg.machine_number)}), "
                        f"Duration={msg.duration}s, Flags=[{msg.get_override_flags_string()}]")
            self.database.record_remove(msg)
            return STATUS_OK

        elif msg.is_fault:
            logger.warning(f"*** WDT FAULT: Machine={msg.machine_number} "
                           f"({machine_name(msg.machine_number)}) rebooted due to watchdog timeout ***")
            self.database.log_csv_fault(msg)
            return STATUS_OK

        return STATUS_ERROR

    def stop(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        logger.info("Server stopped")


class LoginListener:
    """
    TCP listener for Login's (Lee's Pi) login/logout messages, port 45432.

    Fixed 45-byte binary message, big-endian multi-byte fields, one
    connection per message (confirmed with Lee Robertshaw 8/19/2026 --
    see BruceTestSender.py, the reference test sender for this format):
        messageType : 1 byte   uint8   (0 = login, 1 = logout)
        timestamp   : 8 bytes  uint64 big-endian, Unix epoch (UTC)
        memberID    : 4 bytes  uint32 big-endian (matches the same
                                 memberID space used elsewhere, e.g. the
                                 sample users seeded in app.py: 1001-1003)
        firstName   : 16 bytes ASCII, null-padded
        lastName    : 16 bytes ASCII, null-padded

    (Supersedes an earlier 52-byte ASCII draft format -- Lee's actual
    kiosk sends the binary format above.)

    Every message is assumed to be for a valid member (Login only sends
    messages for members it has approved). A login for a member not yet in
    users.json adds that member with full access to all 128 machines.

    A login message inserts/replaces a row in active_members, with
    login_time set directly from the message's own timestamp (not from
    Server's clock) and permissions looked up fresh from the reduced
    member file at that moment. A logout message deletes the row. No
    clock-sync/SyncedClock step -- Server doesn't need one for this.
    """

    MSG_SIZE = 45
    FORMAT = '>BQI16s16s'
    TYPE_LOGIN  = 0
    TYPE_LOGOUT = 1

    def __init__(self, database, host='0.0.0.0', port=45432):
        self.database = database
        self.host = host
        self.port = port
        self.running = False
        self.server_socket = None

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            logger.info(f"Login listener started on {self.host}:{self.port} "
                        f"(expecting {self.MSG_SIZE}-byte binary messages)")
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    t = threading.Thread(target=self.handle_client,
                                         args=(client_socket, client_address))
                    t.daemon = True
                    t.start()
                except Exception as e:
                    if self.running:
                        logger.error(f"Login listener accept error: {e}")
        except Exception as e:
            logger.error(f"Login listener error: {e}")
        finally:
            if self.server_socket:
                self.server_socket.close()

    def handle_client(self, client_socket, client_address):
        try:
            client_socket.settimeout(10.0)  # never block a thread forever on a stalled client
            data = b''
            while len(data) < self.MSG_SIZE:
                chunk = client_socket.recv(self.MSG_SIZE - len(data))
                if not chunk:
                    break
                data += chunk

            if len(data) != self.MSG_SIZE:
                logger.warning(f"Login listener: incomplete message from "
                               f"{client_address} ({len(data)}/{self.MSG_SIZE} bytes)")
                return

            blu_flasher.trigger()
            self.process_message(data, client_address)
        except Exception as e:
            logger.error(f"Login listener error handling {client_address}: {e}")
        finally:
            client_socket.close()

    def process_message(self, data, client_address):
        try:
            msg_type, ts_epoch, member_id, first_raw, last_raw = struct.unpack(self.FORMAT, data)
        except struct.error as e:
            logger.error(f"Login listener: malformed {self.MSG_SIZE}-byte message from "
                         f"{client_address}: {e}")
            return

        first_name = first_raw.split(b'\x00', 1)[0].decode('ascii', errors='replace').strip()
        last_name  = last_raw.split(b'\x00', 1)[0].decode('ascii', errors='replace').strip()

        try:
            login_time = datetime.fromtimestamp(ts_epoch)
        except (ValueError, OSError, OverflowError):
            logger.error(f"Login listener: bad timestamp {ts_epoch!r} from "
                         f"{client_address} -- using Server's local time instead")
            login_time = datetime.now()

        if msg_type == self.TYPE_LOGIN:
            ensure_member(member_id, first_name, last_name)
            permissions = member_permissions(member_id)
            self.database.login_member(member_id, first_name, last_name,
                                       login_time, permissions)
            self.database.log_csv_session_event(
                member_id, f"{first_name} {last_name}".strip(), "LOGIN", login_time)
            logger.info(f"LOGIN: Member={member_id} ({first_name} {last_name}) "
                        f"at {login_time}"
                        + ("" if permissions else "  [WARNING: no permissions on file]"))
        elif msg_type == self.TYPE_LOGOUT:
            self.database.logout_member(member_id)
            self.database.log_csv_session_event(
                member_id, f"{first_name} {last_name}".strip(), "LOGOUT", login_time)
            logger.info(f"LOGOUT: Member={member_id} ({first_name} {last_name}) "
                        f"at {login_time}")
        else:
            logger.warning(f"Login listener: unknown messageType {msg_type!r} "
                           f"from {client_address}")

    def stop(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        logger.info("Login listener stopped")


_shutdown = threading.Event()


def _handle_signal(signum, frame):
    _shutdown.set()


# ── Daily maintenance: log backup (2:00) and NTP time sync (4:00) ─────────────
#
# One background thread (daily_tasks_loop) wakes every ~20 s and runs each job
# once per calendar day at its scheduled local time. Times are easy to change
# here. On startup it also back-fills yesterday's log file if it is missing
# (e.g. the Pi was powered off at 2:00 AM).

LOG_BACKUP_DIR    = os.path.join(BASE_DIR, 'data', 'logs')   # also used by app.py
LOG_BACKUP_TIME   = (2, 0)            # (hour, minute) local time
NTP_SYNC_TIME     = (4, 0)
NTP_SERVER        = 'pool.ntp.org'
NTP_MIN_STEP_SECS = 1.0               # don't touch the clock for smaller offsets

_MONTHS = ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN',
           'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC']

BACKUP_HEADER = [
    "timestamp", "member_id", "member_name", "machine_number", "machine_name",
    "start_time", "stop_time", "connect_time_s", "machine_on_s",
    "avg_current_A", "starts", "event"
]


def backup_filename(day):
    """log<yyyy><MMM><dd>.csv, e.g. log2026OCT05.csv (month is upper-case)."""
    return f"log{day.year:04d}{_MONTHS[day.month - 1]}{day.day:02d}.csv"


def dump_day_log(day):
    """
    Copy every access_log.csv row whose timestamp falls on `day` (a date) into
    LOG_BACKUP_DIR/log<yyyy><MMM><dd>.csv. The source file is left untouched.

    Output has one uniform 12-column layout for post-processing: machine
    session rows (11 columns in access_log.csv) get event=SESSION; kiosk
    LOGIN/LOGOUT rows (6 columns) are widened and keep their event.
    Returns (path, row_count).
    """
    prefix = day.strftime("%Y-%m-%d")
    out_rows = []
    try:
        with open(CSV_LOG_FILE, newline="") as f:
            for raw in csv.reader(f):
                if not raw or raw[0].strip().lower() in ("timestamp", "date"):
                    continue
                if not raw[0].startswith(prefix):
                    continue
                if len(raw) >= 11:                       # machine session row
                    out_rows.append(raw[:11] + ["SESSION"])
                elif len(raw) >= 6:                      # kiosk LOGIN/LOGOUT row
                    ts, mid, name, mnum, mname, event = raw[:6]
                    out_rows.append([ts, mid, name, mnum, mname,
                                     ts, ts, "", "", "", "", event])
    except FileNotFoundError:
        pass

    os.makedirs(LOG_BACKUP_DIR, exist_ok=True)
    path = os.path.join(LOG_BACKUP_DIR, backup_filename(day))
    tmp = path + ".tmp"
    with open(tmp, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(BACKUP_HEADER)
        w.writerows(out_rows)
    os.replace(tmp, path)           # atomic: never leaves a half-written file
    return path, len(out_rows)


def job_log_backup():
    """Back up the previous day's log (the day just completed at 2:00 AM)."""
    yesterday = (datetime.now() - timedelta(days=1)).date()
    try:
        path, n = dump_day_log(yesterday)
        logger.info(f"[BACKUP] wrote {n} row(s) for {yesterday} -> {path}")
    except Exception as e:
        logger.error(f"[BACKUP] failed for {yesterday}: {e}")


def ntp_query(server=NTP_SERVER, timeout=5.0):
    """Return (ntp_unix_time, offset_seconds) from one SNTP request.
    offset = ntp_time - local_time (positive: our clock is behind)."""
    NTP_EPOCH_DELTA = 2208988800          # 1900-01-01 -> 1970-01-01
    packet = b'\x1b' + 47 * b'\0'         # LI=0, VN=3, Mode=3 (client)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        t0 = time.time()
        s.sendto(packet, (server, 123))
        data, _ = s.recvfrom(512)
        t1 = time.time()
    finally:
        s.close()
    if len(data) < 48:
        raise ValueError("short NTP reply")
    secs, frac = struct.unpack('!II', data[40:48])
    ntp_time = secs - NTP_EPOCH_DELTA + frac / 2**32
    offset = ntp_time - (t0 + t1) / 2.0
    return ntp_time, offset


def job_ntp_sync():
    """Read the time from an NTP server and, if our clock is off by more than
    NTP_MIN_STEP_SECS, set the system clock. Setting the clock needs root:
    either run this program as root, or allow the service user to run
    `date -s` without a password (see the sudoers note below)."""
    try:
        ntp_time, offset = ntp_query()
    except Exception as e:
        logger.error(f"[NTP] query to {NTP_SERVER} failed: {e}")
        return
    if abs(offset) < NTP_MIN_STEP_SECS:
        logger.info(f"[NTP] clock OK (offset {offset:+.3f} s from {NTP_SERVER})")
        return
    new_time = time.time() + offset
    try:
        if hasattr(os, 'geteuid') and os.geteuid() == 0:
            time.clock_settime(time.CLOCK_REALTIME, new_time)
        else:
            import subprocess
            r = subprocess.run(['sudo', '-n', '/bin/date', '-s', f'@{int(round(new_time))}'],
                               capture_output=True, text=True, timeout=10)
            if r.returncode != 0:
                raise RuntimeError(r.stderr.strip() or f"date exited {r.returncode}")
        logger.info(f"[NTP] clock was {offset:+.3f} s off -- set from {NTP_SERVER}")
    except Exception as e:
        logger.warning(f"[NTP] clock is {offset:+.3f} s off but could not be set: {e} "
                       f"(run as root, or allow passwordless 'sudo /bin/date')")


def daily_tasks_loop():
    jobs = [("log-backup", LOG_BACKUP_TIME, job_log_backup),
            ("ntp-sync",   NTP_SYNC_TIME,   job_ntp_sync)]
    last_run = {}

    # Back-fill yesterday's file if the Pi was off at 2:00 AM.
    try:
        yesterday = (datetime.now() - timedelta(days=1)).date()
        if not os.path.exists(os.path.join(LOG_BACKUP_DIR, backup_filename(yesterday))):
            path, n = dump_day_log(yesterday)
            logger.info(f"[BACKUP] startup back-fill: {n} row(s) for {yesterday} -> {path}")
    except Exception as e:
        logger.error(f"[BACKUP] startup back-fill failed: {e}")

    while not _shutdown.is_set():
        now = datetime.now()
        for name, (hh, mm), fn in jobs:
            if (now.hour, now.minute) == (hh, mm) and last_run.get(name) != now.date():
                last_run[name] = now.date()
                try:
                    fn()
                except Exception as e:
                    logger.error(f"[DAILY] job {name} crashed: {e}")
        _shutdown.wait(20.0)


def main():
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    logger.info("Starting Woodshop Master Server...")
    server = WoodshopServer(host='0.0.0.0', port=35487)
    login_listener = LoginListener(server.database, host='0.0.0.0', port=45432)

    login_thread  = threading.Thread(target=login_listener.start, daemon=True)
    server_thread = threading.Thread(target=server.start, daemon=True)
    login_thread.start()
    server_thread.start()
    threading.Thread(target=daily_tasks_loop, daemon=True, name="daily-tasks").start()

    # Give both listeners a moment to bind before declaring health.
    time.sleep(1.0)

    tick = 0
    try:
        while not _shutdown.is_set():
            if server_thread.is_alive() and login_thread.is_alive():
                mark_ok()
            else:
                mark_failed("a listener thread has stopped")

            # Heartbeat every ~60s: if the server locks up later, this
            # trail shows whether thread count was climbing beforehand
            # (e.g. stalled clients piling up) versus a clean, sudden stop.
            tick += 1
            if tick % 60 == 0:
                logger.info(f"[HEARTBEAT] alive threads={threading.active_count()}")

            _shutdown.wait(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        logger.info("Shutting down...")
        login_listener.stop()
        server.stop()
        led_red.off()
        led_grn.off()
        led_blu.off()
        led_yel.off()


if __name__ == "__main__":
    main()
