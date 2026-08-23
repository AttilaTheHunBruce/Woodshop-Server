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
from datetime import datetime
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


# Status codes
STATUS_OK                  = 0x0000
STATUS_ERROR               = 0x0001
STATUS_MEMBER_NOT_FOUND    = 0x0002
STATUS_MACHINE_DISABLED    = 0x0003
STATUS_MEMBER_NOT_AUTHORIZED = 0x0004
STATUS_INVALID_MESSAGE     = 0x0005

# ── OTA update flag ───────────────────────────────────────────────────────────
# Set True to signal all nodes to download a software update on next boot.
# Nodes store this in NVS when received; OTA runs at start of next boot cycle.
# Workflow:
#   1. Copy updated .py files to the woodshop firmware/ directory
#   2. Set UPDATE_AVAILABLE = True and restart: sudo systemctl restart woodshop-tcp
#   3. Each node picks up the flag on its next card event and stores it in NVS
#   4. On next reboot the node downloads changed files and clears the flag
#   5. Set UPDATE_AVAILABLE = False and restart again once all nodes updated
#UPDATE_AVAILABLE = False   <-- placed at top of file



# Machine number -> name. Zero-based; must match the numbering used by the
# machine controllers' DIP switches (and by data/machines.json in app.py).
MACHINES = {
     0: "Table Saw",
     1: "Band Saw",
     2: "Lathe",
     3: "Planer",
     4: "Jointer",
     5: "Router Table",
     6: "Drill Press",
     7: "Scroll Saw",
    31: "Admin Override",
}

def machine_name(num):
    return MACHINES.get(num, f"Machine {num}")

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

        Bit convention: bit index == machine_number, 0-based -- matching
        this file's own MACHINES dict (0: "Table Saw", ...). Confirmed:
        machine 0 is not skipped/reserved, so this direct mapping is fine.
        """
        row = self.get_active_member(member_id)
        if row is None:
            return False
        permissions = row[4]
        if not permissions:
            return False
        if machine_number < 0 or machine_number >= len(permissions):
            return False
        return permissions[machine_number] == '1'

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
            data = b''
            while len(data) < BinaryMessage.SIZE:
                chunk = client_socket.recv(BinaryMessage.SIZE - len(data))
                if not chunk:
                    break
                data += chunk

            if len(data) == BinaryMessage.SIZE:
                msg = BinaryMessage.from_bytes(data)
                logger.info(f"From {client_address[0]}: {msg}")
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

    Fixed 52-character ASCII message, one connection per message:
        messageType : 1 char   ('0' = login, '1' = logout -- confirmed,
                                 matches the old 0/1 numeric convention
                                 from the original binary design, just
                                 sent as an ASCII digit now)
        timestamp   : 15 chars 'YYYYMMDD HHMMSS' (Login's own clock --
                                 Server has no independent time source
                                 anymore, no WWVB/DS3231)
        memberID    : 4 chars  decimal, e.g. '1023' (matches the same
                                 memberID space used elsewhere, e.g. the
                                 sample users seeded in app.py: 1001-1003)
        firstName   : 16 chars space-padded
        lastName    : 16 chars space-padded

    A login message inserts/replaces a row in active_members, with
    login_time set directly from the message's own timestamp (not from
    Server's clock) and permissions looked up fresh from the reduced
    member file at that moment. A logout message deletes the row. No
    clock-sync/SyncedClock step -- Server doesn't need one for this.
    """

    MSG_SIZE = 52
    TYPE_LOGIN  = '0'
    TYPE_LOGOUT = '1'

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
                        f"(expecting {self.MSG_SIZE}-byte ASCII messages)")
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

            self.process_message(data, client_address)
        except Exception as e:
            logger.error(f"Login listener error handling {client_address}: {e}")
        finally:
            client_socket.close()

    def process_message(self, data, client_address):
        text = data.decode('ascii', errors='replace')
        msg_type   = text[0:1]
        ts_str     = text[1:16]
        member_str = text[16:20]
        first_name = text[20:36].strip()
        last_name  = text[36:52].strip()

        try:
            member_id = int(member_str.strip())
        except ValueError:
            logger.error(f"Login listener: bad memberID {member_str!r} from {client_address}")
            return

        try:
            login_time = datetime.strptime(ts_str, "%Y%m%d %H%M%S")
        except ValueError:
            logger.error(f"Login listener: bad timestamp {ts_str!r} from "
                         f"{client_address} -- using Server's local time instead")
            login_time = datetime.now()

        if msg_type == self.TYPE_LOGIN:
            permissions = member_permissions(member_id)
            self.database.login_member(member_id, first_name, last_name,
                                       login_time, permissions)
            logger.info(f"LOGIN: Member={member_id} ({first_name} {last_name}) "
                        f"at {login_time}"
                        + ("" if permissions else "  [WARNING: no permissions on file]"))
        elif msg_type == self.TYPE_LOGOUT:
            self.database.logout_member(member_id)
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


def main():
    logger.info("Starting Woodshop Master Server...")
    server = WoodshopServer(host='0.0.0.0', port=35487)
    login_listener = LoginListener(server.database, host='0.0.0.0', port=45432)
    login_thread = threading.Thread(target=login_listener.start, daemon=True)
    login_thread.start()
    try:
        server.start()
    except KeyboardInterrupt:
        logger.info("\nShutting down...")
        login_listener.stop()
        server.stop()


if __name__ == "__main__":
    main()
