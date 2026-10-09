#!/usr/bin/env python3
"""
rfid_admin_card.py -- read / write the machine ADMIN (config) card.

The admin card tells a machine client its machine number and its blast-gate
run-on delay, and carries a machine name for labelling. It is an NTAG215, the
same card type the client reads member cards from. Present it to the machine's
reader when no member is using the machine.

Card layout (UNSIGNED, config card version 2), pages 4.. of the NTAG215:
    byte 0      : 0x02  (CARD_TYPE_CONFIG; can never look like a member card,
                         whose first byte is an ASCII digit)
    byte 1      : 0x02  (version; the client also accepts 0x01 = no name)
    byte 2      : machine number, 1..128
    byte 3      : blast-gate delay in 10 s units, 0..15  (0..150 s)
    byte 4      : 0x00  reserved
    bytes 5..20 : machine name, 16 bytes ASCII, null-padded
    21..119     : zero-filled (clears whatever the card held before)
These values match config.h (CARD_TYPE_CONFIG, CFG_*) in the client firmware.

Hardware: Raspberry Pi + PN532 on SPI (SPI must be enabled on the Pi):
    SCK GPIO11, MISO GPIO9, MOSI GPIO10, SS GPIO8; IRQ and RSTO not connected.
    Defaults below match that wiring. Other wiring: --cs-pin N, and
    --reset-pin N if the module's reset input is wired. (GPIO25, the old
    default reset pin, is also the server's first status LED.)

This script is the only place that touches the reader. The server's
"Admin Card" web page runs it with --json and shows the result, so a USB
reader/writer can replace this file later without changing the web page:
keep the command line and the JSON output below.

Usage:
    rfid_admin_card.py write --machine 3 --name "Table Saw" --blast 30
    rfid_admin_card.py read
    add  --json       machine-readable result on stdout (one JSON object)
         --dry-run    (write) build and show the card, touch nothing
         --force      (write) allow overwriting a card that holds a member card
         --timeout N  seconds to wait for a card (default 20)
         --debug      print pin assignments, /dev/spidev* presence, each
                      connection attempt, and the PN532 library's own raw
                      SPI frame dump -- run this directly (e.g. over SSH)
                      when "Failed to detect the PN532" needs tracking down;
                      the trail is also folded into the --json result as
                      "debug_log" for when it's triggered from the web page.
Exit status 0 = success, 1 = failure.
"""

import argparse
import json
import os
import sys
import time

# Collected by _dbg() regardless of --debug, so a failure's trail is always
# available to attach to the JSON result; --debug additionally streams it
# live to stderr as it happens.
DEBUG_LOG = []


def _dbg(debug, msg):
    DEBUG_LOG.append(msg)
    if debug:
        print(f"DEBUG: {msg}", file=sys.stderr)

CARD_TYPE_CONFIG = 0x02
VERSION_NAMED = 0x02
VERSION_PLAIN = 0x01
OFF_TYPE, OFF_VERSION, OFF_MACHINE, OFF_BLAST, OFF_RESERVED, OFF_NAME = 0, 1, 2, 3, 4, 5
NAME_LEN = 16
BLAST_UNIT_S = 10
MAX_BLAST_UNITS = 15
PAGE_START = 4
CARD_TOTAL_LEN = 120          # 30 pages, same window the client reads
USED_LEN = OFF_NAME + NAME_LEN   # 21 bytes


# ── pure functions (no hardware; used by the tests) ─────────────────────────
class CardError(Exception):
    pass


def build_payload(machine, name, blast_seconds):
    """Return the CARD_TOTAL_LEN-byte image of an admin card."""
    if not isinstance(machine, int) or not (1 <= machine <= 128):
        raise CardError("machine number must be 1 to 128")
    if blast_seconds < 0 or blast_seconds > MAX_BLAST_UNITS * BLAST_UNIT_S:
        raise CardError("blast delay must be 0 to 150 seconds")
    if blast_seconds % BLAST_UNIT_S:
        raise CardError("blast delay must be a multiple of 10 seconds")
    name = (name or "").strip()
    if not name.isascii() or not all(32 <= ord(ch) < 127 for ch in name):
        raise CardError("machine name must be printable ASCII")
    raw = name.encode("ascii")
    if len(raw) > NAME_LEN:
        raise CardError(f"machine name is {len(raw)} characters; the card holds {NAME_LEN}")
    buf = bytearray(CARD_TOTAL_LEN)
    buf[OFF_TYPE] = CARD_TYPE_CONFIG
    buf[OFF_VERSION] = VERSION_NAMED
    buf[OFF_MACHINE] = machine
    buf[OFF_BLAST] = blast_seconds // BLAST_UNIT_S
    buf[OFF_RESERVED] = 0
    buf[OFF_NAME:OFF_NAME + NAME_LEN] = raw.ljust(NAME_LEN, b"\x00")
    return bytes(buf)


def is_member_card(data):
    """True if the first four bytes are ASCII digits (a member card)."""
    return len(data) >= 4 and all(0x30 <= b <= 0x39 for b in data[:4])


def parse_payload(data):
    """Decode an admin card image. Raises CardError if it is not one."""
    if len(data) < OFF_NAME or data[OFF_TYPE] != CARD_TYPE_CONFIG:
        if is_member_card(data):
            raise CardError("this is a member card, not an admin card")
        raise CardError("not an admin card (wrong type byte)")
    version = data[OFF_VERSION]
    if version not in (VERSION_PLAIN, VERSION_NAMED):
        raise CardError(f"unsupported admin card version {version}")
    result = {
        "version": version,
        "machine": data[OFF_MACHINE],
        "blast_s": (data[OFF_BLAST] & 0x0F) * BLAST_UNIT_S,
        "name": "",
    }
    if version == VERSION_NAMED and len(data) >= USED_LEN:
        raw = data[OFF_NAME:OFF_NAME + NAME_LEN].split(b"\x00", 1)[0]
        result["name"] = "".join(chr(b) if 32 <= b < 127 else "?" for b in raw)
    return result


# ── hardware ────────────────────────────────────────────────────────────────
def open_reader(cs_pin, reset_pin, debug=False, attempts=3):
    import board
    import busio
    import digitalio
    from adafruit_pn532.spi import PN532_SPI

    def pin(n):
        return getattr(board, f"D{n}")

    _dbg(debug, f"pins: SCK=board.SCK MOSI=board.MOSI MISO=board.MISO "
                f"CS=board.D{cs_pin}"
                + (f" RESET=board.D{reset_pin}" if reset_pin is not None else " RESET=not used"))
    for dev in ("/dev/spidev0.0", "/dev/spidev0.1"):
        _dbg(debug, f"{dev}: {'present' if os.path.exists(dev) else 'MISSING'}")

    spi = busio.SPI(board.SCK, board.MOSI, board.MISO)
    cs = digitalio.DigitalInOut(pin(cs_pin))
    reset = digitalio.DigitalInOut(pin(reset_pin)) if reset_pin is not None else None

    # Retry a few times with the chip rebuilt fresh each attempt -- a cold or
    # just-rebooted PN532 occasionally misses the first wakeup, and this
    # tells a one-off glitch apart from a reader that never answers at all.
    # debug=True on PN532_SPI makes the adafruit_pn532 library itself print
    # every raw byte it writes/reads over SPI -- the most direct evidence of
    # whether anything is on the other end of the wire at all (all 0xFF back
    # typically means nothing is responding -- wiring/power; a frame that's
    # almost-but-not-quite right points more at clock speed/mode or a wrong
    # pin than at a dead chip).
    last_err = None
    for attempt in range(1, attempts + 1):
        try:
            pn532 = PN532_SPI(spi, cs, reset=reset, debug=debug)
            ic, ver, rev, support = pn532.firmware_version
            _dbg(debug, f"attempt {attempt}/{attempts}: responded -- "
                        f"IC=0x{ic:02X} firmware {ver}.{rev} support=0x{support:02X}")
            pn532.SAM_configuration()
            return pn532
        except Exception as e:
            last_err = e
            _dbg(debug, f"attempt {attempt}/{attempts}: no response "
                        f"({type(e).__name__}: {e})")
            time.sleep(0.3)

    _dbg(debug, "giving up -- the chip never answered GetFirmwareVersion. With "
                 "SPI confirmed enabled and /dev/spidev* present (above), this "
                 "points at wiring or power: re-check SCK/MOSI/MISO/CS against "
                 "the pins noted above, confirm VCC matches what this specific "
                 "breakout needs (3.3V vs 5V), and that RSTO/IRQ -- if wired at "
                 "all -- aren't holding the chip in reset.")
    raise CardError(f"could not detect the PN532 after {attempts} attempts "
                     f"({type(last_err).__name__}: {last_err})") from last_err


def wait_for_card(pn532, timeout_s):
    start = time.monotonic()
    while time.monotonic() - start < timeout_s:
        uid = pn532.read_passive_target(timeout=0.5)
        if uid is not None:
            return uid
    return None


def uid_text(uid):
    return " ".join(f"{b:02X}" for b in uid)


def card_hint(uid):
    """Explain a read failure from the UID length: NTAG215 cards have a
    7-byte UID; a 4-byte UID is a MIFARE Classic card (or similar), which the
    machine clients cannot use either."""
    if len(uid) == 4:
        return ("a 4-byte UID means this is probably a MIFARE Classic card, "
                "not an NTAG215; use NTAG215 cards")
    return "hold the card still, flat and about 3 cm from the antenna"


def read_card_bytes(pn532, total_len=CARD_TOTAL_LEN, uid=b""):
    data = bytearray()
    for i in range((total_len + 3) // 4):
        block = None
        for _ in range(5):
            block = pn532.ntag2xx_read_block(PAGE_START + i)
            if block is not None:
                break
            time.sleep(0.05)
        if block is None:
            raise CardError(f"could not read page {PAGE_START + i} of the card "
                            f"(UID {uid_text(uid)}): {card_hint(uid)}")
        data.extend(block)
    return bytes(data)


def write_card_bytes(pn532, payload, uid=b""):
    for i in range((len(payload) + 3) // 4):
        chunk = payload[i * 4:i * 4 + 4].ljust(4, b"\x00")
        for _ in range(5):
            if pn532.ntag2xx_write_block(PAGE_START + i, chunk):
                break
            time.sleep(0.05)
        else:
            raise CardError(f"write failed on page {PAGE_START + i} "
                            f"(UID {uid_text(uid)}): {card_hint(uid)}")
        time.sleep(0.01)


# ── commands ────────────────────────────────────────────────────────────────
def do_write(args):
    payload = build_payload(args.machine, args.name, args.blast)
    info = parse_payload(payload)
    if args.dry_run:
        return {"ok": True, "action": "write", "dry_run": True, **info}
    pn532 = open_reader(args.cs_pin, args.reset_pin, debug=args.debug)
    uid = wait_for_card(pn532, args.timeout)
    if uid is None:
        raise CardError("no card presented (timed out)")
    existing = read_card_bytes(pn532, 8, uid)
    if existing and is_member_card(existing) and not args.force:
        raise CardError("this card holds a member card; refusing to overwrite it "
                        "(use a blank card, or --force)")
    write_card_bytes(pn532, payload, uid)
    back = read_card_bytes(pn532, USED_LEN + 3, uid)
    if back[:USED_LEN] != payload[:USED_LEN]:
        raise CardError("verify failed: the card does not hold what was written")
    return {"ok": True, "action": "write", "verified": True, **info}


def do_read(args):
    pn532 = open_reader(args.cs_pin, args.reset_pin, debug=args.debug)
    uid = wait_for_card(pn532, args.timeout)
    if uid is None:
        raise CardError("no card presented (timed out)")
    data = read_card_bytes(pn532, USED_LEN + 3, uid)   # only the first 6 pages matter
    return {"ok": True, "action": "read", **parse_payload(data)}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Read or write the machine admin card.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    w = sub.add_parser("write", help="write an admin card")
    w.add_argument("--machine", type=int, required=True, help="machine number 1..128")
    w.add_argument("--name", default="", help="machine name (16 ASCII characters max)")
    w.add_argument("--blast", type=int, default=30, help="blast-gate delay in seconds (0..150, steps of 10)")
    w.add_argument("--dry-run", action="store_true")
    w.add_argument("--force", action="store_true")
    sub.add_parser("read", help="read an admin card")
    for p in (w, sub.choices["read"]):
        p.add_argument("--json", action="store_true", help="print one JSON object")
        p.add_argument("--timeout", type=float, default=20.0)
        p.add_argument("--cs-pin", type=int, default=8, help="BCM pin of the PN532 SS (default 8)")
        p.add_argument("--reset-pin", type=int, default=None, help="BCM pin of the PN532 reset input (default: not wired)")
        p.add_argument("--no-reset", action="store_true", help="(kept for compatibility; reset is not used by default)")
        p.add_argument("--debug", action="store_true",
                       help="log pin assignments, /dev/spidev* presence, each connection "
                            "attempt, and the PN532 library's raw SPI frames to stderr; "
                            "also added to the --json result as \"debug_log\"")
    args = ap.parse_args(argv)
    if args.no_reset:
        args.reset_pin = None

    try:
        result = do_write(args) if args.cmd == "write" else do_read(args)
        code = 0
    except CardError as e:
        result, code = {"ok": False, "action": args.cmd, "error": str(e)}, 1
    except ImportError as e:
        result, code = {"ok": False, "action": args.cmd,
                        "error": f"card reader libraries are not installed ({e}); "
                                 "run: venv/bin/pip install -r requirements-card.txt"}, 1
    except Exception as e:              # reader not wired, SPI off, etc.
        result, code = {"ok": False, "action": args.cmd,
                        "error": f"reader problem: {type(e).__name__}: {e}"}, 1

    if args.debug and DEBUG_LOG:
        result["debug_log"] = DEBUG_LOG

    if args.json:
        print(json.dumps(result))
    elif result["ok"]:
        label = "DRY RUN " if result.get("dry_run") else ""
        print(f"{label}admin card ({result['action']}): machine {result['machine']}, "
              f"name '{result['name']}', blast delay {result['blast_s']} s"
              + (", verified" if result.get("verified") else ""))
    else:
        print("ERROR:", result["error"], file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
