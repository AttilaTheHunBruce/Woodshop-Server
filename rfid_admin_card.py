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

Hardware: Raspberry Pi + PN532 on SPI, same wiring as rfid_write.py:
    SCK GPIO11, MISO GPIO9, MOSI GPIO10, SS GPIO8 (CE0), RSTO GPIO25.
    NOTE: GPIO25 is also the server's first status LED. If both are wired,
    move the PN532 reset with --reset-pin (or use --no-reset).

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
Exit status 0 = success, 1 = failure.
"""

import argparse
import json
import sys
import time

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
def open_reader(cs_pin, reset_pin):
    import board
    import busio
    import digitalio
    from adafruit_pn532.spi import PN532_SPI

    def pin(n):
        return getattr(board, f"D{n}")

    spi = busio.SPI(board.SCK, board.MOSI, board.MISO)
    cs = digitalio.DigitalInOut(pin(cs_pin))
    reset = digitalio.DigitalInOut(pin(reset_pin)) if reset_pin is not None else None
    pn532 = PN532_SPI(spi, cs, reset=reset, debug=False)
    pn532.firmware_version          # raises if the reader does not answer
    pn532.SAM_configuration()
    return pn532


def wait_for_card(pn532, timeout_s):
    start = time.monotonic()
    while time.monotonic() - start < timeout_s:
        uid = pn532.read_passive_target(timeout=0.5)
        if uid is not None:
            return uid
    return None


def read_card_bytes(pn532, total_len=CARD_TOTAL_LEN):
    data = bytearray()
    for i in range((total_len + 3) // 4):
        block = None
        for _ in range(5):
            block = pn532.ntag2xx_read_block(PAGE_START + i)
            if block is not None:
                break
            time.sleep(0.05)
        if block is None:
            return None
        data.extend(block)
    return bytes(data)


def write_card_bytes(pn532, payload):
    for i in range((len(payload) + 3) // 4):
        chunk = payload[i * 4:i * 4 + 4].ljust(4, b"\x00")
        for _ in range(5):
            if pn532.ntag2xx_write_block(PAGE_START + i, chunk):
                break
            time.sleep(0.05)
        else:
            raise CardError(f"write failed on page {PAGE_START + i} "
                            "(hold the card still, about 3 cm from the antenna)")
        time.sleep(0.01)


# ── commands ────────────────────────────────────────────────────────────────
def do_write(args):
    payload = build_payload(args.machine, args.name, args.blast)
    info = parse_payload(payload)
    if args.dry_run:
        return {"ok": True, "action": "write", "dry_run": True, **info}
    pn532 = open_reader(args.cs_pin, args.reset_pin)
    if wait_for_card(pn532, args.timeout) is None:
        raise CardError("no card presented (timed out)")
    existing = read_card_bytes(pn532, 8)
    if existing and is_member_card(existing) and not args.force:
        raise CardError("this card holds a member card; refusing to overwrite it "
                        "(use a blank card, or --force)")
    write_card_bytes(pn532, payload)
    back = read_card_bytes(pn532, USED_LEN + 3)
    if back is None or back[:USED_LEN] != payload[:USED_LEN]:
        raise CardError("verify failed: the card does not hold what was written")
    return {"ok": True, "action": "write", "verified": True, **info}


def do_read(args):
    pn532 = open_reader(args.cs_pin, args.reset_pin)
    if wait_for_card(pn532, args.timeout) is None:
        raise CardError("no card presented (timed out)")
    data = read_card_bytes(pn532)
    if data is None:
        raise CardError("could not read the card")
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
        p.add_argument("--reset-pin", type=int, default=25, help="BCM pin of PN532 RSTO (default 25)")
        p.add_argument("--no-reset", action="store_true", help="PN532 reset line not wired")
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
