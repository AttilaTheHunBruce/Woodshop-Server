"""
server_card_writer.py
Helper module imported by app.py for RFID card write operations.

Card format v1 — every card starts with a type byte and a version byte so
readers can discriminate without inspecting unsigned data.

Member card layout (NTAG215, pages 4-33, 120 bytes):
  Signed payload (54 bytes, '<BBI4I16s16s'):
    Byte   0    : card_type   (0x01 = CARD_TYPE_MEMBER)
    Byte   1    : version     (0x01)
    Bytes  2- 5 : member_id   (uint32, little-endian)
    Bytes  6- 9 : permissions0 (uint32) machines   1-32  (bits 0-31)
    Bytes 10-13 : permissions1 (uint32) machines  33-64  (bits 0-31)
    Bytes 14-17 : permissions2 (uint32) machines  65-96  (bits 0-31)
    Bytes 18-21 : permissions3 (uint32) machines  97-128 (bits 0-31)
    Bytes 22-37 : first_name  (16 bytes UTF-8, null-padded)
    Bytes 38-53 : last_name   (16 bytes UTF-8, null-padded)
  Ed25519 signature (64 bytes)
  2 bytes padding to reach 120 (next 4-byte page boundary)

Config card layout — written by app.py /admin/config-card (unchanged):
    Byte  0     : 0x02 (CARD_TYPE_CONFIG)
    Byte  1     : 0x01 (version)
    Byte  2     : machine number (0-255)
    Byte  3     : blast gate delay (0-15, × 10 s)
    Byte  4     : reserved
    Bytes 5-68  : Ed25519 signature over bytes 0-4

Machine numbering: 1-based externally (machine 1 = bit 0 of permissions0).
Permission string: 128-char '0'/'1' string stored in users.json,
                   index 0 = machine 1, index 127 = machine 128.
"""

import struct
from cryptography.hazmat.primitives.serialization import load_pem_private_key

# ── Constants ─────────────────────────────────────────────────────────────────

CARD_TYPE_MEMBER    = 0x01
CARD_TYPE_CONFIG    = 0x02
MEMBER_CARD_VERSION = 0x01

PAGE_DATA_START = 4
PAYLOAD_FORMAT  = '<BBI4I16s16s'   # type + version + member_id + 4×perms + 2×name
PAYLOAD_LEN     = struct.calcsize(PAYLOAD_FORMAT)   # 54 bytes
SIG_LEN         = 64
# Pad to next 4-byte NTAG page boundary so (CARD_LEN // 4) covers everything.
# 54 + 64 = 118 → round up to 120 (30 pages, pages 4..33).
CARD_LEN        = (PAYLOAD_LEN + SIG_LEN + 3) & ~3  # 120 bytes

assert PAYLOAD_LEN == 54,  f"PAYLOAD_LEN={PAYLOAD_LEN}, expected 54"
assert CARD_LEN    == 120, f"CARD_LEN={CARD_LEN}, expected 120"

# ── Private key ───────────────────────────────────────────────────────────────

def load_private_key(path: str):
    with open(path, 'rb') as f:
        return load_pem_private_key(f.read(), password=None)

# ── Name encoding ─────────────────────────────────────────────────────────────

def _encode_name(name: str, length: int = 16) -> bytes:
    data = name.encode('utf-8')[:length]
    return data + b'\x00' * (length - len(data))

# ── Permission string ↔ four uint32 words ─────────────────────────────────────

def perms_str_to_words(perm_str: str):
    """
    Convert 128-char '0'/'1' permission string to four uint32 words.

    Bit mapping:
      perm_str[0]   → bit 0 of p0  (machine 1)
      perm_str[31]  → bit 31 of p0 (machine 32)
      perm_str[32]  → bit 0 of p1  (machine 33)
      ...
      perm_str[127] → bit 31 of p3 (machine 128)

    Returns (p0, p1, p2, p3).
    """
    bits = (perm_str or "").ljust(128, '0')[:128]
    p = [0, 0, 0, 0]
    for i, c in enumerate(bits):
        if c == '1':
            p[i // 32] |= (1 << (i % 32))
    return p[0], p[1], p[2], p[3]

def perms_to_machines(p0: int, p1: int, p2: int, p3: int) -> list:
    """Return sorted list of 1-based machine numbers from four permission words."""
    machines = []
    for word_idx, word in enumerate([p0, p1, p2, p3]):
        for bit in range(32):
            if word & (1 << bit):
                machines.append(word_idx * 32 + bit + 1)
    return machines

# ── Card data builder ─────────────────────────────────────────────────────────

def create_card_data(member_id: int, p0: int, p1: int, p2: int, p3: int,
                     firstname: str, lastname: str, private_key) -> bytes:
    """
    Build and sign a 120-byte member card payload.

    Args:
        member_id  : uint32 member ID
        p0..p3     : four uint32 permission words
        firstname  : str (max 16 chars)
        lastname   : str (max 16 chars)
        private_key: Ed25519PrivateKey from cryptography library

    Returns:
        120 bytes ready to write to NTAG215 pages 4-33
    """
    payload = struct.pack(PAYLOAD_FORMAT,
                          CARD_TYPE_MEMBER,
                          MEMBER_CARD_VERSION,
                          member_id,
                          p0, p1, p2, p3,
                          _encode_name(firstname),
                          _encode_name(lastname))
    assert len(payload) == PAYLOAD_LEN
    signature = private_key.sign(payload)
    assert len(signature) == SIG_LEN
    card_bytes = payload + signature
    # Pad to page boundary
    card_bytes += b'\x00' * (CARD_LEN - len(card_bytes))
    assert len(card_bytes) == CARD_LEN
    return card_bytes
