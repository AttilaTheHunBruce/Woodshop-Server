"""
DEPRECATED -- delete this file, do not add it to the repo.

As of the Aug 2026 redesign, the server (app.py) no longer reads or writes
any RFID/NFC card of any kind. Card writing for members is done entirely
on Lee's machine with WriteNTAG215.py (plaintext NTAG215 layout, no
signing). There is no server-side config card either -- app.py's
/admin/config-card and /api/config_card_start routes, and the PN532 code
that used this module's load_private_key(), have been removed.

This stub is left behind only because Claude's output folder can't delete
files it already wrote in this session. It isn't imported by anything.
Safe to delete on your end.
"""
