# wwvb.py  –  WWVB decoder for WVB-0860N-03A on ESP32-C3
# T pin (data) → GPIO4.  P1 pin → GND.
# Output is INVERTED: idles LOW, goes HIGH during carrier reduction.
# Pulse widths: ~200ms = 0,  ~500ms = 1,  ~800ms = position marker

from machine import Pin, Timer
import time

DATA_PIN = 4       # GPIO connected to module T pin
PULSE_TIMEOUT = 1200   # ms – if no edge seen, start over

# ── bit classification ────────────────────────────────────────────
def classify_pulse(width_ms):
    if 80 <= width_ms < 350:
        return 0       # zero bit
    elif 350 <= width_ms < 650:
        return 1       # one bit
    elif 650 <= width_ms < 950:
        return 'P'     # position marker
    else:
        return None    # noise / glitch

# ── BCD decode helpers ────────────────────────────────────────────
def bcd(bits, weights):
    """bits: list of 0/1, weights: list of int (MSB first)"""
    return sum(b * w for b, w in zip(bits, weights) if b in (0, 1))

# ── frame decode ─────────────────────────────────────────────────
def decode_frame(frame):
    """
    frame: list of 60 symbols (0, 1, or 'P'), index = second number.
    Returns dict or None on error.
    """
    # Verify position markers at seconds 0,9,19,29,39,49,59
    markers = [0, 9, 19, 29, 39, 49, 59]
    for m in markers:
        if frame[m] != 'P':
            return None   # bad sync

    # Minutes  (BCD): bits 1-8  weights 40,20,10,0,8,4,2,1
    minute = bcd([frame[i] for i in [1,2,3,4,5,6,7,8]],
                 [40,20,10,0,8,4,2,1])

    # Hours    (BCD): bits 12-18  weights 20,10,0,8,4,2,1
    hour   = bcd([frame[i] for i in [12,13,14,15,16,17,18]],
                 [20,10,0,8,4,2,1])

    # Day of year (BCD): bits 22-33  weights 200,100,0,80,40,20,10,0,8,4,2,1
    doy    = bcd([frame[i] for i in [22,23,24,25,26,27,28,29,30,31,32,33]],
                 [200,100,0,80,40,20,10,0,8,4,2,1])

    # Year     (BCD): bits 45-52  weights 80,40,20,10,8,4,2,1
    year   = bcd([frame[i] for i in [45,46,47,48,49,50,51,52]],
                 [80,40,20,10,8,4,2,1])
    year  += 2000

    # DST / leap second flags
    ly     = frame[55]    # leap year
    dst1   = frame[57]    # DST bits
    dst2   = frame[58]

    return {
        'minute': minute, 'hour': hour,
        'doy': doy, 'year': year,
        'leap_year': ly, 'dst': (dst1, dst2)
    }

# ── main receiver loop ────────────────────────────────────────────
def run():
    pin = Pin(DATA_PIN, Pin.IN)

    print("WWVB receiver started. Waiting for signal…")
    print("Tip: orient antenna perpendicular to NNW, away from ESP32.\n")

    frame = []
    synced = False

    while True:
        # Wait for rising edge (start of carrier reduction = pulse start)
        while pin.value() == 0:
            pass
        t_rise = time.ticks_ms()

        # Wait for falling edge (end of pulse)
        deadline = time.ticks_add(t_rise, PULSE_TIMEOUT)
        while pin.value() == 1:
            if time.ticks_diff(time.ticks_ms(), deadline) > 0:
                print("Timeout – resync")
                frame.clear()
                synced = False
                break
        else:
            t_fall = time.ticks_ms()
            width = time.ticks_diff(t_fall, t_rise)
            sym = classify_pulse(width)

            if sym is None:
                print(f"  Glitch ({width} ms) – discarded")
                continue

            # Look for two consecutive position markers = frame boundary
            if len(frame) > 0 and frame[-1] == 'P' and sym == 'P':
                # The PREVIOUS P was second 59, this P is second 0
                frame.append(sym)   # complete the 60-symbol frame
                if len(frame) == 60:
                    result = decode_frame(frame)
                    if result:
                        print(f"\n✓ Frame decoded:")
                        print(f"  UTC  {result['year']}-DoY{result['doy']:03d}"
                              f"  {result['hour']:02d}:{result['minute']:02d}")
                        print(f"  DST flags: {result['dst']}  "
                              f"Leap year: {result['leap_year']}")
                    else:
                        print("  Frame failed position-marker check")
                frame.clear()
                frame.append(sym)   # seed next frame with this P (second 0)
                synced = True
            else:
                frame.append(sym)

            # Progress display
            marker = '*' if sym == 'P' else str(sym)
            print(f"s{len(frame)-1:02d} [{width:4d}ms] {marker}", end='  ')
            if len(frame) % 10 == 0:
                print()

run()
