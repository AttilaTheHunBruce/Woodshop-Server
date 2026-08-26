#!/usr/bin/env python3
"""Standalone hardware test for the four status LEDs, independent of
master_server.py. Run this on the Pi to isolate a wiring/driver problem
from a software problem.

Usage:
    python3 test_status_leds.py        # cycles all four, 2s each
    python3 test_status_leds.py 26     # just GPIO26 (yellow), 5x blink
"""

import sys
import time

from gpiozero import LED

PINS = {25: "red", 20: "green", 24: "blue", 26: "yellow"}


def test_all():
    for pin, name in PINS.items():
        print(f"GPIO{pin} ({name}): ON")
        led = LED(pin)
        led.on()
        time.sleep(2)
        led.off()
        print(f"GPIO{pin} ({name}): off")
        led.close()


def test_one(pin):
    name = PINS.get(pin, "?")
    led = LED(pin)
    print(f"Blinking GPIO{pin} ({name}) 5x -- watch the LED now")
    for _ in range(5):
        led.on()
        time.sleep(0.5)
        led.off()
        time.sleep(0.5)
    led.close()


if __name__ == "__main__":
    if len(sys.argv) == 2:
        test_one(int(sys.argv[1]))
    else:
        test_all()
