# Copyright (c) 2025 VoidCanary-Lab
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import sys
import os

# Ensure we can import from the root workspace
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from amaranth.back import verilog
from gateware.src.packet import SecurityAirlock
from gateware.src.platform import ULX3SPlatform

def build():
    parser = argparse.ArgumentParser()
    parser.add_argument("--flash", action="store_true", help="Synthesize and flash to hardware")
    args = parser.parse_args()

    top = SecurityAirlock()

    if args.flash:
        print("[*] Building for ULX3S Platform...")
        platform = ULX3SPlatform()
        # In a real environment, this would invoke the toolchain
        platform.build(top, do_program=True)
    else:
        print("[*] Generating Verilog (security_airlock.v)...")
        with open("security_airlock.v", "w") as f:
            f.write(verilog.convert(top, ports=[
                top.rx_data, top.rx_valid, top.rx_last, top.rx_ready,
                top.tx_data, top.tx_valid, top.tx_last, top.tx_ready,
                top.heartbeat_in, top.rst_lock, top.status_led
            ]))

if __name__ == "__main__":
    build()