# Copyright (c) 2025 VoidCanary-Lab
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import sys
import os

# Ensure we can import from the root workspace
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from amaranth import *
from amaranth.back import verilog
from gateware.src.packet import SecurityAirlock
from gateware.src.platform import ULX3SPlatform

def build():
    parser = argparse.ArgumentParser()
    parser.add_argument("--flash", action="store_true", help="Synthesize and flash to hardware")
    parser.add_argument("--pinout", default="split_j1_j2", help="Select pinout configuration (default: split_j1_j2)")
    args = parser.parse_args()

    top = SecurityAirlock()

    if args.flash:
        print(f"[*] Building for ULX3S Platform (Pinout: {args.pinout})...")
        platform = ULX3SPlatform(pinout=args.pinout)
        
        class HardwareTop(Elaboratable):
            def elaborate(self, platform):
                m = Module()
                m.submodules.airlock = airlock = SecurityAirlock()
                
                # Request Physical Resources
                led = platform.request("led", 0)
                btn = platform.request("btn", 0)
                hb  = platform.request("heartbeat", 0)
                sw  = platform.request("egress_mode", 0)
                rmii = platform.request("eth_rmii", 0)
                
                # Connect Physical Pins to Airlock Logic
                m.d.comb += [
                    led.o.eq(airlock.status_led),
                    airlock.rst_lock.eq(btn.i),
                    airlock.heartbeat_in.eq(hb.i),
                    airlock.egress_mode.eq(sw.i),
                    
                    # TODO: Instantiate RMII MAC here to convert 2-bit RMII <-> 8-bit Stream
                    # The LAN8720 provides 2 bits at 50MHz. SecurityAirlock expects 8 bits.
                    
                    # Placeholder for RMII connections:
                    # rmii.tx_en.o.eq(...),
                    # rmii.txd0.o.eq(...),
                    # rmii.txd1.o.eq(...),
                    
                    # For now, tie off inputs to prevent floating logic during synthesis
                    airlock.rx_valid.eq(0),
                    airlock.rx_last.eq(0),
                    airlock.rx_data.eq(0),
                    airlock.tx_ready.eq(1),
                ]
                return m

        platform.build(HardwareTop(), do_program=True)
    else:
        print("[*] Generating Verilog (security_airlock.v)...")
        with open("security_airlock.v", "w") as f:
            f.write(verilog.convert(top, ports=[
                top.rx_data, top.rx_valid, top.rx_last, top.rx_ready,
                top.tx_data, top.tx_valid, top.tx_last, top.tx_ready,
                top.heartbeat_in, top.rst_lock, top.status_led,
                top.ingress
            ]))

if __name__ == "__main__":
    build()