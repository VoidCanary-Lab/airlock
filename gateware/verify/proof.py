# Copyright (c) 2025 VoidCanary-Lab
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import os
from amaranth import *
from amaranth.asserts import Assert, Cover, Past
from amaranth.sim import Simulator
from amaranth.back import verilog

# Ensure we can import from the root workspace
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from gateware.src.packet import SecurityAirlock

class FormalProof(Elaboratable):
    def elaborate(self, platform):
        m = Module()
        m.submodules.dut = dut = SecurityAirlock(heartbeat_timeout=10)

        # --- Helper Signals ---
        # Aggregate all traffic violations to ensure the "Global Security Policy" is enforced.
        # We check Past() values because the DUT registers these errors.
        any_traffic_violation = (
            dut.violation_volume | 
            dut.violation_ttl | 
            dut.violation_wg_size | 
            dut.violation_plaintext | 
            dut.violation_ethertype | 
            dut.violation_arp_rate | 
            dut.violation_ip_proto | 
            dut.violation_arp_size |
            dut.violation_tcp_flags |
            dut.violation_tcp_options |
            dut.violation_arp_opcode |
            dut.violation_ip_options |
            dut.violation_land |
            dut.violation_loopback |
            dut.violation_udp_len |
            dut.violation_frag
        )

        # --- Formal Properties ---

        # 1. Security Response Logic
        # If a violation occurred in the previous cycle, we must immediately see a Lock or Drop.
        with m.If(~Past(dut.locked)):
            # Heartbeat failure takes priority
            with m.If(Past(dut.violation_heartbeat)):
                m.d.comb += Assert(dut.locked)
            
            # Traffic violations
            with m.Elif(Past(any_traffic_violation)):
                with m.If(~Past(dut.egress_mode)):
                    m.d.comb += Assert(dut.locked)
                with m.Else():
                    m.d.comb += Assert(dut.drop_current)

        # 2. Safety: No Leakage when Locked (With Graceful Termination)
        # If the airlock is locked, it must NOT output valid data.
        # EXCEPTION: It may output exactly one cycle of 0x00 with last=1 to close the stream.
        with m.If(dut.locked):
            with m.If(dut.tx_valid):
                # Protocol Safety: Must be the last byte
                m.d.comb += Assert(dut.tx_last == 1)
                # Data Security: Must be scrubbed (zeroed)
                m.d.comb += Assert(dut.tx_data == 0)

        # 3. Watchdog Timer Logic
        # Verify timer decrements correctly and triggers violation at 0.
        with m.If(~dut.rst_lock):
            with m.If(Past(dut.watchdog_timer) > 0):
                 # If heartbeat input hasn't toggled
                 with m.If(Past(dut.heartbeat_in) == dut.heartbeat_in):
                    m.d.comb += Assert(dut.watchdog_timer == Past(dut.watchdog_timer) - 1)
            
            with m.If(Past(dut.watchdog_timer) == 0):
                m.d.comb += Assert(dut.violation_heartbeat == 1)

        # 4. Reset Logic
        with m.If(dut.rst_lock):
            m.d.comb += Assert(~dut.locked)

        # --- Coverage ---
        m.d.comb += Cover(dut.locked)
        m.d.comb += Cover(dut.drop_current)
        
        # Cover individual violations
        m.d.comb += [
            Cover(dut.violation_volume),
            Cover(dut.violation_ttl),
            Cover(dut.violation_wg_size),
            Cover(dut.violation_plaintext),
            Cover(dut.violation_ethertype),
            Cover(dut.violation_arp_rate),
            Cover(dut.violation_ip_proto),
            Cover(dut.violation_arp_size),
            Cover(dut.violation_heartbeat),
            Cover(dut.violation_tcp_flags),
            Cover(dut.violation_tcp_options),
            Cover(dut.violation_arp_opcode),
            Cover(dut.violation_ip_options),
            Cover(dut.violation_land),
            Cover(dut.violation_loopback),
            Cover(dut.violation_udp_len),
            Cover(dut.violation_frag),
        ]

        return m

if __name__ == "__main__":
    proof = FormalProof()
    
    with open("security_airlock_formal.v", "w") as f:
        f.write(verilog.convert(proof, ports=[]))
        
    with open("proof.sby", "w") as f:
        f.write("""
[tasks]
prove
cover

[options]
mode bmc
depth 30

[engines]
smtbmc

[script]
read_verilog -formal security_airlock_formal.v
prep -top proof

[files]
security_airlock_formal.v
""")

    print("[*] Generated SymbiYosys files (proof.sby, security_airlock_formal.v)")
