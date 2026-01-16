# Copyright (c) 2025 VoidCanary-Lab
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import os
from amaranth import *
from amaranth import Assert, Cover
from amaranth.back import verilog

# Ensure we can import from the root workspace
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from gateware.src.packet import SecurityAirlock

class FormalProof(Elaboratable):
    def elaborate(self, platform):
        m = Module()
        m.submodules.dut = dut = SecurityAirlock(heartbeat_timeout=10)

        # --- Helper Signals ---
        
        # 1. Aggregate Violations (Current Cycle)
        any_traffic_violation = Signal()
        m.d.comb += any_traffic_violation.eq(
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

        # 2. Create Explicit "Past" Signals
        # Since 'Past()' is deprecated, we manually create registers that lag by one cycle.
        locked_d              = Signal.like(dut.locked)
        violation_heartbeat_d = Signal.like(dut.violation_heartbeat)
        any_traffic_violation_d = Signal.like(any_traffic_violation)
        egress_mode_d         = Signal.like(dut.egress_mode)
        watchdog_timer_d      = Signal.like(dut.watchdog_timer)
        heartbeat_in_d        = Signal.like(dut.heartbeat_in)

        # 3. Update "Past" Signals in Sync
        # At cycle 't', these assignments capture the value for use in cycle 't+1'.
        # Therefore, reading *_d in cycle 't' gives us the value from 't-1'.
        m.d.sync += [
            locked_d.eq(dut.locked),
            violation_heartbeat_d.eq(dut.violation_heartbeat),
            any_traffic_violation_d.eq(any_traffic_violation),
            egress_mode_d.eq(dut.egress_mode),
            watchdog_timer_d.eq(dut.watchdog_timer),
            heartbeat_in_d.eq(dut.heartbeat_in),
        ]

        # --- Formal Properties ---

        # 1. Security Response Logic
        # "If a violation occurred in the previous cycle (checked via *_d signals),
        # we must immediately see a Lock or Drop in the current cycle."
        
        # Note: We check ~locked_d to ensure we catch the transition from Unlocked -> Locked
        with m.If(~locked_d):
            # Heartbeat failure takes priority
            with m.If(violation_heartbeat_d):
                m.d.comb += Assert(dut.locked)
            
            # Traffic violations
            with m.Elif(any_traffic_violation_d):
                with m.If(~egress_mode_d):
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
            # Check against 'watchdog_timer_d' (the value from the previous cycle)
            with m.If(watchdog_timer_d > 0):
                 # If heartbeat input hasn't toggled since the last cycle
                 with m.If(heartbeat_in_d == dut.heartbeat_in):
                    m.d.comb += Assert(dut.watchdog_timer == watchdog_timer_d - 1)
            
            with m.If(watchdog_timer_d == 0):
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