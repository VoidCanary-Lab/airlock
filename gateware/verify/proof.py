# Copyright (c) 2025 VoidCanary-Lab
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import os
from amaranth import *
from amaranth import Assert, Cover
from amaranth.sim import Simulator
from amaranth.back import verilog

# Ensure we can import from the root workspace
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from gateware.src.packet import SecurityAirlock

class FormalProof(Elaboratable):
    def elaborate(self, platform):
        m = Module()
        m.submodules.dut = dut = SecurityAirlock(heartbeat_timeout=10)

        # --- Formal Properties ---

        # Create explicit registers for Past values to address deprecation warnings
        prev_locked = Signal()
        prev_traffic_violation = Signal()
        prev_heartbeat_violation = Signal()
        prev_rst_lock = Signal()
        prev_watchdog_timer = Signal(32)
        prev_heartbeat_in = Signal()
        prev_egress_mode = Signal()

        m.d.sync += [
            prev_locked.eq(dut.locked),
            prev_traffic_violation.eq(dut.violation_volume | dut.violation_ttl | dut.violation_wg_size | dut.violation_plaintext | dut.violation_ethertype | dut.violation_arp_rate | dut.violation_ip_proto | dut.violation_arp_size),
            prev_heartbeat_violation.eq(dut.violation_heartbeat),
            prev_rst_lock.eq(dut.rst_lock),
            prev_watchdog_timer.eq(dut.watchdog_timer),
            prev_heartbeat_in.eq(dut.heartbeat_in),
            prev_egress_mode.eq(dut.egress_mode)
        ]

        # 1. If any violation signal is high, check Lock vs Drop logic.
        with m.If(~prev_locked):
            with m.If(prev_heartbeat_violation):
                m.d.comb += Assert(dut.locked)
            
            with m.Elif(prev_traffic_violation):
                with m.If(~prev_egress_mode):
                    m.d.comb += Assert(dut.locked)
                with m.Else():
                    m.d.comb += Assert(dut.drop_current)

        # 2. If locked, no traffic should pass.
        with m.If(dut.locked):
            m.d.comb += Assert(dut.tx_valid == 0)

        # 3. Watchdog timer should decrement and trigger a violation.
        with m.If(~prev_rst_lock):
            with m.If(prev_watchdog_timer > 0):
                 with m.If(prev_heartbeat_in == dut.heartbeat_in):
                    m.d.comb += Assert(dut.watchdog_timer == prev_watchdog_timer - 1)
            
            with m.If(prev_watchdog_timer == 0):
                m.d.comb += Assert(dut.violation_heartbeat == 1)

        # Cover the lock state to ensure it is reachable
        m.d.comb += Cover(dut.locked)

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
    print("[*] To run verification locally: sby -f proof.sby")