# Copyright (c) 2025 VoidCanary-Lab
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest
from amaranth.sim import Simulator, Tick
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from gateware.src.packet import SecurityAirlock

class TestSecurityAirlock(unittest.TestCase):
    def test_ttl_check(self):
        dut = SecurityAirlock()
        sim = Simulator(dut)

        def test_process():
            # Packet with low TTL (should be dropped)
            # Frame: dest(6) src(6) eth_type(2) ip_ver_ihl(1) ip_tos(1) ip_len(2) ip_id(2) ip_frag(2) ip_ttl(1) ...
            # TTL is at byte 22. We set it to 50.
            packet = bytearray([0x00]*22) + b'\x32' + bytearray([0x00]*10)

            for i, byte in enumerate(packet):
                yield dut.rx_data.eq(byte)
                yield dut.rx_valid.eq(1)
                yield dut.rx_last.eq(i == len(packet) - 1)
                yield Tick()
            
            yield dut.rx_valid.eq(0)
            yield Tick()
            
            # Check that the airlock is locked
            self.assertEqual((yield dut.status_led), 0)

        sim.add_process(test_process)
        sim.run()

    def test_volume_limit(self):
        dut = SecurityAirlock()
        sim = Simulator(dut)
        dut.LIMIT_95MB = 100 # Override for testing

        def test_process():
            packet = b"short packet"
            for _ in range(10):
                for i, byte in enumerate(packet):
                    yield dut.rx_data.eq(byte)
                    yield dut.rx_valid.eq(1)
                    yield dut.rx_last.eq(i == len(packet) - 1)
                    yield Tick()
            
            yield dut.rx_valid.eq(0)
            yield Tick()

            # Check that the airlock is locked
            self.assertEqual((yield dut.status_led), 0)
        
        sim.add_process(test_process)
        sim.run()

    def test_heartbeat(self):
        dut = SecurityAirlock()
        sim = Simulator(dut)
        dut.HEARTBEAT_TIMEOUT = 10 # Override for testing

        def test_process():
            # Let the watchdog time out
            for _ in range(15):
                yield Tick()
            
            # Check that the airlock is locked
            self.assertEqual((yield dut.status_led), 0)

        sim.add_process(test_process)
        sim.run()

    def test_lock_reset(self):
        dut = SecurityAirlock()
        sim = Simulator(dut)

        def test_process():
            # Lock the airlock
            yield dut.rst_lock.eq(1)
            yield Tick()
            yield dut.rst_lock.eq(0)
            yield Tick()
            self.assertEqual((yield dut.status_led), 1)

            # Trigger a lock
            yield dut.violation_ttl.eq(1)
            yield Tick()
            self.assertEqual((yield dut.status_led), 0)

            # Reset the lock
            yield dut.rst_lock.eq(1)
            yield Tick()
            yield dut.rst_lock.eq(0)
            yield Tick()
            self.assertEqual((yield dut.status_led), 1)

        sim.add_process(test_process)
        sim.run()

if __name__ == "__main__":
    unittest.main()
