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
            packet = bytearray([0x00]*22) + b'\x32' + bytearray([0x00]*10)

            for i, byte in enumerate(packet):
                while not (yield dut.rx_ready):
                    yield Tick()
                yield dut.rx_data.eq(byte)
                yield dut.rx_valid.eq(1)
                yield dut.rx_last.eq(i == len(packet) - 1)
                yield Tick()
            
            yield dut.rx_valid.eq(0)
            yield Tick()
            
            self.assertEqual((yield dut.status_led), 0)

        sim.add_process(test_process)
        sim.run()

    def test_volume_limit(self):
        dut = SecurityAirlock()
        sim = Simulator(dut)
        dut.LIMIT_95MB = 100 

        def test_process():
            packet = b"short packet"
            for _ in range(10):
                for i, byte in enumerate(packet):
                    while not (yield dut.rx_ready):
                        yield Tick()
                    yield dut.rx_data.eq(byte)
                    yield dut.rx_valid.eq(1)
                    yield dut.rx_last.eq(i == len(packet) - 1)
                    yield Tick()
            
            yield dut.rx_valid.eq(0)
            yield Tick()

            self.assertEqual((yield dut.status_led), 0)
        
        sim.add_process(test_process)
        sim.run()

    def test_heartbeat(self):
        dut = SecurityAirlock()
        sim = Simulator(dut)
        dut.HEARTBEAT_TIMEOUT = 10

        def test_process():
            for _ in range(15):
                yield Tick()
            
            self.assertEqual((yield dut.status_led), 0)

        sim.add_process(test_process)
        sim.run()

    def test_plaintext_check(self):
        dut = SecurityAirlock()
        sim = Simulator(dut)

        def test_process():
            # Packet with ASCII payload
            packet = bytearray([0x00]*43) + b"this is a test of the plaintext check"

            for i, byte in enumerate(packet):
                while not (yield dut.rx_ready):
                    yield Tick()
                yield dut.rx_data.eq(byte)
                yield dut.rx_valid.eq(1)
                yield dut.rx_last.eq(i == len(packet) - 1)
                yield Tick()
            
            yield dut.rx_valid.eq(0)
            yield Tick()
            
            self.assertEqual((yield dut.status_led), 0)

        sim.add_process(test_process)
        sim.run()

    def test_lock_reset(self):
        dut = SecurityAirlock()
        sim = Simulator(dut)

        def test_process():
            yield dut.rst_lock.eq(1)
            yield Tick()
            yield dut.rst_lock.eq(0)
            yield Tick()
            self.assertEqual((yield dut.status_led), 1)

            yield dut.violation_ttl.eq(1)
            yield Tick()
            self.assertEqual((yield dut.status_led), 0)

            yield dut.rst_lock.eq(1)
            yield Tick()
            yield dut.rst_lock.eq(0)
            yield Tick()
            self.assertEqual((yield dut.status_led), 1)

        sim.add_process(test_process)
        sim.run()

if __name__ == "__main__":
    unittest.main()
