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
            # Construct a valid IPv4 packet with low TTL (EtherType 0x0800, TTL at byte 22)
            packet = bytearray([0x00]*12) + b'\x08\x00' + \
                     b'\x45' + bytearray([0x00]*7) + b'\x32' + bytearray([0x00]*10)

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
        # Set a small volume limit for testing (100 bytes)
        dut = SecurityAirlock(volume_limit=100)
        sim = Simulator(dut)

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
        # Set a small heartbeat timeout for testing (10 cycles)
        dut = SecurityAirlock(heartbeat_timeout=10)
        sim = Simulator(dut)

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
            eth_header = bytearray([0x00]*12) + b'\x08\x00'
            ip_header = b'\x45' + bytearray([0x00]*19)
            payload = b"this is a test of the plaintext check"
            packet = eth_header + ip_header + payload

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

            # Trigger violation via packet (TTL violation)
            packet = bytearray([0x00]*12) + b'\x08\x00' + \
                     b'\x45' + bytearray([0x00]*7) + b'\x32' + bytearray([0x00]*10)
            
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

            yield dut.rst_lock.eq(1)
            yield Tick()
            yield dut.rst_lock.eq(0)
            yield Tick()
            self.assertEqual((yield dut.status_led), 1)

        sim.add_process(test_process)
        sim.run()

if __name__ == "__main__":
    unittest.main()
