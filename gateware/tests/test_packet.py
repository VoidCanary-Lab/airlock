# Copyright (c) 2025 VoidCanary-Lab
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest
from amaranth.sim import Simulator
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from gateware.src.packet import SecurityAirlock

class TestSecurityAirlock(unittest.TestCase):
    def test_ttl_check(self):
        dut = SecurityAirlock()
        sim = Simulator(dut)
        sim.add_clock(1e-6)

        async def test_process(ctx):
            ctx.set(dut.tx_ready, 1)
            # Construct a valid IPv4 packet with low TTL (EtherType 0x0800, TTL at byte 22)
            packet = bytearray([0x00]*12) + b'\x08\x00' + \
                     b'\x45' + bytearray([0x00]*7) + b'\x32' + bytearray([0x00]*10)

            # Send twice: First packet clears flush_state, second triggers violation
            for _ in range(2):
                for i, byte in enumerate(packet):
                    while not ctx.get(dut.rx_ready):
                        await ctx.tick()
                    ctx.set(dut.rx_data, byte)
                    ctx.set(dut.rx_valid, 1)
                    ctx.set(dut.rx_last, i == len(packet) - 1)
                    await ctx.tick()
            
            ctx.set(dut.rx_valid, 0)
            await ctx.tick()
            
            self.assertEqual(ctx.get(dut.status_led), 0)

        sim.add_testbench(test_process)
        sim.run()

    def test_volume_limit(self):
        # Set a small volume limit for testing (100 bytes)
        dut = SecurityAirlock(volume_limit=100)
        sim = Simulator(dut)
        sim.add_clock(1e-6)

        async def test_process(ctx):
            ctx.set(dut.tx_ready, 1)
            # Ensure first byte is even (Unicast) so violation triggers a Lock
            packet = b"\x02short packet"
            for _ in range(10):
                for i, byte in enumerate(packet):
                    while not ctx.get(dut.rx_ready):
                        await ctx.tick()
                    ctx.set(dut.rx_data, byte)
                    ctx.set(dut.rx_valid, 1)
                    ctx.set(dut.rx_last, i == len(packet) - 1)
                    await ctx.tick()
            
            ctx.set(dut.rx_valid, 0)
            await ctx.tick()

            self.assertEqual(ctx.get(dut.status_led), 0)
        
        sim.add_testbench(test_process)
        sim.run()

    def test_heartbeat(self):
        # Set a small heartbeat timeout for testing (10 cycles)
        dut = SecurityAirlock(heartbeat_timeout=10)
        sim = Simulator(dut)
        sim.add_clock(1e-6)

        async def test_process(ctx):
            ctx.set(dut.tx_ready, 1)
            for _ in range(15):
                await ctx.tick()
            
            self.assertEqual(ctx.get(dut.status_led), 0)

        sim.add_testbench(test_process)
        sim.run()

    def test_plaintext_check(self):
        dut = SecurityAirlock()
        sim = Simulator(dut)
        sim.add_clock(1e-6)

        async def test_process(ctx):
            ctx.set(dut.tx_ready, 1)
            # Packet with ASCII payload
            eth_header = bytearray([0x00]*12) + b'\x08\x00'
            ip_header = b'\x45' + bytearray([0x00]*19)
            payload = b"this is a test of the plaintext check"
            packet = eth_header + ip_header + payload

            # Send twice: First packet clears flush_state, second triggers violation
            for _ in range(2):
                for i, byte in enumerate(packet):
                    while not ctx.get(dut.rx_ready):
                        await ctx.tick()
                    ctx.set(dut.rx_data, byte)
                    ctx.set(dut.rx_valid, 1)
                    ctx.set(dut.rx_last, i == len(packet) - 1)
                    await ctx.tick()
            
            ctx.set(dut.rx_valid, 0)
            await ctx.tick()
            
            self.assertEqual(ctx.get(dut.status_led), 0)

        sim.add_testbench(test_process)
        sim.run()

    def test_lock_reset(self):
        dut = SecurityAirlock()
        sim = Simulator(dut)
        sim.add_clock(1e-6)

        async def test_process(ctx):
            ctx.set(dut.tx_ready, 1)
            ctx.set(dut.rst_lock, 1)
            await ctx.tick()
            ctx.set(dut.rst_lock, 0)
            await ctx.tick()
            self.assertEqual(ctx.get(dut.status_led), 1)

            # Trigger violation via packet (TTL violation)
            packet = bytearray([0x00]*12) + b'\x08\x00' + \
                     b'\x45' + bytearray([0x00]*7) + b'\x32' + bytearray([0x00]*10)
            
            # Send twice: First packet clears flush_state, second triggers violation
            for _ in range(2):
                for i, byte in enumerate(packet):
                    while not ctx.get(dut.rx_ready):
                        await ctx.tick()
                    ctx.set(dut.rx_data, byte)
                    ctx.set(dut.rx_valid, 1)
                    ctx.set(dut.rx_last, i == len(packet) - 1)
                    await ctx.tick()
            
            ctx.set(dut.rx_valid, 0)
            await ctx.tick()
            self.assertEqual(ctx.get(dut.status_led), 0)

            ctx.set(dut.rst_lock, 1)
            await ctx.tick()
            ctx.set(dut.rst_lock, 0)
            await ctx.tick()
            self.assertEqual(ctx.get(dut.status_led), 1)

        sim.add_testbench(test_process)
        sim.run()

    def test_trailing_garbage(self):
        dut = SecurityAirlock()
        sim = Simulator(dut)
        sim.add_clock(1e-6)

        async def test_process(ctx):
            ctx.set(dut.tx_ready, 1)
            
            # Allow one tick for flush_state to clear (since rx_valid is 0 initially)
            await ctx.tick()

            # IP Packet: 20 bytes header, 10 bytes payload. Total IP Len = 30.
            # Eth Header (14) + IP (20) + Payload (10) = 44 bytes.
            # Min frame 64. So we pad to 64.
            
            # Construct packet
            # IP Len = 30 (0x001E)
            ip_len_bytes = b'\x00\x1E'
            
            packet = bytearray([0x00]*12) + b'\x08\x00' # Eth
            packet += b'\x45\x00' + ip_len_bytes # IP start
            packet += bytearray([0x00]*16) # Rest of IP header
            packet += bytearray([0xAA]*10) # Payload
            packet += bytearray([0x00]*20) # Padding to 64
            
            # Add 1 byte of garbage (Byte 65) - This should trigger violation
            packet += b'\xFF'
            
            for i, byte in enumerate(packet):
                while not ctx.get(dut.rx_ready):
                    await ctx.tick()
                ctx.set(dut.rx_data, byte)
                ctx.set(dut.rx_valid, 1)
                ctx.set(dut.rx_last, i == len(packet) - 1)
                await ctx.tick()
            
            self.assertEqual(ctx.get(dut.status_led), 0)

        sim.add_testbench(test_process)
        sim.run()

if __name__ == "__main__":
    unittest.main()
