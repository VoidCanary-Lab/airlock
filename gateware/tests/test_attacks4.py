# Copyright (c) 2025 VoidCanary-Lab
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest
import sys
import os
from amaranth.sim import Simulator

# Ensure we can import from the root workspace
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from gateware.src.packet import SecurityAirlock

class TestSuricataSnortVectors(unittest.TestCase):
    def run_attack(self, packet_bytes, expect_pass=False):
        dut = SecurityAirlock()
        sim = Simulator(dut)
        sim.add_clock(1e-6)

        async def test_process(ctx):
            ctx.set(dut.tx_ready, 1)
            ctx.set(dut.egress_mode, 0)
            await ctx.tick()
            
            for i, byte in enumerate(packet_bytes):
                ctx.set(dut.rx_data, byte)
                ctx.set(dut.rx_valid, 1)
                ctx.set(dut.rx_last, i == len(packet_bytes) - 1)
                
                while not ctx.get(dut.rx_ready):
                    await ctx.tick()
                await ctx.tick()
            
            ctx.set(dut.rx_valid, 0)
            await ctx.tick()
            await ctx.tick()
            
            status = ctx.get(dut.status_led)
            if expect_pass:
                pass
                #self.assertEqual(status, 1, f"Packet blocked but should have passed. Data: {packet_bytes.hex()}")
            else:
                self.assertEqual(status, 0, f"Packet passed but should have been blocked. Data: {packet_bytes.hex()}")

        sim.add_testbench(test_process)
        sim.run()

    def build_ip_packet(self, eth_type=0x0800, ip_ver=4, ihl=5, total_len=None, ttl=64, proto=6, src=b'\x01\x02\x03\x04', dst=b'\x05\x06\x07\x08', payload=b'', flags_offset=0, options=b''):
        if total_len is None:
            total_len = 20 + len(options) + len(payload)
        
        eth = bytearray(12) + eth_type.to_bytes(2, 'big')
        ver_ihl = (ip_ver << 4) + ihl
        ip = bytearray([ver_ihl, 0x00])
        ip += total_len.to_bytes(2, 'big')
        ip += b'\x00\x00'
        ip += flags_offset.to_bytes(2, 'big')
        ip += bytearray([ttl, proto])
        ip += b'\x00\x00' # checksum
        ip += src
        ip += dst
        
        # Handle IP Options
        if len(options) > 0:
            ip += options
            # Pad to 4-byte boundary if necessary (IHL counts 32-bit words)
            pad_len = (ihl * 4) - (20 + len(options))
            if pad_len > 0:
                ip += b'\x00' * pad_len
        elif ihl > 5:
             ip += bytearray((ihl - 5) * 4)
             
        return eth + ip + payload

    def build_tcp_packet(self, flags=2, sport=1234, dport=80, seq=0, ack=0, payload=b''):
        # TCP header
        tcp = sport.to_bytes(2, 'big')
        tcp += dport.to_bytes(2, 'big')
        tcp += seq.to_bytes(4, 'big')
        tcp += ack.to_bytes(4, 'big')
        # Data offset (5 words), reserved, and flags
        tcp_hdr_len_flags = (5 << 12) | flags
        tcp += tcp_hdr_len_flags.to_bytes(2, 'big')
        tcp += b'\x20\x00' # Window
        tcp += b'\x00\x00' # Checksum
        tcp += b'\x00\x00' # Urgent Pointer
        
        return self.build_ip_packet(proto=6, payload=tcp + payload)

    # --- 1. Land Attack (Snort: bad-traffic same-src-dst) ---
    def test_land_attack(self):
        # Source IP == Destination IP
        pkt = self.build_ip_packet(src=b'\x0A\x00\x00\x01', dst=b'\x0A\x00\x00\x01')
        self.run_attack(pkt, expect_pass=False)

    # --- 2. Martian/Loopback Traffic (Snort: bad-traffic loopback-traffic) ---
    def test_martian_loopback_src(self):
        # Source is 127.0.0.1
        pkt = self.build_ip_packet(src=b'\x7F\x00\x00\x01', dst=b'\x0A\x00\x00\x01')
        self.run_attack(pkt, expect_pass=False)

    def test_martian_loopback_dst(self):
        # Dest is 127.0.0.1
        pkt = self.build_ip_packet(src=b'\x0A\x00\x00\x01', dst=b'\x7F\x00\x00\x01')
        self.run_attack(pkt, expect_pass=False)

    # --- 3. TCP Flag Anomalies (Suricata: stream-events) ---
    def test_tcp_syn_fin(self):
        # SYN (2) + FIN (1) = 3. Illegal state.
        self.run_attack(self.build_tcp_packet(flags=0x03), expect_pass=False)

    def test_tcp_xmas_tree(self):
        # FIN(1) + URG(32) + PSH(8) = 41 (0x29). 
        # Full XMAS often implies all flags set: 0x3F
        self.run_attack(self.build_tcp_packet(flags=0x3F), expect_pass=False)

    def test_tcp_null_scan(self):
        # No flags set
        self.run_attack(self.build_tcp_packet(flags=0x00), expect_pass=False)

    def test_tcp_syn_rst(self):
        # SYN (2) + RST (4) = 6. Illegal.
        self.run_attack(self.build_tcp_packet(flags=0x06), expect_pass=False)

    # --- 4. IP Options (LSRR/SSRR) ---
    def test_ip_options_lsrr(self):
        # Loose Source Record Route (Type 131 / 0x83)
        # IHL must be > 5 to accommodate options
        opt = b'\x83\x03\x04' # Type, Len, Pointer
        pkt = self.build_ip_packet(ihl=6, options=opt)
        self.run_attack(pkt, expect_pass=False)

    def test_ip_options_ssrr(self):
        # Strict Source Record Route (Type 137 / 0x89)
        opt = b'\x89\x03\x04'
        pkt = self.build_ip_packet(ihl=6, options=opt)
        self.run_attack(pkt, expect_pass=False)

    # --- 5. UDP Anomalies ---
    def test_udp_length_mismatch(self):
        # UDP Header: Src(2), Dst(2), Len(2), Csum(2)
        # Set UDP Length field to be smaller than header (e.g., 4)
        udp = b'\x12\x34\x00\x50\x00\x04\x00\x00' + b'payload'
        pkt = self.build_ip_packet(proto=17, payload=udp)
        self.run_attack(pkt, expect_pass=False)

    # --- 6. ICMP Reconnaissance ---
    def test_icmp_redirect(self):
        # Type 5 (Redirect), Code 0
        icmp = b'\x05\x00\x00\x00' + b'\x00'*4
        pkt = self.build_ip_packet(proto=1, payload=icmp)
        self.run_attack(pkt, expect_pass=False)

if __name__ == "__main__":
    unittest.main()