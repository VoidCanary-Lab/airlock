# gateware/tests/test_attacks2.py
import unittest
import sys
import os
from amaranth.sim import Simulator

# Ensure we can import from the root workspace
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from gateware.src.packet import SecurityAirlock

class TestGeneratedHackerAttacks(unittest.TestCase):
    def run_attack(self, packet_bytes, expect_pass=False):
        dut = SecurityAirlock()
        sim = Simulator(dut)
        sim.add_clock(1e-6)

        async def test_process(ctx):
            ctx.set(dut.tx_ready, 1)
            # Default to Ingress (Secure)
            ctx.set(dut.egress_mode, 0)
            await ctx.tick()
            
            # Send packet
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
                self.assertEqual(status, 1, f"Packet blocked but should have passed. Data: {packet_bytes.hex()}")
            else:
                self.assertEqual(status, 0, f"Packet passed but should have been blocked. Data: {packet_bytes.hex()}")

        sim.add_testbench(test_process)
        sim.run()

    def build_ip_packet(self, eth_type=0x0800, ip_ver=4, ihl=5, total_len=None, ttl=64, proto=6, src=b'\x01\x02\x03\x04', dst=b'\x05\x06\x07\x08', payload=b'', flags_offset=0):
        if total_len is None:
            total_len = 20 + len(payload)
        
        eth = bytearray(12) + eth_type.to_bytes(2, 'big')
        ver_ihl = (ip_ver << 4) + ihl
        ip = bytearray([ver_ihl, 0x00])
        ip += total_len.to_bytes(2, 'big')
        ip += b'\x00\x00'
        ip += flags_offset.to_bytes(2, 'big')
        ip += bytearray([ttl, proto])
        ip += b'\x00\x00'
        ip += src
        ip += dst
        if ihl > 5:
            ip += bytearray((ihl - 5) * 4)
        return eth + ip + payload

def make_ttl_test(ttl_val):
    def test(self):
        packet = self.build_ip_packet(ttl=ttl_val)
        self.run_attack(packet, expect_pass=False)
    return test

for i in range(60):
    setattr(TestGeneratedHackerAttacks, f'test_generated_ttl_{i}', make_ttl_test(i))

def make_proto_test(proto_val):
    def test(self):
        packet = self.build_ip_packet(proto=proto_val)
        self.run_attack(packet, expect_pass=False)
    return test

allowed_protos = {6, 17}
for i in range(256):
    if i not in allowed_protos:
        setattr(TestGeneratedHackerAttacks, f'test_generated_proto_{i}', make_proto_test(i))

def make_ihl_test(ihl_val):
    def test(self):
        packet = self.build_ip_packet(ihl=ihl_val)
        self.run_attack(packet, expect_pass=False)
    return test

for i in range(6, 16):
    setattr(TestGeneratedHackerAttacks, f'test_generated_ihl_{i}', make_ihl_test(i))

def make_payload_test(payload, name, expect_pass=False):
    def test(self):
        packet = self.build_ip_packet(payload=payload)
        self.run_attack(packet, expect_pass=expect_pass)
    return test

# 400 tests of varying printable character lengths
for i in range(128, 528):
    payload = ('P' * i).encode('ascii')
    setattr(TestGeneratedHackerAttacks, f'test_payload_printable_len_{i}', make_payload_test(payload, f'printable_len_{i}'))

def make_arp_op_test(op_val):
    def test(self):
        # EtherType for ARP is 0x0806. Opcode is at bytes 6-7 of the ARP packet.
        packet = bytearray(12) + (0x0806).to_bytes(2, 'big') + bytearray(6) + op_val.to_bytes(2, 'big') + bytearray(20) + bytearray(18)
        self.run_attack(packet, expect_pass=False)
    return test

for i in range(3, 256):
    setattr(TestGeneratedHackerAttacks, f'test_arp_op_fuzz_{i}', make_arp_op_test(i))


if __name__ == "__main__":
    unittest.main()