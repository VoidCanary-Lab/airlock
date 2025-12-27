# gateware/tests/test_attacks3.py
import unittest
import sys
import os
from amaranth.sim import Simulator

# Ensure we can import from the root workspace
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from gateware.src.packet import SecurityAirlock

class TestAdvancedHackerAttacks(unittest.TestCase):
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
        ip += b'\x00\x00' # checksum
        ip += src
        ip += dst
        if ihl > 5:
            ip += bytearray((ihl - 5) * 4)
        return eth + ip + payload

    def build_tcp_packet(self, flags=2, sport=1234, dport=80, seq=0, ack=0, data_offset=5, window=8192, payload=b''):
        # TCP header
        tcp = sport.to_bytes(2, 'big')
        tcp += dport.to_bytes(2, 'big')
        tcp += seq.to_bytes(4, 'big')
        tcp += ack.to_bytes(4, 'big')
        # Data offset, reserved, and flags
        tcp_hdr_len_flags = (data_offset << 12) | flags
        tcp += tcp_hdr_len_flags.to_bytes(2, 'big')
        tcp += window.to_bytes(2, 'big')
        tcp += b'\x00\x00' # checksum
        tcp += b'\x00\x00' # urgent pointer
        if data_offset > 5:
            tcp += bytearray((data_offset - 5) * 4)
        
        return self.build_ip_packet(proto=6, payload=tcp + payload)

# TCP Flag fuzzing
valid_flags = {0x02, 0x12, 0x10, 0x01, 0x11, 0x04, 0x14, 0x18} # SYN, SYN-ACK, ACK, FIN, FIN-ACK, RST, RST-ACK, PSH-ACK
ports_to_test = [22, 80, 443, 3389, 8080, 8443, 1337, 4444, 9000, 10000]

def make_tcp_flag_test(flags, dport):
    def test(self):
        packet = self.build_tcp_packet(flags=flags, dport=dport)
        self.run_attack(packet, expect_pass=False)
    return test

for flags in range(512):
    if flags not in valid_flags:
        for dport in ports_to_test:
            setattr(TestAdvancedHackerAttacks, f'test_tcp_invalid_flags_{flags}_port_{dport}', make_tcp_flag_test(flags, dport))


# TCP Option fuzzing
def make_tcp_option_test(option_kind, option_len):
    def test(self):
        if option_len > 40:
            # Manually craft the packet to bypass the builder's limitations
            options = option_kind.to_bytes(1, 'big')
            if option_len > 1:
                options += option_len.to_bytes(1, 'big')
            if option_len > 2:
                options += bytearray(option_len - 2)
            
            # Create a TCP header with a data offset that is invalid, but will be overridden
            # by the raw packet construction.
            tcp_header = self.build_tcp_packet(data_offset=15, payload=options)
            
            # Now, create the final packet as a raw byte array
            packet = self.build_ip_packet(proto=6, payload=tcp_header)
            self.run_attack(packet, expect_pass=False)
        else:
            if option_len < 2 and option_kind > 1:
                 self.skipTest("Invalid option length for this kind")

            num_words = (option_len + 3) // 4
            data_offset = 5 + num_words

            options = option_kind.to_bytes(1, 'big')
            if option_len > 1:
                options += option_len.to_bytes(1, 'big')
            if option_len > 2:
                options += bytearray(option_len - 2)
            
            options += bytearray(num_words * 4 - option_len)

            packet = self.build_tcp_packet(data_offset=data_offset, payload=options)
            self.run_attack(packet, expect_pass=False)
    return test

for kind in range(256):
    for length in [2, 3, 4, 8, 16, 32, 40, 64, 128, 200, 255]:
        setattr(TestAdvancedHackerAttacks, f'test_tcp_option_kind_{kind}_len_{length}', make_tcp_option_test(kind, length))


# ICMP fuzzing
def make_icmp_test(icmp_type, icmp_code):
    def test(self):
        icmp = icmp_type.to_bytes(1, 'big') + icmp_code.to_bytes(1, 'big') + b'\x00\x00' # checksum
        icmp += b'\x00\x00\x00\x00' # rest of header
        packet = self.build_ip_packet(proto=1, payload=icmp)
        self.run_attack(packet, expect_pass=False)
    return test

for icmp_type in range(256):
    for icmp_code in range(10): # Test 10 codes for each type
        setattr(TestAdvancedHackerAttacks, f'test_icmp_type_{icmp_type}_code_{icmp_code}', make_icmp_test(icmp_type, icmp_code))


if __name__ == "__main__":
    unittest.main()
