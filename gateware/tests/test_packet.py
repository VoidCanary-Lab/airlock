# Copyright (c) 2025 VoidCanary-Lab
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest
from amaranth.sim import Simulator, Tick
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from gateware.src.packet import EthernetFilter

class TestEthernetFilter(unittest.TestCase):
    def test_filter_logic(self):
        dut = EthernetFilter()
        sim = Simulator(dut)

        def test_process():
            # --- Test 1: Send a VALID packet ---
            valid_packet = b"PAYLOAD_VALID_DATA"
            
            # Present each byte of the valid packet
            for i, byte in enumerate(valid_packet):
                yield dut.rx_data.eq(byte)
                yield dut.rx_valid.eq(1)
                yield dut.rx_last.eq(i == len(valid_packet) - 1)
                yield Tick()
            
            yield dut.rx_valid.eq(0)
            yield Tick()
            
            # Check that the packet was forwarded
            self.assertEqual((yield dut.tx_valid), 1)

            # --- Test 2: Send a MALICIOUS packet ---
            malicious_packet = b"PAYLOAD_MALICIOUS_DATA"
            
            # Present each byte of the malicious packet
            for i, byte in enumerate(malicious_packet):
                yield dut.rx_data.eq(byte)
                yield dut.rx_valid.eq(1)
                yield dut.rx_last.eq(i == len(malicious_packet) - 1)
                yield Tick()

            yield dut.rx_valid.eq(0)
            yield Tick()
            
            # Check that the packet was dropped
            self.assertEqual((yield dut.tx_valid), 0)

        sim.add_process(test_process)
        sim.run()

if __name__ == "__main__":
    unittest.main()
