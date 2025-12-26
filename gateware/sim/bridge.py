# Copyright (c) 2025 VoidCanary-Lab
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import sys
import os
from scapy.all import sniff, sendp, Ether
from amaranth.sim import Simulator

# Ensure we can import from the root workspace
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from gateware.src.packet import EthernetFilter

# This function mimics the FPGA hardware loop
def run_bridge(rx_interface, tx_interface):
    dut = EthernetFilter()
    sim = Simulator(dut)
    
    # This process handles the packet flow
    def simulation_process():
        # Initialize
        yield dut.rx_valid.eq(0)
        
        def process_packet(pkt):
            raw_bytes = bytes(pkt)
            print(f"[*] Simulating packet: {len(raw_bytes)} bytes")
            
            output_buffer = []

            # --- AMARANTH SIMULATION ---
            # 1. Present each byte to the filter
            for i, byte in enumerate(raw_bytes):
                yield dut.rx_data.eq(byte)
                yield dut.rx_valid.eq(1)
                yield dut.rx_last.eq(i == len(raw_bytes) - 1)
                
                # Wait for the filter to be ready
                while (yield dut.rx_ready) == 0:
                    yield
                
                # If the filter produces output, capture it
                if (yield dut.tx_valid):
                    output_buffer.append((yield dut.tx_data))

                yield
            
            # 2. De-assert valid
            yield dut.rx_valid.eq(0)
            
            # 3. Check if the packet was forwarded
            if output_buffer:
                print(f"[>] FORWARDING Packet to {tx_interface}")
                sendp(Ether(b"".join([x.to_bytes(1, 'little') for x in output_buffer])), iface=tx_interface, verbose=False)
            else:
                print(f"[!] DROPPING Packet")

        # Sniff on the RX interface and process every packet
        sniff(iface=rx_interface, prn=process_packet, store=False)

    sim.add_process(simulation_process)
    sim.run()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--rx", required=True)
    parser.add_argument("--tx", required=True)
    args = parser.parse_args()
    
    print(f"[*] Starting Amaranth Simulation Bridge: {args.rx} -> {args.tx}")
    run_bridge(args.rx, args.tx)