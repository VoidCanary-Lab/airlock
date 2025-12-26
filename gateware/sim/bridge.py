# Copyright (c) 2025 VoidCanary-Lab
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import sys
import os
import time
from scapy.all import sniff, sendp, Ether
from amaranth.sim import Simulator, Tick

# Ensure we can import from the root workspace
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from gateware.src.packet import SecurityAirlock

def run_bridge(rx_interface, tx_interface):
    dut = SecurityAirlock()
    sim = Simulator(dut)

    def heartbeat_process():
        while True:
            yield dut.heartbeat_in.eq(~(yield dut.heartbeat_in))
            yield Tick()
            time.sleep(0.5)

    def status_monitor_process():
        led_status = "ON"
        while True:
            if (yield dut.status_led) == 0 and led_status == "ON":
                print("[!] Status LED is OFF. Airlock is locked.")
                led_status = "OFF"
            elif (yield dut.status_led) == 1 and led_status == "OFF":
                print("[*] Status LED is ON. Traffic is flowing.")
                led_status = "ON"
            yield Tick()

    def simulation_process():
        yield dut.rx_valid.eq(0)
        
        def process_packet(pkt):
            raw_bytes = bytes(pkt)
            print(f"[*] Simulating packet: {len(raw_bytes)} bytes")
            
            output_buffer = []

            for i, byte in enumerate(raw_bytes):
                yield dut.rx_data.eq(byte)
                yield dut.rx_valid.eq(1)
                yield dut.rx_last.eq(i == len(raw_bytes) - 1)
                yield Tick()

                if (yield dut.tx_valid):
                    output_buffer.append((yield dut.tx_data))

            yield dut.rx_valid.eq(0)
            yield Tick()
            
            if output_buffer:
                print(f"[>] FORWARDING Packet to {tx_interface}")
                sendp(Ether(b"".join([x.to_bytes(1, 'little') for x in output_buffer])), iface=tx_interface, verbose=False)
            else:
                print(f"[!] DROPPING Packet")

        sniff(iface=rx_interface, prn=process_packet, store=False)

    sim.add_process(simulation_process)
    sim.add_process(heartbeat_process)
    sim.add_process(status_monitor_process)
    sim.run()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--rx", required=True)
    parser.add_argument("--tx", required=True)
    args = parser.parse_args()
    
    print(f"[*] Starting Amaranth Simulation Bridge: {args.rx} -> {args.tx}")
    run_bridge(args.rx, args.tx)