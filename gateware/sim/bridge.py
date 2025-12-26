# Copyright (c) 2025 VoidCanary-Lab
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import sys
import os
import time
import socket
import subprocess
import warnings
from amaranth.sim import Simulator, Tick, Settle

# Ensure we can import from the root workspace
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from gateware.src.packet import SecurityAirlock

DEBUG = False

# Suppress Amaranth deprecation warnings for cleaner output
warnings.filterwarnings("ignore", category=DeprecationWarning)

def run_bridge(rx_interface, tx_interface):
    dut = SecurityAirlock()
    sim = Simulator(dut)

    def heartbeat_process():
        while True:
            yield dut.heartbeat_in.eq(~(yield dut.heartbeat_in))
            for _ in range(500000): # 0.5s at 1MHz
                yield Tick()


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
        yield dut.ingress.eq(1) # Default to Ingress (Outside -> Inside) for this bridge
        
        print(f"[*] Listening on {rx_interface}...", flush=True)
        # Ensure interface is in promiscuous mode to capture all traffic
        subprocess.run(["ip", "link", "set", rx_interface, "promisc", "on"], check=False)
        subprocess.run(["ethtool", "-K", rx_interface, "gro", "off"], check=False)

        # Use raw sockets for performance and reliability
        rx_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        rx_socket.bind((rx_interface, 0))
        rx_socket.setblocking(0)

        tx_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        tx_socket.bind((tx_interface, 0))
        
        last_print = time.time()
        print("[*] Bridge loop active.", flush=True)
        while True:
            try:
                raw_bytes = rx_socket.recv(65535)
                print(f"[*] Simulating packet: {len(raw_bytes)} bytes", flush=True)
            except (BlockingIOError, InterruptedError):
                raw_bytes = None
            except Exception as e:
                print(f"[*] Error receiving packet: {e}", flush=True)
                raw_bytes = None

            if raw_bytes:
                    output_buffer = []

                    for i, byte in enumerate(raw_bytes):
                        if DEBUG:
                            print(f"[DEBUG] Byte {i}: {hex(byte)}", flush=True)

                        yield dut.rx_data.eq(byte)
                        yield dut.rx_valid.eq(1)
                        yield dut.rx_last.eq(i == len(raw_bytes) - 1)
                        yield Tick()
                        yield Settle()

                        if DEBUG:
                            tx_v = yield dut.tx_valid
                            led = yield dut.status_led
                            print(f"[DEBUG] State -> TX_Valid: {tx_v}, LED: {led}", flush=True)

                        if (yield dut.tx_valid):
                            output_buffer.append((yield dut.tx_data))

                    yield dut.rx_valid.eq(0)
                    yield Tick()
                    yield Settle()
                    
                    is_locked = (yield dut.status_led) == 0

                    # Check if packet was truncated (Drop or Lock mid-stream)
                    was_truncated = len(output_buffer) < len(raw_bytes)

                    if output_buffer:
                        if is_locked:
                            print(f"[!] FORWARDING TRUNCATED Packet (Locked mid-stream)", flush=True)
                        elif was_truncated:
                            print(f"[!] FORWARDING TRUNCATED Packet (Drop Active)", flush=True)
                        else:
                            print(f"[>] FORWARDING Packet to {tx_interface}", flush=True)
                        tx_socket.send(bytes(output_buffer))
                    else:
                        print(f"[!] DROPPING Packet (Locked: {is_locked})", flush=True)
            
            yield Tick()
            
            if time.time() - last_print > 1:
                print("[*] Bridge heartbeat (waiting for packets)...", flush=True)
                last_print = time.time()

    sim.add_process(simulation_process)
    sim.add_process(heartbeat_process)
    sim.add_process(status_monitor_process)
    sim.add_clock(1e-6)
    sim.run()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--rx", required=True)
    parser.add_argument("--tx", required=True)
    args = parser.parse_args()
    
    print(f"[*] Starting Amaranth Simulation Bridge: {args.rx} -> {args.tx}")
    run_bridge(args.rx, args.tx)