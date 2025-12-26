# Copyright (c) 2025 VoidCanary-Lab
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import time
from scapy.all import sendp, Ether, IP, UDP, Raw

def run_attacker(interface, traffic_type):
    print(f"[*] Sending {traffic_type} traffic on {interface}...")
    
    # Construct a basic packet
    pkt = Ether() / IP(dst="192.168.100.2") / UDP(dport=1234)
    
    if traffic_type == "MALICIOUS":
        # Signature that should be dropped
        pkt = pkt / Raw(load=b"PAYLOAD_MALICIOUS_DATA")
    else:
        # Signature that should pass
        pkt = pkt / Raw(load=b"PAYLOAD_VALID_DATA")

    # Send a burst to ensure capture
    for _ in range(3):
        sendp(pkt, iface=interface, verbose=False)
        time.sleep(0.1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", required=True, help="Network interface to send on")
    parser.add_argument("--type", choices=["MALICIOUS", "VALID"], required=True, help="Traffic profile")
    args = parser.parse_args()
    
    run_attacker(args.interface, args.type)