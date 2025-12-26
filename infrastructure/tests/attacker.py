# Copyright (c) 2025 VoidCanary-Lab
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import time
from scapy.all import sendp, Ether, IP, UDP, Raw

def run_attacker(interface, traffic_type):
    print(f"[*] Sending {traffic_type} traffic on {interface}...")
    
    if traffic_type == "VALID":
        pkt = Ether() / IP(dst="192.168.100.2") / UDP(dport=1234) / Raw(load="VALID")
    elif traffic_type == "TTL":
        pkt = Ether() / IP(dst="192.168.100.2", ttl=50) / UDP(dport=1234) / Raw(load="TTL")
    elif traffic_type == "PLAINTEXT":
        pkt = Ether() / IP(dst="192.168.100.2") / UDP(dport=1234) / Raw(load="PLAINTEXT")

    # Send a burst to ensure capture
    for _ in range(3):
        sendp(pkt, iface=interface, verbose=False)
        time.sleep(0.1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", required=True, help="Network interface to send on")
    parser.add_argument("--type", choices=["VALID", "TTL", "PLAINTEXT"], required=True, help="Traffic profile")
    args = parser.parse_args()
    
    run_attacker(args.interface, args.type)