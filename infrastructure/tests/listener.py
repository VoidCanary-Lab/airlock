# Copyright (c) 2025 VoidCanary-Lab
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
from scapy.all import sniff

def packet_callback(pkt):
    # Just print the payload for the CI grep check
    if pkt.haslayer(Raw):
        print(pkt[Raw].load.decode('utf-8', errors='ignore'))
    
    # Ensure output is flushed immediately for logs
    sys.stdout.flush()

if __name__ == "__main__":
    print("[*] Listening for traffic in Vault...")
    # Sniff packets. In the test environment, this runs until killed or timeout.
    # We set a timeout to allow the script to exit naturally in some test cases.
    sniff(prn=packet_callback, store=False, timeout=15)