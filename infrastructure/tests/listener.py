# Copyright (c) 2025 VoidCanary-Lab
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import json
import base64
from scapy.all import sniff, Raw

def packet_callback(pkt):
    # Just print the payload for the CI grep check
    if pkt.haslayer(Raw):
        payload = pkt[Raw].load.decode('utf-8', errors='ignore')
        print(payload)

        # Attempt to decode base64 content in JSON bodies (common in Azure Agent)
        try:
            if "\r\n\r\n" in payload:
                _, body = payload.split("\r\n\r\n", 1)
                data = json.loads(body)
                if "content" in data:
                    print("\n[+] Decoded Content:\n" + base64.b64decode(data["content"]).decode('utf-8', errors='ignore') + "\n")
        except Exception:
            pass
    
    # Ensure output is flushed immediately for logs
    sys.stdout.flush()

if __name__ == "__main__":
    print("[*] Listening for traffic in Vault...")
    # Sniff packets. In the test environment, this runs until killed or timeout.
    # We set a timeout to allow the script to exit naturally in some test cases.
    sniff(iface="veth_out_peer", prn=packet_callback, store=False, timeout=60, filter="not port 443")