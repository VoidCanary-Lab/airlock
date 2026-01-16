# Airlock

![VoidCanary-Lab](assets/voidcanary-lab.jpeg)

![CI Status](https://github.com/VoidCanary-Lab/airlock/actions/workflows/gateware-verify.yml/badge.svg)
![License](https://img.shields.io/badge/License-GPLv3-blue.svg)

**Correct-by-construction network security using Amaranth HDL.**

## Overview
Airlock is an FPGA-based hardware security research project. It moves security policy enforcement from the OS Kernel (Software) to the Gateware (Hardware).

By defining packet processing logic in Amaranth HDL, Airlock allows us to use **Bounded Model Checking (BMC)** to mathematically prove that security rules—like volume limits or protocol checks—cannot be bypassed, regardless of OS vulnerabilities.

## Why Airlock? (The Motivation)
Traditional firewalls operate in software (Kernel/OS). This architecture has a fundamental flaw: **The firewall shares the same physical resources (CPU/RAM) as the attack surface.** If the OS kernel is compromised (e.g., a Zero-Day in the TCP/IP stack), the firewall is bypassed instantly.

**Airlock is the answer to "Kernel-Bypass" attacks.**
By moving the security logic into an FPGA (Field-Programmable Gate Array), we achieve:

1.  **Physical Isolation:** The filtering logic runs on dedicated silicon, physically separate from the Gateway OS.
2.  **Zero-Day Immunity:** A bug in the Linux Kernel cannot crash the FPGA. The gateware keeps filtering even if the host OS panics.
3.  **Mathematical Certainty:** Unlike C/C++ code, our hardware logic is formally verified. We don't just *think* it works; we *prove* it drops the packet.

**This is not just a faster firewall. It is a different state of matter for network security.**

## Reference Topology
The FPGA acts as a physical gatekeeper. The filtering logic operates at wire speed, ensuring only valid, safe traffic reaches the internal gateway.

```text
ZONE 0: HOSTILE INTERNET        ZONE 2: THE AIRLOCK (FPGA)     ZONE 3: GATEWAY VM
+--------------------------+    +---------------------------+    +--------------+
|       USER TRAFFIC       |    |                           |    |              |
| +---------------------+  |    |   [ SECURITY STATE ]      |    |              |
| |(Encrypted WireGuard)|  |    |   (Internal Watchdog)     |    |              |
| +-----+---------------+  |    |                           |    |              |
+-------|------------------+    |                           |    |    DEBIAN    |
        |                       |                           |    |              |
        |                       |   +--------+              |    |              |
        | ZONE 1: FW            |   | STATUS |              |    |              |
+-------|------------------+    |   | ON/OFF |   NO OS      |    |              |
|       | DEBIAN(IPTABLES) |    |   +----+---+   NO KERNEL  |    |              |
|       |                  |    |        |     0-DAY IMMUNE |    |              |
|       | (Data Flow)      |    |        v                  |    |              |
|       |                  |IPv4|    +-------+              |IPv4| +----------+ |
|       +----------------------------| DATA  |<------------------| | WireGuard| |
|                          |UDP |    |FILTER |(Check: TTL,  |UDP | | Encrypted| |    
|                          |HTTPS|   +-------+ Size, Speed) |HTTPS|+-+--------+ |
+--------------------------+    +---------------------------+    |   |          |
                                                                 +---|----------+
                                                                     |
                                                     (Decrypted IP)  | 
                                                                     ^
ZONE 5: INTERNAL SERVICES    ZONE 4: SECURITY STACK (The Filter)     |
+---------------------+     +----------------------------------------|-+
|                     |     |                                        | |
|                     |     |   +--------------+   +-------------+   | |
| [ SENSITIVE APPS ]  |     |   |   IPTABLES   |-->|   PI-HOLE   |   | |
| - Database          |     |   |  (Firewall)  |   |             | --+ |
| - Git Repos         |-------->|              |   +------+------+     |
|                     |     |   +--------------+                       |
|                     |     |                      +-------------+     |
|                     |     |     DEBIAN           |     MDR     |     |
|                     |     |                      |(Wazuh-agent)|     |
|                     |     |                      +-------------+     |
+---------------------+     +------------------------------------------+
```


## Key Capabilities

The Silicon Shield (Anti-Reconnaissance): Airlock enforces strict TTL floors and protocol compliance at the byte level. Scanners like nmap see a black hole. We don't just drop packets; we erase their existence.

Volumetric Lockdown: Automatically severs connections after specific data thresholds are exceeded, preventing data exfiltration even if encryption keys are stolen.

The Logic Lock (Formal Verification): We use SymbiYosys to prove our code. Example Assertion: "It is mathematically impossible for a packet with Source IP X to appear at Output Y."

The Kill Switch (Hardware Watchdog): A dead-man's switch for your network. The FPGA monitors the host's "heartbeat." If the host is compromised or crashes, the FPGA physically cuts the line. No software can override this.

## Quick Start (Simulation)

You can simulate the hardware logic on a standard Linux machine using the Python Bridge. This creates a virtual TAP interface that passes traffic through the Amaranth gateware code.

Bash

```
# 1. Install dependencies
pip install -r requirements.txt
```

## 2. Run the Virtual Bridge (Requires Root for TAP creation)
```
sudo python3 gateware/sim/bridge.py --rx tap0 --tx tap1
```

## 3.Verification


To execute the formal proofs and verify the state machine properties:

Bash

```
cd gateware/verify
python3 proof.py
```

## 4.License

Copyright (c) 2025 VoidCanary-Lab. Licensed under the GNU General Public License v3.0.