# Airlock

![VoidCanary-Lab](assets/voidcanary-lab.jpeg)

![CI Status](https://github.com/VoidCanary-Lab/airlock/actions/workflows/gateware-verify.yml/badge.svg)
![License](https://img.shields.io/badge/License-GPLv3-blue.svg)

**Experimental research into formal verification of network state machines using Amaranth HDL.**

## Abstract
Airlock is a gateware research project exploring the application of Python-based Hardware Description Languages (HDL) to create correct-by-construction packet filtering logic. 

The primary goal is to demonstrate how Bounded Model Checking (BMC) can be used to mathematically prove that specific ingress traffic patterns are rejected before they reach the Operating System kernel.

## Architecture

This project implements a "Virtual Bridge" for development, allowing hardware logic to be simulated and verified against real network traffic in a userspace environment.

```text
[ Network Source ] --(TAP)--> [ Amaranth Gateware ] --(TAP)--> [ Isolated Environment ]
       |                              ^                                   |
       |                              |                                   |
    (Unverified)               (Formally Verified)                     (Verified)
```

### Repository Structure
 * `gateware/`: Core Amaranth HDL source code and simulation definitions.
 * `infrastructure/`: Infrastructure-as-Code (Terraform/Ansible) for the test bench topology.
 * `verify/`: Formal proofs and assertions (SymbiYosys).

### Getting Started (Simulation)
This project requires Python 3.10+ and the Amaranth toolchain.
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the Virtual Bridge (Requires Root for TAP creation)
sudo python3 gateware/sim/bridge.py --rx tap0 --tx tap1
```

### Formal Verification
To run the formal proofs against the gateware logic:
```bash
cd gateware/verify
python3 proof.py
```

## License
Copyright (c) 2025 VoidCanary-Lab.
This project is licensed under the GNU General Public License v3.0.
