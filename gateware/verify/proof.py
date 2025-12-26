# Copyright (c) 2025 VoidCanary-Lab
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import os
from amaranth import *
from amaranth.sim import Simulator
from amaranth.back import verilog
from amaranth.formal import *

# Ensure we can import from the root workspace
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from gateware.src.packet import EthernetFilter

class FormalProof(Elaboratable):
    def elaborate(self, platform):
        m = Module()
        m.submodules.dut = dut = EthernetFilter()

        # --- Formal Properties ---

        # 1. Main Safety Property: If a packet is marked as malicious, 
        #    it must never be sent to the output.
        m.d.comb += Assert(~(dut.is_malicious & dut.tx_valid))
        
        # 2. Liveness Property: Ensure we can actually detect a malicious packet.
        #    This is a "cover" statement, asking the solver to find a path
        #    to this state. It proves the malicious detection logic is reachable.
        m.d.comb += Cover(dut.is_malicious)

        return m

if __name__ == "__main__":
    # To run this proof, you need SymbiYosys. The CI workflow handles this.
    # Local execution: sby -f proof.sby
    
    # We will generate the necessary files for SymbiYosys
    proof = FormalProof()
    
    # Generate Verilog
    with open("ethernet_filter_formal.v", "w") as f:
        f.write(verilog.convert(proof, ports=[]))
        
    # Generate SBY config
    with open("proof.sby", "w") as f:
        f.write("""
[tasks]
prove
cover

[options]
mode bmc
depth 20

[engines]
smtbmc

[script]
read_verilog -formal ethernet_filter_formal.v
prep -top proof

[files]
ethernet_filter_formal.v
""")

    print("[*] Generated SymbiYosys files (proof.sby, ethernet_filter_formal.v)")
    print("[*] To run verification locally: sby -f proof.sby")