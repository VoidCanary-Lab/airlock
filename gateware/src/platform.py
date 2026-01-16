# Copyright (c) 2025 VoidCanary-Lab
# SPDX-License-Identifier: GPL-3.0-or-later

from amaranth.build import *
from amaranth.vendor.lattice_ecp5 import LatticeECP5Platform
import subprocess

# Placeholder for ULX3S and Virtual Platform definitions
class VirtualPlatform(Platform):
    pass

class ULX3SPlatform(LatticeECP5Platform):
    device = "LFE5U-85F"
    package = "BG381"
    speed = "6"
    default_clk = "clk25"
    
    resources = [
        Resource("clk25", 0, Pins("G2", dir="i"), Clock(25e6), Attrs(IO_TYPE="LVCMOS33")),
        
        # LEDs
        Resource("led", 0, Pins("B2", dir="o"), Attrs(IO_TYPE="LVCMOS33")),
        
        # Buttons (Fire 1 as Reset)
        Resource("btn", 0, Pins("D6", dir="i"), Attrs(IO_TYPE="LVCMOS33")),
        Resource("btn", 0, Pins("R1", dir="i"), Attrs(IO_TYPE="LVCMOS33")),
        
        # Heartbeat Input (Mapped to GN25 / G3 on J1 Header)
        # Heartbeat Input (Mapped to GP12 / G3)
        Resource("heartbeat", 0, Pins("G3", dir="i"), Attrs(IO_TYPE="LVCMOS33")),
        
        # Egress Mode Switch (Mapped to GN26 / F3 on J1 Header)
        # Egress Mode Switch (Mapped to GN12 / F3)
        Resource("egress_mode", 0, Pins("F3", dir="i"), Attrs(IO_TYPE="LVCMOS33")),
    ]
    connectors = []

    pinouts = {
        "split_j1_j2": [
            # --- Ethernet 1: Top Header (J2) ---
            Resource("eth_rmii", 0,
                Subsignal("clk",     Pins("B11", dir="i")), # 0+ (GP0) -> nINT/RETCLK (50MHz)
                Subsignal("tx_en",   Pins("C11", dir="o")), # 0- (GN0) -> TX_EN
                Subsignal("txd0",    Pins("A10", dir="o")), # 1+ (GP1) -> TXD0
                Subsignal("txd1",    Pins("A11", dir="o")), # 1- (GN1) -> TX1
                Subsignal("rxd0",    Pins("A9",  dir="i")), # 2+ (GP2) -> RX0
                Subsignal("rxd1",    Pins("B10", dir="i")), # 2- (GN2) -> RX1
                Subsignal("crs_dv",  Pins("B9",  dir="i")), # 3+ (GP3) -> CRS
                Subsignal("mdc",     Pins("C10", dir="o")), # 3- (GN3) -> MDC
                Subsignal("mdio",    Pins("A7",  dir="io")),# 4+ (GP4) -> MDIO
                Attrs(IO_TYPE="LVCMOS33")
            ),
            # --- Ethernet 2: Bottom Header (J1) ---
            Resource("eth_rmii", 1,
                Subsignal("clk",     Pins("U18", dir="i")), # 0+ (GP0) -> nINT/RETCLK (50MHz)
                Subsignal("tx_en",   Pins("U17", dir="o")), # 0- (GN0) -> TX_EN
                Subsignal("txd0",    Pins("N17", dir="o")), # 1+ (GP1) -> TXD0
                Subsignal("txd1",    Pins("P16", dir="o")), # 1- (GN1) -> TX1
                Subsignal("rxd0",    Pins("M18", dir="i")), # 2+ (GP2) -> RX0
                Subsignal("rxd1",    Pins("N16", dir="i")), # 2- (GN2) -> RX1
                Subsignal("crs_dv",  Pins("L16", dir="i")), # 3+ (GP3) -> CRS
                Subsignal("mdc",     Pins("L17", dir="o")), # 3- (GN3) -> MDC
                Subsignal("mdio",    Pins("H18", dir="io")),# 4+ (GP4) -> MDIO
                Attrs(IO_TYPE="LVCMOS33")
            ),
        ],
        "2xEth100mbps_oneside_j1": [
            # Placeholder for 2xEth100mbps_oneside_j1 configuration
        ]
    }

    def __init__(self, pinout="split_j1_j2", **kwargs):
        if pinout not in self.pinouts:
            raise ValueError(f"Unknown pinout: {pinout}. Available: {list(self.pinouts.keys())}")
        
        all_resources = self.resources + self.pinouts[pinout]
        super().__init__(resources=all_resources, **kwargs)

    def toolchain_program(self, products, name):
        print(f"[*] Flashing {name} to ULX3S...")
        with products.extract(f"{name}.bit") as bitstream_filename:
            subprocess.check_call(["openFPGALoader", "-b", "ulx3s", bitstream_filename])