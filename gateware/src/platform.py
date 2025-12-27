# Copyright (c) 2025 VoidCanary-Lab
# SPDX-License-Identifier: GPL-3.0-or-later

from amaranth.build import Platform

# Placeholder for ULX3S and Virtual Platform definitions
class VirtualPlatform(Platform):
    pass

class ULX3SPlatform(Platform):
    # Minimal stub to satisfy build script
    device = "LFE5U-85F"
    package = "BG381"
    default_clk = "clk25"
    resources = []
    connectors = []

    def toolchain_program(self, products, name):
        print(f"[*] Flashing {name} to ULX3S (Stub)...")