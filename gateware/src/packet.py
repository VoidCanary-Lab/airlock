# Copyright (c) 2025 VoidCanary-Lab
# SPDX-License-Identifier: GPL-3.0-or-later

from amaranth import *

class EthernetFilter(Elaboratable):
    """
    EthernetFilter: A streaming packet filter module.
    
    Interfaces:
        rx: Sink (Input) - Data, Valid, Last, Ready
        tx: Source (Output) - Data, Valid, Last, Ready
    """
    def __init__(self):
        # RX Interface (Sink)
        self.rx_data  = Signal(8)
        self.rx_valid = Signal()
        self.rx_last  = Signal()
        self.rx_ready = Signal()

        # TX Interface (Source)
        self.tx_data  = Signal(8)
        self.tx_valid = Signal()
        self.tx_last  = Signal()
        self.tx_ready = Signal()

    def elaborate(self, platform):
        m = Module()

        # Latches to store pattern matching state
        match_pos = Signal(4) # Position in the "MALICIOUS" pattern
        is_malicious = Signal() # Flag if packet is deemed malicious
        
        # The signature to detect, converted to integer values
        malicious_signature = [ord(c) for c in "MALICIOUS"]

        with m.FSM(reset="IDLE") as fsm:
            
            # State: IDLE - Waiting for start of packet
            with m.State("IDLE"):
                # When a new packet arrives...
                with m.If(self.rx_valid & self.rx_ready):
                    # Reset matching logic
                    m.d.sync += [
                        match_pos.eq(0),
                        is_malicious.eq(0)
                    ]
                    # Start streaming and checking bytes
                    m.next = "STREAMING"
                
                # Default: Pass-through non-packet data (e.g. preambles)
                m.d.comb += [
                    self.tx_data.eq(self.rx_data),
                    self.tx_valid.eq(self.rx_valid),
                    self.tx_last.eq(self.rx_last),
                    self.rx_ready.eq(self.tx_ready)
                ]

            # State: STREAMING - Forwarding packet while checking for signature
            with m.State("STREAMING"):
                # By default, forward the packet
                m.d.comb += [
                    self.tx_data.eq(self.rx_data),
                    self.tx_valid.eq(self.rx_valid),
                    self.tx_last.eq(self.rx_last),
                    self.rx_ready.eq(self.tx_ready)
                ]

                # --- Signature Matching Logic ---
                with m.If(self.rx_valid & self.tx_ready):
                    current_byte_is_match = Signal()
                    
                    # Check if current byte matches the signature at the current position
                    with m.Switch(match_pos):
                        for i, char_code in enumerate(malicious_signature):
                            with m.Case(i):
                                m.d.comb += current_byte_is_match.eq(self.rx_data == char_code)
                    
                    # If byte matches, advance pattern position. If not, reset.
                    with m.If(current_byte_is_match):
                        m.d.sync += match_pos.eq(match_pos + 1)
                    with m.Else():
                        m.d.sync += match_pos.eq(0)
                
                # If we've found the full signature, mark packet as malicious
                with m.If(match_pos == len(malicious_signature) - 1):
                    m.d.sync += is_malicious.eq(1)

                # If packet is malicious and we are at the end, go to DROP state
                with m.If(self.rx_last & is_malicious):
                    m.next = "DROP"
                # If packet is not malicious and we are at the end, go to IDLE
                with m.If(self.rx_last & ~is_malicious):
                    m.next = "IDLE"

            # State: DROP - Suppress output for a malicious packet
            with m.State("DROP"):
                # Absorb remaining data by asserting ready, but do not forward
                m.d.comb += [
                    self.rx_ready.eq(1),
                    self.tx_valid.eq(0),
                    self.tx_last.eq(0)
                ]
                
                # Once the packet has been fully received, return to IDLE
                with m.If(self.rx_valid & self.rx_last):
                    m.next = "IDLE"
        
        return m