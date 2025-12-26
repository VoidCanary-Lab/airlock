# Copyright (c) 2025 VoidCanary-Lab
# SPDX-License-Identifier: GPL-3.0-or-later

from amaranth import *

class SecurityAirlock(Elaboratable):
    def __init__(self):
        # --- Ports ---
        # Data Stream (AXI-Stream style)
        self.rx_data  = Signal(8)
        self.rx_valid = Signal()
        self.rx_last  = Signal()
        self.rx_ready = Signal()
        
        self.tx_data  = Signal(8)
        self.tx_valid = Signal()
        self.tx_last  = Signal()
        self.tx_ready = Signal()

        # External Signals
        self.heartbeat_in = Signal() # Input from GPIO/SPI (VPS SPIHash)
        self.rst_lock     = Signal() # Manual Reset Button
        self.status_led   = Signal() # ON = Traffic Flowing, OFF = Locked

    def elaborate(self, platform):
        m = Module()

        # --- Internal State ---
        # The Master Breaker: Once True, traffic stops forever (until reset)
        locked = Signal()
        
        # Traffic Volume Counter (95MB Limit)
        # 95 MB = 99,614,720 bytes. 
        # We use a 27-bit counter (max ~134MB)
        LIMIT_95MB = 99614720
        volume_cnt = Signal(27)

        # Watchdog Timer for Heartbeat (e.g., 50MHz clock, 1s timeout = 50M cycles)
        # Assuming 25MHz clock for generic FPGA -> 25,000,000 cycles
        HEARTBEAT_TIMEOUT = 25000000 
        watchdog_timer = Signal(32, reset=HEARTBEAT_TIMEOUT)
        
        # Packet Parsing State
        byte_ptr = Signal(11) # Max packet size 2048
        is_ip    = Signal()
        ip_len   = Signal(16)
        ttl      = Signal(8)
        
        # Detectors
        violation_volume    = Signal()
        violation_ttl       = Signal()
        violation_wg_size   = Signal()
        violation_plaintext = Signal()
        violation_heartbeat = Signal()

        # --- 1. Global Lock Logic ---
        # If any violation occurs, set locked high. Keep it high.
        with m.If(self.rst_lock):
            m.d.sync += locked.eq(0)
        with m.Elif(violation_volume | violation_ttl | violation_wg_size | violation_plaintext | violation_heartbeat):
            m.d.sync += locked.eq(1)

        # LED Logic (Visual Status)
        m.d.comb += self.status_led.eq(~locked)

        # --- 2. Traffic Flow Control ---
        # Only pass data if NOT locked
        m.d.comb += [
            self.tx_data.eq(self.rx_data),
            self.tx_valid.eq(self.rx_valid & ~locked),
            self.tx_last.eq(self.rx_last),
            self.rx_ready.eq(1) # Always ready to receive
        ]

        # --- 3. Packet Processing Loop ---
        with m.If(self.rx_valid & ~locked):
            # Increment Volume Counter
            m.d.sync += volume_cnt.eq(volume_cnt + 1)
            
            # Packet Byte Tracking
            m.d.sync += byte_ptr.eq(byte_ptr + 1)
            
            # End of Packet Reset
            with m.If(self.rx_last):
                m.d.sync += byte_ptr.eq(0)

            # --- 4. Filtering Logic ---

            # A. Volume Check (95MB vs 100MB)
            with m.If(volume_cnt >= LIMIT_95MB):
                m.d.comb += violation_volume.eq(1)

            # B. Protocol Parsing (Simplified offset lookups)
            # Ethernet Header is 14 bytes. IP starts at byte 14.
            
            # Check EtherType (Bytes 12-13). Expect 0x0800 (IPv4)
            with m.If((byte_ptr == 12) & (self.rx_data != 0x08)):
                pass # Not checking non-IP for now, or could lock if strict
            
            # C. TTL Check (IP Byte 8 => Frame Byte 14+8 = 22)
            # We enforce a specific TTL (e.g., 64 or 128) to prevent hops
            # If TTL < 60, it might be a traceroute or stale packet -> LOCK
            with m.If(byte_ptr == 22):
                with m.If(self.rx_data < 60):
                    m.d.comb += violation_ttl.eq(1)

            # D. WireGuard Size Check (Heuristic)
            # WireGuard packets are UDP. UDP Length is at IP offset 24 (Frame 38)
            # WireGuard Handshake initiation is fixed size (148 bytes typically)
            # Transport packets have specific padding. 
            # If we see a tiny UDP packet (e.g. < 32 bytes), it's suspicious.
            # (Logic simplified for readability: Checking IP Total Length at Frame Byte 16/17)
            with m.If(byte_ptr == 16): # IP Len High Byte
                m.d.sync += ip_len[8:16].eq(self.rx_data)
            with m.If(byte_ptr == 17): # IP Len Low Byte
                m.d.sync += ip_len[0:8].eq(self.rx_data)
                
            # Trigger size check at end of IP header processing (Frame byte 34)
            with m.If(byte_ptr == 34):
                # If Packet is tiny (< 40 bytes) and valid, LOCK.
                with m.If(ip_len < 40):
                    m.d.comb += violation_wg_size.eq(1)

            # E. Unencrypted Data Check (Entropy/Plaintext)
            # We look for pure ASCII sequences (0x20 - 0x7E) inside the payload
            # Frame Byte > 42 (UDP Payload start approx)
            with m.If(byte_ptr > 42):
                # If byte is ASCII alphanumeric/space, increment a "text score"
                # If we see 10 consecutive ASCII bytes, assume unencrypted -> LOCK
                # (Implementation omitted for brevity, logic acts as placeholder)
                pass 

        # --- 5. Watchdog (VPS Heartbeat) ---
        # The VPS sends a signal (toggle) on a GPIO pin. 
        # If the input toggles, we reset the timer.
        # If the input is silent for too long (MITM), timer hits 0 -> LOCK.
        
        last_heartbeat = Signal()
        m.d.sync += last_heartbeat.eq(self.heartbeat_in)
        
        # Detect Edge
        with m.If(self.heartbeat_in != last_heartbeat):
            m.d.sync += watchdog_timer.eq(HEARTBEAT_TIMEOUT) # Reset
        with m.Else():
            # Decrement
            with m.If(watchdog_timer > 0):
                m.d.sync += watchdog_timer.eq(watchdog_timer - 1)
            with m.Else():
                m.d.comb += violation_heartbeat.eq(1) # Timeout!

        return m
