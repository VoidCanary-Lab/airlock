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
        locked = Signal()
        LIMIT_95MB = 99614720
        volume_cnt = Signal(27)
        HEARTBEAT_TIMEOUT = 25000000 
        watchdog_timer = Signal(32, reset=HEARTBEAT_TIMEOUT)
        byte_ptr = Signal(11) 
        is_ip    = Signal()
        ip_len   = Signal(16)
        ttl      = Signal(8)
        
        violation_volume    = Signal()
        violation_ttl       = Signal()
        violation_wg_size   = Signal()
        violation_plaintext = Signal()
        violation_heartbeat = Signal()
        
        # Plaintext check counter
        plaintext_cnt = Signal(4)

        # --- 1. Global Lock Logic ---
        with m.If(self.rst_lock):
            m.d.sync += locked.eq(0)
        with m.Elif(violation_volume | violation_ttl | violation_wg_size | violation_plaintext | violation_heartbeat):
            m.d.sync += locked.eq(1)

        m.d.comb += self.status_led.eq(~locked)

        # --- 2. Traffic Flow Control ---
        tx_ready_internal = Signal()
        m.d.comb += self.tx_ready.eq(tx_ready_internal)
        m.d.comb += tx_ready_internal.eq(1)

        m.d.comb += [
            self.tx_data.eq(self.rx_data),
            self.tx_valid.eq(self.rx_valid & ~locked),
            self.tx_last.eq(self.rx_last),
            self.rx_ready.eq(1)
        ]

        # --- 3. Packet Processing Loop ---
        with m.If(self.rx_valid & ~locked):
            m.d.sync += volume_cnt.eq(volume_cnt + 1)
            m.d.sync += byte_ptr.eq(byte_ptr + 1)
            
            with m.If(self.rx_last):
                m.d.sync += byte_ptr.eq(0)
                m.d.sync += is_ip.eq(0)
                m.d.sync += plaintext_cnt.eq(0)

            # --- 4. Filtering Logic ---
            with m.If(volume_cnt >= LIMIT_95MB):
                m.d.sync += violation_volume.eq(1)

            with m.If((byte_ptr == 12) & (self.rx_data == 0x08)):
                m.d.sync += is_ip.eq(1)
            
            with m.If(is_ip):
                with m.If(byte_ptr == 22):
                    m.d.sync += ttl.eq(self.rx_data)
                    with m.If(self.rx_data < 60):
                        m.d.sync += violation_ttl.eq(1)

                with m.If(byte_ptr == 16):
                    m.d.sync += ip_len[8:16].eq(self.rx_data)
                with m.If(byte_ptr == 17):
                    m.d.sync += ip_len[0:8].eq(self.rx_data)
                
                with m.If(byte_ptr == 34):
                    with m.If(ip_len < 40):
                        m.d.sync += violation_wg_size.eq(1)

                with m.If(byte_ptr > 42):
                    with m.If((self.rx_data >= 0x20) & (self.rx_data <= 0x7E)):
                        m.d.sync += plaintext_cnt.eq(plaintext_cnt + 1)
                    with m.Else():
                        m.d.sync += plaintext_cnt.eq(0)
                    
                    with m.If(plaintext_cnt >= 10):
                        m.d.sync += violation_plaintext.eq(1)

        # --- 5. Watchdog (VPS Heartbeat) ---
        last_heartbeat = Signal()
        m.d.sync += last_heartbeat.eq(self.heartbeat_in)
        
        with m.If(self.heartbeat_in != last_heartbeat):
            m.d.sync += watchdog_timer.eq(HEARTBEAT_TIMEOUT)
        with m.Else():
            with m.If(watchdog_timer > 0):
                m.d.sync += watchdog_timer.eq(watchdog_timer - 1)
            with m.Else():
                m.d.sync += violation_heartbeat.eq(1)

        return m

