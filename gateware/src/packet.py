# Copyright (c) 2025 VoidCanary-Lab
# SPDX-License-Identifier: GPL-3.0-or-later

from amaranth import *

class SecurityAirlock(Elaboratable):
    def __init__(self, heartbeat_timeout=25000000, volume_limit=99614720):
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
        self.ingress      = Signal(reset=1) # 1=From Outside (Ingress), 0=From Inside (Egress)

        # --- Internal State ---
        self.locked = Signal()
        self.violation_volume    = Signal()
        self.violation_ttl       = Signal()
        self.violation_wg_size   = Signal()
        self.violation_plaintext = Signal()
        self.violation_heartbeat = Signal()
        self.violation_ethertype = Signal()
        self.is_unicast          = Signal()
        self.drop_current        = Signal()
        
        self.HEARTBEAT_TIMEOUT = heartbeat_timeout
        self.VOLUME_LIMIT = volume_limit
        self.watchdog_timer = Signal(32, init=self.HEARTBEAT_TIMEOUT)

    def elaborate(self, platform):
        m = Module()

        # --- Internal State ---
        volume_cnt = Signal(27)
        byte_ptr = Signal(16) 
        
        # IP Header Fields
        is_ip = Signal()
        ip_len = Signal(16)
        ip_hdr_len = Signal(4)
        ttl = Signal(8)
        
        plaintext_cnt = Signal(4)

        # Consolidate violations
        traffic_violation = Signal()
        m.d.comb += traffic_violation.eq(self.violation_volume | self.violation_ttl | self.violation_wg_size | self.violation_plaintext | self.violation_ethertype)

        # --- 1. Global Lock Logic ---
        with m.If(self.rst_lock):
            m.d.sync += self.locked.eq(0)
            m.d.sync += self.drop_current.eq(0)
        with m.Elif(self.violation_heartbeat):
            # Heartbeat failure is a system integrity issue; always lock.
            m.d.sync += self.locked.eq(1)
        with m.Elif(traffic_violation):
            # Lock ONLY if Unicast AND coming from Outside. Otherwise, just drop the packet.
            with m.If(self.ingress & self.is_unicast):
                m.d.sync += self.locked.eq(1)
            with m.Else():
                m.d.sync += self.drop_current.eq(1)

        m.d.comb += self.status_led.eq(~self.locked)

        # --- 2. Traffic Flow Control ---
        tx_ready_internal = Signal()
        m.d.comb += self.tx_ready.eq(tx_ready_internal)
        m.d.comb += tx_ready_internal.eq(1)

        m.d.comb += [
            self.tx_data.eq(self.rx_data),
            self.tx_valid.eq(self.rx_valid & ~self.locked & ~self.drop_current),
            self.tx_last.eq(self.rx_last),
            self.rx_ready.eq(1)
        ]

        # --- 3. Packet Processing Loop ---
        with m.If(self.rx_valid & ~self.locked):
            m.d.sync += volume_cnt.eq(volume_cnt + 1)
            
            with m.If(self.rx_last):
                m.d.sync += byte_ptr.eq(0)
                m.d.sync += is_ip.eq(0)
                m.d.sync += plaintext_cnt.eq(0)
                # Clear per-packet violations so they don't taint the next packet
                m.d.sync += self.violation_ttl.eq(0)
                m.d.sync += self.violation_wg_size.eq(0)
                m.d.sync += self.violation_plaintext.eq(0)
                m.d.sync += self.violation_ethertype.eq(0)
            with m.Else():
                m.d.sync += byte_ptr.eq(byte_ptr + 1)

            # Capture Unicast/Multicast at Byte 0 (LSB of 1st byte: 0=Unicast, 1=Multicast)
            with m.If(byte_ptr == 0):
                m.d.sync += self.is_unicast.eq(~self.rx_data[0])
                m.d.sync += self.drop_current.eq(0)

            # --- 4. Filtering Logic ---
            with m.If(volume_cnt >= self.VOLUME_LIMIT):
                m.d.sync += self.violation_volume.eq(1)

            # Check for EtherType 0x0800 (IPv4)
            with m.If((byte_ptr == 12) & (self.rx_data == 0x08)):
                m.d.sync += is_ip.eq(1)
            with m.If(byte_ptr == 13):
                with m.If(self.rx_data != 0x00):
                    m.d.sync += is_ip.eq(0)
                
                # Strict IPv4 Check: If not 0x0800, trigger violation (which may Lock or Drop based on direction)
                with m.If(~is_ip | (self.rx_data != 0x00)):
                    m.d.sync += self.violation_ethertype.eq(1)

            # IP Packet Processing
            with m.If(is_ip):
                # IHL is at byte 14
                with m.If(byte_ptr == 14):
                    m.d.sync += ip_hdr_len.eq(self.rx_data & 0x0F)
                
                # Total Length is at bytes 16 and 17
                with m.If(byte_ptr == 16):
                    m.d.sync += ip_len[8:16].eq(self.rx_data)
                with m.If(byte_ptr == 17):
                    m.d.sync += ip_len[0:8].eq(self.rx_data)

                # TTL is at byte 22
                with m.If(byte_ptr == 22):
                    m.d.sync += ttl.eq(self.rx_data)
                    with m.If(self.rx_data < 60):
                        m.d.sync += self.violation_ttl.eq(1)
                
                # Use IHL to determine end of IP header
                with m.If((byte_ptr == (14 + ip_hdr_len * 4 -1)) & (byte_ptr > 14)):
                    with m.If(ip_len < 32): # Check for tiny packets
                        m.d.sync += self.violation_wg_size.eq(1)

                # Plaintext check in payload
                with m.If(byte_ptr > (14 + ip_hdr_len * 4 -1)):
                    with m.If((self.rx_data >= 0x20) & (self.rx_data <= 0x7E)):
                        with m.If(plaintext_cnt < 15):
                            m.d.sync += plaintext_cnt.eq(plaintext_cnt + 1)
                    with m.Else():
                        m.d.sync += plaintext_cnt.eq(0)
                    
                    with m.If(plaintext_cnt >= 10):
                        m.d.sync += self.violation_plaintext.eq(1)

        # --- 5. Watchdog (VPS Heartbeat) ---
        last_heartbeat = Signal()
        m.d.sync += last_heartbeat.eq(self.heartbeat_in)
        
        with m.If(self.heartbeat_in != last_heartbeat):
            m.d.sync += self.watchdog_timer.eq(self.HEARTBEAT_TIMEOUT)
        with m.Else():
            with m.If(self.watchdog_timer > 0):
                m.d.sync += self.watchdog_timer.eq(self.watchdog_timer - 1)
            with m.Else():
                m.d.sync += self.violation_heartbeat.eq(1)

        # --- 6. Manual Reset Logic ---
        # Clear violation flags and counters when reset is requested.
        # Placed at the end to override other assignments in the same cycle.
        with m.If(self.rst_lock):
            m.d.sync += [
                self.violation_volume.eq(0),
                self.violation_ttl.eq(0),
                self.violation_wg_size.eq(0),
                self.violation_plaintext.eq(0),
                self.violation_heartbeat.eq(0),
                self.violation_ethertype.eq(0),
                self.drop_current.eq(0),
                self.watchdog_timer.eq(self.HEARTBEAT_TIMEOUT),
                volume_cnt.eq(0)
            ]

        return m
