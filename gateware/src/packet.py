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
        self.egress_mode  = Signal() # 0=Ingress (Secure/Default), 1=Egress (Permissive)

        # --- Internal State ---
        self.locked = Signal()
        # Violation signals (kept for status reporting)
        self.violation_volume    = Signal()
        self.violation_ttl       = Signal()
        self.violation_wg_size   = Signal()
        self.violation_plaintext = Signal()
        self.violation_heartbeat = Signal()
        self.violation_ethertype = Signal()
        self.violation_arp_rate  = Signal()
        self.violation_ip_proto  = Signal()
        self.violation_arp_size  = Signal()
        self.violation_frag      = Signal()
        self.violation_ip_options = Signal()
        self.violation_arp_opcode = Signal()
        self.violation_land      = Signal()
        self.violation_loopback  = Signal()
        self.violation_tcp_flags = Signal()
        self.violation_tcp_options = Signal()
        self.violation_udp_len   = Signal()
        self.drop_current        = Signal()
        
        self.tcp_flags_high_bit = Signal()
        
        self.HEARTBEAT_TIMEOUT = heartbeat_timeout
        self.VOLUME_LIMIT = volume_limit
        self.watchdog_timer = Signal(32, init=self.HEARTBEAT_TIMEOUT)

    def elaborate(self, platform):
        m = Module()

        # --- Internal State ---
        volume_cnt = Signal(27)
        byte_ptr = Signal(17) 
        self.byte_ptr = byte_ptr # Expose for formal verification
        
        # Reset Synchronization State
        flush_state = Signal(init=1)
        
        # IP Header Fields
        is_ip = Signal()
        self.is_ip = is_ip # Expose for formal verification
        ip_len = Signal(16)
        self.ip_len = ip_len # Expose for formal verification
        ip_hdr_len = Signal(4, init=5)
        ttl = Signal(8)
        src_ip = Signal(32)
        self.src_ip = src_ip # Expose for formal verification
        dst_ip = Signal(32)
        self.dst_ip = dst_ip # Expose for formal verification
        ip_proto = Signal(8)
        self.ip_proto = ip_proto # Expose for formal verification
        udp_len_reg = Signal(16)
        self.udp_len_reg = udp_len_reg # Expose for formal verification
        
        # ARP Rate Limiter State
        is_arp = Signal()
        arp_bucket = Signal(16)
        arp_leak_timer = Signal(14)
        arp_opcode_high = Signal(8)
        ARP_LEAK_INTERVAL = 10000 # 25MHz / 2500 Bps (20kbps)
        ARP_BURST_LIMIT = 4000
        
        plaintext_cnt = Signal(8)

        # Consolidate violations
        traffic_violation = Signal()
        m.d.comb += traffic_violation.eq(self.violation_volume | self.violation_ttl | self.violation_wg_size | self.violation_plaintext | self.violation_ethertype | self.violation_arp_rate | self.violation_ip_proto | self.violation_arp_size | self.violation_frag | self.violation_ip_options | self.violation_arp_opcode | self.violation_land | self.violation_loopback | self.violation_tcp_flags | self.violation_tcp_options | self.violation_udp_len)

        # --- Combinatorial Allow Rules (Whitelist) ---
        # Define what is explicitly ALLOWED. Anything else triggers a violation.
        
        # 1. EtherType Check (Byte 13)
        # Rule: Must be IPv4 (0x0800) or ARP (0x0806). 
        # is_ip is set if Byte 12 was 0x08.
        check_ethertype = (byte_ptr == 13)
        allow_ethertype = is_ip & ((self.rx_data == 0x00) | (self.rx_data == 0x06))

        # 2. TTL Check (Byte 22)
        # Rule: TTL must be >= 60
        check_ttl = is_ip & (byte_ptr == 22)
        allow_ttl = (self.rx_data >= 60)
        
        # 3. WG Size / Packet Structure Checks
        header_end_ptr = (14 + (ip_hdr_len << 2) - 1)
        
        # 3a. Minimum Size (at header end)
        # Adjusted min size to 28 (20 IP + 8 UDP) to allow empty UDP packets.
        check_min_size = is_ip & (byte_ptr == header_end_ptr) & (byte_ptr > 14)
        allow_min_size = (ip_len >= 28) & ((ip_proto != 6) | (ip_len >= 40))
        
        # 3b. No Trailing Garbage (Physical > Logical)
        check_trailing = is_ip & (byte_ptr > 17) & (byte_ptr >= (14 + ip_len)) & (byte_ptr >= 64)
        allow_trailing = Const(0) # Never allowed
        
        # 3c. No Truncation (Physical < Logical) - Checked at rx_last
        check_truncation = is_ip & self.rx_last
        allow_truncation = (byte_ptr >= (14 + ip_len - 1)) & (ip_len >= 28) & ((ip_proto != 6) | (ip_len >= 40))

        # 3d. Runt Check (Must be at least Ethernet Header)
        check_runt = self.rx_last & (byte_ptr < 14)
        
        # 4. Plaintext Check
        # Rule: Printable characters allowed only up to limit
        is_printable = ((self.rx_data >= 0x20) & (self.rx_data <= 0x7E)) | (self.rx_data == 0x0A) | (self.rx_data == 0x0D) | (self.rx_data == 0x09)
        check_plaintext = (is_ip | is_arp) & is_printable
        allow_plaintext = (plaintext_cnt < 127)
        
        # 5. Volume Limit
        # Rule: Volume count must be within limit
        check_volume = Const(1) # Always checked
        allow_volume = (volume_cnt < self.VOLUME_LIMIT)
        
        # 6. ARP Rate Limit
        # Rule: ARP bucket must be within limit
        check_arp_rate = is_arp
        allow_arp_rate = (arp_bucket < ARP_BURST_LIMIT)

        # 7. Protocol Check (Byte 23)
        # Rule: Allow TCP (0x06) and UDP (0x11) ONLY
        check_protocol = is_ip & (byte_ptr == 23)
        allow_protocol = (self.rx_data == 0x06) | (self.rx_data == 0x11)
        
        # 8. ARP Size Check
        # Rule: ARP packets must be <= 64 bytes
        check_arp_size = is_arp & (byte_ptr > 63)
        allow_arp_size = Const(0) # Never allowed
        
        # 9. Fragmentation Check (Bytes 20 & 21)
        # Rule: No MF flag, No Offset
        check_frag_flags = is_ip & (byte_ptr == 20)
        allow_frag_flags = ((self.rx_data & 0xBF) == 0)
        
        check_frag_offset = is_ip & (byte_ptr == 21)
        allow_frag_offset = (self.rx_data == 0)

        # 10. IP Options Check (Byte 14)
        # Rule: IHL must be 5 (20 bytes)
        check_ip_options = is_ip & (byte_ptr == 14)
        allow_ip_options = (self.rx_data == 0x45)

        # 11. ARP Opcode Check (Bytes 20 & 21)
        # Rule: Opcode must be 1 (Request) or 2 (Reply)
        check_arp_opcode = is_arp & (byte_ptr == 21)
        allow_arp_opcode = (arp_opcode_high == 0) & ((self.rx_data == 1) | (self.rx_data == 2))

        # 12. Land Attack (Src=Dst) - Check at Byte 33
        check_land = is_ip & (byte_ptr == 33)
        allow_land = (src_ip != Cat(self.rx_data, dst_ip[8:32]))

        # 13. Loopback Check (127.x.x.x)
        check_loopback = is_ip & ((byte_ptr == 26) | (byte_ptr == 30))
        allow_loopback = (self.rx_data != 127)

        # 14. TCP Options (Byte 46)
        # Rule: Data Offset must be 5 (No options)
        check_tcp_options = is_ip & (ip_proto == 6) & (byte_ptr == 46)
        allow_tcp_options = (self.rx_data == 0x50)

        # 15. TCP Flags (Byte 47)
        # Rule: Only specific flag combinations allowed
        # Flags: NS(8) CWR(7) ECE(6) URG(5) ACK(4) PSH(3) RST(2) SYN(1) FIN(0)
        check_tcp_flags = is_ip & (ip_proto == 6) & (byte_ptr == 47)
        full_tcp_flags = Cat(self.rx_data, self.tcp_flags_high_bit)
        allow_tcp_flags = (
            (full_tcp_flags == 0x002) | # SYN
            (full_tcp_flags == 0x012) | # SYN-ACK
            (full_tcp_flags == 0x010) | # ACK
            (full_tcp_flags == 0x018) | # PSH-ACK
            (full_tcp_flags == 0x001) | # FIN
            (full_tcp_flags == 0x011) | # FIN-ACK
            (full_tcp_flags == 0x004) | # RST
            (full_tcp_flags == 0x014)   # RST-ACK
        )

        # 16. UDP Length (Byte 39)
        # Rule: Length must match IP length - 20 and be >= 8
        full_udp_len_comb = Cat(self.rx_data, udp_len_reg[8:16])
        check_udp_len = is_ip & (ip_proto == 17) & (byte_ptr == 39)
        allow_udp_len = (full_udp_len_comb >= 8) & (full_udp_len_comb == (ip_len - 20))

        # --- Violation Trigger ---
        # If a check is active AND the value is NOT allowed -> Violation
        violation_now = Signal()
        
        m.d.comb += violation_now.eq(
            self.rx_valid & (
                (check_ethertype & ~allow_ethertype) |
                (check_ttl & ~allow_ttl) |
                (check_min_size & ~allow_min_size) |
                (check_runt) |
                (check_trailing & ~allow_trailing) |
                (check_truncation & ~allow_truncation) |
                (check_plaintext & ~allow_plaintext) |
                (check_volume & ~allow_volume) |
                (check_arp_rate & ~allow_arp_rate) |
                (check_protocol & ~allow_protocol) |
                (check_arp_size & ~allow_arp_size) |
                (check_frag_flags & ~allow_frag_flags) |
                (check_frag_offset & ~allow_frag_offset) |
                (check_ip_options & ~allow_ip_options) |
                (check_arp_opcode & ~allow_arp_opcode) |
                (check_land & ~allow_land) |
                (check_loopback & ~allow_loopback) |
                (check_tcp_flags & ~allow_tcp_flags) |
                (check_tcp_options & ~allow_tcp_options) |
                (check_udp_len & ~allow_udp_len)
            )
        )

        # --- 1. Global Lock Logic ---
        
        # Fate Sharing Prevention
        any_violation = traffic_violation | violation_now
        
        with m.If(self.rst_lock):
            m.d.sync += self.locked.eq(0)
            m.d.sync += self.drop_current.eq(0)
            m.d.sync += flush_state.eq(1)
        with m.Elif(self.violation_heartbeat):
            m.d.sync += self.locked.eq(1)
        with m.Elif(any_violation):
            with m.If(~self.egress_mode):
                m.d.sync += self.locked.eq(1)
            with m.Else():
                with m.If(~self.rx_last):
                    m.d.sync += self.drop_current.eq(1)

        m.d.comb += self.status_led.eq(~self.locked)

        # --- 2. Traffic Flow Control ---
        force_terminate = (self.drop_current | violation_now) & self.rx_last & ~self.locked
        gate_tx = self.locked | self.drop_current | self.rst_lock | flush_state | traffic_violation | self.violation_heartbeat | violation_now

        m.d.comb += [
            self.tx_data.eq(Mux(force_terminate, 0, self.rx_data)),
            self.tx_valid.eq((self.rx_valid & ~gate_tx) | force_terminate),
            self.tx_last.eq(self.rx_last),
            self.rx_ready.eq(self.tx_ready | gate_tx)
        ]

        # --- 3. Packet Processing Loop ---
        rx_fire = self.rx_valid & self.rx_ready
        
        with m.If(flush_state & ~self.rx_valid):
            m.d.sync += flush_state.eq(0)
        
        with m.If(rx_fire & ~self.locked):
            m.d.sync += volume_cnt.eq(volume_cnt + 1)
            
            with m.If(flush_state):
                with m.If(self.rx_last):
                    m.d.sync += flush_state.eq(0)
                    m.d.sync += byte_ptr.eq(0)
                    m.d.sync += is_ip.eq(0)
                    m.d.sync += ip_len.eq(0)
                    m.d.sync += plaintext_cnt.eq(0)
                    # Clear violations
                    m.d.sync += [
                        self.violation_ttl.eq(0), self.violation_wg_size.eq(0), self.violation_plaintext.eq(0),
                        self.violation_ethertype.eq(0), self.violation_arp_rate.eq(0), self.violation_ip_proto.eq(0),
                        self.violation_arp_size.eq(0), self.violation_frag.eq(0), self.violation_ip_options.eq(0),
                        self.violation_arp_opcode.eq(0), self.violation_land.eq(0), self.violation_loopback.eq(0),
                        self.violation_tcp_flags.eq(0), self.violation_tcp_options.eq(0), self.violation_udp_len.eq(0),
                        is_arp.eq(0), self.drop_current.eq(0), ip_proto.eq(0)
                    ]
            
            with m.Elif(self.rx_last):
                m.d.sync += byte_ptr.eq(0)
                m.d.sync += is_ip.eq(0)
                m.d.sync += ip_len.eq(0)
                m.d.sync += plaintext_cnt.eq(0)
                m.d.sync += ip_hdr_len.eq(5)
                m.d.sync += [
                    self.violation_ttl.eq(0), self.violation_wg_size.eq(0), self.violation_plaintext.eq(0),
                    self.violation_ethertype.eq(0), self.violation_arp_rate.eq(0), self.violation_ip_proto.eq(0),
                    self.violation_arp_size.eq(0), self.violation_frag.eq(0), self.violation_ip_options.eq(0),
                    self.violation_arp_opcode.eq(0), self.violation_land.eq(0), self.violation_loopback.eq(0),
                    self.violation_tcp_flags.eq(0), self.violation_tcp_options.eq(0), self.violation_udp_len.eq(0),
                    is_arp.eq(0), self.drop_current.eq(0), ip_proto.eq(0)
                ]

                # Check Truncation / Runt at end of packet
                with m.If((check_truncation & ~allow_truncation) | check_runt):
                    m.d.sync += self.violation_wg_size.eq(1)
                    with m.If(~self.egress_mode):
                        m.d.sync += self.locked.eq(1)
                with m.Else():
                    m.d.sync += self.violation_wg_size.eq(0)

                with m.If(byte_ptr < 13):
                    with m.If(~self.egress_mode):
                        m.d.sync += self.locked.eq(1)
            with m.Else():
                with m.If(byte_ptr < 0x1FFFF):
                    m.d.sync += byte_ptr.eq(byte_ptr + 1)

            # --- 4. Filtering Logic (State Updates) ---
            # Update state variables and register violations if allow rules failed
            
            with m.If(check_volume & ~allow_volume & ~self.rx_last): m.d.sync += self.violation_volume.eq(1)
            
            # IP Detection State
            with m.If((byte_ptr == 12) & (self.rx_data == 0x08) & ~self.rx_last):
                m.d.sync += is_ip.eq(1)
            with m.If((byte_ptr == 13) & ~self.rx_last):
                with m.If(self.rx_data != 0x00):
                    m.d.sync += is_ip.eq(0)
                with m.If(check_ethertype & ~allow_ethertype):
                    m.d.sync += self.violation_ethertype.eq(1)
                with m.If(is_ip & (self.rx_data == 0x06)):
                    m.d.sync += is_arp.eq(1)

            # ARP Processing
            with m.If(is_arp):
                with m.If(byte_ptr == 20): m.d.sync += arp_opcode_high.eq(self.rx_data)
                with m.If(check_arp_opcode & ~allow_arp_opcode & ~self.rx_last): m.d.sync += self.violation_arp_opcode.eq(1)
                with m.If(arp_bucket < 0xFFFF): m.d.sync += arp_bucket.eq(arp_bucket + 1)
                with m.If(check_arp_rate & ~allow_arp_rate & ~self.rx_last): m.d.sync += self.violation_arp_rate.eq(1)
            
            with m.If(check_arp_size & ~allow_arp_size & ~self.rx_last): m.d.sync += self.violation_arp_size.eq(1)

            # IP Processing
            with m.If(is_ip):
                with m.If(byte_ptr == 14):
                    with m.If((self.rx_data[4:8] != 4) & ~self.rx_last): m.d.sync += self.violation_ethertype.eq(1)
                    m.d.sync += ip_hdr_len.eq(self.rx_data & 0x0F)
                    with m.If(check_min_size & ~allow_min_size & ~self.rx_last): m.d.sync += self.violation_wg_size.eq(1)
                    with m.If(check_ip_options & ~allow_ip_options & ~self.rx_last): m.d.sync += self.violation_ip_options.eq(1)
                
                with m.If(byte_ptr == 16): m.d.sync += ip_len[8:16].eq(self.rx_data)
                with m.If(byte_ptr == 17): m.d.sync += ip_len[0:8].eq(self.rx_data)

                with m.If(byte_ptr == 22):
                    m.d.sync += ttl.eq(self.rx_data)
                    with m.If(check_ttl & ~allow_ttl & ~self.rx_last): m.d.sync += self.violation_ttl.eq(1)
                
                with m.If((check_min_size & ~allow_min_size) | (check_trailing & ~allow_trailing)):
                    with m.If(~self.rx_last): m.d.sync += self.violation_wg_size.eq(1)

                with m.If(check_protocol & ~allow_protocol & ~self.rx_last): m.d.sync += self.violation_ip_proto.eq(1)
                with m.If(byte_ptr == 23): m.d.sync += ip_proto.eq(self.rx_data)

                with m.If(byte_ptr == 26): m.d.sync += src_ip[24:32].eq(self.rx_data)
                with m.If(byte_ptr == 27): m.d.sync += src_ip[16:24].eq(self.rx_data)
                with m.If(byte_ptr == 28): m.d.sync += src_ip[8:16].eq(self.rx_data)
                with m.If(byte_ptr == 29): m.d.sync += src_ip[0:8].eq(self.rx_data)
                
                with m.If(byte_ptr == 30): m.d.sync += dst_ip[24:32].eq(self.rx_data)
                with m.If(byte_ptr == 31): m.d.sync += dst_ip[16:24].eq(self.rx_data)
                with m.If(byte_ptr == 32): m.d.sync += dst_ip[8:16].eq(self.rx_data)
                with m.If(byte_ptr == 33): m.d.sync += dst_ip[0:8].eq(self.rx_data)

                with m.If((ip_proto == 17) & (byte_ptr == 38)): m.d.sync += udp_len_reg[8:16].eq(self.rx_data)
                with m.If((ip_proto == 6) & (byte_ptr == 46)): m.d.sync += self.tcp_flags_high_bit.eq(self.rx_data[0])

                with m.If((check_frag_flags & ~allow_frag_flags) | (check_frag_offset & ~allow_frag_offset)):
                    with m.If(~self.rx_last): m.d.sync += self.violation_frag.eq(1)

                # Plaintext Logic
                with m.If(byte_ptr > (14 + ip_hdr_len * 4 -1)):
                    with m.If(is_printable):
                        with m.If(plaintext_cnt < 255): m.d.sync += plaintext_cnt.eq(plaintext_cnt + 1)
                    with m.Else():
                        with m.If(plaintext_cnt > 0): m.d.sync += plaintext_cnt.eq(plaintext_cnt - 1)
                    
                    with m.If(check_plaintext & ~allow_plaintext & ~self.rx_last):
                        m.d.sync += self.violation_plaintext.eq(1)

                with m.If(check_land & ~allow_land & ~self.rx_last): m.d.sync += self.violation_land.eq(1)
                with m.If(check_loopback & ~allow_loopback & ~self.rx_last): m.d.sync += self.violation_loopback.eq(1)
                with m.If(check_tcp_flags & ~allow_tcp_flags & ~self.rx_last): m.d.sync += self.violation_tcp_flags.eq(1)
                with m.If(check_tcp_options & ~allow_tcp_options & ~self.rx_last): m.d.sync += self.violation_tcp_options.eq(1)
                with m.If(check_udp_len & ~allow_udp_len & ~self.rx_last): m.d.sync += self.violation_udp_len.eq(1)

        # --- ARP Leaky Bucket Logic ---
        m.d.sync += arp_leak_timer.eq(arp_leak_timer + 1)
        with m.If(arp_leak_timer >= ARP_LEAK_INTERVAL):
            m.d.sync += arp_leak_timer.eq(0)
            with m.If(arp_bucket > 0):
                m.d.sync += arp_bucket.eq(arp_bucket - 1)

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
        with m.If(self.rst_lock):
            m.d.sync += [
                self.violation_volume.eq(0), self.violation_ttl.eq(0), self.violation_wg_size.eq(0),
                self.violation_plaintext.eq(0), self.violation_heartbeat.eq(0), self.violation_ethertype.eq(0),
                self.violation_arp_rate.eq(0), self.violation_ip_proto.eq(0), self.violation_arp_size.eq(0),
                self.violation_frag.eq(0), self.violation_ip_options.eq(0), self.violation_arp_opcode.eq(0),
                self.violation_land.eq(0), self.violation_loopback.eq(0), self.violation_tcp_flags.eq(0),
                self.violation_tcp_options.eq(0), self.violation_udp_len.eq(0), self.drop_current.eq(0),
                self.watchdog_timer.eq(self.HEARTBEAT_TIMEOUT), volume_cnt.eq(0), arp_bucket.eq(0),
                byte_ptr.eq(0), is_ip.eq(0), is_arp.eq(0), plaintext_cnt.eq(0)
            ]

        return m
