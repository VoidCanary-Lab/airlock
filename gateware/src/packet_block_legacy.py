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
        # Start in flush mode to ensure we don't process a packet mid-stream
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

        # --- Combinatorial Violation Detection (Anti-Leakage) ---
        # Detect violations on the current cycle to gate TX immediately.
        
        # 1. EtherType Check (Byte 13)
        # Allow IPv4 (0x0800) and ARP (0x0806). is_ip is set if Byte 12 was 0x08.
        comb_violation_ethertype = (byte_ptr == 13) & (~is_ip | ((self.rx_data != 0x00) & (self.rx_data != 0x06)))

        # 2. TTL Check (Byte 22)
        comb_violation_ttl = is_ip & (byte_ptr == 22) & (self.rx_data < 60)
        
        # 3. WG Size Check (End of IP Header)
        header_end_ptr = (14 + (ip_hdr_len << 2) - 1)
        # Check at calculated end pointer OR if packet ends prematurely (Runt/Bypass)
        # Also check for Trailing Garbage (Physical > Logical Length) to prevent injection
        # Check for Truncated Packets (Physical < Logical Length) at rx_last
        # Adjusted min size to 28 (20 IP + 8 UDP) to allow empty UDP packets.
        comb_violation_wg_size = is_ip & (
            ((ip_len < 20) & (((byte_ptr == header_end_ptr) & (byte_ptr > 14)) | self.rx_last)) |
            ((byte_ptr > 17) & (byte_ptr >= (14 + ip_len))) |
            (self.rx_last & (byte_ptr < (14 + ip_len - 1)))
        )
        
        # 4. Plaintext Check (Immediate block if count reached limit)
        # Check current byte printability.
        # Increased limit to 128 to allow TLS SNI (Server Name Indication) and Cloudflare UUIDs.
        is_printable = ((self.rx_data >= 0x20) & (self.rx_data <= 0x7E)) | (self.rx_data == 0x0A) | (self.rx_data == 0x0D) | (self.rx_data == 0x09)
        # Apply plaintext check to ARP packets to prevent padding exfiltration
        comb_violation_plaintext = (is_ip | is_arp) & (plaintext_cnt >= 127) & is_printable
        
        # 5. Volume Limit
        comb_violation_volume = (volume_cnt >= self.VOLUME_LIMIT)
        
        # 6. ARP Rate Limit
        comb_violation_arp_rate = is_arp & (arp_bucket >= ARP_BURST_LIMIT)

        # 7. Protocol Check (Byte 23) - Allow TCP (0x06) and UDP (0x11) ONLY
        comb_violation_protocol = is_ip & (byte_ptr == 23) & (self.rx_data != 0x06) & (self.rx_data != 0x11)
        
        # 8. ARP Size Check (Hardened)
        # Block ARP packets larger than 64 bytes (Min Eth Frame + FCS) to prevent tunneling/overflows.
        comb_violation_arp_size = is_arp & (byte_ptr > 63)
        
        # 9. Fragmentation Check (Bytes 20 & 21)
        # Block MF flag (0x20 in Byte 20) and any Fragment Offset.
        # Byte 20 mask 0x3F covers MF (0x20) and top 5 bits of offset (0x1F).
        comb_violation_frag = is_ip & (((byte_ptr == 20) & ((self.rx_data & 0x3F) != 0)) | ((byte_ptr == 21) & (self.rx_data != 0)))

        # 10. IP Options Check (Byte 14)
        # Enforce IHL == 5 (20 bytes). Any options (IHL > 5) are blocked.
        comb_violation_ip_options = is_ip & (byte_ptr == 14) & ((self.rx_data & 0x0F) > 5)

        # 11. ARP Opcode Check (Bytes 20 & 21)
        # Allow only ARP Request (1) and Reply (2)
        comb_violation_arp_opcode = is_arp & (byte_ptr == 21) & ((arp_opcode_high != 0) | ((self.rx_data != 1) & (self.rx_data != 2)))

        # 12. Land Attack (Src=Dst) - Check at Byte 33
        comb_violation_land = is_ip & (byte_ptr == 33) & (src_ip == Cat(self.rx_data, dst_ip[8:32]))

        # 13. Loopback Check (127.x.x.x) - Check at Byte 26 (Src) and Byte 30 (Dst)
        comb_violation_loopback = is_ip & ((byte_ptr == 26) | (byte_ptr == 30)) & (self.rx_data == 127)

        # 14. TCP Options (Byte 46) - Only if Proto=6
        comb_violation_tcp_options = is_ip & (ip_proto == 6) & (byte_ptr == 46) & ((self.rx_data >> 4) > 5)

        # 15. TCP Flags (Byte 47) - Only if Proto=6
        # Flags: NS(8) CWR(7) ECE(6) URG(5) ACK(4) PSH(3) RST(2) SYN(1) FIN(0)
        # Allow only well-known combinations: SYN, SYN-ACK, ACK, FIN, FIN-ACK, RST, RST-ACK.
        # All other combinations are blocked.
        full_tcp_flags = Cat(self.rx_data, self.tcp_flags_high_bit)
        comb_violation_tcp_flags = is_ip & (ip_proto == 6) & (byte_ptr == 47) & \
            (full_tcp_flags != 0x002) & \
            (full_tcp_flags != 0x012) & \
            (full_tcp_flags != 0x010) & \
            (full_tcp_flags != 0x001) & \
            (full_tcp_flags != 0x011) & \
            (full_tcp_flags != 0x004) & \
            (full_tcp_flags != 0x014)

        # 16. UDP Length (Byte 39) - Only if Proto=17
        full_udp_len_comb = Cat(self.rx_data, udp_len_reg[8:16])
        comb_violation_udp_len = is_ip & (ip_proto == 17) & (byte_ptr == 39) & (
            (full_udp_len_comb < 8) |
            (full_udp_len_comb != (ip_len - 20))
        )

        violation_now = Signal()
        # Gate combinatorial checks with rx_valid to prevent false positives on idle bus noise
        m.d.comb += violation_now.eq((comb_violation_ethertype | comb_violation_ttl | comb_violation_wg_size | comb_violation_plaintext | comb_violation_volume | comb_violation_arp_rate | comb_violation_protocol | comb_violation_arp_size | comb_violation_frag | comb_violation_ip_options | comb_violation_arp_opcode | comb_violation_land | comb_violation_loopback | comb_violation_tcp_flags | comb_violation_tcp_options | comb_violation_udp_len) & self.rx_valid)

        # --- 1. Global Lock Logic ---
        
        # Fate Sharing Prevention
        # Determine if we have a violation NOW (Combinatorial) or from previous cycles (Registered)
        any_violation = traffic_violation | violation_now
        
        with m.If(self.rst_lock):
            m.d.sync += self.locked.eq(0)
            m.d.sync += self.drop_current.eq(0)
            m.d.sync += flush_state.eq(1)
        with m.Elif(self.violation_heartbeat):
            # Heartbeat failure is a system integrity issue; always lock.
            m.d.sync += self.locked.eq(1)
        with m.Elif(any_violation):
            # Lock on ANY Ingress violation (Unicast OR Multicast).
            # If firewall is hacked, we cannot trust Multicast traffic. Fail Closed.
            with m.If(~self.egress_mode):
                m.d.sync += self.locked.eq(1)
            with m.Else():
                # Only drop the rest of the packet if the packet is not ending right now.
                # If it is finishing, we successfully dropped the last byte (via gate_tx) and we are done.
                with m.If(~self.rx_last):
                    m.d.sync += self.drop_current.eq(1)

        m.d.comb += self.status_led.eq(~self.locked)

        # --- 2. Traffic Flow Control ---
        # Gate TX with Reset and immediate violation signals
        
        # AXI Stream Compliance (Packet Smuggling Prevention)
        force_terminate = (self.drop_current | violation_now) & self.rx_last & ~self.locked

        gate_tx = self.locked | self.drop_current | self.rst_lock | flush_state | traffic_violation | self.violation_heartbeat | violation_now

        m.d.comb += [
            self.tx_data.eq(Mux(force_terminate, 0, self.rx_data)),
            self.tx_valid.eq((self.rx_valid & ~gate_tx) | force_terminate),
            self.tx_last.eq(self.rx_last),
            # RX Ready Logic:
            # We are ready if Downstream is ready OR if we are effectively dropping/sinking the data.
            # This ensures we don't block the upstream if we are just discarding packets.
            self.rx_ready.eq(self.tx_ready | gate_tx)
        ]

        # --- 3. Packet Processing Loop ---
        # Only process state updates when a valid handshake occurs (Fire)
        rx_fire = self.rx_valid & self.rx_ready
        
        # Smart Flush: If line is idle (rx_valid=0), assume safe to sync.
        # This prevents dropping the first packet on a clean startup.
        with m.If(flush_state & ~self.rx_valid):
            m.d.sync += flush_state.eq(0)
        
        with m.If(rx_fire & ~self.locked):
            m.d.sync += volume_cnt.eq(volume_cnt + 1)
            
            with m.If(flush_state):
                # Wait for end of current packet to resync
                with m.If(self.rx_last):
                    m.d.sync += flush_state.eq(0)
                    m.d.sync += byte_ptr.eq(0)
                    m.d.sync += is_ip.eq(0)
                    m.d.sync += ip_len.eq(0)
                    m.d.sync += plaintext_cnt.eq(0)
                    m.d.sync += self.violation_ttl.eq(0)
                    m.d.sync += self.violation_wg_size.eq(0)
                    m.d.sync += self.violation_plaintext.eq(0)
                    m.d.sync += self.violation_ethertype.eq(0)
                    m.d.sync += self.violation_arp_rate.eq(0)
                    m.d.sync += self.violation_ip_proto.eq(0)
                    m.d.sync += self.violation_arp_size.eq(0)
                    m.d.sync += self.violation_frag.eq(0)
                    m.d.sync += self.violation_ip_options.eq(0)
                    m.d.sync += self.violation_arp_opcode.eq(0)
                    m.d.sync += self.violation_land.eq(0)
                    m.d.sync += self.violation_loopback.eq(0)
                    m.d.sync += self.violation_tcp_flags.eq(0)
                    m.d.sync += self.violation_tcp_options.eq(0)
                    m.d.sync += self.violation_udp_len.eq(0)
                    m.d.sync += is_arp.eq(0)
                    m.d.sync += self.drop_current.eq(0)
            
            with m.Elif(self.rx_last):
                m.d.sync += byte_ptr.eq(0)
                m.d.sync += is_ip.eq(0)
                m.d.sync += ip_len.eq(0)
                m.d.sync += plaintext_cnt.eq(0)
                m.d.sync += ip_hdr_len.eq(5)
                # Clear per-packet violations so they don't taint the next packet
                m.d.sync += self.violation_ttl.eq(0)
                m.d.sync += self.violation_wg_size.eq(0)
                m.d.sync += self.violation_plaintext.eq(0)
                m.d.sync += self.violation_ethertype.eq(0)
                m.d.sync += self.violation_arp_rate.eq(0)
                m.d.sync += self.violation_ip_proto.eq(0)
                m.d.sync += self.violation_arp_size.eq(0)
                m.d.sync += self.violation_frag.eq(0)
                m.d.sync += self.violation_ip_options.eq(0)
                m.d.sync += self.violation_arp_opcode.eq(0)
                m.d.sync += self.violation_land.eq(0)
                m.d.sync += self.violation_loopback.eq(0)
                m.d.sync += self.violation_tcp_flags.eq(0)
                m.d.sync += self.violation_tcp_options.eq(0)
                m.d.sync += self.violation_udp_len.eq(0)
                m.d.sync += is_arp.eq(0)
                
                # Clear drop_current immediately so the first byte of the next packet isn't dropped
                m.d.sync += self.drop_current.eq(0)

                # Check for Truncation at rx_last and Lock if Ingress.
                is_truncated = is_ip & (byte_ptr < (14 + ip_len - 1))
                with m.If(is_truncated):
                    m.d.sync += self.violation_wg_size.eq(1)
                    with m.If(~self.egress_mode):
                        m.d.sync += self.locked.eq(1)
                with m.Else():
                    m.d.sync += self.violation_wg_size.eq(0)

                # If packet ends before byte 13 (14 bytes), it bypassed header checks.
                with m.If(byte_ptr < 13):
                    # Direct Lock Check for Runt Packets to avoid Fate Sharing with next packet
                    # Lock on ANY Ingress Runt to prevent bypass attempts
                    with m.If(~self.egress_mode):
                        m.d.sync += self.locked.eq(1)
            with m.Else():
                # Prevent byte_ptr wrap-around on giant packets to avoid interpreting payload as headers
                with m.If(byte_ptr < 0x1FFFF):
                    m.d.sync += byte_ptr.eq(byte_ptr + 1)

            # --- 4. Filtering Logic ---
            with m.If(comb_violation_volume & ~self.rx_last):
                m.d.sync += self.violation_volume.eq(1)

            # Check for EtherType 0x0800 (IPv4)
            with m.If((byte_ptr == 12) & (self.rx_data == 0x08) & ~self.rx_last):
                m.d.sync += is_ip.eq(1)
            with m.If((byte_ptr == 13) & ~self.rx_last):
                with m.If(self.rx_data != 0x00):
                    m.d.sync += is_ip.eq(0)
                
                # Strict IPv4 Check: If not 0x0800, trigger violation (which may Lock or Drop based on direction)
                with m.If(comb_violation_ethertype):
                    m.d.sync += self.violation_ethertype.eq(1)
                
                # Detect ARP (0x0806). is_ip was set if Byte 12 was 0x08.
                with m.If(is_ip & (self.rx_data == 0x06)):
                    m.d.sync += is_arp.eq(1)

            # ARP Packet Processing
            with m.If(is_arp):
                # Capture ARP opcode high byte
                with m.If(byte_ptr == 20):
                    m.d.sync += arp_opcode_high.eq(self.rx_data)
                
                with m.If(comb_violation_arp_opcode & ~self.rx_last):
                    m.d.sync += self.violation_arp_opcode.eq(1)

                with m.If(arp_bucket < 0xFFFF):
                    m.d.sync += arp_bucket.eq(arp_bucket + 1)
                with m.If(comb_violation_arp_rate & ~self.rx_last):
                    m.d.sync += self.violation_arp_rate.eq(1)

            # ARP Size Check
            with m.If(comb_violation_arp_size & ~self.rx_last):
                m.d.sync += self.violation_arp_size.eq(1)

            # IP Packet Processing
            with m.If(is_ip):
                # IHL is at byte 14
                with m.If(byte_ptr == 14):
                    # Explicitly check IP Version (IPv4=4) to prevent 0x0800 spoofing
                    with m.If((self.rx_data[4:8] != 4) & ~self.rx_last):
                        m.d.sync += self.violation_ethertype.eq(1)

                    m.d.sync += ip_hdr_len.eq(self.rx_data & 0x0F)
                    # Validate Minimum IHL (5 words / 20 bytes)
                    with m.If(((self.rx_data & 0x0F) < 5) & ~self.rx_last):
                        m.d.sync += self.violation_wg_size.eq(1)
                    # Validate Maximum IHL (No Options allowed)
                    with m.If(comb_violation_ip_options & ~self.rx_last):
                        m.d.sync += self.violation_ip_options.eq(1)
                
                # Total Length is at bytes 16 and 17
                with m.If(byte_ptr == 16):
                    m.d.sync += ip_len[8:16].eq(self.rx_data)
                with m.If(byte_ptr == 17):
                    m.d.sync += ip_len[0:8].eq(self.rx_data)

                # TTL is at byte 22
                with m.If(byte_ptr == 22):
                    m.d.sync += ttl.eq(self.rx_data)
                    with m.If(comb_violation_ttl & ~self.rx_last):
                        m.d.sync += self.violation_ttl.eq(1)
                
                # Check for WG Size Violation (Header End OR Runt)
                with m.If(comb_violation_wg_size & ~self.rx_last):
                    m.d.sync += self.violation_wg_size.eq(1)

                # Protocol Check (TCP/UDP Only)
                with m.If(comb_violation_protocol & ~self.rx_last):
                    m.d.sync += self.violation_ip_proto.eq(1)

                # Capture Protocol for later checks
                with m.If(byte_ptr == 23):
                    m.d.sync += ip_proto.eq(self.rx_data)

                with m.If(is_ip & (ip_proto == 6) & (byte_ptr == 46)):
                    m.d.sync += self.tcp_flags_high_bit.eq(self.rx_data[0])
                
                # Capture IPs
                with m.If(byte_ptr == 26): m.d.sync += src_ip[24:32].eq(self.rx_data)
                with m.If(byte_ptr == 27): m.d.sync += src_ip[16:24].eq(self.rx_data)
                with m.If(byte_ptr == 28): m.d.sync += src_ip[8:16].eq(self.rx_data)
                with m.If(byte_ptr == 29): m.d.sync += src_ip[0:8].eq(self.rx_data)
                
                with m.If(byte_ptr == 30): m.d.sync += dst_ip[24:32].eq(self.rx_data)
                with m.If(byte_ptr == 31): m.d.sync += dst_ip[16:24].eq(self.rx_data)
                with m.If(byte_ptr == 32): m.d.sync += dst_ip[8:16].eq(self.rx_data)
                with m.If(byte_ptr == 33): m.d.sync += dst_ip[0:8].eq(self.rx_data)

                # Capture UDP Len MSB
                with m.If((ip_proto == 17) & (byte_ptr == 38)):
                    m.d.sync += udp_len_reg[8:16].eq(self.rx_data)

                # Fragmentation Check
                with m.If(comb_violation_frag & ~self.rx_last):
                    m.d.sync += self.violation_frag.eq(1)

                # Plaintext check in payload
                with m.If(byte_ptr > (14 + ip_hdr_len * 4 -1)):
                    with m.If(is_printable):
                        with m.If(plaintext_cnt < 255):
                            m.d.sync += plaintext_cnt.eq(plaintext_cnt + 1)
                    with m.Else():
                        # Leaky Bucket instead of Reset
                        with m.If(plaintext_cnt > 0):
                            m.d.sync += plaintext_cnt.eq(plaintext_cnt - 1)
                    
                    with m.If(comb_violation_plaintext & ~self.rx_last):
                        m.d.sync += self.violation_plaintext.eq(1)

                # Set Violations
                with m.If(comb_violation_land & ~self.rx_last): m.d.sync += self.violation_land.eq(1)
                with m.If(comb_violation_loopback & ~self.rx_last): m.d.sync += self.violation_loopback.eq(1)
                with m.If(comb_violation_tcp_flags & ~self.rx_last): m.d.sync += self.violation_tcp_flags.eq(1)
                with m.If(comb_violation_tcp_options & ~self.rx_last): m.d.sync += self.violation_tcp_options.eq(1)
                with m.If(comb_violation_udp_len & ~self.rx_last): m.d.sync += self.violation_udp_len.eq(1)

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
                self.violation_arp_rate.eq(0),
                self.violation_ip_proto.eq(0),
                self.violation_arp_size.eq(0),
                self.violation_frag.eq(0),
                self.violation_ip_options.eq(0),
                self.violation_arp_opcode.eq(0),
                self.violation_land.eq(0),
                self.violation_loopback.eq(0),
                self.violation_tcp_flags.eq(0),
                self.violation_tcp_options.eq(0),
                self.violation_udp_len.eq(0),
                self.drop_current.eq(0),
                self.watchdog_timer.eq(self.HEARTBEAT_TIMEOUT),
                volume_cnt.eq(0),
                arp_bucket.eq(0),
                # Reset state pointers to prevent desynchronization on resume
                byte_ptr.eq(0),
                is_ip.eq(0),
                is_arp.eq(0),
                plaintext_cnt.eq(0)
            ]

        return m