# Copyright (c) 2025 VoidCanary-Lab
# SPDX-License-Identifier: GPL-3.0-or-later

from amaranth import *

class CRC32(Elaboratable):
    """Ethernet CRC32 Generator/Checker (Polynomial: 0x04C11DB7)"""
    def __init__(self):
        self.input  = Signal(8)
        self.enable = Signal()
        self.reset  = Signal()
        self.crc    = Signal(32, init=0xFFFFFFFF)
        self.output = Signal(32)

    def elaborate(self, platform):
        m = Module()
        
        # Standard Ethernet CRC32 (LSB first)
        poly = 0xEDB88320
        cur = self.crc
        val = self.input
        
        for i in range(8):
            mask = (cur[0] ^ val[0])
            cur = (cur >> 1) ^ Mux(mask, poly, 0)
            val = val >> 1
            
        with m.If(self.reset):
            m.d.sync += self.crc.eq(0xFFFFFFFF)
        with m.Elif(self.enable):
            m.d.sync += self.crc.eq(cur)
            
        m.d.comb += self.output.eq(~self.crc) # Final inversion
        return m

class RMII_RX(Elaboratable):
    """RMII Receiver: Deserializes 2-bit RMII to 8-bit Stream"""
    def __init__(self, pads):
        self.pads = pads
        # Output Stream
        self.source_data  = Signal(8)
        self.source_valid = Signal()
        self.source_last  = Signal()
        self.source_error = Signal()
        
        # CRC Stripping Buffer (Depth 4: 4 CRC bytes)
        self.shift_reg = Signal(32)
        self.fill_lvl  = Signal(range(5))
        
        # Pipeline Register for Look-Ahead
        self.out_byte  = Signal(8)
        self.out_valid = Signal()
        
        # Last Byte Lookahead Buffer (to align source_last correctly)
        self.delayed_byte  = Signal(8)
        self.delayed_valid = Signal()
        self.latched_error = Signal()
        
    def elaborate(self, platform):
        m = Module()
        
        # Input Synchronization
        crs_dv = Signal()
        rxd    = Signal(2)
        m.d.sync += [
            crs_dv.eq(self.pads.crs_dv.i),
            rxd.eq(Cat(self.pads.rxd0.i, self.pads.rxd1.i))
        ]
        
        # Default outputs
        m.d.sync += self.source_valid.eq(0)
        m.d.sync += self.source_last.eq(0)
        m.d.sync += self.source_error.eq(0)
        m.d.sync += self.delayed_valid.eq(0)
        m.d.sync += self.out_valid.eq(0)

        assembly_reg = Signal(8)
        cnt = Signal(2)
        
        crc = m.submodules.crc = CRC32()

        # State Machine
        with m.FSM(reset="IDLE"):
            with m.State("IDLE"):
                m.d.sync += self.out_valid.eq(0)
                with m.If(crs_dv & (rxd == 0x1)): # Preamble pattern 01...
                    m.next = "PREAMBLE"
                    m.d.comb += crc.reset.eq(1)
            
            with m.State("PREAMBLE"):
                # Wait for SFD (Start Frame Delimiter): 0xD5 (RMII: 11, 01, 01, 01 -> LSB first)
                # RMII sends di-bits LSB first. 0xD5 = 11010101
                # Di-bits: 01, 01, 01, 11.
                # We look for the '11' (3) at the end of preamble.
                with m.If(~crs_dv):
                    m.next = "IDLE"
                with m.Elif(rxd == 0x3): # SFD detected
                    m.next = "DATA"
                    m.d.sync += self.fill_lvl.eq(0)
                    m.d.sync += cnt.eq(0)
                    m.d.comb += crc.reset.eq(1) # Reset CRC before data starts
                    
            with m.State("DATA"):
                # Pipeline Output Logic with Lookahead
                # We delay output by 1 cycle to detect the "last" byte when crs_dv drops.
                
                with m.If(self.out_valid):
                    # Push new byte into lookahead buffer
                    m.d.sync += self.delayed_byte.eq(self.out_byte)
                    m.d.sync += self.delayed_valid.eq(1)
                    
                    # If we already had a byte waiting, send it now (it wasn't the last one)
                    with m.If(self.delayed_valid):
                        m.d.sync += self.source_data.eq(self.delayed_byte)
                        m.d.sync += self.source_valid.eq(1)
                        m.d.sync += self.source_last.eq(0)
                
                # Check for End of Frame (crs_dv dropped)
                with m.If(~crs_dv):
                    # The line went idle. The byte currently in delayed_byte is the LAST data byte.
                    # (The bytes currently in shift_reg are the CRC, which we discard).
                    
                    # Check CRC (Residue: 0xDEBB20E3 for standard Ethernet CRC32)
                    # Check Alignment (cnt must be 0)
                    is_error = (crc.crc != 0xDEBB20E3) | (cnt != 0)
                    
                    # Flush Pipeline:
                    # If delayed_valid is high, emit it.
                    with m.If(self.delayed_valid):
                        m.d.sync += self.source_data.eq(self.delayed_byte)
                        m.d.sync += self.source_valid.eq(1)
                        
                        # If out_valid is ALSO high, we have one more byte to go.
                        with m.If(self.out_valid):
                            m.d.sync += self.source_last.eq(0)
                            m.next = "FLUSH_LAST"
                            m.d.sync += self.latched_error.eq(is_error)
                        with m.Else():
                            m.d.sync += self.source_last.eq(1)
                            m.d.sync += self.source_error.eq(is_error)
                            m.next = "IDLE"
                    with m.Else():
                        m.next = "IDLE"
                    
                    m.d.sync += self.out_valid.eq(0)
                    m.d.sync += self.delayed_valid.eq(0)
                    m.d.sync += self.fill_lvl.eq(0)

                # Handle Runt/Early Termination (Empty Pipeline)
                with m.If(~crs_dv & ~self.out_valid):
                    m.next = "IDLE"
                    m.d.sync += self.fill_lvl.eq(0)

                # Byte Assembly
                with m.If(crs_dv):
                    m.d.sync += cnt.eq(cnt + 1)
                    with m.Switch(cnt):
                        with m.Case(0): m.d.sync += assembly_reg[0:2].eq(rxd)
                        with m.Case(1): m.d.sync += assembly_reg[2:4].eq(rxd)
                        with m.Case(2): m.d.sync += assembly_reg[4:6].eq(rxd)
                        with m.Case(3): 
                            new_byte = Cat(assembly_reg[0:6], rxd)
                            # Shift in new byte at bottom [0:8]
                            m.d.sync += self.shift_reg.eq(Cat(new_byte, self.shift_reg[0:24]))
                            
                            # Feed CRC Calculation (Include all bytes, even CRC bytes)
                            m.d.comb += crc.input.eq(new_byte)
                            m.d.comb += crc.enable.eq(1)
                            
                            with m.If(self.fill_lvl < 4):
                                m.d.sync += self.fill_lvl.eq(self.fill_lvl + 1)
                            with m.Else():
                                # Buffer full. Oldest byte [24:32] goes to pipeline.
                                m.d.sync += self.out_byte.eq(self.shift_reg[24:32])
                                m.d.sync += self.out_valid.eq(1)

            with m.State("FLUSH_LAST"):
                # Emit the final byte that was in out_byte
                m.d.sync += self.source_data.eq(self.out_byte)
                m.d.sync += self.source_valid.eq(1)
                m.d.sync += self.source_last.eq(1)
                m.d.sync += self.source_error.eq(self.latched_error)
                m.next = "IDLE"

        return m

class RMII_TX(Elaboratable):
    """RMII Transmitter: Serializes 8-bit Stream to 2-bit RMII"""
    def __init__(self, pads):
        self.pads = pads
        # Input Stream
        self.sink_data  = Signal(8)
        self.sink_valid = Signal()
        self.sink_last  = Signal()
        self.sink_ready = Signal()
        
    def elaborate(self, platform):
        m = Module()
        
        tx_en = Signal()
        txd   = Signal(2)
        
        # Drive Pads
        m.d.comb += [
            self.pads.tx_en.o.eq(tx_en),
            self.pads.txd0.o.eq(txd[0]),
            self.pads.txd1.o.eq(txd[1])
        ]
        
        crc = m.submodules.crc = CRC32()
        
        shifter = Signal(8)
        cnt = Signal(2)
        shifter_last = Signal()
        
        with m.FSM(reset="IDLE"):
            with m.State("IDLE"):
                m.d.sync += tx_en.eq(0)
                m.d.sync += self.sink_ready.eq(1) # Ready for new packet
                m.d.sync += crc.reset.eq(1)
                
                with m.If(self.sink_valid):
                    m.d.sync += self.sink_ready.eq(0) # Busy
                    m.d.sync += shifter.eq(self.sink_data)
                    m.d.sync += shifter_last.eq(self.sink_last)
                    m.d.sync += crc.reset.eq(0)
                    m.next = "PREAMBLE"
                    
            with m.State("PREAMBLE"):
                # Send 7 bytes of 0x55 and 1 byte of 0xD5
                pre_cnt = Signal(6)
                m.d.sync += tx_en.eq(1)
                m.d.sync += pre_cnt.eq(pre_cnt + 1)
                
                # 0x55 = 01 01 01 01. 0xD5 = 11 01 01 01
                with m.If(pre_cnt < 28): # 7 bytes * 4 dibits
                    m.d.sync += txd.eq(0x1)
                with m.Else():
                    # SFD: 01 01 01 11 (LSB first)
                    with m.Switch(pre_cnt):
                        with m.Case(28): m.d.sync += txd.eq(0x1)
                        with m.Case(29): m.d.sync += txd.eq(0x1)
                        with m.Case(30): m.d.sync += txd.eq(0x1)
                        with m.Case(31): 
                            m.d.sync += txd.eq(0x3) # The '11'
                            m.next = "DATA_SHIFT"
                            m.d.sync += cnt.eq(0)
                            # Feed the first byte (captured in IDLE) to CRC
                            m.d.comb += crc.input.eq(shifter)
                            m.d.comb += crc.enable.eq(1)
                            
            with m.State("DATA_SHIFT"):
                m.d.sync += txd.eq(shifter[0:2])
                m.d.sync += shifter.eq(shifter >> 2)
                m.d.sync += cnt.eq(cnt + 1)
                m.d.sync += self.sink_ready.eq(0) # Default to not ready
                
                with m.If(cnt == 3):
                    with m.If(shifter_last):
                        m.next = "CRC"
                    with m.Else():
                        m.d.sync += self.sink_ready.eq(1) # Ready for next
                        with m.If(self.sink_valid):
                            m.d.sync += shifter.eq(self.sink_data)
                            m.d.sync += shifter_last.eq(self.sink_last)
                            m.d.sync += cnt.eq(0)
                            m.d.comb += crc.input.eq(self.sink_data)
                            m.d.comb += crc.enable.eq(1)
                            m.d.sync += self.sink_ready.eq(1) # Pulse ready to ACK read
                        with m.Else():
                            # Underrun
                            m.next = "CRC"

            with m.State("CRC"):
                # Send 4 bytes of CRC
                crc_cnt = Signal(5)
                m.d.sync += crc_cnt.eq(crc_cnt + 1)
                
                # CRC is 32-bit. We send LSB first.
                current_byte = Signal(8)
                with m.Switch(crc_cnt >> 2): # Byte index
                    with m.Case(0): m.d.comb += current_byte.eq(crc.output[0:8])
                    with m.Case(1): m.d.comb += current_byte.eq(crc.output[8:16])
                    with m.Case(2): m.d.comb += current_byte.eq(crc.output[16:24])
                    with m.Case(3): m.d.comb += current_byte.eq(crc.output[24:32])
                
                # Select dibit
                with m.Switch(crc_cnt[0:2]):
                    with m.Case(0): m.d.sync += txd.eq(current_byte[0:2])
                    with m.Case(1): m.d.sync += txd.eq(current_byte[2:4])
                    with m.Case(2): m.d.sync += txd.eq(current_byte[4:6])
                    with m.Case(3): m.d.sync += txd.eq(current_byte[6:8])
                
                with m.If(crc_cnt == 15):
                    m.next = "IPG"

            with m.State("IPG"):
                m.d.sync += tx_en.eq(0)
                # Inter-Packet Gap (96 bits = 48 cycles)
                ipg_cnt = Signal(6)
                m.d.sync += ipg_cnt.eq(ipg_cnt + 1)
                with m.If(ipg_cnt == 48):
                    m.next = "IDLE"

        return m