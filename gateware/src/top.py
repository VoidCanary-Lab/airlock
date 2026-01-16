# Copyright (c) 2025 VoidCanary-Lab
# SPDX-License-Identifier: GPL-3.0-or-later

from amaranth import *
from amaranth.lib.fifo import AsyncFIFO, SyncFIFO
from amaranth.lib.cdc import ResetSynchronizer, FFSynchronizer, AsyncResetSynchronizer

# Assuming platform.py exists in the same directory or python path
try:
    # Try relative import first to avoid conflict with stdlib 'platform'
    from .platform import ULX3SPlatform
except ImportError:
    try:
        from platform import ULX3SPlatform
    except ImportError:
        pass

from packet import SecurityAirlock
from mac import RMII_RX, RMII_TX

class AirlockTop(Elaboratable):
    def elaborate(self, platform):
        m = Module()
        
        # --- 1. Clock Domains ---
        # System Clock (25MHz)
        clk25 = platform.request("clk25")
        m.domains.sys = ClockDomain()
        m.d.comb += ClockSignal("sys").eq(clk25.i)
        
        # RMII Clocks (50MHz from PHY/Board)
        # We create separate domains for RX (Eth0) and TX (Eth1) interfaces
        eth0_pads = platform.request("eth_rmii", 0) # Ingress (Internet)
        eth1_pads = platform.request("eth_rmii", 1) # Egress (Internal)
        
        m.domains.rmii_rx = ClockDomain()
        m.d.comb += ClockSignal("rmii_rx").eq(eth0_pads.clk.i)
        
        m.domains.rmii_tx = ClockDomain()
        m.d.comb += ClockSignal("rmii_tx").eq(eth1_pads.clk.i)
        
        # --- 2. Instantiate Modules ---
        
        # Core Logic (Runs in System Domain)
        airlock = m.submodules.airlock = SecurityAirlock()
        
        # MACs (Run in RMII Domains)
        # We use DomainRenamer to put the MAC logic in the correct clock domain
        mac_rx = DomainRenamer({"sync": "rmii_rx"})(RMII_RX(eth0_pads))
        m.submodules.mac_rx = mac_rx
        
        mac_tx = DomainRenamer({"sync": "rmii_tx"})(RMII_TX(eth1_pads))
        m.submodules.mac_tx = mac_tx
        
        # --- 3. Cross-Domain Buffering (AsyncFIFOs) ---
        
        # RX Path: RMII_RX -> FIFO -> Airlock
        # We use an AsyncFIFO for CDC, followed by a FWFT SyncFIFO to adapt to the Airlock's stream interface.
        rx_fifo = m.submodules.rx_fifo = AsyncFIFO(width=10, depth=2048, r_domain="sys", w_domain="rmii_rx")
        rx_stream = m.submodules.rx_stream = SyncFIFO(width=10, depth=4, fwft=True) # Sys domain
        
        # Pack data+last into FIFO
        m.d.comb += [
            rx_fifo.w_data.eq(Cat(mac_rx.source_data, mac_rx.source_last, mac_rx.source_error)),
            rx_fifo.w_en.eq(mac_rx.source_valid & rx_fifo.w_rdy) # Protect against overflow
        ]

        # Pump Logic: AsyncFIFO -> SyncFIFO (FWFT)
        # We pre-fetch data from AsyncFIFO into SyncFIFO to hide the read latency.
        rx_pump = Signal()
        rx_pump_d = Signal() # Delayed pump signal to match AsyncFIFO read latency
        m.d.comb += rx_pump.eq(rx_fifo.r_rdy & (rx_stream.level < 2))
        m.d.comb += rx_fifo.r_en.eq(rx_pump)
        m.d.sync += rx_pump_d.eq(rx_pump)
        m.d.sync += rx_stream.w_en.eq(rx_pump_d)
        m.d.sync += rx_stream.w_data.eq(rx_fifo.r_data)

        # Connect FWFT Stream to Airlock
        m.d.comb += [
            airlock.rx_data.eq(rx_stream.r_data[0:8]),
            airlock.rx_last.eq(rx_stream.r_data[8]),
            airlock.rx_valid.eq(rx_stream.r_rdy),
            rx_stream.r_en.eq(airlock.rx_ready)
        ]
        
        # Extract Error Signal (Bit 9)
        rx_error = Signal()
        m.d.comb += rx_error.eq(rx_stream.r_data[9])
        
        # Map CRC Error to LED[1] (if available) for physical layer monitoring
        # Airlock does not currently support an error input, so we visualize it.
        led_err = platform.request("led", 1)
        m.d.comb += led_err.o.eq(rx_error)
        
        # TX Path: Airlock -> FIFO -> RMII_TX
        tx_fifo = m.submodules.tx_fifo = AsyncFIFO(width=9, depth=2048, r_domain="rmii_tx", w_domain="sys")
        tx_stream = m.submodules.tx_stream = DomainRenamer("rmii_tx")(SyncFIFO(width=9, depth=4, fwft=True))
        
        m.d.comb += [
            # Airlock Outputs
            tx_fifo.w_data.eq(Cat(airlock.tx_data, airlock.tx_last)),
            tx_fifo.w_en.eq(airlock.tx_valid),
            airlock.tx_ready.eq(tx_fifo.w_rdy), # Backpressure if FIFO full
        ]

        # Pump Logic: AsyncFIFO -> SyncFIFO (FWFT) in RMII_TX domain
        tx_pump = Signal()
        tx_pump_d = Signal() # Delayed pump signal to match AsyncFIFO read latency
        m.d.comb += tx_pump.eq(tx_fifo.r_rdy & (tx_stream.level < 2))
        m.d.comb += tx_fifo.r_en.eq(tx_pump)
        m.d["rmii_tx"] += tx_pump_d.eq(tx_pump)
        m.d["rmii_tx"] += tx_stream.w_en.eq(tx_pump_d)
        m.d["rmii_tx"] += tx_stream.w_data.eq(tx_fifo.r_data)

        # Connect FWFT Stream to MAC
        m.d.comb += [
            mac_tx.sink_data.eq(tx_stream.r_data[0:8]),
            mac_tx.sink_last.eq(tx_stream.r_data[8]),
            mac_tx.sink_valid.eq(tx_stream.r_rdy),
            tx_stream.r_en.eq(mac_tx.sink_ready)
        ]
        
        # --- 4. Peripherals ---
        led = platform.request("led", 0)
        m.d.comb += led.o.eq(airlock.status_led)
        
        # Buttons / GPIO
        sys_rst = Signal()
        # Handle potential duplicate resource definitions in platform.py
        # Try requesting index 1 (Fire 1) first, as it is usually Active High on ULX3S
        try:
            btn_rst = platform.request("btn", 1)
            m.d.comb += sys_rst.eq(btn_rst.i)
        except:
            try:
                # Fallback to btn 0 (Power). Note: On some revs this is Active Low (inverted).
                btn_rst = platform.request("btn", 0)
                m.d.comb += sys_rst.eq(btn_rst.i)
            except:
                m.d.comb += sys_rst.eq(0)

        # --- 5. Reset Synchronization (Crucial for BLOCK RESETPATHS) ---
        # Synchronize the raw reset signal into every clock domain.
        # Use AsyncResetSynchronizer for robust external reset handling.
        m.submodules.sys_rst_sync = AsyncResetSynchronizer(sys_rst, domain="sys")
        m.submodules.rx_rst_sync  = AsyncResetSynchronizer(sys_rst, domain="rmii_rx")
        m.submodules.tx_rst_sync  = AsyncResetSynchronizer(sys_rst, domain="rmii_tx")
        
        # Tie off Airlock manual reset (handled by domain reset)
        m.d.comb += airlock.rst_lock.eq(0)
            
        # Heartbeat & Egress Mode
        try:
            hb = platform.request("heartbeat", 0)
            m.submodules.hb_sync = FFSynchronizer(hb.i, airlock.heartbeat_in, o_domain="sys")
            
            egress = platform.request("egress_mode", 0)
            m.submodules.egress_sync = FFSynchronizer(egress.i, airlock.egress_mode, o_domain="sys")
        except:
            pass
            
        # --- 6. PHY Management (MDC/MDIO) ---
        # Drive MDC/MDIO to idle to prevent floating inputs on PHY
        m.d.comb += [
            eth0_pads.mdc.o.eq(0),
            eth0_pads.mdio.o.eq(1),
            eth0_pads.mdio.oe.eq(1),
            
            eth1_pads.mdc.o.eq(0),
            eth1_pads.mdio.o.eq(1),
            eth1_pads.mdio.oe.eq(1),
        ]

        return m

if __name__ == "__main__":
    platform = ULX3SPlatform()
    platform.build(AirlockTop(), do_program=True)