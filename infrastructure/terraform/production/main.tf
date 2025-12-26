# Copyright (c) 2025 VoidCanary-Lab
# SPDX-License-Identifier: GPL-3.0-or-later

terraform {
  required_providers {
    libvirt = {
      source = "dmacvicar/libvirt"
    }
  }
}

provider "libvirt" {
  uri = "qemu:///system"
}

resource "libvirt_domain" "gateway" {
  name   = "gateway-vm"
  memory = "1024"
  vcpu   = 1

  network_interface {
    bridge = "tap1" # Connected to Python Bridge
  }

  network_interface {
    network_name = "default" # Management
  }
}