#!/bin/bash
# Copyright (c) 2025 VoidCanary-Lab
# SPDX-License-Identifier: GPL-3.0-or-later

# deploy.sh - Void Canary Orchestrator

set -e

usage() {
    echo "Usage: $0 <dev|prod>"
    exit 1
}

if [ "$#" -ne 1 ]; then
    usage
fi

MODE=$1

if [ "$MODE" == "dev" ]; then
    echo "[*] Starting Virtual Development Environment..."
    
    # 1. Setup Virtual Topology
    echo "[*] Setting up virtual network topology..."
    sudo ip netns add vault_ns
    sudo ip link add veth_in type veth peer name veth_in_peer
    sudo ip link add veth_out type veth peer name veth_out_peer
    sudo ip link set veth_out_peer netns vault_ns
    sudo ip link set veth_in up
    sudo ip link set veth_in_peer up
    sudo ip link set veth_out up
    sudo ip netns exec vault_ns ip link set veth_out_peer up
    sudo ip netns exec vault_ns ip addr add 192.168.100.2/24 dev veth_out_peer

    # 2. Start the Virtual Bridge (Python/Amaranth)
    echo "[*] Initializing Amaranth Virtual Bridge..."
    sudo python3 gateware/sim/bridge.py --rx veth_in_peer --tx veth_out &
    PID_BRIDGE=$!
    
    # 3. Launch VMs via Terraform (QEMU)
    echo "[*] Provisioning QEMU VMs..."
    (cd infrastructure/terraform/development && terraform apply -auto-approve)
    
    echo "[*] Environment Live. Traffic passing through Python Gateware."
    
elif [ "$MODE" == "prod" ]; then
    echo "[*] Starting Production Deployment..."
    
    # 1. Synthesize and Flash FPGA
    echo "[*] Flashing ULX3S..."
    (cd gateware && python3 src/build.py --flash)
    
    # 2. Provision Proxmox
    echo "[*] Provisioning Proxmox VMs..."
    (cd infrastructure/terraform/production && terraform apply -auto-approve)
fi

# 3. Configure Software (Common)
echo "[*] Applying Ansible Configurations..."
(cd infrastructure/ansible && ansible-playbook -i inventory.ini playbook.yml)

echo "[+] Airlock Deployed successfully."

if [ ! -z "$PID_BRIDGE" ]; then
    trap "sudo kill $PID_BRIDGE" EXIT
    wait $PID_BRIDGE
fi