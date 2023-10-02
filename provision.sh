#!/bin/bash

# Title: provision tonleh proxy
# Description: This script provisions the proxy so that it configures itself into a
#              network bridge for all the packets.
# Author: Winston Tan

# ------------------------------
# Script Logic
# ------------------------------

# Install iproute2 for bridge utils
apt install -y iproute2
# NOTE: more uses of iproute2 can be found at: https://wiki.archlinux.org/title/network_bridge

# Add the bridge and bring it up
ip link add name tonleh_br0 type bridge
ip link set dev tonleh_br0 up

# Add device interfaces into the bridge
ip link set enx5c628b686485 master tonleh_br0
ip link set enxb827eb8d9534 master tonleh_br0

# outputs the bridge status
bridge link show

# add the host IP to the bridge
ip addr add 192.168.1.36/24 dev tonleh_br0

# add the bridge as the default route
ip route add default via 192.168.1.1 dev tonleh_br0

# we need br_netfilter to make sure that iptable is able to get packets from the bridge
modprobe br_netfilter
# reading: https://unix.stackexchange.com/questions/499756/how-does-iptable-work-with-linux-bridge

# ------------------------------
# End of Script
# ------------------------------
