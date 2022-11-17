#!/bin/bash

set -x -e

CLIENT_IFACE_NAME=${CLIENT_IFACE_NAME:-veth0_}
CLIENT_ADDR=${CLIENT_ADDR:-10.0.0.1}
SERVER_IFACE_NAME=${SERVER_IFACE_NAME:-veth0}
SERVER_ADDR=${SERVER_ADDR:-10.0.0.2}

ip netns add ns0
ip link add "$SERVER_IFACE_NAME" type veth peer name "$CLIENT_IFACE_NAME" netns ns0
ip link set dev "$SERVER_IFACE_NAME" up
ip addr add "$SERVER_ADDR"/30 dev "$SERVER_IFACE_NAME"
ip netns exec ns0 ip link set dev "$CLIENT_IFACE_NAME" up
ip netns exec ns0 ip addr add "$CLIENT_ADDR"/30 dev "$CLIENT_IFACE_NAME"
ip netns exec ns0 ip route add default via "$SERVER_ADDR"
