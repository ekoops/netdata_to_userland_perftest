#!/bin/bash

set -x -e

CLIENT_ADDR=${CLIENT_ADDR:-10.0.0.1}
SERVER_ADDR=${SERVER_ADDR:-10.0.0.2}

ip netns add ns0
ip link add veth0 type veth peer name veth0_ netns ns0
ip link set dev veth0 up
ip addr add "$SERVER_ADDR"/30 dev veth0
ip netns exec ns0 ip link set dev veth0_ up
ip netns exec ns0 ip addr add "$CLIENT_ADDR"/30 dev veth0_
ip netns exec ns0 ip route add default via "$SERVER_ADDR"
