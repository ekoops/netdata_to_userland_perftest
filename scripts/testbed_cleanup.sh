#!/bin/bash

set -x

ip link del dev veth0
ip netns del ns0