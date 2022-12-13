#!/bin/bash

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

function cleanup {
	set +e
	[[ -n "$SERVER_PID" ]] && kill "$SERVER_PID"
	[[ -n "$PERF_READER_PID" ]] && wait "$PERF_READER_PID"
#	ip link set dev veth0 xdpdrv off
  ../testbed_cleanup.sh
}
trap cleanup EXIT

set -x -e

CLIENT_IFACE_NAME=${CLIENT_IFACE_NAME:-veth0_}
CLIENT_ADDR=${CLIENT_ADDR:-10.0.0.1}
SERVER_IFACE_NAME=${SERVER_IFACE_NAME:-veth0}
SERVER_ADDR=${SERVER_ADDR:-10.0.0.2}
CLIENT_PIN_CORE_NUM=0
SERVER_PIN_CORE_NUM=2
SCTP_PACKET_LEN=512

# testbed setup, load and attach xdp program and create perf buffer
CLIENT_ADDR="$CLIENT_ADDR" SERVER_ADDR="$SERVER_ADDR" ../testbed_setup.sh

# start iperf3 server
iperf3 -s "$SERVER_ADDR" &> /dev/null &
SERVER_PID=$!

# get ifindex of the interface on which the iperf3 server will listen
PROG_TYPE="${PROG:-xdp}"
SERVER_IFACE_IFINDEX=$(ip -o link | grep "$SERVER_IFACE_NAME" | cut -d ':' -f 1)

# load and attach XDP/TC program on the interface and start to read from perf buffer in background
./.output/perf_buffer "$PROG_TYPE" "$SERVER_IFACE_IFINDEX" 8 &
PERF_READER_PID=$!

# wait for perf buffer reader to be ready
sleep 3

# notify perf buffer reader to start reading
kill -SIGINT $PERF_READER_PID
# start iperf3 client
ip netns exec ns0 iperf3 -A $CLIENT_PIN_CORE_NUM,$SERVER_PIN_CORE_NUM -c "$SERVER_ADDR" --sctp -l $SCTP_PACKET_LEN
# notify perf buffer reader to stop reading and wait for it to exit
kill -SIGINT $PERF_READER_PID
wait $PERF_READER_PID