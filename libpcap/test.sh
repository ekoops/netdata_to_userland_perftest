#!/bin/bash

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

function cleanup {
	set +e
	[[ -n "$SERVER_PID" ]] && kill "$SERVER_PID"
	[[ -n "$PCAP_READER_PID" ]] && kill -9 "$PCAP_READER_PID"
  ../testbed_cleanup.sh
}
trap cleanup EXIT

set -x -e

CLIENT_ADDR=${CLIENT_ADDR:-10.0.0.1}
SERVER_ADDR=${SERVER_ADDR:-10.0.0.2}
CLIENT_PIN_CORE_NUM=0
SERVER_PIN_CORE_NUM=2
SCTP_PACKET_LEN=512

# testbed setup, load and attach xdp program and create perf buffer
CLIENT_ADDR="$CLIENT_ADDR" SERVER_ADDR="$SERVER_ADDR" ../testbed_setup.sh

# start iperf3 server
iperf3 -s "$SERVER_ADDR" &> /dev/null &
SERVER_PID=$!

# start pcap reader in background
./.output/libpcap veth0 &
PCAP_READER_PID=$!

# wait for pcap reader to be ready
sleep 3

# notify pcap reader to start reading
kill -SIGINT $PCAP_READER_PID
# start iperf3 client
ip netns exec ns0 iperf3 -A $CLIENT_PIN_CORE_NUM,$SERVER_PIN_CORE_NUM -c "$SERVER_ADDR" --sctp -l $SCTP_PACKET_LEN
# notify pcap reader to stop reading
kill -SIGINT $PCAP_READER_PID