#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit
fi

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

function cleanup {
	set +e
	[[ -n "$SERVER_PID" ]] && kill "$SERVER_PID"
	[[ -n "$PERF_READER_PID" ]] && wait "$PERF_READER_PID"
  "$SCRIPT_DIR"/../testbed/cleanup.sh || true
}
trap cleanup EXIT

set -x -e

if [[ -z "$OUTPUT_DIR" ]]; then
  echo "Please provide output folder path"
  exit
fi

CLIENT_NETNS_NAME=${CLIENT_NETNS_NAME:-ns0}
CLIENT_IFACE_NAME=${CLIENT_IFACE_NAME:-veth0_}
SERVER_IFACE_NAME=${SERVER_IFACE_NAME:-veth0}
CLIENT_IFACE_ADDR=${CLIENT_IFACE_ADDR:-10.0.0.1}
SERVER_IFACE_ADDR=${SERVER_IFACE_ADDR:-10.0.0.2}
CLIENT_PIN_CORE_NUM=${CLIENT_PIN_CORE_NUM:-0}
READER_PIN_CORE_NUM=${READER_PIN_CORE_NUM:-1}
SERVER_PIN_CORE_NUM=${SERVER_PIN_CORE_NUM:-2}
BUFFER_PAGES_NUM=${BUFFER_PAGES_NUM:-64}
PACKET_LEN=${PACKET_LEN:-512}

# TRAFFIC env variable can be undefined (defaulted to tcp) or assume one of the following values: tcp, udp, sctp.
# It determines which kind of traffic the iperf3 client will generates and the reader will focus on
CLIENT_FLAGS="-l $PACKET_LEN"
if [[ -z "$TRAFFIC" || "$TRAFFIC" == "tcp" ]]; then
  READER_TRAFFIC_FILTER="tcp"
elif [[ "$TRAFFIC" == "udp" ]]; then
  READER_TRAFFIC_FILTER="udp"
  CLIENT_FLAGS="--udp -b 0 $CLIENT_FLAGS"
elif [[ "$TRAFFIC" == "sctp" ]]; then
  READER_TRAFFIC_FILTER="sctp"
  CLIENT_FLAGS="--sctp $CLIENT_FLAGS"
else
  echo "TRAFFIC env variable allowed values are tcp, udp or sctp"
  exit
fi

# testbed setup
"$SCRIPT_DIR"/../testbed/setup.sh

# start iperf3 server
iperf3 -s "$SERVER_IFACE_ADDR" &> /dev/null &
SERVER_PID=$!

# load and attach uprobe programs on the interface and start to read from ring buffer in background
BINARY_PATH=${BINARY_PATH:-"/lib/x86_64-linux-gnu/libc.so.6"}
taskset $((1 << READER_PIN_CORE_NUM)) "$OUTPUT_DIR"/uprobe/uprobe "$SERVER_PID" "$BINARY_PATH" "$BUFFER_PAGES_NUM" "$READER_TRAFFIC_FILTER" &
PERF_READER_PID=$!

# wait for ring buffer reader to be ready
sleep 3

# notify ring buffer reader to start reading
kill -SIGINT $PERF_READER_PID
# start iperf3 client
# shellcheck disable=SC208
ip netns exec "$CLIENT_NETNS_NAME" iperf3 -A "$CLIENT_PIN_CORE_NUM","$SERVER_PIN_CORE_NUM" -c "$SERVER_IFACE_ADDR" $CLIENT_FLAGS
# notify ring buffer reader to stop reading and wait for it to exit
kill -SIGINT $PERF_READER_PID
wait $PERF_READER_PID