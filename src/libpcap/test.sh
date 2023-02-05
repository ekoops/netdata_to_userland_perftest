#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit
fi

function cleanup {
  set +e
  [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID"
  [[ -n "$PCAP_READER_PID" ]] && wait "$PCAP_READER_PID"
  ../../scripts/testbed_cleanup.sh || true
}
trap cleanup EXIT

set -x -e

CLIENT_PIN_CORE_NUM=${CLIENT_PIN_CORE_NUM:-0}
READER_PIN_CORE_NUM=${READER_PIN_CORE_NUM:-1}
SERVER_PIN_CORE_NUM=${SERVER_PIN_CORE_NUM:-2}
CLIENT_ADDR=${CLIENT_ADDR:-10.0.0.1}
SERVER_ADDR=${SERVER_ADDR:-10.0.0.2}
SERVER_PORT=${SERVER_PORT:-5201}
PACKET_LEN=${PACKET_LEN:-512}

# GEN env variable can assume one of the following values: iperf3, tcpgen.
GEN=${GEN:-"iperf3"}
if [[ "$GEN" != "iperf3" && "$GEN" != "tcpgen" ]]; then
  echo "GEN env variable allowed values are: iperf3, tcpgen"
  exit
fi

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
  echo "TRAFFIC env variable allowed values are: tcp, udp, sctp"
  exit
fi

# testbed setup
CLIENT_ADDR="$CLIENT_ADDR" SERVER_ADDR="$SERVER_ADDR" ../../scripts/testbed_setup.sh

# start server
if [[ "$GEN" == "iperf3" ]]; then
  iperf3 -s "$SERVER_ADDR" &>/dev/null &
else
  taskset $((1 << SERVER_PIN_CORE_NUM)) ../tools/tcpgen/.output/tcpgen -s "$SERVER_ADDR" "$SERVER_PORT" "$PACKET_LEN" &>/dev/null &
fi
SERVER_PID=$!

# activate random packet dropper if generated traffic is TCP
if [[ "$TRAFFIC" == "tcp" ]]; then
  ip link set dev veth0 xdpdrv obj ../../common/.output/dropper.bpf.o sec xdp
fi

# start pcap reader in background
taskset $((1 << READER_PIN_CORE_NUM)) ./.output/libpcap veth0 "$READER_TRAFFIC_FILTER" &
PCAP_READER_PID=$!

# wait for pcap reader to be ready
sleep 3

# notify pcap reader to start reading
kill -SIGINT $PCAP_READER_PID
# start client
if [[ "$GEN" == "iperf3" ]]; then
  # shellcheck disable=SC2086
  ip netns exec ns0 iperf3 -A "$CLIENT_PIN_CORE_NUM","$SERVER_PIN_CORE_NUM" -c "$SERVER_ADDR" $CLIENT_FLAGS
else
  ip netns exec ns0 taskset $((1 << CLIENT_PIN_CORE_NUM)) ../tools/tcpgen/.output/tcpgen -c "$SERVER_ADDR" "$SERVER_PORT" "$PACKET_LEN"
fi

# notify pcap reader to stop reading and wait for it to exit
kill -SIGINT $PCAP_READER_PID
wait $PCAP_READER_PID
