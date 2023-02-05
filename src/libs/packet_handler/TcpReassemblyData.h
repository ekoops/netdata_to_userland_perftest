#ifndef NETDATA_TO_USERLAND_PERFTEST_TCPREASSEMBLYDATA_H
#define NETDATA_TO_USERLAND_PERFTEST_TCPREASSEMBLYDATA_H

/**
 * A struct to contain all data save on a specific connection. It contains stats data on the connection
 */
class TcpReassemblyData {
public:
    // stats data: num of data packets on each side, bytes seen on each side and messages seen on each side
    int numOfDataPackets[2];
    int numOfMessagesFromSide[2];
    int bytesFromSide[2];

    // a flag indicating on which side was the latest message on this connection
    int8_t curSide;

    /**
     * the default c'tor. Initializes counters to 0
     */
    TcpReassemblyData() : numOfDataPackets{}, numOfMessagesFromSide{}, bytesFromSide{}, curSide{-1} {}
};


#endif //NETDATA_TO_USERLAND_PERFTEST_TCPREASSEMBLYDATA_H
