#ifndef NETDATA_TO_USERLAND_PERFTEST_PACKETHANDLER_H
#define NETDATA_TO_USERLAND_PERFTEST_PACKETHANDLER_H

#include <map>
#include <mutex>
#include "pcapplusplus/header/TcpReassembly.h"
#include "TcpReassemblyData.h"

// typedef representing the connection manager and its iterator
typedef std::map <uint32_t, TcpReassemblyData> TcpReassemblyConnMgr;
typedef std::map<uint32_t, TcpReassemblyData>::iterator TcpReassemblyConnMgrIter;

class PacketHandler {
    pcpp::TcpReassembly tcpReassembly_;

    /**
     * The callback being called by the TCP reassembly module whenever new data arrives on a certain connection
     */
    static void msgReadyHandler(int8_t sideIndex, const pcpp::TcpStreamData &tcpData, void *userCookie);

    /**
     * The callback being called by the TCP reassembly module whenever a new connection is found. This method adds the connection to the connection manager
     */
    static void connectionStartHandler(const pcpp::ConnectionData &connectionData, void *userCookie);

    /**
     * The callback being called by the TCP reassembly module whenever a connection is ending. This method removes the connection from the connection manager and writes the metadata file if requested
     * by the user
     */
    static void connectionEndHandler(const pcpp::ConnectionData &connectionData,
                                     pcpp::TcpReassembly::ConnectionEndReason reason, void *userCookie);

public:
    explicit PacketHandler(TcpReassemblyConnMgr *connManager);

    void handle(const u_char *pkt, int len, struct timeval timestamp);


};


#endif //NETDATA_TO_USERLAND_PERFTEST_PACKETHANDLER_H
