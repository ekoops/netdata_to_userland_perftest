#include "PacketHandler.h"
#include <iostream>
#include <sstream>

int msg_counter_ = 0;
std::mutex m_;
int get_and_inc() {
    std::unique_lock<std::mutex> ul {m_};
    int x = msg_counter_;
    msg_counter_++;
    return x;
}

PacketHandler::PacketHandler(TcpReassemblyConnMgr *connManager) : tcpReassembly_{PacketHandler::msgReadyHandler,
                                                                                 connManager,
                                                                                 PacketHandler::connectionStartHandler,
                                                                                 PacketHandler::connectionEndHandler} {}

void PacketHandler::handle(const u_char *pkt, int len, struct timeval timestamp) {
//    std::cout << "handle" << std::endl;
    uint8_t *cloned_pkt = new uint8_t[len];
    memcpy(cloned_pkt, pkt, len);
    pcpp::RawPacket raw_pkt{cloned_pkt, len, timestamp, false};
//    pcpp::RawPacket raw_pkt {pkt, len, timestamp, false};
    auto status = this->tcpReassembly_.reassemblePacket(&raw_pkt);
//    std::cout << status << std::endl;
}

void PacketHandler::connectionStartHandler(const pcpp::ConnectionData &connectionData, void *userCookie) {
    std::cout << "connectionStartHandler" << std::endl;
    // get a pointer to the connection manager
    TcpReassemblyConnMgr *connMgr = (TcpReassemblyConnMgr *) userCookie;

    // look for the connection in the connection manager
    TcpReassemblyConnMgrIter iter = connMgr->find(connectionData.flowKey);

    // assuming it's a new connection
    if (iter == connMgr->end()) {
        // add it to the connection manager
        connMgr->insert(std::make_pair(connectionData.flowKey, TcpReassemblyData()));
    }
}

void PacketHandler::msgReadyHandler(int8_t sideIndex, const pcpp::TcpStreamData &tcpData, void *userCookie) {
    // extract the connection manager from the user cookie
    TcpReassemblyConnMgr *connMgr = (TcpReassemblyConnMgr *) userCookie;

    // check if this flow already appears in the connection manager. If not add it
    TcpReassemblyConnMgrIter iter = connMgr->find(tcpData.getConnectionData().flowKey);
    if (iter == connMgr->end()) {
        connMgr->insert(std::make_pair(tcpData.getConnectionData().flowKey, TcpReassemblyData{}));
        iter = connMgr->find(tcpData.getConnectionData().flowKey);
    }

    // if this messages comes on a different side than previous message seen on this connection
    if (sideIndex != iter->second.curSide) {
        // count number of message in each side
        iter->second.numOfMessagesFromSide[sideIndex]++;
        // set side index as the current active side
        iter->second.curSide = sideIndex;
    }

    // count number of packets and bytes in each side of the connection
    iter->second.numOfDataPackets[sideIndex]++;
    iter->second.bytesFromSide[sideIndex] += (int) tcpData.getDataLength();

    std::ostringstream oss;
    int counter = get_and_inc();
    oss << "msgReadyHandler - counter: " << counter << ", msg: " << (const char *) tcpData.getData() << std::endl;
    std::cout << oss.str();

    // write the new data to the file
//    iter->second.fileStreams[side]->write((char *) tcpData.getData(), tcpData.getDataLength());
}

void PacketHandler::connectionEndHandler(const pcpp::ConnectionData &connectionData,
                                         pcpp::TcpReassembly::ConnectionEndReason reason, void *userCookie) {
    std::cout << "connectionEndHandler" << std::endl;
    // get a pointer to the connection manager
    TcpReassemblyConnMgr *connMgr = (TcpReassemblyConnMgr *) userCookie;

    // find the connection in the connection manager by the flow key
    TcpReassemblyConnMgrIter iter = connMgr->find(connectionData.flowKey);

    // connection wasn't found - shouldn't get here
    if (iter == connMgr->end()) {
        return;
    }

    std::cout << "Number of data packets in side 0:  " << iter->second.numOfDataPackets[0] << std::endl;
    std::cout << "Number of data packets in side 1:  " << iter->second.numOfDataPackets[1] << std::endl;
    std::cout << "Total number of data packets:      "
              << (iter->second.numOfDataPackets[0] + iter->second.numOfDataPackets[1]) << std::endl;
    std::cout << std::endl;
    std::cout << "Number of bytes in side 0:         " << iter->second.bytesFromSide[0] << std::endl;
    std::cout << "Number of bytes in side 1:         " << iter->second.bytesFromSide[1] << std::endl;
    std::cout << "Total number of bytes:             "
              << (iter->second.bytesFromSide[0] + iter->second.bytesFromSide[1]) << std::endl;
    std::cout << std::endl;
    std::cout << "Number of messages in side 0:      " << iter->second.numOfMessagesFromSide[0] << std::endl;
    std::cout << "Number of messages in side 1:      " << iter->second.numOfMessagesFromSide[1] << std::endl;

    // remove the connection from the connection manager
    connMgr->erase(iter);
}