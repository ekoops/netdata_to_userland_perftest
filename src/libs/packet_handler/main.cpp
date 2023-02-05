#include <iostream>
#include "PacketHandler.h"
#include "pcapplusplus/header/RawPacket.h"

int main() {
    TcpReassemblyConnMgr connMgr;
    PacketHandler ph {&connMgr};
    timeval tv {3, 10};
    uint8_t pRawData[4] = {0x00, 0x01, 0x02, 0x03};
    pcpp::RawPacket rp {pRawData, 4, tv, false};
    ph.handle(&rp);
    std::cout << "ciao" << std::endl;
}