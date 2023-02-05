/**
 * TcpReassembly application
 * =========================
 * This is an application that captures data transmitted as part of TCP connections, organizes the data and stores it in a way that is convenient for protocol analysis and debugging.
 * This application reconstructs the TCP data streams and stores each connection in a separate file(s). TcpReassembly understands TCP sequence numbers and will correctly reconstruct
 * data streams regardless of retransmissions, out-of-order delivery or data loss.
 * TcpReassembly works more or less the same like tcpflow (https://linux.die.net/man/1/tcpflow) but probably with less options.
 * The main purpose of it is to demonstrate the TCP reassembly capabilities in PcapPlusPlus.
 * Main features and capabilities:
 *   - Captures packets from pcap/pcapng files or live traffic
 *   - Handles TCP retransmission, out-of-order packets and packet loss
 *   - Possibility to set a BPF filter to process only part of the traffic
 *   - Write each connection to a separate file
 *   - Write each side of each connection to a separate file
 *   - Limit the max number of open files in each point in time (to avoid running out of file descriptors for large files / heavy traffic)
 *   - Write a metadata file (txt file) for each connection with various stats on the connection: number of packets (in each side + total), number of TCP messages (in each side + total),
 *     number of bytes (in each side + total)
 *   - Write to console only (instead of files)
 *   - Set a directory to write files to (default is current directory)
 *
 * For more details about modes of operation and parameters run TcpReassembly -h
 */


#include <stdlib.h>
#include <stdio.h>
#include <map>
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include "TcpReassembly.h"
#include "PcapLiveDeviceList.h"
#include "PcapFileDevice.h"
#include "SystemUtils.h"
#include "PcapPlusPlusVersion.h"
#include "LRUList.h"
#include <getopt.h>


#define EXIT_WITH_ERROR(reason) do { \
    printUsage(); \
    std::cout << std::endl << "ERROR: " << reason << std::endl << std::endl; \
    exit(1); \
    } while(0)


static struct option TcpAssemblyOptions[] =
        {
                {"interface",        required_argument, 0, 'i'},
                {"help",             no_argument,       0, 'h'},
                {0, 0,                                  0, 0}
        };


/**
 * A singleton class containing the configuration as requested by the user. This singleton is used throughout the application
 */
class GlobalConfig {
private:

    /**
     * A private c'tor (as this is a singleton)
     */
    GlobalConfig(): m_RecentConnsWithActivity {NULL} {}

    // A least-recently-used (LRU) list of all connections seen so far. Each connection is represented by its flow key. This LRU list is used to decide which connection was seen least
    // recently in case we reached max number of open file descriptors and we need to decide which files to close
    pcpp::LRUList<uint32_t> *m_RecentConnsWithActivity;

public:

    /**
     * A method getting connection parameters as input and returns a filename and file path as output.
     * The filename is constructed by the IPs (src and dst) and the TCP ports (src and dst)
     */
    std::string getFileName(pcpp::ConnectionData connData, int side, bool separareSides) {
        std::stringstream stream;

        std::string sourceIP = connData.srcIP.toString();
        std::string destIP = connData.dstIP.toString();

        // for IPv6 addresses, replace ':' with '_'
        std::replace(sourceIP.begin(), sourceIP.end(), ':', '_');
        std::replace(destIP.begin(), destIP.end(), ':', '_');

        // side == 0 means data is sent from client->server
        if (side <= 0 || !separareSides) {
            stream << sourceIP << '.' << connData.srcPort << '-' << destIP << '.' << connData.dstPort;
        }
        else { // side == 1 means data is sent from server->client
            stream << destIP << '.' << connData.dstPort << '-' << sourceIP << '.' << connData.srcPort;
        }

        // return the file path
        return stream.str();
    }


    /**
     * Return a pointer to the least-recently-used (LRU) list of connections
     */
    pcpp::LRUList<uint32_t> *getRecentConnsWithActivity() {
        // This is a lazy implementation - the instance isn't created until the user requests it for the first time.
        // the side of the LRU list is determined by the max number of allowed open files at any point in time. Default is DEFAULT_MAX_NUMBER_OF_CONCURRENT_OPEN_FILES
        // but the user can choose another number
        if (m_RecentConnsWithActivity == NULL)
            m_RecentConnsWithActivity = new pcpp::LRUList<uint32_t>(10);

        // return the pointer
        return m_RecentConnsWithActivity;
    }


    /**
     * The singleton implementation of this class
     */
    static GlobalConfig &getInstance() {
        static GlobalConfig instance;
        return instance;
    }

    /**
     * d'tor
     */
    ~GlobalConfig() {
        delete m_RecentConnsWithActivity;
    }
};








/**
 * Print application usage
 */
void printUsage() {
    std::cout << std::endl
              << "Usage:" << std::endl
              << "------" << std::endl
              << pcpp::AppName::get()
              << " [-h] [-i interface]" << std::endl
              << std::endl
              << "Options:" << std::endl
              << std::endl
              << "    -i interface  : Use the specified interface. Can be interface name (e.g eth0) or interface IPv4 address. Required argument for capturing from live interface"
              << std::endl
              << "    -h            : Display this help message and exit" << std::endl
              << std::endl;
}

/**
 * The callback being called by the TCP reassembly module whenever a new connection is found. This method adds the connection to the connection manager
 */
static void tcpReassemblyConnectionStartCallback(const pcpp::ConnectionData &connectionData, void *userCookie) {
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


/**
 * The callback being called by the TCP reassembly module whenever new data arrives on a certain connection
 */
static void tcpReassemblyMsgReadyCallback(int8_t sideIndex, const pcpp::TcpStreamData &tcpData, void *userCookie) {
    // extract the connection manager from the user cookie
    TcpReassemblyConnMgr *connMgr = (TcpReassemblyConnMgr *) userCookie;

    // check if this flow already appears in the connection manager. If not add it
    TcpReassemblyConnMgrIter iter = connMgr->find(tcpData.getConnectionData().flowKey);
    if (iter == connMgr->end()) {
        connMgr->insert(std::make_pair(tcpData.getConnectionData().flowKey, TcpReassemblyData {}));
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

    // write the new data to the file
//    iter->second.fileStreams[side]->write((char *) tcpData.getData(), tcpData.getDataLength());
}


/**
 * The callback being called by the TCP reassembly module whenever a connection is ending. This method removes the connection from the connection manager and writes the metadata file if requested
 * by the user
 */
static void tcpReassemblyConnectionEndCallback(const pcpp::ConnectionData &connectionData,
                                               pcpp::TcpReassembly::ConnectionEndReason reason, void *userCookie) {
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
    std::cout << "Total number of data packets:      " << (iter->second.numOfDataPackets[0] + iter->second.numOfDataPackets[1]) << std::endl;
    std::cout << std::endl;
    std::cout << "Number of bytes in side 0:         " << iter->second.bytesFromSide[0] << std::endl;
    std::cout << "Number of bytes in side 1:         " << iter->second.bytesFromSide[1] << std::endl;
    std::cout << "Total number of bytes:             " << (iter->second.bytesFromSide[0] + iter->second.bytesFromSide[1]) << std::endl;
    std::cout << std::endl;
    std::cout << "Number of messages in side 0:      " << iter->second.numOfMessagesFromSide[0] << std::endl;
    std::cout << "Number of messages in side 1:      " << iter->second.numOfMessagesFromSide[1] << std::endl;

    // remove the connection from the connection manager
    connMgr->erase(iter);
}


/**
 * The callback to be called when application is terminated by ctrl-c. Stops the endless while loop
 */
static void onApplicationInterrupted(void *cookie) {
    bool *shouldStop = (bool *) cookie;
    *shouldStop = true;
}


/**
 * packet capture callback - called whenever a packet arrives on the live device (in live device capturing mode)
 */
static void onPacketArrives(pcpp::RawPacket *packet, pcpp::PcapLiveDevice *dev, void *tcpReassemblyCookie) {
    // get a pointer to the TCP reassembly instance and feed the packet arrived to it
    pcpp::TcpReassembly *tcpReassembly = (pcpp::TcpReassembly *) tcpReassemblyCookie;
    tcpReassembly->reassemblePacket(packet);
}


/**
 * The method responsible for TCP reassembly on live traffic
 */
void doTcpReassemblyOnLiveTraffic(pcpp::PcapLiveDevice *dev, pcpp::TcpReassembly &tcpReassembly) {
    // try to open device
    if (!dev->open()) {
        EXIT_WITH_ERROR("Cannot open interface");
    }

    std::cout << "Starting packet capture on '" << dev->getIPv4Address() << "'..." << std::endl;

//    // start capturing packets. Each packet arrived will be handled by onPacketArrives method
//    dev->startCapture(onPacketArrives, &tcpReassembly);

    // register the on app close event to print summary stats on app termination
    bool shouldStop = false;
    pcpp::ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, &shouldStop);

    // run in an endless loop until the user presses ctrl+c
    while (!shouldStop) {
        pcpp::multiPlatformSleep(1);
    }
    std::cout << "trying to stop 1" << std::endl;

    // stop capturing and close the live device
    dev->stopCapture();
    std::cout << "trying to stop 2" << std::endl;
    dev->close();
    std::cout << "trying to stop 3" << std::endl;
    // close all connections which are still opened
    tcpReassembly.closeAllConnections();
    std::cout << "trying to stop 4" << std::endl;
    std::cout << "Done! processed " << tcpReassembly.getConnectionInformation().size() << " connections" << std::endl;
}


/**
 * main method of this utility
 */
int main(int argc, char *argv[]) {
    pcpp::AppName::init(argc, argv);

    std::string interfaceNameOrIP;

    int optionIndex = 0;
    int opt = 0;

    while ((opt = getopt_long(argc, argv, "i:h", TcpAssemblyOptions, &optionIndex)) != -1) {
        switch (opt) {
            case 0:
                break;
            case 'i':
                interfaceNameOrIP = optarg;
                break;
            case 'h':
                printUsage();
                exit(0);
                break;
            default:
                printUsage();
                exit(-1);
        }
    }

    if (interfaceNameOrIP.empty()) {
        EXIT_WITH_ERROR("No interface was provided");
    }

    // create the object which manages info on all connections
    TcpReassemblyConnMgr connMgr;

    // create the TCP reassembly instance
    pcpp::TcpReassembly tcpReassembly(tcpReassemblyMsgReadyCallback, &connMgr, tcpReassemblyConnectionStartCallback,
                                      tcpReassemblyConnectionEndCallback);

    // analyze in live traffic mode
    // extract pcap live device by interface name or IP address
    pcpp::PcapLiveDevice *dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIpOrName(interfaceNameOrIP);
    if (dev == NULL) {
        EXIT_WITH_ERROR("Couldn't find interface by provided IP address or name");
    }

    // start capturing packets and do TCP reassembly
    doTcpReassemblyOnLiveTraffic(dev, tcpReassembly);
}
