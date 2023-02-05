cmake_minimum_required(VERSION 3.22)
project(netdata_to_userland_perftest)

add_subdirectory(src/libpcap)
add_subdirectory(src/xdp_tc)
#add_subdirectory(src/tracepoint)
#add_subdirectory(src/uprobe)

include_directories(include src/libs/packet_handler)