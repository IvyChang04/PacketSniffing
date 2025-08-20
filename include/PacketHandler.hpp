#ifndef PACKET_HANDLER_HPP
#define PACKET_HANDLER_HPP

#include <pcap.h>
#include <iostream>
#include <sstream>

class PacketHandler {
public:
    static void handlePacket(u_char* args, const struct pcap_pkthdr* header, const u_char* packet);
};

#endif