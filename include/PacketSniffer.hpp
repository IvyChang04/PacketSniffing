#ifndef PACKET_SNIFFER_HPP
#define PACKET_SNIFFER_HPP

#include <pcap.h>
#include <string>
#include <iostream>

class PacketSniffer {
public:
    PacketSniffer(const std::string& interface);
    bool startCapture();
private:
    std::string interfaceName;
    pcap_t* handle;
};

#endif