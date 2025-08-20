#ifndef PACKET_PARSER_HPP
#define PACKET_PARSER_HPP

#include <pcap.h>
#include <string>
#include <vector>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <iostream>
#include <cstring>
#include <cctype>
#include <iomanip>
#include <sstream>
#include <ctime>
#include <cstdint>

struct ParsedPacket {
    std::string timeStamp = "";
    std::string srcIP = "";
    std::string dstIP = "";
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;
    std::string protocol = "";
    std::string summary = "";
    std::vector<uint8_t> payload = {};
    int packetSize = 0;
};

struct arp_header {
    uint16_t hwType;
    uint16_t pType;
    uint8_t hwLength;
    uint8_t pLength;
    uint16_t opCode;
    uint8_t sha[6];
    uint8_t spa[4];
    uint8_t tha[6];
    uint8_t tpa[4];
};

class PacketParser{
public:
    ParsedPacket parsePacket(const struct pcap_pkthdr* header, const u_char* packet);
private:
    ParsedPacket parsedPacket;
    void parseEthernet(const u_char* packet);
    void parseARP(const u_char* packet);
    void parseIPv4(const u_char* packet);
    void parseIPv6(const u_char* packet);
    void parseTCP(const u_char* packet, int ipHeaderLength, bool isIPv6 = false);
    void parseUDP(const u_char* packet, int ipHeaderLength, bool isIPv6 = false);
    void printPayload(const u_char* payload, int size);
};

#endif