#include "../include/PacketParser.hpp"

ParsedPacket PacketParser::parsePacket(const struct pcap_pkthdr* header, const u_char* packet) {
    parsedPacket = {};
    parsedPacket.packetSize = header->len;

    time_t rawtime = header->ts.tv_sec;
    suseconds_t micro = header->ts.tv_usec;

    struct tm * timeinfo = localtime(&rawtime);
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%F %T", timeinfo);

    parsedPacket.timeStamp = "[" + std::string(buffer) + "." + std::to_string(micro) + "]";

    parseEthernet(packet);
    return parsedPacket;
}

void PacketParser::parseEthernet(const u_char* packet) {
    const struct ether_header* eth = (struct ether_header*) packet;
    uint16_t etherType = ntohs(eth->ether_type);
    if (etherType == ETHERTYPE_IP) {
        parseIPv4(packet + sizeof(struct ether_header));
    }
    else if (etherType == ETHERTYPE_ARP) {
        parseARP(packet + sizeof(struct ether_header));
        parsedPacket.protocol = "ARP";
    }
    else if (etherType == ETHERTYPE_IPV6) {
        parseIPv6(packet + sizeof(struct ether_header));
    }
    else {
        parsedPacket.summary = "unsupported packet type" + std::to_string(etherType);
        parsedPacket.protocol = etherType;
    }
}

void PacketParser::parseARP(const u_char* packet){
    const struct arp_header* arpHeader = (struct arp_header*) packet;
    uint16_t opCode = ntohs(arpHeader->opCode);

    char senderIP[INET_ADDRSTRLEN];
    char targetIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, arpHeader->spa, senderIP, sizeof(senderIP));
    inet_ntop(AF_INET, arpHeader->tpa, targetIP, sizeof(targetIP));

    char senderMAC[18];
    snprintf(senderMAC, sizeof(senderMAC), "%02x:%02x:%02x:%02x:%02x:%02x",
             arpHeader->sha[0], arpHeader->sha[1], arpHeader->sha[2],
             arpHeader->sha[3], arpHeader->sha[4], arpHeader->sha[5]);

    if (opCode == 1){
        parsedPacket.summary = std::string("ARP Request: Who has ") + targetIP + "? Tell " + senderIP;
    }
    else if (opCode == 2){
        parsedPacket.summary = std::string("ARP Reply: ") + senderIP + " is at " + senderMAC;
    }
    else {
        parsedPacket.summary = "Unknown ARP operation code: " + std::to_string(opCode);
    }
    
}

void PacketParser::parseIPv4(const u_char* packet) {
    const struct ip* ipHeader = (struct ip*) packet;
    int ipHeaderLength = ipHeader->ip_hl * 4;

    parsedPacket.srcIP = inet_ntoa(ipHeader->ip_src);
    parsedPacket.dstIP = inet_ntoa(ipHeader->ip_dst);

    switch (ipHeader->ip_p){
        case IPPROTO_TCP: {
            parsedPacket.protocol = "TCP";
            parseTCP(packet + ipHeaderLength, ipHeaderLength);
            break;
        }
        case IPPROTO_UDP: {
            parsedPacket.protocol = "UDP";
            parseUDP(packet + ipHeaderLength, ipHeaderLength);
            break;
        }
        case IPPROTO_ICMP: {
            const struct icmp* icmpHeader = (struct icmp*)(packet + ipHeaderLength);
            if (icmpHeader->icmp_type == ICMP_ECHO){
                parsedPacket.summary = "Type: Echo Request";
            }
            else if (icmpHeader->icmp_type == ICMP_ECHOREPLY){
                parsedPacket.summary = "Type: Echo Reply";
            }
            else {
                parsedPacket.summary = "Type: " + std::to_string(icmpHeader->icmp_type);
            }
            parsedPacket.protocol = "ICMP";
            break;
        }
        default: {
            parsedPacket.protocol = "Unsupported protocol";
            parsedPacket.summary = "Unsupported protocol: " + std::to_string(ipHeader->ip_p);
        }
    }
}

void PacketParser::parseIPv6(const u_char* packet) {
    const struct ip6_hdr* ip6Header = (struct ip6_hdr*) packet;
    int ipHeaderLength = 40;  // IPv6 headers are fixed at 40 bytes

    char srcIP[INET6_ADDRSTRLEN];
    char dstIP[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(ip6Header->ip6_src), srcIP, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ip6Header->ip6_dst), dstIP, INET6_ADDRSTRLEN);

    parsedPacket.srcIP = std::string(srcIP);
    parsedPacket.dstIP = std::string(dstIP);

    switch (ip6Header->ip6_nxt) {
        case IPPROTO_TCP: {
            parsedPacket.protocol = "TCP";
            parseTCP(packet + ipHeaderLength, ipHeaderLength, true);
            break;
        }
        case IPPROTO_UDP: {
            parsedPacket.protocol = "UDP";
            parseUDP(packet + ipHeaderLength, ipHeaderLength, true);
            break;
        }
        case IPPROTO_ICMPV6: {
            const struct icmp6_hdr* icmp6Header = (struct icmp6_hdr*)(packet + ipHeaderLength);
            if (icmp6Header->icmp6_type == 128){
                parsedPacket.summary = "Type: Echo Request";
            }
            else if (icmp6Header->icmp6_type == 129){
                parsedPacket.summary = "Type: Echo Reply";
            } else {
                parsedPacket.summary = "Type: " + std::to_string(icmp6Header->icmp6_type);
            }
            parsedPacket.protocol = "ICMPv6";
            break;
        }
        default: {
            parsedPacket.protocol = "Unsupported protocol";
            parsedPacket.summary = "Unsupported protocol: " + std::to_string(ip6Header->ip6_nxt);
        }
    }
}

void PacketParser::parseTCP(const u_char* packet, int ipHeaderLength,  bool isIPv6) {
    const struct tcphdr* tcp = (struct tcphdr*)(packet + ipHeaderLength);

    // Port numbers
    parsedPacket.srcPort = ntohs(tcp->th_sport);
    parsedPacket.dstPort = ntohs(tcp->th_dport);

    // Payload
    const u_char* payload = packet + ipHeaderLength + tcp->th_off * 4;
    int payloadSize;

    if (isIPv6) {
        const struct ip6_hdr* ip6 = (struct ip6_hdr*)(packet);
        payloadSize = ntohs(ip6->ip6_plen) - tcp->th_off * 4;
    }
    else{
        const struct ip* ip4 = (struct ip*)(packet);
        payloadSize = ntohs(ip4->ip_len) - ipHeaderLength - tcp->th_off * 4;
    }

    if(payloadSize > 0) {
        parsedPacket.payload.assign(payload, payload + payloadSize);
    }

    // Flags
    parsedPacket.summary = "Flags: ";
    if (tcp->th_flags & TH_FIN)  parsedPacket.summary += "FIN ";
    if (tcp->th_flags & TH_SYN)  parsedPacket.summary += "SYN ";
    if (tcp->th_flags & TH_RST)  parsedPacket.summary += "RST ";
    if (tcp->th_flags & TH_PUSH) parsedPacket.summary += "PUSH ";
    if (tcp->th_flags & TH_ACK)  parsedPacket.summary += "ACK ";
    if (tcp->th_flags & TH_URG)  parsedPacket.summary += "URG ";
    if (tcp->th_flags & TH_ECE)  parsedPacket.summary += "ECE ";
    if (tcp->th_flags & TH_CWR)  parsedPacket.summary += "CWR ";
}

void PacketParser::parseUDP(const u_char* packet, int ipHeaderLength, bool isIPv6) {
    const struct udphdr* udp = (struct udphdr*)(packet + ipHeaderLength);

    parsedPacket.srcPort = ntohs(udp->uh_sport);
    parsedPacket.dstPort = ntohs(udp->uh_dport);

    const u_char* payload = packet + ipHeaderLength + sizeof(struct udphdr);
    int payloadSize = ntohs(udp->uh_ulen) - sizeof(struct udphdr);

    if (isIPv6) {
        const struct ip6_hdr* ip6 = (struct ip6_hdr*)(packet - ipHeaderLength);
        payloadSize = ntohs(ip6->ip6_plen) - sizeof(struct udphdr);
    } else {
        const struct ip* ip4 = (struct ip*)(packet - ipHeaderLength);
        payloadSize = ntohs(ip4->ip_len) - ipHeaderLength - sizeof(struct udphdr);
    }

    if(payloadSize > 0) {
        parsedPacket.payload.assign(payload, payload + payloadSize);
    }
}

void PacketParser::printPayload(const u_char* payload, int size) {
    std::cout << "Payload:\n";
    for (int i = 0; i < size; ++i) {
        char c = static_cast<char>(payload[i]);
        std::cout << (std::isprint(c) ? c : '.');
    }
    std::cout << "\n\n";
}