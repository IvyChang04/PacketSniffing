#include "../include/PacketHandler.hpp"
#include "../include/PacketParser.hpp"
#include "../include/Logger.hpp"

void PacketHandler::handlePacket(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    PacketParser parser;
    ParsedPacket parsedPaket = parser.parsePacket(header, packet);
    Logger logger("packet_log.log");

    std::stringstream ss;

    if (parsedPaket.protocol == "TCP") {
        ss << parsedPaket.timeStamp << " " 
           << parsedPaket.protocol << " " 
           << parsedPaket.srcIP << ":" << parsedPaket.srcPort
           << " -> " 
           << parsedPaket.dstIP << ":" << parsedPaket.dstPort
           << " | Packet Length: " << parsedPaket.packetSize
           << " | " << parsedPaket.summary;
    }
    else if (parsedPaket.protocol == "UDP") {
        ss << parsedPaket.timeStamp << " " 
           << parsedPaket.protocol << " " 
           << parsedPaket.srcIP << ":" << parsedPaket.srcPort
           << " -> " 
           << parsedPaket.dstIP << ":" << parsedPaket.dstPort
           << " | Packet Length: " << parsedPaket.packetSize;
    }
    else if (parsedPaket.protocol == "ICMP") {
        ss << parsedPaket.timeStamp << " " 
           << parsedPaket.protocol << " " 
           << parsedPaket.srcIP
           << " -> " 
           << parsedPaket.dstIP
           << " | Packet Length: " << parsedPaket.packetSize
           << " | " << parsedPaket.summary;
    }
    else if (parsedPaket.protocol == "ARP") {
        ss << parsedPaket.timeStamp << " "
           << parsedPaket.summary;
    }
    else {
        ss << parsedPaket.timeStamp << " "
           << parsedPaket.protocol << " "
           << parsedPaket.srcIP << " -> "
           << parsedPaket.dstIP
           << " | Packet Length: " << parsedPaket.packetSize
           << " | " << parsedPaket.summary;
    }
 
    logger.log(ss.str());
    std::cout << ss.str() << "\n";
}