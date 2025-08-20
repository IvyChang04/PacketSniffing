#include "../include/PacketSniffer.hpp"
#include "../include/PacketHandler.hpp"

PacketSniffer::PacketSniffer(const std::string& interface) : interfaceName(interface), handle(nullptr){}

bool PacketSniffer::startCapture(){
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live(interfaceName.c_str(), BUFSIZ, 1, 1000, errbuf);

    if(handle == nullptr){
        std::cerr << "Error capturing packets on interface " << interfaceName << ": " << errbuf <<std::endl;
        return false;
    }

    std::cout << "Starting packet cpature on interface " << interfaceName << std::endl;
    pcap_loop(handle, 0, PacketHandler::handlePacket, nullptr);
    pcap_close(handle);
    return true;
}