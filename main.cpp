#include "include/PacketSniffer.hpp"
#include <cxxopts.hpp>

int main(int argc, const char * argv[]) {
    cxxopts::Options options(
        "PacketSniffer",
        "A simple packet sniffing tool using libpcap"
    );

    

    std::string interface = argv[1];

    PacketSniffer sniffer(interface);

    if (!sniffer.startCapture()) {
        std::cerr << "Failed to start packet capture on interface: " << interface << "\n";
        return 1;
    }

    return 0;
}
