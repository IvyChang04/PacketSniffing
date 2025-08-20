# PacketSniffing

A simple packet sniffing tool using libpcap, written in C++. It captures and parses network packets on a specified interface, logging details about TCP, UDP, ICMP, ARP, and IPv6 traffic.

## Features

-   Captures packets on a specified network interface
-   Parses Ethernet, IPv4, IPv6, TCP, UDP, ICMP, and ARP headers
-   Logs packet details to `packet_log.log`
-   Outputs packet summaries to the console

## Requirements

-   C++17 compiler (tested with `clang++`)
-   [libpcap](https://www.tcpdump.org/)
-   [cxxopts](https://github.com/jarro2783/cxxopts) (for command-line parsing)

## Build

```sh
make
```

## Usage

```sh
./PacketSniffing <netowrk-interface>
```

Example:

```
./PacketSniffing eth0
```

## Output

-   Packet details are printed to the console and logged to `packet_log.log`.
-   Each log entry includes timestamp, protocol, source/destination IP and port, packet length, and protocol-specific summary.

### File Structure

-   `main.cpp` — Entry point, parses arguments and starts capture
-   `src/PacketSniffer.cpp` — Handles packet capture loop
-   `src/PacketHandler.cpp` — Processes and logs each packet
-   `src/PacketParser.cpp` — Parses packet headers and payloads
-   `src/Logger.cpp` — Thread-safe logging to file
-   `include/` — Header files for each component
-   `Makefile` — Build instructions
