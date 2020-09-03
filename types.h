#pragma once
#include <cstdint>
#include <libnet.h>

#pragma pack(push, 1)
struct ETHIP{
    libnet_ethernet_hdr eth_hdr;
    libnet_ipv4_hdr ip_hdr;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct ETHIPTCP{
    libnet_ethernet_hdr eth_hdr;
    libnet_ipv4_hdr ip_hdr;
    libnet_tcp_hdr tcp_hdr;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct ETHIPUDP{
    libnet_ethernet_hdr eth_hdr;
    libnet_ipv4_hdr ip_hdr;
    libnet_udp_hdr udp_hdr;
};
#pragma pack(pop)