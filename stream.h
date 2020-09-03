#pragma once
#include <string>
#include "types.h"

struct flowinfo{
    std::string protocol;
    std::string src_ip;
    int src_port;
    std::string dst_ip;
    int dst_port;

    bool operator<(const flowinfo& other) const;
    bool operator==(const flowinfo& other) const;
};

struct streaminfo{
    
    std::string protocol;
    flowinfo f1;                // A->B
    flowinfo f2;                // B->A
    
    int total_pkts = 0;
    int f1_pkts = 0;
    int f2_pkts = 0;
    
    int total_bytes = 0;
    int f1_bytes = 0;
    int f2_bytes = 0;

    bool operator<(const streaminfo& other) const;
};