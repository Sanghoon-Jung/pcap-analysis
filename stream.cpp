#include "stream.h"

bool flowinfo::operator<(const flowinfo& other) const{
    if(protocol != other.protocol) return protocol < other.protocol;
    if(src_ip != other.src_ip) return src_ip < other.src_ip;
    if(src_port != other.src_port) return src_port < other.src_port;
    if(dst_ip != other.dst_ip) return dst_ip < other.dst_ip;
    return dst_port < other.dst_port;
};

bool flowinfo::operator==(const flowinfo& other) const{
    return (protocol == other.protocol) && (src_ip == other.src_ip)
            && (src_port == other.src_port) && (dst_ip == other.dst_ip)
            && (dst_port == other.dst_port);
};

bool streaminfo::operator<(const streaminfo& other) const{
    if(protocol != other.protocol) return protocol < other.protocol;
    return f1 < other.f1;
};