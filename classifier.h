#pragma once
#include <cstdio>
#include <pcap.h>
#include <map>
#include <arpa/inet.h>
#include "stream.h"

class Classifier{

private:
    std::map<flowinfo, int> flowmap;
    std::map<int, streaminfo> streamtable;

    flowinfo tmp;
    flowinfo tmp2;
    streaminfo stream;
    
    flowinfo getFlowinfo(const u_char* packet, int ip_p);
    
public:
    Classifier();
    ~Classifier();
    int classify(struct pcap_pkthdr* header, const u_char* packet);
    void printresult();
};