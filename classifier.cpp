#include "classifier.h"

Classifier::Classifier(){ }

/* 질문할 부분 : 소멸자에서 초기화 안했더니 Segmentation Fault. 이유는? */
Classifier::~Classifier(){
    memset(&tmp, 0, sizeof(flowinfo));
    memset(&tmp2, 0, sizeof(flowinfo));
    memset(&stream, 0, sizeof(streaminfo));
}

void Classifier::printresult(){
    
    printf("---------------------------------------------------------------------- Conversations ----------------------------------------------------------------------\n\n");
    
    printf("%-12s%-18s%-12s%-18s%-12s%-12s%-12s%-16s%-16s%-16s%-16s\n", 
        "PROTOCOL", "Address A", "Port A", "Address B", "Port B", "Packets", "Bytes",
        "Packets A->B", "Bytes A->B", "Packets B->A", "Bytes B->A");
    
    std::map<int, streaminfo>::iterator iter;
    
    for(iter = streamtable.begin(); iter != streamtable.end(); iter++){
        printf("%-12s%-18s%-12d%-18s%-12d%-12d%-12d%-16d%-16d%-16d%-16d\n", 
            iter->second.protocol.c_str(), iter->second.f1.src_ip.c_str(), 
            iter->second.f1.src_port, iter->second.f2.src_ip.c_str(), 
            iter->second.f2.src_port, iter->second.total_pkts,
            iter->second.total_bytes, iter->second.f1_pkts, iter->second.f1_bytes,
            iter->second.f2_pkts, iter->second.f2_bytes);
    }
}

flowinfo Classifier::getFlowinfo(const u_char* packet, int ip_p){

    flowinfo flow;
    
    if(ip_p == IPPROTO_TCP){
        ETHIPTCP* tcp_pkt = (ETHIPTCP*)packet;
        flow.protocol = "TCP";
        flow.src_ip = inet_ntoa(tcp_pkt->ip_hdr.ip_src);
        flow.src_port = ntohs(tcp_pkt->tcp_hdr.th_sport);
        flow.dst_ip = inet_ntoa(tcp_pkt->ip_hdr.ip_dst);
        flow.dst_port = ntohs(tcp_pkt->tcp_hdr.th_dport);
    }
    else if(ip_p == IPPROTO_UDP){
        ETHIPUDP* udp_pkt = (ETHIPUDP*)packet;
        flow.protocol = "UDP";
        flow.src_ip = inet_ntoa(udp_pkt->ip_hdr.ip_src);
        flow.src_port = ntohs(udp_pkt->udp_hdr.uh_sport);
        flow.dst_ip = inet_ntoa(udp_pkt->ip_hdr.ip_dst);
        flow.dst_port = ntohs(udp_pkt->udp_hdr.uh_dport);
    }
    else{
        flow.protocol = "OTHERS";
    }

    return flow;
}

int Classifier::classify(struct pcap_pkthdr* header, const u_char* packet){
    
    // ip packet이 아닌경우 리턴
    ETHIP* ethip = (ETHIP*)packet;
    if(ntohs(ethip->eth_hdr.ether_type) != ETHERTYPE_IP) return -1;
    
    // flow information 저장
    tmp = getFlowinfo(packet, (int)ethip->ip_hdr.ip_p);
    if(tmp.protocol == "OTHERS") return -1;
    
    std::map<flowinfo, int>::iterator it = flowmap.find(tmp);  // 내가 잡은 패킷의 flow

    int streamid;

    // 내가 잡은 flow가 존재 x -> 반대까지 함께 생성
    if(it == flowmap.end()){
        memset(&stream, 0, sizeof(streaminfo));
        
        // 내가 잡은 패킷의 반대 flow 생성
        tmp2.protocol = tmp.protocol;
        tmp2.src_ip = tmp.dst_ip;
        tmp2.src_port = tmp.dst_port;
        tmp2.dst_ip = tmp.src_ip;
        tmp2.dst_port = tmp.src_port;

        streamid = streamtable.size() + 1;          // 현재 flow를 포함하는 stream의 id 새로 부여
        
        // 내가 잡은 패킷 flow -> protocol 정보 추가
        memcpy(&(stream.f1), &tmp, sizeof(flowinfo));
        stream.protocol = tmp.protocol;
        
        memcpy(&(stream.f2), &tmp2, sizeof(flowinfo));
        
        flowmap.insert(std::make_pair(tmp, streamid));
        flowmap.insert(std::make_pair(tmp2, streamid));
        streamtable.insert(std::make_pair(streamid, stream));
    }
    // 패킷 flow가 존재하는 경우
    else{
        streamid = it->second;
    }
    
    // stream total 정보 추가
    streamtable[streamid].total_pkts += 1;
    streamtable[streamid].total_bytes += header->caplen;

    // 지금 잡은 패킷의 flow가 f1인지 비교
    if(streamtable[streamid].f1 == tmp){
        streamtable[streamid].f1_pkts += 1;
        streamtable[streamid].f1_bytes += header->caplen;
    }
    // 아니면 f2이므로 f2에 정보 추가
    else{
        streamtable[streamid].f2_pkts += 1;
        streamtable[streamid].f2_bytes += header->caplen;
    }

    return 0;
}