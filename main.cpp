// #include <sys/stat.h>    주석처리한 부분 : open_live를 이용할때 ctrl+z로 stop하도록.
// #include <unistd.h>
#include <pcap.h>
#include <cstdio>
#include "classifier.h"

void usage();
//void sighandler(int signo);

//void (*CtrlZ)(int);
//bool stop = false;

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* fname = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(fname, errbuf);
    //pcap_t* handle = pcap_open_online(dev, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_offline(%s) return nullptr - %s\n", fname, errbuf);
        return -1;
    }
    
    printf("TCP/UDP Packet Capturing Start...\n");
    printf("filename: %s\n\n", fname);
    //printf("press < ctrl + z > to stop capturing and see the result\n");

    //CtrlZ = signal(SIGTSTP, sighandler);

    Classifier cf = Classifier();
    int count = 0;
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if(res == 0) continue;
        if(res == -1) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        if(res == -2){
            printf("\nEnd of packets\n");
            printf("total: %d packets\n\n", count);
            break;
        }
        
        if(cf.classify(header, packet) == -1) continue;
        count++;
        printf("#%d packet captured\n", count);

        //if(stop) break;
    }
    cf.printresult();

    pcap_close(handle);

    return 0;
}

void usage() {
    printf("syntax: pcap-analysis <pcap filename>\n");
    printf("sample: pcap-analysis demo.pcap\n");
}

/*
void sighandler(int signo){
    printf("\nStop Capturing...\n");
    stop = true;
}
*/
