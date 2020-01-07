#include <iostream>
#include <pcap.h>
#include <libnet.h>
#include <thread>
#include "dbManage.h"
#include "dnsManage.h"
#include "tcpManage.h"

using namespace std;
/*
./traffic_manager eth0 localhost root toor ccitproject
*/

int main(int argc, char* argv[])
{
    if(argc < 2) exit(0);
    DbManage db(argv[2], argv[3], argv[5]);
    dnsManage dns;
    tcpManage tcp;
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr* header;
    const u_char* packet;
    //pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    pcap_t* handle = pcap_open_offline("/root/Desktop/3.pcap",errbuf);
    if( handle == nullptr){
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        exit(-1);
    }
    while(1){
        int res = pcap_next_ex(handle, &header, &packet);
        if( res == -1 | res == -2 ){
            fprintf(stderr, "pcap_open_offline() Read Finish ! \n");
            exit(-1);
        }
        struct libnet_ethernet_hdr* eth_p = reinterpret_cast<struct libnet_ethernet_hdr*>(const_cast<u_char*>(packet));
        if(ntohs(eth_p->ether_type) == ETHERTYPE_IP){
            struct libnet_ipv4_hdr* ipv4_p = reinterpret_cast<struct libnet_ipv4_hdr*>(const_cast<u_char*>(packet) + sizeof(struct libnet_ethernet_hdr));
            if(ipv4_p->ip_p == IPPROTO_UDP){
                struct libnet_udp_hdr* udp_p = reinterpret_cast<struct libnet_udp_hdr*>(reinterpret_cast<char*>(ipv4_p) + (ipv4_p->ip_hl<<2));
                if(ntohs(udp_p->uh_sport) == 53){// Query Response
                    dns.doResponse(const_cast<u_char*>(packet),ref(db));
                }
            }
            else{
                tcp.doTraffic(const_cast<u_char*>(packet),header,ref(db));
            }

        }
    }
}




