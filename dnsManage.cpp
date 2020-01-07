#include "dnsManage.h"
#include <dbManage.h>

using namespace std;

dnsManage::dnsManage(){ };
dnsManage::~dnsManage(){ };

void dnsManage::doResponse(u_char* packet,class DbManage& db){
    struct libnet_ethernet_hdr* eth_p = reinterpret_cast<struct libnet_ethernet_hdr*>(const_cast<u_char*>(packet));
    struct libnet_ipv4_hdr* ipv4_p = reinterpret_cast<struct libnet_ipv4_hdr*>(const_cast<u_char*>(packet) + sizeof(struct libnet_ethernet_hdr));
    struct libnet_udp_hdr* udp_p = reinterpret_cast<struct libnet_udp_hdr*>(reinterpret_cast<char*>(ipv4_p) + (ipv4_p->ip_hl<<2));
    struct libnet_dnsv4udp_hdr* dns_p = reinterpret_cast<struct libnet_dnsv4udp_hdr*>(reinterpret_cast<char*>(udp_p) + sizeof(struct libnet_udp_hdr));
    uint8_t* dns_query = reinterpret_cast<uint8_t*>( reinterpret_cast<char*>(dns_p) + sizeof(struct libnet_dnsv4udp_hdr));
    string host(reinterpret_cast<char*>(dns_query));
    struct dnsAnswer* ans = reinterpret_cast<struct dnsAnswer*>( reinterpret_cast<char*>(dns_query) + host.size()+5);
    uint16_t num = ntohs(dns_p->num_answ_rr);//DNS Answer's num
    uint8_t* c_m = eth_p->ether_dhost;
    memset(&addr,0,sizeof(struct in_addr));
    switch(num){
    case 0:
        break;
    case 1:
        if( ntohs(ans->type) == 1){
            memcpy(&server_ip, &ans->address, 4);
            memcpy(&addr.s_addr, &ans->address, 4);
            s_i = inet_ntoa(addr);
            mu.lock();
            db.insertServer(s_i,const_cast<char*>(host.c_str()),c_m);
            mu.unlock();
            //cout << host << "  /  " << "1----server ip : " << inet_ntoa(addr) << endl;
        }
        break;
    default:
        for(; num>0; num--){
            if( ntohs(ans->type) == 1){// A
                memcpy( &server_ip, &ans->address, 4);
                memcpy(&addr.s_addr, &ans->address, 4);
                s_i = inet_ntoa(addr);
                mu.lock();
                db.insertServer(s_i,const_cast<char*>(host.c_str()),c_m);
                mu.unlock();
                //cout << host << "  /  " << "2---server ip : " << inet_ntoa(addr) << endl;
                ans = reinterpret_cast<struct dnsAnswer*>(reinterpret_cast<char*>(ans) + sizeof(struct dnsAnswer));
            }
            else if(ntohs(ans->type)==5){// CNAME
                ans = reinterpret_cast<struct dnsAnswer*>(reinterpret_cast<char*>(ans) + 12 + ntohs(ans->data_length));
            }
        }
    }
    memcpy(&addr.s_addr, &ipv4_p->ip_dst.s_addr, 4);
    c_i = inet_ntoa(addr);
//    printf("%02X%02X%02X%02X%02X%02X",c_m[0],c_m[1],c_m[2],c_m[3],c_m[4],c_m[5]);
//    cout << " / " << inet_ntoa(addr) << endl;
    mu.lock();
    db.insertClient(c_m,c_i);
    mu.unlock();
}
