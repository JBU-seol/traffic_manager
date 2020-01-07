#include "tcpManage.h"
#include "dbManage.h"

tcpManage::tcpManage(){
    hdsh[0] = false;
    hdsh[1] = false;
    hdsh[2] = false;
    c_m=nullptr;
    bps = 0;
    pps = 0;
    iter = flow.end();
};
tcpManage::~tcpManage(){ };

void tcpManage::hdshzero(){
    hdsh[0]=false;
    hdsh[1]=false;
    hdsh[2]=false;
}

bool tcpManage::hdshcheck(){
    if( hdsh[0]==true && hdsh[1]==true && hdsh[2]==true) return true;
    else return false;
}

void tcpManage::doTraffic(u_char* packet,struct pcap_pkthdr* header,class DbManage& db){
    struct libnet_ethernet_hdr* eth_p = reinterpret_cast<struct libnet_ethernet_hdr*>(const_cast<u_char*>(packet));
    struct libnet_ipv4_hdr* ipv4_p = reinterpret_cast<struct libnet_ipv4_hdr*>(const_cast<u_char*>(packet) + sizeof(struct libnet_ethernet_hdr));
    struct libnet_tcp_hdr* tcp_p = reinterpret_cast<struct libnet_tcp_hdr*>(reinterpret_cast<char*>(ipv4_p) + (ipv4_p->ip_hl<<2));
    memset(&row,0,sizeof(row));
    memset(&addr,0,sizeof(struct in_addr));
    sport = ntohs(tcp_p->th_sport);
    if( sport > 1024 ){
        c_m = eth_p->ether_shost;
        dport = ntohs(tcp_p->th_dport);
        c_i = ipv4_p->ip_src.s_addr;
        s_i = ipv4_p->ip_dst.s_addr;
    }
    else{
        c_m = eth_p->ether_dhost;
        sport = ntohs(tcp_p->th_dport);
        dport = ntohs(tcp_p->th_sport);
        c_i = ipv4_p->ip_dst.s_addr;
        s_i = ipv4_p->ip_src.s_addr;
    }
    flowkey fk(c_i,s_i,sport,dport);
    switch(tcp_p->th_flags){
    case TH_SYN:
        hdsh[0]=true;
        break;
    case (TH_SYN|TH_ACK):
        hdsh[1]=true;
        break;
    case TH_ACK:
        hdsh[2]=true;
        break;
    case (TH_FIN|TH_ACK): // Session finish 1
    case TH_RST: // Session finish 2
        std::cout << "FIN & RST " << std::endl;
        iter = flow.find(fk);
        if(iter != flow.end() && iter->second.pps != 0){
            memcpy(&addr.s_addr, &iter->first.server_ip, 4);
            s_pointer = inet_ntoa(addr);
            std::cout  <<iter->second.pps << " / " <<iter->second.bps << std::endl;
            printf("%s\n",s_pointer);
            row = db.getDomain(s_pointer);
            if(row == nullptr){
                std::cout << " fail" << std::endl;
            }
            else{
                std::cout << " success" << std::endl;
                db.insertLog(iter->second.macaddr,row[0],static_cast<unsigned int>(iter->second.stime),static_cast<unsigned int>(header->ts.tv_sec),iter->second.bps,iter->second.pps);

            }
        }
        flow.erase(fk);
        iter = flow.end();
        hdshzero();
        break;
    case (TH_PUSH|TH_ACK): // TCP Data
        iter = flow.find(fk);
        if( iter != flow.end()){
            iter->second.bps+=header->caplen;
            iter->second.pps++;
        }
        hdshzero();
        break;
    }
    if(hdshcheck()){ // 3WAY Hand Shaking
        std::cout << "3WAY Hand Shaking " << std::endl;
        t = header->ts.tv_sec;
        flowvalue fv(c_m,t,bps,pps);
        if( flow.find(fk) == flow.end() ){
            auto ret = flow.insert(std::pair<flowkey,flowvalue>(fk,fv));
            if(ret.second == false){
                addr.s_addr = fk.server_ip;
                std::cout << " flow map insert error " << inet_ntoa(addr)<< std::endl;
                addr.s_addr = ret.first->first.server_ip;
                std::cout << " flow map insert error " << inet_ntoa(addr)<< std::endl;
            }
        }
    }
}
