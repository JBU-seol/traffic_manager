#include <libnet.h>
#include <iostream>
#include <time.h>
#include <pcap.h>
#include <map>
#include <mutex>
#include "dbManage.h"
#ifndef TCPMANAGE_H
#define TCPMANAGE_H

#endif // TCPMANAGE_H

class flowkey{
public:
    uint32_t client_ip;
    uint32_t server_ip;
    uint16_t client_port;
    uint16_t server_port;
    flowkey(){ }
    ~flowkey(){ }
    flowkey(uint32_t c_i, uint32_t s_i, uint16_t sport, uint16_t dport){
        client_ip = c_i;
        server_ip = s_i;
        client_port = sport;
        server_port = dport;
    }
    bool operator<(const flowkey& k) const
    {
        if( client_ip != k.client_ip){
            return client_ip < k.client_ip;
        }
        else if( server_ip != k.server_ip){
            return server_ip < k.server_ip;
        }
        else if( client_port != k.client_port){
            return client_port < k.client_port;
        }
        return server_port < k.server_port;
    }
};

class flowvalue{
public:
    uint8_t macaddr[6];
    __time_t stime;
    uint32_t bps;
    uint32_t pps;
    flowvalue(){ }
    ~flowvalue(){ }
    flowvalue(uint8_t* m,__time_t _stime,uint32_t _bps, uint32_t _pps){
        memcpy(macaddr, m, 6);
        stime = _stime;
        bps = _bps;
        pps = _pps;
    }
    bool operator<(const flowvalue& v) const
    {
        if( macaddr != v.macaddr){
            return macaddr < v.macaddr;
        }
        else if( stime != v.stime){
            return stime < v.stime;
        }
        else if( bps != v.bps){
            return bps < v.bps;
        }
        return pps < v.pps;
    }
};

class tcpManage{
public:
    bool hdsh[3];
    uint32_t c_i, s_i;
    uint16_t sport, dport;
    uint8_t* c_m;
    uint8_t c_mac[6];
    uint32_t bps = 0;
    uint32_t pps = 0;
    __time_t t;
    char* s_pointer;
    char* temp;
    struct in_addr addr;
    MYSQL_ROW row;
    std::map<flowkey,flowvalue> flow;
    std::map<flowkey,flowvalue>::iterator iter;
    tcpManage();
    ~tcpManage();
    void hdshzero();
    bool hdshcheck();
    void doTraffic(u_char* packet,struct pcap_pkthdr* header,class DbManage& db);
};




