#include <libnet.h>
#include <string>
#include <mutex>
#ifndef DNSMANAGE_H
#define DNSMANAGE_H

#endif // DNSMANAGE_H


struct dnsAnswer{
    uint16_t name;
    uint16_t type;
    uint16_t cls;
    uint16_t ttl1;
    uint16_t ttl2;
    uint16_t data_length;
    uint32_t address;
};

class dnsManage{
public:
    uint32_t server_ip;
    char* c_i = nullptr;
    char* s_i = nullptr;
    struct in_addr addr;
    std::mutex mu;
    dnsManage();
    ~dnsManage();
    void doResponse(u_char* packet,class DbManage& db);
};
