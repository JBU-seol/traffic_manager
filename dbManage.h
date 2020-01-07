#include <iostream>
#include <string.h>
#include <stdlib.h>
#include <ctime>
#include <mariadb/my_global.h>
#include <mariadb/mysql.h>
#pragma once
class DbManage{
public:

    MYSQL *conn = mysql_init(nullptr);
    MYSQL_RES *result;
    MYSQL_ROW row;

    DbManage();
    ~DbManage();
    DbManage(const char *db_server, const char *user, const char* db_name);
    DbManage(const char* db_server, const char* user, const char* pass, const char *db_name);
    void test();
    void insertClient(uint8_t *mac, char* ip);
    void insertServer(char *ip, char* domain, uint8_t* mac);
    void insertLog(uint8_t *c_mac, char* domain, unsigned int stime, unsigned int etime, uint32_t bps, uint32_t pps);
    MYSQL_ROW getDomain(char *ip);
    MYSQL_ROW getLog(char* mac, int st, int et);
};
