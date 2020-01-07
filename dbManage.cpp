#include "dbManage.h"

DbManage::DbManage() { }

DbManage::~DbManage(){
    mysql_free_result(result);
    mysql_close(conn);
}

DbManage::DbManage(const char* db_server, const char* user, const char* db_name){
    if(!mysql_real_connect(conn, db_server, user, "", nullptr, 0, nullptr, 1)){
        printf("cannot connect");
        //exit(1);
    }
    else{
        if (mysql_select_db(conn, db_name)){
            printf("cannot use databases");
            //exit(1);
        }
    }
}

DbManage::DbManage(const char* db_server, const char* user, const char* pass, const char* db_name){
    if(!mysql_real_connect(conn, db_server, user, pass, nullptr, 0, nullptr, 1)){
        printf("cannot connect");
        exit(1);
    }
    else{
        if (mysql_select_db(conn, db_name)){
            printf("cannot use databases");
            //exit(1);
        }
    }
}

void DbManage::insertClient(uint8_t* mac, char* ip){
    char tmp_time[16];
    char macbuf[16];
    char query_buffer[2048]={0, };
    sprintf(tmp_time, "%ld", time(nullptr));
    sprintf(query_buffer, "REPLACE INTO Client (Mac, Ip, log) VALUES (");
    strcat(query_buffer, "\"");
    sprintf(macbuf,"%02X%02X%02X%02X%02X%02X",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    strcat(query_buffer,macbuf);
    strcat(query_buffer, "\",\"");
    strcat(query_buffer, ip);
    strcat(query_buffer, "\",");
    strcat(query_buffer, tmp_time);
    strcat(query_buffer, ")");
    //mysql_free_result(result);
    if (mysql_query(conn, query_buffer)){
        printf("query faild : %s\n error : %s\n", query_buffer, mysql_error(conn));
    }

    result = mysql_use_result(conn);
    while ((row = mysql_fetch_row(result)) != nullptr)
        printf("%s \n", row[0]);

}

void DbManage::insertServer(char *ip, char* domain, uint8_t* mac){
    char query_buffer[2048]={0, };
    char macbuf[16];
    char tmp_time[16];
    sprintf(tmp_time, "%ld", time(nullptr));

    sprintf(query_buffer, "INSERT INTO Server (Ip, Domain, ClientMac) VALUES (");
    strcat(query_buffer, "\"");
    strcat(query_buffer, ip);
    strcat(query_buffer, "\",\"");
    strcat(query_buffer, domain);
    strcat(query_buffer, "\",\"");
    sprintf(macbuf,"%02X%02X%02X%02X%02X%02X",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    strcat(query_buffer, macbuf);
    strcat(query_buffer, "\")");

    //mysql_free_result(result);
    if (mysql_query(conn, query_buffer)){
        printf("query faild : %s\n error: %s\n", query_buffer, mysql_error(conn));
    }

    result = mysql_use_result(conn);
    while ((row = mysql_fetch_row(result)) != nullptr)
        printf("%s \n", row[0]);

}

void DbManage::insertLog(uint8_t *c_mac, char *domain, unsigned int stime, unsigned int etime, uint32_t bps, uint32_t pps){
    char query_buffer[2048]={0, };
    char macbuf[16];
    char s_time[16], e_time[16], byteps[16], packetps[16];
    sprintf(e_time, "%d", etime);
    sprintf(s_time, "%d", stime);
    sprintf(byteps, "%d", bps);
    sprintf(packetps,"%d",pps);
    sprintf(query_buffer, "INSERT INTO Log (ClientMac, Domain, STime, ETime, Bps, Pps) VALUES (");
    strcat(query_buffer, "\"");
    sprintf(macbuf,"%02X%02X%02X%02X%02X%02X",c_mac[0],c_mac[1],c_mac[2],c_mac[3],c_mac[4],c_mac[5]);
    strcat(query_buffer, macbuf);
    strcat(query_buffer, "\",\"");
    strcat(query_buffer, domain);
    strcat(query_buffer, "\",");
    strcat(query_buffer, s_time);
    strcat(query_buffer, ",");
    strcat(query_buffer, e_time);
    strcat(query_buffer, ",");
    strcat(query_buffer, byteps);
    strcat(query_buffer, ",");
    strcat(query_buffer, packetps);
    strcat(query_buffer, ")");
    std::cout << "mysql free " << std::endl;
    mysql_free_result(result);
    if (mysql_query(conn, query_buffer)){
        printf("query faild : %s\n error : %s\n", query_buffer, mysql_error(conn));
        //exit(1);
    }
    std::cout << "mysql free result " << std::endl;
    result = mysql_use_result(conn);
    while ((row = mysql_fetch_row(result)) != nullptr)
        printf("%s \n", row[0]);

}

MYSQL_ROW DbManage::getDomain(char* ip){
    char query_buffer[2048]={0, };
    // select Domain from Server where Ip="175.35.241.150"
    sprintf(query_buffer, "SELECT Domain FROM Server WHERE Ip =\"");
    strcat(query_buffer, ip);
    strcat(query_buffer, "\"");
    if (mysql_query(conn, query_buffer)){
        printf("query faild : %s\n error : %s\n", query_buffer, mysql_error(conn));
        //exit(1);
    }
    //mysql_free_result(result);
    result = mysql_use_result(conn);
    if ((row = mysql_fetch_row(result)) != nullptr){
        printf("Get Domain : %s \n", row[0]);
        return row;
    }
    else
        return nullptr;
}

//MYSQL_ROW DbManage::getLog(char* c_mac, int st, int et){
//    char query_buffer[2048]={0, };
//    char macbuf[16];
//    char stime[16];
//    char etime[16];
//    sprintf(stime,"%d",st);
//    sprintf(etime,"%d",et);
//    // select ClientMac, Domain, Bps, Pps from Log
//    //where ClientMac="[macaddr]" and STime>=[st] and ETime<[et];
//    sprintf(query_buffer, "SELECT ClientMac, Domain, Bps, Pps FROM Log WHERE ClientMac =\"");
//    sprintf(macbuf,"%c%c%c%c%c%c%c%c%c%c%c%c",c_mac[0],c_mac[1],c_mac[2],c_mac[3],c_mac[4],c_mac[5],c_mac[6],c_mac[7],c_mac[8],c_mac[9],c_mac[10],c_mac[11]);
//    strcat(query_buffer, macbuf);
//    strcat(query_buffer, "\" AND STime>=");
//    strcat(query_buffer, stime);
//    strcat(query_buffer, " AND ETime<");
//    strcat(query_buffer, etime);
//    //mysql_free_result(result);
//    if (mysql_query(conn, query_buffer)){
//        printf("query faild : %s\n error : %s\n", query_buffer, mysql_error(conn));
//        //exit(1);
//    }
//    std::cout << "[Log DATA]" << std::endl;
//    result = mysql_use_result(conn);
//    while ((row = mysql_fetch_row(result)) != nullptr){
//        printf("Client : %s     Domain : %s     Bps : %s    Pps : %s\n", row[0],row[1],row[2],row[3]);
//    }
//    return row;
//}
