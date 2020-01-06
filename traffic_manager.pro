TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

LIBS += -lpcap
LIBS += -lpthread
LIBS += -lmariadbclient

SOURCES += \
        dbManage.cpp \
        dnsManage.cpp \
        main.cpp \
        tcpManage.cpp

HEADERS += \
    dbManage.h \
    dnsManage.h \
    tcpManage.h



