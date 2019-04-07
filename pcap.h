#pragma once

#include <stdint.h>

struct ethernet_header{
    uint8_t dmac[6];
    uint8_t smac[6];
    uint16_t type;
};

struct ip_header{
    uint8_t hlength:4;	//Endian
    uint8_t ver:4;	//Endian
    uint8_t tos;
    uint16_t totallen;
    uint16_t id;
    uint16_t flagsandoff;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t sip;
    uint32_t dip;
};

struct tcp_header{
    uint16_t sport;
    uint16_t dport;
    uint32_t seqnum;
    uint32_t acknum;
    uint8_t reserved:4; //Endian
    uint8_t offset:4;	//Endian
    uint8_t flag;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgentpointer;
};

