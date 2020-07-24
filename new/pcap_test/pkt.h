#pragma once

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define ETH_LEN 14

#define IP_P_TCP 0x06


void printMAC(uint8_t *mac);

void printIP(uint32_t ip);

void printTCPDATA(uint8_t* tcpdata,int tcpdata_len);

void parsing(const u_char* packet);
