#pragma once

#include <iostream>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

using namespace std;

void printMAC(uint8_t *mac);

void parsing(const u_char* packet);
