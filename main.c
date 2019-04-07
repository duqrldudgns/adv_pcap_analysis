#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "pcap.h"

void printMAC(uint8_t* mac){
    for(int i=0;i<6;i++){
        printf("%02x",mac[i]);
        if(i<5)printf(":");
    }
}

void printIP(uint32_t ip){
    char buf[20];
    printf("%s",inet_ntop(AF_INET,&ip,buf,sizeof(buf)));
}

void printTCP(uint16_t tcp){
    printf("%d", ntohs(tcp));
}

void printHTTP(uint8_t* http,int count){
    if(count >16)count=16;
    for(int i=0;i<count;i++) printf("%c",*(http+i));
}

void usage() {
    printf("syntax: pcap_test <interface>\n");
    printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    while (1) {
        struct pcap_pkthdr* header;
        const uint8_t* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        printf("%u bytes captured\n", header->caplen);

        struct ethernet_header *eh 	= (struct ethernet_header *) packet;
        if(ntohs(eh->type)==0x0800){
            struct ip_header *iph 	= (struct ip_header *) (packet+sizeof(struct ethernet_header));
            if(iph->protocol==6){
                struct tcp_header *tcph	= (struct tcp_header *) ((uint8_t *)iph+(iph->hlength<<2));
                if((ntohs(tcph->dport)==80 || ntohs(tcph->sport)==80)){
                    uint8_t * httph = (uint8_t *)tcph+(tcph->offset<<2);
                    int count = ntohs(iph->totallen) - (iph->hlength<<2) - (tcph->offset<<2);
                    if(count ==0)continue;	//http x
                    printf("=============HTTP CATCH==============");

                    printf("\nSmac  : ");
                    printMAC(eh->smac);
                    printf("\nDmac  : ");
                    printMAC(eh->dmac);

                    printf("\nSIP   : ");
                    printIP(iph->sip);
                    printf("\nDIP   : ");
                    printIP(iph->dip);

                    printf("\nSPort : ");
                    printTCP(tcph->sport);
                    printf("\nDPort : ");
                    printTCP(tcph->dport);

                    printf("\nHTTP  : ");
                    printHTTP(httph, count);

                    printf("\n=====================================\n");
                }
            }

        }
    }
    pcap_close(handle);
    return 0;
}

