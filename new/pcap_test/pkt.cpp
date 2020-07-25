#include "pkt.h"

void printMAC(uint8_t *mac){
    for(int i=0; i<6; i++){
        printf("%02x",mac[i]);
        if(i<5) printf(":");
    }
}

void parsing(const u_char* packet){
    static int pktcnt=1;
    struct ether_header *eth = (struct ether_header *) packet;

    if ( ntohs(eth->ether_type) == ETHERTYPE_IP ){
        struct ip *iph = (struct ip *)( (uint8_t *)eth + ETHER_HDR_LEN );

        if ( iph->ip_p == IPPROTO_TCP ){
            struct tcphdr *tcph = (struct tcphdr *)( (uint8_t *)iph + (iph->ip_hl << 2) );

            uint8_t *tcpdata = (uint8_t *)tcph + (tcph->th_off << 2);
            int tcpdata_len = ntohs(iph->ip_len) - (iph->ip_hl << 2) - (tcph->th_off << 2);

            printf("-------%02d TCP packet--------", pktcnt++);

            printf("\nEth dst  : ");
            printMAC(eth->ether_dhost);
            printf("\nEth src  : ");
            printMAC(eth->ether_shost);

            printf("\n IP src  : %s", inet_ntoa(iph->ip_src));
            printf("\n IP dst  : %s", inet_ntoa(iph->ip_dst));

            printf("\nTCP sport: %d", ntohs(tcph->th_sport));
            printf("\nTCP dport: %d", ntohs(tcph->th_dport));

            printf("\nTCP data : ");
            if ( tcpdata_len == 0 ) printf("0");
            else for(int i=0; i<min(tcpdata_len,16) ;i++) printf("%c", tcpdata[i]);

            printf("\n----------------------------\n");
        }
    }
}
