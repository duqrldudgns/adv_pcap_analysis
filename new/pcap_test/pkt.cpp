#include "pkt.h"

void printMAC(uint8_t *mac){
    for(int i=0; i<6; i++){
        printf("%02x",mac[i]);
        if(i<5) printf(":");
    }
}

void printIP(uint32_t ip){
    for(int i=0; i<4; i++){
        printf("%d",( ip >>(24-i*8) ) & 0xFF );
        if(i<3)printf(".");
    }
}

void printTCPDATA(uint8_t* tcpdata,int tcpdata_len){
    if(tcpdata_len > 16) tcpdata_len = 16;
    for(int i=0; i<tcpdata_len ;i++) printf("%c", tcpdata[i]);
}

void parsing(const u_char* packet){
    static int pktcnt=1;
    struct ethhdr *eth = (struct ethhdr *) packet;

    if ( ntohs(eth->h_proto) == ETH_P_IP ){
        struct  iphdr *iph = (struct  iphdr *)( (uint8_t *)eth + ETH_LEN );

        if ( iph->protocol == IP_P_TCP ){
            struct tcphdr *tcph = (struct tcphdr *)( (uint8_t *)iph + (iph->ihl << 2) );

            uint8_t *tcpdata = (uint8_t *)tcph + (tcph->th_off << 2);
            int tcpdata_len = ntohs(iph->tot_len) - (iph->ihl << 2) - (tcph->th_off << 2);

            printf("-------%02d TCP packet--------", pktcnt++);

            printf("\nEth dst  : ");
            printMAC(eth->h_dest);
            printf("\nEth src  : ");
            printMAC(eth->h_source);

            printf("\n IP src  : ");
            printIP(ntohl(iph->saddr));
            printf("\n IP dst  : ");
            printIP(ntohl(iph->daddr));

            printf("\nTCP sport: %d", ntohs(tcph->th_sport));
            printf("\nTCP dport: %d", ntohs(tcph->th_dport));

            printf("\nTCP data : ");
            if ( tcpdata_len == 0 ) printf("0");
            else printTCPDATA(tcpdata, tcpdata_len);

            printf("\n----------------------------\n");
        }
    }
}
