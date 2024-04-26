#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

void process_sniffed_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethhdr *eth_header = (struct ethhdr *)packet;
    uint16_t ether_type = ntohs(eth_header->h_proto);

    if (ether_type == ETH_P_IP) {
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ethhdr));
        uint16_t ip_header_length = ip_header->ip_hl << 2;
        uint16_t total_header_length = sizeof(struct ethhdr) + ip_header_length;

        uint16_t protocol = ip_header->ip_p;

        if (protocol == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + total_header_length);
            uint16_t tcp_header_length = tcp_header->doff << 2;

            if (ntohs(tcp_header->th_dport) == 80 || ntohs(tcp_header->th_dport) == 443 ||
                ntohs(tcp_header->th_sport) == 80 || ntohs(tcp_header->th_sport) == 443) {
                const char *payload = (const char *)(packet + total_header_length + tcp_header_length);
                // Process HTTP/HTTPS payload
            }
        }
    }
}

void sniff(const char *interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        return;
    }

    pcap_loop(handle, 0, process_sniffed_packet, NULL);

    pcap_close(handle);
}

int main() {
    char interface[100];
    printf("[+] Enter the Interface to Sniff: ");
    if (scanf("%99s", interface) != 1) {
        fprintf(stderr, "Error: Invalid input\n");
        return 1;
    }
    sniff(interface);

    return 0;
}
