#include <stdio.h>
#include <pcap.h>
#include <netinet/ether.h> // For Ethernet header
#include <netinet/ip.h>    // For IP header
#include <netinet/tcp.h>   // For TCP header

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // Extract Ethernet header
    struct ether_header *eth_header = (struct ether_header *)packet;

    // Check if the packet is an IP packet (EtherType == 0x0800 for IP)
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        // Extract IP header
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));

        // Check if the IP packet contains TCP protocol
        if (ip_header->ip_p == IPPROTO_TCP) {
            // Extract TCP header
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header->ip_hl * 4);

            // Extract source and destination IP addresses
            char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

            // Extract source and destination ports
            uint16_t src_port = ntohs(tcp_header->th_sport);
            uint16_t dst_port = ntohs(tcp_header->th_dport);

            // Calculate the length of the TCP data
            int tcp_data_length = pkthdr->len - (sizeof(struct ether_header) + ip_header->ip_hl * 4 + tcp_header->th_off * 4);

            // Print Ethernet Header
            printf("Ethernet Header\n");
            printf("  Source MAC: %s\n", ether_ntoa((struct ether_addr *)eth_header->ether_shost));
            printf("  Destination MAC: %s\n", ether_ntoa((struct ether_addr *)eth_header->ether_dhost));

            // Print IP Header
            printf("IP Header\n");
            printf("  Source IP: %s\n", src_ip);
            printf("  Destination IP: %s\n", dst_ip);

            // Print TCP Header
            printf("TCP Header\n");
            printf("  Source Port: %u\n", src_port);
            printf("  Destination Port: %u\n", dst_port);

            // Print TCP Data (message)
            printf("TCP Data\n");
            for (int i = 0; i < tcp_data_length; i++) {
                printf("%c", packet[sizeof(struct ether_header) + ip_header->ip_hl * 4 + tcp_header->th_off * 4 + i]);
            }
            printf("\n\n");
        }
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Open the network interface for packet capture
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        return 1;
    }

    // Set filter to capture only TCP packets
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Error compiling filter expression\n");
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error setting filter\n");
        return 1;
    }

    // Start packet capture loop
    pcap_loop(handle, 0, packet_handler, NULL);

    // Close the capture handle
    pcap_close(handle);

    return 0;
}
