#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pcap/pcap.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <time.h>

/*
Code based from https://www.tcpdump.org/ documentation. 
*/

pcap_t* handle;
int linkhdrlen; //data link header lenght
int packets;

void get_link_header_len(pcap_t* handle){

    int linktype;
    // Determine the type.
    if ((linktype = pcap_datalink(handle)) == PCAP_ERROR) {
        printf("pcap_datalink(): %s\n", pcap_geterr(handle));
        return;
    }
 
    // Set the size based om the type.
    switch (linktype){
        case DLT_NULL:
            linkhdrlen = 4;
            break;
    
        case DLT_EN10MB:
            linkhdrlen = 14;
            break;
    
        case DLT_SLIP:
        case DLT_PPP:
            linkhdrlen = 24;
            break;
    
        default:
            printf("Datalink is invalid(%d)\n", linktype);
            linkhdrlen = 0;
    }
}

void print_packets(u_char *user, const struct pcap_pkthdr *packethdr, const u_char *packetptr){

    struct ip* iphdr;
    struct icmp* icmphdr;
    struct tcphdr* tcphdr;
    struct udphdr* udphdr;
    char src_ip[256];
    char dst_ip[256];

    //Use packet timestamp to create log time
    time_t now;
    struct tm *tm;
    now = packethdr->ts.tv_sec;
    if ((tm = localtime (&now)) == NULL) {
        printf ("Error extracting time\n");
    }
 
    packetptr += linkhdrlen; //skip datalink layer header.
    iphdr = (struct ip*)packetptr; //get the IP header fields
    strcpy(src_ip, inet_ntoa(iphdr->ip_src));
    strcpy(dst_ip, inet_ntoa(iphdr->ip_dst));
 
    /*
    Move to the transport layer header, parse, and display the fields depending 
    on whether the header is tcp, udp, or icmp.
    */
    packetptr += 4*iphdr->ip_hl;
    switch (iphdr->ip_p){
        case IPPROTO_TCP:
            tcphdr = (struct tcphdr*)packetptr;
            printf("<%04d-%02d-%02d %02d:%02d:%02d> from: %s:%d to: %s:%d     LenWire:%d\n\n",
            tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
            tm->tm_hour, tm->tm_min, tm->tm_sec, src_ip, ntohs(tcphdr->th_sport),
                dst_ip, ntohs(tcphdr->th_dport), packethdr->len);
            printf("--------------------------------------------------\n\n");
            packets += 1;
            break;
    
        case IPPROTO_UDP:
            udphdr = (struct udphdr*)packetptr;
            printf("<%04d-%02d-%02d %02d:%02d:%02d> from: %s:%d to: %s:%d     LenWire:%d\n\n",
            tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
            tm->tm_hour, tm->tm_min, tm->tm_sec, src_ip, ntohs(udphdr->uh_sport),
                dst_ip, ntohs(udphdr->uh_dport), packethdr->len);
            printf("--------------------------------------------------\n\n");
            packets += 1;
            break;
    
        case IPPROTO_ICMP:
            icmphdr = (struct icmp*)packetptr;
            printf("<%04d-%02d-%02d %02d:%02d:%02d> from: %s:%d to: %s:%d     LenWire:%d\n\n",
            tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
            tm->tm_hour, tm->tm_min, tm->tm_sec,  src_ip, dst_ip, packethdr->len);
            printf("--------------------------------------------------\n\n");
            packets += 1;
            break;
    }
}

int main(int argc, char *argv[]){

    int count = 0;
    char device[256];
    *device = 0;
    char filter_exp[] = "dst port 443 or dst port 80";  //The filter expression
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    pcap_if_t* devices = NULL;
    bpf_u_int32 netmask;
    bpf_u_int32 src_ip;
    struct bpf_program bpf; /* The compiled filter expression */

    // In case no network interface (device) is specfied, get the first one.
    if (!*device) {
    	if (pcap_findalldevs(&devices, errbuf)) {
            fprintf(stderr, "pcap_findalldevs(): %s\n", errbuf);
            handle = NULL;
        }
        strcpy(device, devices[0].name);
    }

    // Get the network-device's source IP address and net-mask.
    if (pcap_lookupnet(device, &src_ip, &netmask, errbuf) == PCAP_ERROR) {
        fprintf(stderr, "pcap_lookupnet: %s\n", errbuf);
        handle = NULL;
    }

    // Create the packet capture handle
    // Open device for live capture.
    handle = pcap_open_live(device, 120, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
    }

    // Compile and set the filter
    // from epxression to a packet filter binary.
    if (pcap_compile(handle, &bpf, filter_exp, 0, netmask) == -1) {
        fprintf(stderr, "pcap_compile(): %s\n", pcap_geterr(handle));
        handle = NULL;
    }

    // Bind the packet filter to the libpcap handle.    
    if (pcap_setfilter(handle, &bpf) == -1) {
        fprintf(stderr, "pcap_setfilter(): %s\n", pcap_geterr(handle));
        handle = NULL;
    }

    if (handle == NULL) {
        return -1;
    }

    // Get the type of link layer.
    get_link_header_len(handle);
    if (linkhdrlen == 0) {
        return -1;
    }

    // Start the packet capture with a set count or continually if the count is 0.
    if (pcap_loop(handle, count, print_packets, (u_char*)NULL) == -1) {
        fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(handle));
        return -1;
    }
}
