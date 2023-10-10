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

pcap_t* handle;
int linkhdrlen;
int packets;

pcap_t* create_handle(char* device, char* filter)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    pcap_if_t* devices = NULL;
    bpf_u_int32 netmask;
    bpf_u_int32 srcip;
    struct bpf_program bpf; /* The compiled filter expression */

    // If no network interface (device) is specfied, get the first one.
    if (!*device) {
    	if (pcap_findalldevs(&devices, errbuf)) {
            fprintf(stderr, "pcap_findalldevs(): %s\n", errbuf);
            return NULL;
        }
        strcpy(device, devices[0].name);
    }

    // Get network device source IP address and netmask.
    if (pcap_lookupnet(device, &srcip, &netmask, errbuf) == PCAP_ERROR) {
        fprintf(stderr, "pcap_lookupnet: %s\n", errbuf);
        return NULL;
    }

    // Open the device for live capture.
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
        return NULL;
    }

    // Compile and set filter
    // Convert the packet filter epxression into a packet filter binary.
    if (pcap_compile(handle, &bpf, filter, 0, netmask) == -1) {
        fprintf(stderr, "pcap_compile(): %s\n", pcap_geterr(handle));
        return NULL;
    }

    // Bind the packet filter to the libpcap handle.    
    if (pcap_setfilter(handle, &bpf) == -1) {
        fprintf(stderr, "pcap_setfilter(): %s\n", pcap_geterr(handle));
        return NULL;
    }

    return handle;
}

void get_link_header_len(pcap_t* handle)
{
    int linktype;
 
    // Determine the datalink layer type.
    if ((linktype = pcap_datalink(handle)) == PCAP_ERROR) {
        printf("pcap_datalink(): %s\n", pcap_geterr(handle));
        return;
    }
 
    // Set the datalink layer header size.
    switch (linktype)
    {
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
        printf("Unsupported datalink (%d)\n", linktype);
        linkhdrlen = 0;
    }
}

void print_packets(u_char *user, const struct pcap_pkthdr *packethdr, const u_char *packetptr)
{
    struct ip* iphdr;
    struct icmp* icmphdr;
    struct tcphdr* tcphdr;
    struct udphdr* udphdr;
    char srcip[256];
    char dstip[256];

    /*Use packet timestamp to create log time*/
    time_t now;
    struct tm *tm;
    now = packethdr->ts.tv_sec;
    if ((tm = localtime (&now)) == NULL) {
        printf ("Error extracting time stuff\n");
    }
 
    // Skip the datalink layer header and get the IP header fields.
    packetptr += linkhdrlen;
    iphdr = (struct ip*)packetptr;
    strcpy(srcip, inet_ntoa(iphdr->ip_src));
    strcpy(dstip, inet_ntoa(iphdr->ip_dst));
 
    // Advance to the transport layer header then parse and display
    // the fields based on the type of hearder: tcp, udp or icmp.
    packetptr += 4*iphdr->ip_hl;
    switch (iphdr->ip_p)
    {
    case IPPROTO_TCP:
        tcphdr = (struct tcphdr*)packetptr;
        /*
        printf(" from: %s:%d to: %s:%d     LenWire:%d\n  ", srcip, ntohs(tcphdr->th_sport),
               dstip, ntohs(tcphdr->th_dport), packethdr->len);
        */

        printf("<%04d-%02d-%02d %02d:%02d:%02d> from: %s:%d to: %s:%d     LenWire:%d\n",
        tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
        tm->tm_hour, tm->tm_min, tm->tm_sec, srcip, ntohs(tcphdr->th_sport),
               dstip, ntohs(tcphdr->th_dport), packethdr->len);
        printf("--------------------------------------------------\n\n");
        packets += 1;
        break;
 
    case IPPROTO_UDP:
        udphdr = (struct udphdr*)packetptr;
        /*
        printf("<%ld.%6ld> from: %s:%d to: %s:%d     LenWire:%d\n", packethdr->ts.tv_sec, packethdr->ts.tv_usec, srcip, ntohs(udphdr->uh_sport),
               dstip, ntohs(udphdr->uh_dport), packethdr->len);
        */

        printf("<%04d-%02d-%02d %02d:%02d:%02d> from: %s:%d to: %s:%d     LenWire:%d\n",
        tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
        tm->tm_hour, tm->tm_min, tm->tm_sec, srcip, ntohs(udphdr->uh_sport),
               dstip, ntohs(udphdr->uh_dport), packethdr->len);
	    printf("--------------------------------------------------\n\n");
        packets += 1;
        break;
 
    case IPPROTO_ICMP:
        icmphdr = (struct icmp*)packetptr;
        /*
        printf("<%ld.%6ld> from: %s to: %s      LenWire:%d\n", packethdr->ts.tv_sec, packethdr->ts.tv_usec, srcip, dstip, packethdr->len);
        */
        printf("<%04d-%02d-%02d %02d:%02d:%02d> from: %s:%d to: %s:%d     LenWire:%d\n",
        tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
        tm->tm_hour, tm->tm_min, tm->tm_sec,  srcip, dstip, packethdr->len);
        printf("--------------------------------------------------\n\n");
        packets += 1;
        break;
    }
}

int main(int argc, char *argv[])
{
    int count = 0;
    char device[256];

    *device = 0;
    char filter_exp[] = "dst port 443 or dst port 80";  /* The filter expression */

    /*
    int opt;
    // Get the command line options, if any
    while ((opt = getopt(argc, argv, "hi:n:")) != -1)
    {
        switch (opt)
        {
        case 'h':
            printf("usage: %s [-h] [-i interface] [-n count] [BPF expression]\n", argv[0]);
            exit(0);
            break;
        case 'i':
            strcpy(device, optarg);
            break;
        case 'n':
            count = atoi(optarg);
            break;
        }
    }
    */
    
    // Create packet capture handle & Compile and set filter
    handle = create_handle(device, filter_exp); //filter
    if (handle == NULL) {
        return -1;
    }

    // Get the type of link layer.
    get_link_header_len(handle);
    if (linkhdrlen == 0) {
        return -1;
    }

    // Start the packet capture with a set count or continually if the count is 0.
    if (pcap_loop(handle, count, print_packets, (u_char*)NULL) == PCAP_ERROR) {
        fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(handle));
        return -1;
    }
}
