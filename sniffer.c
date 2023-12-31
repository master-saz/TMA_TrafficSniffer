#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pcap/pcap.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

int linkhdrlen;

/*
The callback function processes captured packets.
This function just prints out a running count of packets, as captured.
*/
void my_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* 
    packet) 
{ 
    static int count = 1; 
    fprintf(stdout, "%3d, ", count);
    fflush(stdout);
    count++; 
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

void another_callback(u_char *arg, const struct pcap_pkthdr* pkthdr, 
        const u_char* packet, const u_char *packetptr) 
{ 
    int i=0; 
    static int count=0;
    struct ip* iphdr;

    packetptr += linkhdrlen;
    iphdr = (struct ip*)packetptr;

    /* print source and destination IP addresses */
    printf("       From: %s\n", inet_ntoa(iphdr->ip_src));
    printf("         To: %s\n", inet_ntoa(iphdr->ip_dst));

    //printf("<%ld.%6ld> src: %s det:  LenWire:%d \n", pkthdr->ts.tv_sec, pkthdr->ts.tv_usec, ip->ip_src, pkthdr->len);    /* Length of header */
}


int main(int argc,char **argv) 
{ 
    int i;
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE]; 
    pcap_t* descr; 
    const u_char *packet; 
    struct pcap_pkthdr hdr;
    struct ether_header *eptr;    /* net/ethernet.h */
    struct bpf_program fp;        /* hold compiled program */
    bpf_u_int32 maskp;            /* subnet mask */
    bpf_u_int32 netp;             /* ip */
 
    if(argc != 2){
        fprintf(stdout, "Usage: %s \"expression\"\n"
            ,argv[0]);
        return 0;
    } 
 
    /* Now get a device */
    dev = pcap_lookupdev(errbuf); 
     
    if(dev == NULL) {
        fprintf(stderr, "%s\n", errbuf);
        exit(1);
    } 
        /* Get the network address and mask */
    pcap_lookupnet(dev, &netp, &maskp, errbuf); 
 
    /* open device for reading in promiscuous mode */
    descr = pcap_open_live(dev, BUFSIZ, 1,-1, errbuf); 
    if(descr == NULL) {
        printf("pcap_open_live(): %s\n", errbuf);
        exit(1);
    } 
 
    /* Now we'll compile the filter expression*/
    if(pcap_compile(descr, &fp, argv[1], 0, netp) == -1) {
        fprintf(stderr, "Error calling pcap_compile\n");
        exit(1);
    } 
 
    /* set the filter */
    if(pcap_setfilter(descr, &fp) == -1) {
        fprintf(stderr, "Error setting filter\n");
        exit(1);
    }


    // Get the type of link layer.
    get_link_header_len(descr);
    if (linkhdrlen == 0) {
        return -1;
    }
 
    /* loop for callback function */
    pcap_loop(descr, -1, another_callback, NULL); 
    return 0; 
}
