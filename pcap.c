#include "pcap.h"
#include <pcap.h>
#include <stdio.h>

// Initialize pcap for capturing packets
pcap_t *init_pcap(const char *dev, int timeout) {
    char errbuf[PCAP_ERRBUF_SIZE]; // Buffer for error messages
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, timeout, errbuf); // Open device for live capture
    if (!handle) {
        fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
        return NULL;
    }

    // Filter for ICMP Echo Reply and Destination Unreachable packets
    char filter_exp[] = "icmp and (icmp[icmptype] = icmp-echoreply or icmp[icmptype] = icmp-unreach)";

    struct bpf_program fp; // Compiled filter program
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "pcap_compile() failed\n");
        return NULL;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "pcap_setfilter() failed\n");
        return NULL;
    }

    return handle;
}

