#ifndef PCAP_H
#define PCAP_H

#include <pcap.h>

// Initialize pcap for live packet capture on a given device
pcap_t *init_pcap(const char *dev, int timeout);

// Capture and process ICMP reply packets
void capture_icmp_reply(pcap_t *handle, const char *target_ip, int seq, int timeout);

#endif

