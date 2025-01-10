#ifndef FILL_PACKET_H
#define FILL_PACKET_H

#include <netinet/ip_icmp.h>
#include <netinet/ip.h>

typedef unsigned short u16;  // Define a shorthand for unsigned short type

// Function to calculate the checksum for given data
u16 fill_cksum(u16 *addr, int len);

// Function to fill the ICMP header with the given data and sequence number
void fill_icmphdr(struct icmphdr *icmp_hdr, const char *data, int seq);

// Function to fill the IP header with source and destination IPs and payload length
void fill_iphdr(struct iphdr *ip_hdr, const char *src_ip, const char *dest_ip, int payload_len);

#endif

