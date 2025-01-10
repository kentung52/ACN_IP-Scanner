#include "fill_packet.h"
#include "pcap.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>
#include <unistd.h>

#define ICMP_DATA_SIZE 10 // Size of the ICMP payload

// Function to retrieve the local IP address and subnet mask of a given network interface
void get_local_ip_and_netmask(const char *interface, char *ip, char *netmask) {
    int sockfd;
    struct ifreq ifr;

    // Create a socket for retrieving network interface information
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Retrieve the IP address of the given interface
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        perror("Failed to get IP address");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in *ip_addr = (struct sockaddr_in *)&ifr.ifr_addr;
    strcpy(ip, inet_ntoa(ip_addr->sin_addr));

    // Retrieve the subnet mask of the given interface
    if (ioctl(sockfd, SIOCGIFNETMASK, &ifr) < 0) {
        perror("Failed to get netmask");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in *netmask_addr = (struct sockaddr_in *)&ifr.ifr_addr;
    strcpy(netmask, inet_ntoa(netmask_addr->sin_addr));

    close(sockfd);
}

// Function to construct and send a raw ICMP Echo Request packet
void send_raw_icmp(const char *src_ip, const char *dest_ip, int seq, int sockfd) {
    char packet[sizeof(struct iphdr) + sizeof(struct icmphdr) + ICMP_DATA_SIZE];
    struct iphdr *ip_hdr = (struct iphdr *)packet; // Pointer to the IP header
    struct icmphdr *icmp_hdr = (struct icmphdr *)(packet + sizeof(struct iphdr)); // Pointer to the ICMP header

    // Fill the IP header
    fill_iphdr(ip_hdr, src_ip, dest_ip, sizeof(struct icmphdr) + ICMP_DATA_SIZE);

    // Fill the ICMP header
    char data[ICMP_DATA_SIZE] = "M133040039"; // Example payload (replace with actual data)
    fill_icmphdr(icmp_hdr, data, seq);

    struct sockaddr_in target_addr = {0};
    target_addr.sin_family = AF_INET;
    inet_pton(AF_INET, dest_ip, &target_addr.sin_addr);

    // Send the ICMP packet
    if (sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&target_addr, sizeof(target_addr)) < 0) {
        perror("Failed to send ICMP packet");
        printf("     Skipping unreachable target: %s\n", dest_ip);
    }
}

// Function to send an ICMP Echo Request and capture the response for a specific target IP
void scan_target_ip(const char *src_ip, const char *dest_ip, int seq, pcap_t *handle, int timeout) {
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW); // Create a raw socket
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Set socket options to include custom IP headers
    int opt = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)) < 0) {
        perror("Failed to set IP_HDRINCL");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("PING %s (data size = 10, id = 0x%04x, seq = %d, timeout = %d ms)\n",
           dest_ip, getpid() & 0xFFFF, seq, timeout);

    // Send the ICMP packet
    send_raw_icmp(src_ip, dest_ip, seq, sockfd);

    // Capture and handle the ICMP reply
    capture_icmp_reply(handle, dest_ip, seq, timeout);

    close(sockfd);
}

// Function to scan all hosts within the subnet
void scan_subnet(const char *self_ip, const char *netmask, pcap_t *handle, int timeout) {
    struct in_addr addr, mask;
    u_int32_t network_base;

    // Parse the local IP and subnet mask
    if (!inet_aton(self_ip, &addr)) {
        fprintf(stderr, "Invalid IP address: %s\n", self_ip);
        return;
    }

    if (!inet_aton(netmask, &mask)) {
        fprintf(stderr, "Invalid netmask: %s\n", netmask);
        return;
    }

    // Calculate the subnet base address (assuming a /24 subnet mask)
    network_base = ntohl(addr.s_addr) & 0xFFFFFF00;

    printf("Scanning subnet: %u.%u.%u.1 - %u.%u.%u.254\n",
           (network_base >> 24) & 0xFF,
           (network_base >> 16) & 0xFF,
           (network_base >> 8) & 0xFF,
           (network_base >> 24) & 0xFF,
           (network_base >> 16) & 0xFF,
           (network_base >> 8) & 0xFF);

    // Iterate through all possible hosts in the subnet
    for (u_int32_t host = 1; host <= 254; host++) {
        u_int32_t target_ip = network_base | host;
        struct in_addr current_ip = {.s_addr = htonl(target_ip)};
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &current_ip, ip_str, sizeof(ip_str));
      
        // Skip the local IP address
        if (strcmp(ip_str, self_ip) == 0) {
            printf("Skipping self IP: %s\n", self_ip);
            continue;
        }

        // Send ICMP Echo Request to the target IP
        scan_target_ip(self_ip, ip_str, host, handle, timeout);
    }
}

// Main entry point of the program
int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s -i <interface> -t <timeout>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *interface = argv[2]; // Network interface to use
    int timeout = atoi(argv[4]); // Timeout value in milliseconds

    char self_ip[INET_ADDRSTRLEN];
    char netmask[INET_ADDRSTRLEN];

    // Automatically retrieve the local IP and subnet mask
    get_local_ip_and_netmask(interface, self_ip, netmask);

    printf("Self IP: %s\n", self_ip);
    printf("Netmask: %s\n", netmask);
    
    // Initialize pcap for packet capture
    pcap_t *handle = init_pcap(interface, timeout);
    if (!handle) {
        exit(EXIT_FAILURE);
    }

    // Start scanning the subnet
    scan_subnet(self_ip, netmask, handle, timeout);

    // Close the pcap handle
    pcap_close(handle);
    
    return 0;
}

