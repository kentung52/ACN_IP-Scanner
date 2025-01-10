# ACN_IP-Scanner
Advanced Computer Networks-Subnet Scanning and Inspection

Objective:
Develop a subnet IP scanner in C on Ubuntu 24.04 OS to identify live hosts in a subnet using ICMP echo requests.

Key Features:
ICMP Echo Request and Reply:

Send ICMP echo requests (Type 8) to all subnet IP addresses, excluding the host itself.
Capture ICMP echo replies (Type 0) to determine live hosts.
Packet Configuration:

IP Header:
Header length and total length: Calculated dynamically.
TTL: Set to 1 to confine requests to the local subnet.
Protocol: Set to ICMP.
Flags: "Don't Fragment."
ICMP Packet:
ID: Set to the process ID.
Sequence Number: Starts at 1, increments for each request.
Data: Include the student's ID, ensuring data size aligns with the IP header.
Response Handling:

Validate ICMP replies by checking:
Source IP in the IP header.
ICMP type (Type 0).
Matching ID and sequence number in the ICMP message.
Efficient Packet Filtering:

Use libpcap to filter packets efficiently.
Apply filtering rules similar to tcpdump to minimize packet processing overhead.

Usage: sudo ./ipscanner -i [Network Interface Name] -t [timeout(ms)]

Automatically retrieves the host's IP address and subnet mask for the specified interface.
Scans all IPs in the subnet range (e.g., 140.117.171.1~140.117.171.254 for 255.255.255.0).
