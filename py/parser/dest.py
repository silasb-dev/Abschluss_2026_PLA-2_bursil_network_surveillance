#--------------------------------
# Author: Silas Burkhard
# Created: 26-06-04
# Last Changed: 26-06-04
# Description:
# Loads a Wireshark capture file,
# show graph with dst ip per packet,
# highlight malicious Traffic
# (predefined)
#--------------------------------

from scapy.all import *
from scapy.layers.inet import IP
import matplotlib.pyplot as plt
import numpy as np

# Load Capture File
packets = rdpcap("captures/7min.pcapng")


# Id of malicious Packets. These do NOT actually work. this is an old file. I am not fixing it
highlight_packets = {
    509, 1329, 3239, 5529, 6045,
    6675, 7165, 8392, 9404, 10072,
    10553, 11872, 12417, 13103,
    13599, 14388, 14966
}
# get packet numbers and destination ip's
packet_numbers = []
dst_ips = []

for i, pkt in enumerate(packets):
    if IP in pkt:
        packet_numbers.append(i)
        dst_ips.append(pkt[IP].dst)

# Convert IPs y positions
unique_ips = sorted(set(dst_ips))
ip_map = {ip: idx for idx, ip in enumerate(unique_ips)}

y_values = [ip_map[ip] for ip in dst_ips]

# Normal packets
normal_x = []
normal_y = []

# malicious packets
highlight_x = []
highlight_y = []

# Send malicious packets in other array than normal ones
for x, y in zip(packet_numbers, y_values):
    if x in highlight_packets:
        highlight_x.append(x)
        highlight_y.append(y)
    else:
        normal_x.append(x)
        normal_y.append(y)

# Plot Graph with matplotlib
plt.figure(figsize=(15, 8))
plt.scatter(normal_x,normal_y,s=5,color="lightgray",label="Normal")
plt.scatter(highlight_x,highlight_y,s=50,color="red",label="C2")
plt.yticks(range(len(unique_ips)),unique_ips)
plt.xlabel("Packet Number")
plt.ylabel("Destination IP")
plt.title("Destination IP by Packet")
plt.legend()
plt.tight_layout()
plt.show()