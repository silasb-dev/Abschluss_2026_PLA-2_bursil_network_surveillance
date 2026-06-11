#--------------------------------
# Author: Silas Burkhard
# Created: 26-06-04
# Last Changed: 26-06-04
# Description:
# Loads a Wireshark capture file,
# show graph with packet size per packet,
# highlight malicious Traffic
# (predefined)
#--------------------------------

from scapy.all import *
import matplotlib.pyplot as plt
import numpy as np


# Load Capture File
packets = rdpcap("captures/7min.pcapng")
# Id of malicious Packets. These do NOT actually work. this is an old file. I am not fixing it
highlight = [508, 1328, 3238, 5528, 6044, 6674, 7164, 8391, 9403, 10071, 10552, 11871, 12416, 13102, 13598, 14387, 14965]

# Create x and y arrays
x = [i for i in range(len(packets))]
y = []

# add packet size as y
for pkt in packets:
    y.append(len(pkt))

# show normal points with lightgrey
plt.scatter(x,y,color="lightgray",s=5,label="Normal")

highlight_x = []
highlight_y = []

for n in highlight:
    if n < len(packets):
        highlight_x.append(n)
        highlight_y.append(len(packets[n]))
# show malicious points with red
plt.scatter(highlight_x,highlight_y,color="red",s=50,marker="o",label="C2")
plt.xlabel("Packet Number")
plt.ylabel("Packet Size")
plt.title("Packet Size by Packet")
plt.legend()
plt.show()
