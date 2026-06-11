#--------------------------------
# Author: Silas Burkhard
# Created: 26-06-10
# Last Changed: 26-06-10
# Description:
# Simulate C2 Traffic
# that uses DNS-Tunneling
#--------------------------------
import socket
import dnslib
import time
import random

# DNS Packet to send
dns_packet = dnslib.DNSRecord.question("example.com").pack()
cs = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

while True:
    # Send dns packet to 1.1.1.1
    cs.sendto(dns_packet,("1.1.1.1",53))
    # Periodicly wait to mimic beaconing, random introduces jitter
    time.sleep(30+random.uniform(-5,5))


