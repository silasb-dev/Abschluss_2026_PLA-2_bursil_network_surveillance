import socket
import dnslib
import time
import random

dns_packet = dnslib.DNSRecord.question("example.com")

cs = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

while True:
    cs.sendto(dns_packet,("192.168.12.3",53))
    time.sleep(30+random.uniform(-5,5))


