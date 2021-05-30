#!/usr/bin/env python3
from scapy.all import *
a = IP()
a.dst = '1.2.3.4'
a.ttl = 6
b = ICMP()
p = a/b
send(p)
