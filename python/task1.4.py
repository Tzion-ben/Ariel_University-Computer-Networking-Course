#!/usr/bin/python3
from scapy.all import *
def spoof_packet(packet):

  if ICMP in packet and packet[ICMP].type == 8:
     print("Original Packet.........")
     print("Source IP : ", packet[IP].src)
     print("Destination IP :", packet[IP].dst)
     print("The TTL of original Packet is", packet[IP].ttl)

     a = IP() #create  and will cook an ip header
     a.src = packet[IP].dst #assigning the src of cooked IP header with the destation ip
                         #packet of sniffed packed
     a.dst = packet[IP].src #assigning the dst of cooked IP header with the sourc ip of
                         #packet of sniffed packet
     a.ihl = packet[IP].ihl #assigning the size of the cooked ip header will be the same 
                         #as of the sniffed packet

     icmp = ICMP() #create and will cook an icmp header
     icmp.type = 0 #ICMP reply code in the cooked icmp header will
                   # be 0 - ICMP reply code
     # will assigning all the fields at the icmp cooked packet as at the sniffed packet
     icmp.id - packet[ICMP].id
     icmp.seq = packet[ICMP].seq
     newpkt = a/icmp

     print("Spoofed Packet.........")
     print("Source IP : ", newpkt[IP].src)
     print("Destination IP :", newpkt[IP].dst)
     print("The TTL of spoofed Packet is", newpkt[IP].ttl)

     send(newpkt,verbose=0)

packet = sniff(filter='icmp or arp or src 10.0.9.5',prn=spoof_packet)