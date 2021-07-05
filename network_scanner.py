import scapy.all as scapy
import argparse
from socket import *
import time
import threading
from queue import Queue

#getting the argument <IP>
parser = argparse.ArgumentParser()
parser.add_argument('-i', '--ip', help='python network_scanner.py 192.168.1.0/24')
options = parser.parse_args()

#checking if the IP address has been given as argument
if not options.ip:
    parser.error("Please mention the IP address")

#a function to create packets, send them out and return an array of live hosts 
def scan(ip):
    
    #framing a ARP packet with respective destination IP
    arp_frame = scapy.ARP(pdst = ip)
    
    #framing an ethernet packet with broadcast address as destination
    ether_frame = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    
    #framing the final packet by enclosing the ARP packet inside it
    broadcast_frame = ether_frame / arp_frame
    
    #sending out packets and receiving the response tuple
    answered_list = scapy.srp(broadcast_frame, timeout = 1, verbose = False)[0]
    
    live_hosts = []
    
    #loop to iterate through the tuple
    for i in range(0, len(answered_list)):
        
        #saving IP and MAC of live hosts only
        client_dict = {"ip": answered_list[i][1].psrc, "mac": answered_list[i][1].hwsrc}
        live_hosts.append(client_dict)
        
    return live_hosts

scan_result = scan(options.ip)
print("HOSTS UP: " + str(len(scan_result)))
print("=========================================================")
for i in scan_result:
    print("IP: " + str(i["ip"]) + "\t\tMAC: " + str(i["mac"]))
