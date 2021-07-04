import scapy.all as scapy
import argparse

#getting the argument <IP>
parser = argparse.ArgumentParser()
parser.add_argument('-i', '--ip', help='python network_scanner.py 192.168.1.0/24')
options = parser.parse_args()

#checking if the IP address has been given as argument
if not options.ip:
    parser.error("Please mention the IP address")

def scan(ip):
    arp_frame = scapy.ARP(pdst = ip)
    ether_frame = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    broadcast_frame = ether_frame / arp_frame
    answered_list = scapy.srp(broadcast_frame, timeout = 1, verbose = False)[0]
    
    live_hosts = []
    for i in range(0, len(answered_list)):
        client_dict = {"ip": answered_list[i][1].psrc, "mac": answered_list[i][1].hwsrc}
        live_hosts.append(client_dict)
        
    return live_hosts

scan_result = scan(options.ip)
print("=========================================================================")
for i in scan_result:
    print("IP: " + str(i["ip"]) + "\t\tMAC: " + str(i["mac"]))
    
