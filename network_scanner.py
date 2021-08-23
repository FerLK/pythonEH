import scapy.all as scapy
import subprocess
import optparse
import re

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest = "target", help = "IP target")
    (options,arguments) = parser.parse_args()
    if not options.target:
        parser.error("[-] Pls, specify a IP")
    return options

def scan(ip):
    # to see the fields inside de obj,looking for ip:
    # scapy.ls(scapy.ARP())
    arp_request = scapy.ARP()
    arp_request.pdst = ip
    # to see the fields inside de obj,looking for dst:
    # scapy.ls(scapy.Ether())
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    #creating a combination with /, because scapy allowed
    arp_request_broadcast = broadcast/arp_request
    arp_request_broadcast.show()

    #answered_list, unanswered_list = scapy.srp(arp_request_broadcast, timeout=1)
    #print(answered_list.summary())

    answered_list = scapy.srp(arp_request_broadcast, timeout = 1, verbose = False)[0]
    print(answered_list.summary())

    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
        #to see the full pack > show()
        # to see ip and mac pack > psrc() hwsrc
    return clients_list

def print_result(results_list):
    print("IP\t\t\tMAC Adress\n-------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])


options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)

# scan_result = scan("10.0.2.1/24")
# print_result(scan_result)