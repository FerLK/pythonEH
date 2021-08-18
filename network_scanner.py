import scapy.all as scapy

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

    answered_list, unanswered_list = scapy.srp(arp_request_broadcast, timeout=1)
    print(answered_list.summary())

scan("10.0.2.1/24")