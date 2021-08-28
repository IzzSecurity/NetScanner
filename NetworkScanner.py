#!/usr/bin/env python

import scapy.all as scapy


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_requests_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_lists = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)
    return clients_list

def print_result(results_lists):
    print("IP\t\t\tMAC Address\n-------------------------------------")
    for client in results_lists:
        print(client["ip"] + "\t\t" + client["mac"])

scan_result = scan("10.0.2.1/24")
print_result(scan_result)
