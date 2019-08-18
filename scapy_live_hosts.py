from scapy.all import *


def scapy_live_hosts():

    live_hosts = []

    def arp_display(pkt):
        if pkt[0][1].op == 1:
            print("{} with MAC {} is asking where {} is".format(pkt[ARP].psrc, pkt[ARP].hwsrc, pkt[ARP].pdst))
        elif pkt[0][1].op == 2:
            print("{} is at {}".format(pkt[ARP].psrc, pkt[ARP].hwsrc))
        host_dict = {
            "IP Address" : pkt[ARP].psrc,
            "MAC Address" : pkt[ARP].hwsrc
        }
        # Check if IP Address is in our list:
        # Also eliminate the special '0.0.0.0' case (Host without IP address yet):
        if not any(d.get('IP Address') == pkt[ARP].psrc or (pkt[ARP].psrc == '0.0.0.0') for d in live_hosts):
            live_hosts.append(host_dict)
            print(live_hosts)

        # If an IP Address has been allocated to another host, update the MAC address:
        elif any(d.get('IP Address') == pkt[ARP].psrc and not d.get('MAC Address') == pkt[ARP].hwsrc for d in live_hosts):
            for d in live_hosts:
                if d['IP Address'] == pkt[ARP].psrc:
                    d['MAC Address'] = pkt[ARP].hwsrc
            print("Host {} updated with new MAC Address {}".format(pkt[ARP].psrc, pkt[ARP].hwsrc))
            print(live_hosts)

    print(sniff(prn=arp_display, filter="arp"))
    print(live_hosts)


scapy_live_hosts()
