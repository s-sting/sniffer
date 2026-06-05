from scapy.all import *
import json
import time
from datetime import datetime
from abc import ABC, abstractmethod


class Storage:
    def __init__(self):
        self.last_result = None
        self.history = []

    def save_result(self, data, filepath):
        self.last_result = data
        self.history.append(f"filepath {filepath}, time {datetime.now()} ")
        with open(filepath, "w", encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)


class BaseSniffer(ABC):
    def __init__(self, name, filter_str, storage: Storage):
        self.name = name
        self.filter_str = filter_str
        self.storage = storage

    def sniffer(self, count=10):
        pkts = sniff(filter=self.filter_str, count=count)
        result = self.build_result(pkts, count)
        filename = f"logs_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.json"
        self.storage.save_result(result, filename)

        return result

    def watch(self):
        packets = []

        def handler(pkt):
            packets.append(pkt)
            process = self.process_pkts(pkt, len(packets) - 1)
            if process:
                self.display_print(process)

        try:
            sniff(filter=self.filter_str, prn=handler, store=False)
        except KeyboardInterrupt:

            result = self.build_result(packets, len(packets))
            filename = f"logs_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.json"
            self.storage.save_result(result, filename)
            return result

    @abstractmethod
    def display_print(self, process):
        pass

    @abstractmethod
    def process_pkts(self, pkt, index):
        pass

    def build_result(self, pkts, count):
        result = {
            "capture_info": {
                "protocol": self.name,
                "packet_count": count,
                "filter": self.filter_str
            },
            "packets": []
        }
        result["packets"] = [self.process_pkts(pkt, i) for i, pkt in enumerate(pkts)]

        return result


class HTTPsniffer(BaseSniffer):
    def __init__(self, storage):
        super().__init__("HTTP", "tcp port 80", storage)

    def process_pkts(self, pkt, index):
        if pkt.haslayer(Raw):
            return {"index": index, "data": pkt[Raw].load.decode(errors='ignore')}
        return {"index": index, "data": None}

    def display_print(self, process):
        print(f"{datetime.now()} {process.get('index')}")


class HTTPSsniffer(BaseSniffer):
    def __init__(self, storage):
        super().__init__("HTTPS", "tcp port 443", storage)
        load_layer("tls")
        self.sni_results = {}

    def process_pkts(self, pkt, index):
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(TLS)):
            return None

        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        tls_layer = pkt[TLS]

        for msg in tls_layer.msg:
            if isinstance(msg, TLSClientHello) or (hasattr(msg, 'type') and msg.type == 1):

                for ext in msg.ext:
                    if ext.type == 0:
                        sni = ext.servernames[0].servername.decode('utf-8')

                        return {
                            "index": index,
                            "src_ip": ip_src,
                            "dst_ip": ip_dst,
                            "sni": sni,
                            "connection": f"{ip_src} -> {ip_dst}"
                        }

        return None

    def display_print(self, process):
        print(f"{datetime.now()} SNI: {process.get('sni', '?')}")


class DNSsniffer(BaseSniffer):
    def __init__(self, storage):
        super().__init__("DNS", "port 53", storage)

    def process_pkts(self, pkt, index):
        if not (pkt.haslayer(DNS)):
            return None

        dns = pkt[DNS]

        if dns.qr != 0 or dns.qd.qtype != 1 or dns.qd.qclass != 1:
            return None

        if pkt.haslayer(UDP):
            clientPort = pkt.getlayer(UDP).sport
            protocol = "UDP"
        elif pkt.haslayer(TCP):
            clientPort = pkt.getlayer(TCP).sport
            protocol = "TCP"
        else:
            protocol = "UNKNOWN"
            clientPort = 0

        clientDNSQuery = pkt.getlayer(DNS).qd.qname.decode('utf-8') if isinstance(pkt.getlayer(DNS).qd.qname,
                                                                                  bytes) else str(
            pkt.getlayer(DNS).qd.qname)

        return {
            "index": index + 1,
            "timestamp": time.time(),
            "client_ip": pkt.getlayer(IP).src,
            "server_ip": pkt.getlayer(IP).dst,
            "client_port": clientPort,
            "protocol": protocol,
            "query_id": pkt.getlayer(DNS).id,
            "query_name": clientDNSQuery,
            "query_type": 1,
            "query_class": 1
        }

    def display_print(self, process):
        print(f"{datetime.now()} Query name: {process.get('query_name', '?')}")


class ARPsniffer(BaseSniffer):
    def __init__(self, storage):
        super().__init__("ARP", "arp", storage)

    def process_pkts(self, pkt, index):
        if ARP in pkt:
            if pkt[ARP].op == 1:
                return {
                    "type": "request",
                    "index": index,
                    "timestamp": datetime.now(),
                    "ARPRequest": pkt[ARP].pdst,  # кто хочет узнать
                    "ARPsender": pkt[ARP].psrc  # кто спрашивает
                }
            elif pkt[ARP].op == 2:
                return {
                    "type": "reply",
                    "index": index,
                    "timestamp": datetime.now(),
                    "ARPsender": pkt[ARP].psrc,  # IP ответчика
                    "MACsender": pkt[ARP].hwsrc  # MAC ответчика
                }

    def display_print(self, process):
        if process['type'] == 'request':
            print(f"{datetime.now()} ARP: Who has {process.get('ARPRequest', '?')} => {process.get('ARPsender', '?')}")
        else:
            print(f"{datetime.now()} ARP: {process.get('ARPsender', '?')} => {process.get('MACsender', '?')}")


class SnifferCLI:
    def __init__(self):
        self.storage = Storage()
        self.sniffers = {
            "http": HTTPsniffer(self.storage),
            "https": HTTPSsniffer(self.storage),
            "dns": DNSsniffer(self.storage),
            "arp": ARPsniffer(self.storage),
        }

    def run(self, protocol, count=10):
        if protocol in self.sniffers:
            return self.sniffers[protocol].sniffer(count)
        print(f"Unknown protocol: {protocol}")


def StartPoint():
    cli = SnifferCLI()
    print("Sniffer by sting")
    print("Type 'help' or 'help <command>' for more information")

    def show_help(command=None):
        if command is None:
            print("\n=== SNIFFER HELP ===")
            print("Available commands:")
            print("  http [count]   - Sniff HTTP packets (default: 10)")
            print("  https [count]  - Sniff HTTPS packets (default: 10)")
            print("  dns [count]    - Sniff DNS packets (default: 10)")
            print("  arp [count]    - Sniff ARP packets (default: 5)")
            print("  watch <protocol>  - Continuous capture (Ctrl+C to stop)")
            print("  history        - Show capture history")
            print("  help           - Show this help")
            print("  exit           - Exit the sniffer")
            print("\nExamples:")
            print("  sniffer> dns 5")
            print("  sniffer> watch http")
            print("  sniffer> history")
        elif command == "http":
            print("HTTP Sniffer: Captures HTTP packets")
            print("Usage: http [count]")
            print("  count - number of packets to capture (default: 10)")
        elif command == "https":
            print("HTTPS Sniffer: Captures HTTPS packets")
            print("Usage: https [count]")
            print("  count - number of packets to capture (default: 10)")
        elif command == "dns":
            print("DNS Sniffer: Captures DNS queries and responses")
            print("Usage: dns [count]")
            print("  count - number of packets to capture (default: 10)")
        elif command == "arp":
            print("ARP Sniffer: Captures ARP requests and replies")
            print("Usage: arp [count]")
            print("  count - number of packets to capture (default: 5)")
        else:
            print(f"Unknown command: {command}")

    while 1:
        command = input("sniffer> ").strip().lower().split()
        if not command:
            continue
        match command[0]:
            case "http" | "https" | "dns" | "arp":
                count = int(command[1]) if len(command) > 1 else 10
                print("Running...")
                cli.run(command[0], count)
                print("The process is completed ")
            case "watch":
                if len(command) < 2:
                    print("Usage: watch <protocol>")
                else:
                    protocol = command[1]
                    if protocol in cli.sniffers:
                        print(f"Watching {protocol}")
                        print("Press Ctrl+C to stop")
                        cli.sniffers[protocol].watch()
                    else:
                        print("Unknown protocol")
            case "help" | "-help" | "--help" | "-h":
                if len(command) > 1:
                    show_help(command[1])
                else:
                    show_help()
            case "history":
                if not cli.storage.history:
                    print("No history yet")
                else:
                    count = 0
                    for i in cli.storage.history:
                        count += 1
                        print(count, i)
            case "exit" | "ex":
                break
            case _:
                print("Unknown command")
                print("Type 'help' for available commands")


if __name__ == "__main__":
    StartPoint()
