
from scapy.all import *
import json
import struct


def sniffer_for_http(count):
    pkts = sniff(filter="tcp port 80", count=count)

    result = {
        "capture_info": {
            "packet_count": count,
            "filter": "tcp port 80"
        },
        "packets": []
    }

    for i, pkt in enumerate(pkts):
        packet_info = {
            "index": i + 1,
            "has_raw": pkt.haslayer(Raw),
            "data": None
        }

        if pkt.haslayer(Raw):
            raw_data = pkt[Raw].load.decode('utf-8', errors='ignore')
            packet_info["data"] = raw_data
            packet_info["length"] = len(pkt[Raw].load)

        result["packets"].append(packet_info)

    with open("logs.json", "w", encoding='utf-8') as file:
        json.dump(result, file, indent=2, ensure_ascii=False)

    print(f"Сохранено {count} пакетов в logs.json")


def sniffer_for_https(count):
    pkts = sniff(filter="tcp port 443", count=count)
    load_layer("tls")

    sni_results = {}

    for pkt in pkts:
        if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(TLS):
            ip_src = pkt[IP].src
            ip_dst = pkt[IP].dst
            tls_layer = pkt[TLS]
            for msg in tls_layer.msg:

                if isinstance(msg, TLSClientHello) or (hasattr(msg, 'type') and msg.type == 1):

                    for ext in msg.ext:
                        if ext.type == 0:
                            sni = ext.servernames[0].servername.decode('utf-8')

                            key = f"{ip_src} -> {ip_dst}"
                            if key not in sni_results:
                                sni_results[key] = []
                            if sni not in sni_results[key]:
                                sni_results[key].append(sni)
                            break

    result = {
        "capture_info": {
            "packet_count": len(pkts),
            "filter": "tcp port 443",
        },
        "sni_results": sni_results
    }

    with open("logs.json", "w", encoding='utf-8') as file:
        json.dump(result, file, indent=2, ensure_ascii=False)


def sniffer_for_dns(count):
    pkts = sniff(filter="port 53", count=count)

    result = {
        "capture_info": {
            "packet_count": count,
            "filter": "port 53",
            "note": "Только DNS A запросы (type=1, class=1)"
        },
        "dns_a_queries": []
    }

    for i, pkt in enumerate(pkts):
        if (pkt.haslayer(DNS)) and (pkt.getlayer(DNS).qr == 0) and (pkt.getlayer(DNS).qd.qtype == 1) and (
                pkt.getlayer(DNS).qd.qclass == 1):

            clientIP = pkt.getlayer(IP).src
            serverIP = pkt.getlayer(IP).dst

            if pkt.haslayer(UDP):
                clientPort = pkt.getlayer(UDP).sport
                protocol = "UDP"
            elif pkt.haslayer(TCP):
                clientPort = pkt.getlayer(TCP).sport
                protocol = "TCP"

            clientDNSQueryID = pkt.getlayer(DNS).id
            clientDNSQuery = pkt.getlayer(DNS).qd.qname.decode('utf-8') if isinstance(pkt.getlayer(DNS).qd.qname,
                                                                                      bytes) else str(
                pkt.getlayer(DNS).qd.qname)

            query_info = {
                "index": i + 1,
                "timestamp": time.time(),
                "client_ip": clientIP,
                "server_ip": serverIP,
                "client_port": clientPort,
                "protocol": protocol,
                "query_id": clientDNSQueryID,
                "query_name": clientDNSQuery,
                "query_type": 1,
                "query_class": 1
            }

            result["dns_a_queries"].append(query_info)

    with open("logs.json", "w", encoding='utf-8') as file:
        json.dump(result, file, indent=2, ensure_ascii=False)

    return result


def sniffer_for_arp(count):
    result = {
        "capture_info": {
            "packet_count": count,
            "filter": "ARP",
            "note": ""
        },
        "ARP_a_queries": []
    }
    pkts = sniff(filter="arp", count=count)

    for pkt in pkts:
        if ARP in pkt:
            if pkt[ARP].op == 1:
                query_info = {
                    "type": "request",
                    "ARPRequest": pkt[ARP].pdst,  # кто хочет узнать
                    "ARPsender": pkt[ARP].psrc  # кто спрашивает
                }
                result["ARP_a_queries"].append(query_info)
            elif pkt[ARP].op == 2:
                query_info = {
                    "type": "reply",
                    "ARPsender": pkt[ARP].psrc,   # IP ответчика
                    "MACsender": pkt[ARP].hwsrc   # MAC ответчика
                }
                result["ARP_a_queries"].append(query_info)
    with open("logs.json", "w", encoding='utf-8') as file:
        json.dump(result, file, indent=2, ensure_ascii=False)


print("Sniffer by sting")
print("Type 'help' or 'help <command>' for more information")

def show_help(command = None):
    if command is None:
        print("\n=== SNIFFER HELP ===")
        print("Available commands:")
        print("  http [count]  - Sniff HTTP packets (default: 10)")
        print("  https [count] - Sniff HTTPS packets (default: 10)")
        print("  dns [count]   - Sniff DNS packets (default: 10)")
        print("  arp [count]   - Sniff ARP packets (default: 5)")
        print("  help [command] - Show this help message")
        print("  exit          - Exit the sniffer")
        print("\nExamples:")
        print("  sniffer> http        # Sniff 10 HTTP packets")
        print("  sniffer> https 20    # Sniff 20 HTTPS packets")
        print("  sniffer> help http   # Show help for HTTP command")
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
        case "http":
            count = int(command[1]) if len(command) > 1 else 10
            print("Running...")
            sniffer_for_http(count)
            print("The process is completed ")
        case "https":
            count = int(command[1]) if len(command) > 1 else 10
            print("Running...")
            sniffer_for_https(count)
            print("The process is completed ")
        case "dns":
            count = int(command[1]) if len(command) > 1 else 10
            print("Running...")
            sniffer_for_dns(count)
            print("The process is completed ")
        case "arp":
            count = int(command[1]) if len(command) > 1 else 5
            print("Running...")
            sniffer_for_arp(count)
            print("The process is completed ")
        case "help" | "-help" | "--help" | "-h":
            if len(command) > 1:
                show_help(command[1])
            else:
                show_help()
        case "exit":
            break
        case _:
            print("Unknown command")
            print("Type 'help' for available commands")
