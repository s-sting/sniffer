from scapy.all import *
import json
import struct


def Simply_sniffer_for_http(count):

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


def Simple_sniffer_for_https(count):

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

                            print(f"Найден SNI: {sni} (from {ip_src} to {ip_dst})")
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
            clientDNSQuery = pkt.getlayer(DNS).qd.qname.decode('utf-8') if isinstance(pkt.getlayer(DNS).qd.qname,bytes) else str(pkt.getlayer(DNS).qd.qname)

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

    print(f"\n✅ Найдено {len(result['dns_a_queries'])} DNS A запросов из {count} пакетов")
    return result





#Simply_sniffer_for_http(10)
#Simple_sniffer_for_https(50)
sniffer_for_dns(10)