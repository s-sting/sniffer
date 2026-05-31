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


#Simply_sniffer_for_http(10)
Simple_sniffer_for_https(50)