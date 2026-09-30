#!/usr/bin/env python3
"""
Basic Network Sniffer - CodeAlpha Cyber Security Task 1
Captures network packets and displays source/destination IPs,
protocol, ports, and payload.

For educational use only. Use on your own network or with permission.
"""

import argparse
import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw


def get_protocol_name(proto_num):
    return {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto_num, f"OTHER({proto_num})")


def format_payload(payload, max_len=80):
    try:
        text = payload.decode(errors="replace")
    except Exception:
        text = repr(payload)
    text = text.replace("\n", " ").replace("\r", " ")
    if len(text) > max_len:
        text = text[:max_len] + "..."
    return text


def packet_callback(packet):
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")

    if IP in packet:
        ip_layer = packet[IP]
        src = ip_layer.src
        dst = ip_layer.dst
        proto = get_protocol_name(ip_layer.proto)

        print(f"\n[{timestamp}] {src} -> {dst} | Protocol: {proto} | Length: {len(packet)} bytes")

        if TCP in packet:
            tcp = packet[TCP]
            print(f"   TCP Port: {tcp.sport} -> {tcp.dport} | Flags: {tcp.flags}")

        elif UDP in packet:
            udp = packet[UDP]
            print(f"   UDP Port: {udp.sport} -> {udp.dport}")

        elif ICMP in packet:
            icmp = packet[ICMP]
            print(f"   ICMP Type: {icmp.type} | Code: {icmp.code}")

        if Raw in packet:
            payload = bytes(packet[Raw])
            print(f"   Payload: {format_payload(payload)}")

    elif ARP in packet:
        arp = packet[ARP]
        op = "Request" if arp.op == 1 else "Reply" if arp.op == 2 else str(arp.op)
        print(f"\n[{timestamp}] ARP {op}: {arp.psrc} -> {arp.pdst} | MAC: {arp.hwsrc} -> {arp.hwdst}")


def main():
    parser = argparse.ArgumentParser(description="Basic Network Sniffer - CodeAlpha Task 1")
    parser.add_argument("-i", "--interface", help="Network interface (e.g., eth0, wlan0).")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = infinite).")
    parser.add_argument("-f", "--filter", default="", help="BPF filter, e.g., 'tcp', 'udp', 'icmp', 'port 80'")
    args = parser.parse_args()

    print("=" * 60)
    print("Basic Network Sniffer - CodeAlpha Cyber Security Task 1")
    print("Educational use only. Capture only your own network traffic.")
    print("=" * 60)

    if args.interface:
        print(f"Interface: {args.interface}")
    if args.filter:
        print(f"Filter: {args.filter}")
    print(f"Count: {'infinite' if args.count == 0 else args.count}")
    print("Press Ctrl+C to stop.\n")

    try:
        sniff(
            iface=args.interface,
            filter=args.filter,
            prn=packet_callback,
            count=args.count,
            store=False
        )
    except KeyboardInterrupt:
        print("\n[!] Sniffing stopped by user.")
    except Exception as e:
        print(f"[!] Error: {e}")
        print("Tip: Run as root. Check interface name with: ip a")


if __name__ == "__main__":
    main()
