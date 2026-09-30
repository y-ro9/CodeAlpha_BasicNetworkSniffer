# CodeAlpha Basic Network Sniffer

This project is part of the CodeAlpha Cyber Security Internship - Task 1.

## Objective
Build a Python program to capture network traffic packets, analyze their structure, and display useful information like source/destination IPs, protocols, ports, and payloads.

## Tools Used
- Python 3
- Scapy

## Installation
```bash
sudo pacman -S --needed python python-pip tcpdump libpcap
sudo pip install scapy --break-system-packages


```bash
sudo python3 basic_network_sniffer.py -i eth0 -c 20 -f "tcp"

## Options:

    -i : Network interface

    -c : Packet count

    -f : BPF filter

## Features

    Captures live network packets

    Displays source and destination IP

    Identifies TCP, UDP, ICMP, ARP

    Shows port numbers and payload preview

    Supports BPF filters

## Ethical Note

This tool is for educational purposes only. Use it only on your own network or with explicit permission.

## Author

Yash Raj
