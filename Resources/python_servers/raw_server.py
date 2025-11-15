#!/usr/bin/python3

from scapy.all import sniff, IP, TCP, Raw
import base64
import subprocess
import ipaddress
import os

RESPONSE_PORT = 9999  # Netcat response port

# Load allowed names (converted to lowercase for case-insensitive matching)
def load_allowed_names(file_path='allowed_names.txt'):
    with open(file_path, 'r') as f:
        return {name.strip().lower() for name in f if name.strip()}

# Decode payload based on protocol
def decode_payload(payload, protocol):
    try:
        if protocol == 16:
            return bytes.fromhex(payload.decode()).decode('utf-8', errors='ignore')
        elif protocol == 6:
            return base64.b64decode(payload).decode('utf-8', errors='ignore')
    except Exception:
        return None
    return None

# Execute the command (a string) in a subshell.
os.system("clear")

# Display names with color (green if seen, red if not)
def display_names():
    for name in sorted(original_allowed_names):
        if name.lower() in used_names:
            print(f"\033[32m{name}\033[0m", end=" ")  # Green
        else:
            print(f"\033[31m{name}\033[0m", end=" ")  # Red
    print()

# Extract IP and TCP info for response
def extract_info(packet):
    if IP not in packet:
        return None
    ip = packet[IP]
    proto = ip.proto

    ip_info = (
        f"IP Info:\n"
        f"  DSCP: {(ip.tos & 0b11111100) >> 2}\n"
        f"  ECN: {ip.tos & 0b11}\n"
        f"  Total Length: {ip.len}\n"
        f"  ID: {ip.id}\n"
        f"  Flags: {ip.flags}\n"
        f"  Fragment Offset: {ip.frag}\n"
        f"  TTL: {ip.ttl}\n"
        f"  Source IP: {ip.src}\n"
        f"  Destination IP: {ip.dst}\n"
    )

    if proto == 16:
        return ip_info
    elif proto == 6 and TCP in packet:
        tcp = packet[TCP]
        tcp_info = (
            f"TCP Info:\n"
            f"  Source Port: {tcp.sport}\n"
            f"  Destination Port: {tcp.dport}\n"
            f"  Sequence Number: {tcp.seq}\n"
            f"  Acknowledgment Number: {tcp.ack}\n"
            f"  TCP Flags: {tcp.flags}\n"
            f"  Window Size: {tcp.window}\n"
            f"  Urgent Pointer: {tcp.urgptr}\n"
        )
        return ip_info + tcp_info
    return None

# Send response back to sender using netcat
def send_via_netcat(ip_dst, message):
    try:
        ipaddress.ip_address(ip_dst)
        subprocess.run(
            ["nc", "-w1", ip_dst, str(RESPONSE_PORT)],
            input=message.encode(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        print(f"[+] Sent info to {ip_dst}:{RESPONSE_PORT}")
    except Exception as e:
        print(f"[-] Netcat error: {e}")

# Handle incoming packet
def handle_packet(packet):
    if IP not in packet:
        return

    proto = packet[IP].proto
    src_ip = packet[IP].src

    if proto not in [6, 16]:
        return

    raw_payload = b""
    if Raw in packet:
        raw_payload = bytes(packet[Raw].load)

    if not raw_payload:
        return

    name = decode_payload(raw_payload, proto)
    if not name:
        return

    normalized_name = name.strip().lower()

    if (
        not name.isprintable()
        or not normalized_name.isalnum()
        or len(normalized_name) > 20
        or normalized_name not in allowed_names
    ):
        return

    # Valid and allowed name (case-insensitive match)
    if normalized_name not in used_names:
        print(f"[+] Name matched: {name}")
        used_names.add(normalized_name)
    else:
        print(f"[+] Repeated match: {name}")
    display_names()

    # Respond only for allowed names
    info = extract_info(packet)
    if info:
        send_via_netcat(src_ip, info)

# --- MAIN ---
original_allowed_names = load_allowed_names()         # For display
allowed_names = {name.lower() for name in original_allowed_names}  # For matching
used_names = set()

print("***Set your Netcat to listen on port 9999 (nc -lvp 9999) for the response.***")
print("[*] Sniffer started. Waiting for packets...")

display_names()
sniff(filter="ip", prn=handle_packet, store=0)
