#!/usr/bin/python3

import socket
import random
import threading

PORT_RANGE = (10000, 20000)
NUM_PORTS = 10
MESSAGE_FILE = 'messages.txt'  # Update this if needed

def load_messages(file_path):
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def start_tcp_server(port, message):
    def handler():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', port))
            s.listen(5)
            print(f"[TCP] Listening on port {port}")
            while True:
                conn, addr = s.accept()
                with conn:
                    print(f"[TCP] Connection from {addr} on port {port}")
                    # Add newline before and after the message
                    modified_message = f"\n{message}\n"
                    conn.sendall(modified_message.encode())
    threading.Thread(target=handler, daemon=True).start()

def start_udp_server(port, message):
    def handler():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(('', port))
            print(f"[UDP] Listening on port {port}")
            while True:
                data, addr = s.recvfrom(1024)
                print(f"[UDP] Received from {addr} on port {port}")
                # Add newline before and after the message
                modified_message = f"\n{message}\n\n"
                s.sendto(modified_message.encode(), addr)
    threading.Thread(target=handler, daemon=True).start()

def get_unique_ports(count):
    return random.sample(range(*PORT_RANGE), count)

def main():
    messages = load_messages(MESSAGE_FILE)
    if len(messages) < NUM_PORTS * 2:
        print(f"Error: Need at least {NUM_PORTS * 2} messages in {MESSAGE_FILE}")
        return
    tcp_ports = get_unique_ports(NUM_PORTS)
    udp_ports = get_unique_ports(NUM_PORTS)
    for i in range(NUM_PORTS):
        tcp_port = tcp_ports[i]
        udp_port = udp_ports[i]
        tcp_msg = random.choice(messages)
        udp_msg = random.choice(messages)
        start_tcp_server(tcp_port, tcp_msg)
        start_udp_server(udp_port, udp_msg)
    print("Servers running. Press Ctrl+C to stop.")
    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("Shutting down.")

if __name__ == "__main__":
    main()
