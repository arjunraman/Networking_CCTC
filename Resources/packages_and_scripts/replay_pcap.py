#!/usr/bin/env python3

"""
PCAP Replay Tool with Speed Control

Usage:
  sudo python3 replay_pcap.py <pcap_file> [interface] [count] [pps]

Arguments:
  pcap_file    Path to the PCAP file to replay (required)
  interface    Network interface to send packets on (optional, default: scapy default)
  count        Number of times to replay the entire PCAP file (optional, default: 1; 0 = infinite)
  pps          Packets per second to send (optional, default: 10; 0 = max speed with no delay)

Example:
  sudo python3 replay_pcap.py capture.pcap eth0 2 50
  - Replays 'capture.pcap' twice on interface eth0 at 50 packets per second

Notes:
- Root privileges are required to send raw packets.
- Use Ctrl+C to stop the replay early.
- Setting pps to 0 will send packets as fast as possible.
"""

from scapy.all import rdpcap, sendp
import sys
import time

def replay_pcap(pcap_file, iface=None, count=1, pps=10):
    """
    Replay packets from a PCAP file on specified interface with speed control.
    
    :param pcap_file: Path to PCAP file.
    :param iface: Network interface to send packets on (e.g., 'eth0'). If None, scapy default used.
    :param count: Number of times to replay the pcap (0 = infinite).
    :param pps: Packets per second (speed control). Use 0 for max speed (no delay).
    """
    print(f"Reading packets from {pcap_file}...")
    packets = rdpcap(pcap_file)
    if not packets:
        print("No packets found in the PCAP file.")
        return
    
    print(f"Loaded {len(packets)} packets.")
    print(f"Sending on interface: {iface or 'default'}")
    print(f"Packets per second: {pps if pps > 0 else 'max speed (no delay)'}")
    
    delay = 1.0 / pps if pps > 0 else 0
    
    loop = 0
    try:
        while count == 0 or loop < count:
            print(f"Sending iteration {loop + 1}...")
            for pkt in packets:
                sendp(pkt, iface=iface, verbose=False)
                if delay > 0:
                    time.sleep(delay)
            loop += 1
    except KeyboardInterrupt:
        print("\nStopped by user.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    
    pcap_path = sys.argv[1]
    interface = sys.argv[2] if len(sys.argv) > 2 else None
    count = int(sys.argv[3]) if len(sys.argv) > 3 else 1
    pps = int(sys.argv[4]) if len(sys.argv) > 4 else 10
    
    replay_pcap(pcap_path, interface, count, pps)