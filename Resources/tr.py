#!/usr/bin/env python3
import subprocess
import sys
import shutil
import os
import time
import json
import urllib.request
import platform
import re
import statistics
import textwrap

class Color:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    RESET = '\033[0m'

def is_traceroute_installed():
    return shutil.which("traceroute") is not None

def install_traceroute():
    print("traceroute utility is not installed. Attempting to install it now...")
    distro = platform.system()
    if distro == "Linux":
        if shutil.which("apt-get"):
            subprocess.run(["sudo", "apt-get", "update"], check=True)
            subprocess.run(["sudo", "apt-get", "install", "-y", "traceroute"], check=True)
        elif shutil.which("yum"):
            subprocess.run(["sudo", "yum", "install", "-y", "traceroute"], check=True)
        elif shutil.which("pacman"):
            subprocess.run(["sudo", "pacman", "-Sy", "traceroute"], check=True)
        else:
            print("Unsupported Linux package manager. Please install traceroute manually.")
            sys.exit(1)
    elif distro == "Darwin":
        if shutil.which("brew"):
            subprocess.run(["brew", "install", "traceroute"], check=True)
        else:
            print("Homebrew not found. Please install Homebrew or traceroute manually.")
            sys.exit(1)
    else:
        print(f"Unsupported OS: {distro}. Please install traceroute manually.")
        sys.exit(1)

def check_and_prompt_sudo(protocol):
    if platform.system() == "Linux" and protocol in ("icmp", "tcp"):
        if os.geteuid() != 0:
            print(f"\nProtocol '{protocol}' requires elevated permissions on Linux.")
            try:
                subprocess.run(["sudo", "-v"], check=True)
            except subprocess.CalledProcessError:
                print("Failed to obtain sudo permissions. Exiting.")
                sys.exit(1)
            return True
    return False

def prompt_protocol_and_port():
    protocol = input("Select protocol to use [udp (default), tcp, icmp]: ").strip().lower()
    if protocol == "":
        protocol = "udp"
    while protocol not in ("udp", "tcp", "icmp"):
        print("Invalid choice. Please enter udp, tcp, or icmp.")
        protocol = input("Select protocol to use [udp (default), tcp, icmp]: ").strip().lower()
        if protocol == "":
            protocol = "udp"

    port = None
    if protocol == "tcp":
        port_str = input("Enter TCP port to use (default 80): ").strip()
        if port_str == "":
            port = 80
        else:
            try:
                port = int(port_str)
                if port < 1 or port > 65535:
                    raise ValueError
            except ValueError:
                print("Invalid port number. Using default port 80.")
                port = 80
    return protocol, port

def parse_args():
    import argparse
    parser = argparse.ArgumentParser(description="Traceroute with UDP, TCP, ICMP modes and GeoIP lookup")
    parser.add_argument("destination", nargs='?', help="Destination hostname or IP to traceroute")
    parser.add_argument("-m", "--max-hops", type=int, default=30, help="Maximum number of hops (default 30)")
    parser.add_argument("-p", "--port", type=int, default=None, help="Port number to use for UDP traceroute (TCP port prompted separately)")
    parser.add_argument("-w", "--wait", type=int, default=3, help="Wait time per probe in seconds (default 3)")
    parser.add_argument("-6", "--ipv6", action="store_true", help="Use IPv6")
    return parser.parse_args()

def build_traceroute_command(args, protocol):
    cmd = ["traceroute", "-m", str(args.max_hops), "-w", str(args.wait)]
    if args.ipv6:
        cmd.append("-6")
    if protocol == "icmp":
        cmd.append("-I")
    elif protocol == "tcp":
        cmd.append("-T")
        port = args.port if args.port else 80
        cmd.extend(["-p", str(port)])
    else:
        if args.port:
            cmd.extend(["-p", str(args.port)])
    cmd.append(args.destination)
    return cmd

def geoip_lookup(ip):
    if ip == "*" or ip == "":
        return "No response"
    try:
        with urllib.request.urlopen(f"https://ipinfo.io/{ip}/json", timeout=5) as response:
            data = json.load(response)
            city = data.get("city", "")
            region = data.get("region", "")
            country = data.get("country", "")
            org = data.get("org", "")
            loc = data.get("loc", "")
            loc_str = f"({loc})" if loc else ""
            geo_str = ", ".join(filter(None, [city, region, country]))
            return f"{geo_str} {loc_str} {org}".strip()
    except Exception:
        return "GeoIP lookup failed"

def is_ip(address):
    ipv4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
    ipv6 = re.compile(r"^[0-9a-fA-F:]+$")
    return ipv4.match(address) or ipv6.match(address)

def parse_traceroute_output(line):
    parts = line.strip().split()
    if len(parts) < 2:
        return None, None, []

    hop = parts[0]
    ip = "*"
    times = []

    for p in parts[1:]:
        if p.startswith("(") and p.endswith(")"):
            candidate = p[1:-1]
            if is_ip(candidate):
                ip = candidate
                break
        elif is_ip(p):
            ip = p
            break

    i = 1
    while i < len(parts):
        p = parts[i]
        if p == "*":
            times.append("*")
            i += 1
        elif p.replace('.', '', 1).isdigit():
            if i + 1 < len(parts) and parts[i + 1] == "ms":
                times.append(p + " ms")
                i += 2
            else:
                i += 1
        else:
            i += 1

    return hop, ip, times

def interpret_rtt(times):
    ms_values = []
    for t in times:
        if t.endswith("ms"):
            try:
                ms = float(t.replace("ms", "").strip())
                ms_values.append(ms)
            except:
                pass
    if not ms_values:
        return "No response"
    avg = statistics.mean(ms_values)
    stddev = statistics.stdev(ms_values) if len(ms_values) > 1 else 0

    if avg < 5:
        return "Local or same LAN"
    elif avg > 150:
        return "High latency/distant hop"
    elif stddev > 10:
        return "Possible congestion or jitter"
    else:
        return "Stable"

def run_traceroute(cmd, use_sudo):
    if use_sudo:
        cmd = ["sudo"] + cmd

    print(f"\n{Color.CYAN}Running traceroute command:{Color.RESET} {' '.join(cmd)}\n")
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    print(f"{'Hop':<5} {'IP':<40} {'Times':<30} {'Location':<40} RTT Analysis")
    print("-" * 140)

    hops = []

    while True:
        line = process.stdout.readline()
        if not line:
            break
        if line.lower().startswith("traceroute to "):
            continue
        hop, ip, times = parse_traceroute_output(line)
        if hop and ip:
            hops.append((hop, ip, times))
        else:
            print(line.strip())

    process.wait()

    if not hops:
        print("No traceroute hops found.")
        return

    *main_hops, final_hop = hops

    max_loc_width = 40

    for hop, ip, times in main_hops:
        location = geoip_lookup(ip)
        times_str = ' '.join(t for t in times if t != '*')
        rtt_comment = interpret_rtt(times)
        color = Color.GREEN
        if '*' in times and times_str:
            times_str += " (partial timeout)"
            color = Color.YELLOW
        elif '*' in times:
            times_str = "(no response)"
            color = Color.RED

        # Wrap location text
        loc_lines = textwrap.wrap(location, width=max_loc_width) or [""]

        # Print first line with all columns including RTT comment
        print(f"{color}{hop:<5} {ip:<40} {times_str:<30} {loc_lines[0]:<{max_loc_width}} {rtt_comment}{Color.RESET}")

        # Print continuation lines for wrapped location only
        for line in loc_lines[1:]:
            print(f"{color}{'':<5} {'':<40} {'':<30} {line:<{max_loc_width}} {'':<10}{Color.RESET}")

    print()
    hop, ip, times = final_hop
    location = geoip_lookup(ip)
    times_str = ' '.join(t for t in times if t != '*')
    if '*' in times and not times_str:
        times_str = "(no response)"
    elif '*' in times:
        times_str += " (partial timeout)"
    comment = interpret_rtt(times)

    # Wrap final location as well
    loc_lines = textwrap.wrap(location, width=max_loc_width) or [""]

    print(f"{Color.CYAN}Final hop {hop} -> {ip} Times: {times_str} Location: {loc_lines[0]} RTT: {comment}{Color.RESET}")
    for line in loc_lines[1:]:
        print(f"{Color.CYAN}{'':<14} {'':<40} {'':<30} Location: {line}{Color.RESET}")

def main():
    os.system('clear' if os.name == 'posix' else 'cls')  # Clear screen first

    if not is_traceroute_installed():
        install_traceroute()
        print("Restarting after traceroute install...")
        time.sleep(2)
        os.execv(sys.executable, [sys.executable] + sys.argv)

    args = parse_args()

    # Prompt for destination manually if not provided via CLI
    if not args.destination:
        args.destination = input("Enter destination hostname or IP to traceroute: ").strip()
        while not args.destination:
            print("Destination cannot be empty.")
            args.destination = input("Enter destination hostname or IP to traceroute: ").strip()

    protocol, user_port = prompt_protocol_and_port()
    need_sudo = check_and_prompt_sudo(protocol)

    if protocol == "tcp" and user_port:
        args.port = user_port

    cmd = build_traceroute_command(args, protocol)
    run_traceroute(cmd, need_sudo)

if __name__ == "__main__":
    main()
