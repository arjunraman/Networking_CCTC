# tcpdump Master Cheat Sheet

## Table of Contents

1. [Overview & Basics](#overview--basics)  
2. [Installation](#installation)  
3. [How tcpdump Works (Conceptual)](#how-tcpdump-works-conceptual)  
4. [Command-Line Options](#command-line-options)  
   - [Packet-Capturing Options](#packet-capturing-options)  
   - [Display / Output Options](#display--output-options)  
   - [File-Based Capture & Analysis](#file-based-capture--analysis)  
5. [Capture Filter Primitives](#capture-filter-primitives)  
   - [Hosts & Networks](#hosts--networks)  
   - [Ports & Services](#ports--services)  
   - [Length, Protocol, Broadcast, VLAN, MPLS](#length-protocol-broadcast-vlan-mpls)  
   - [Protocol Keywords](#protocol-keywords)  
6. [Logical & Comparison Operators](#logical--comparison-operators)  
7. [Simple Examples](#simple-examples)  
8. [Complex Examples](#complex-examples)  
9. [Advanced BPF / Byte-Offset Filters](#advanced-bpf--byte-offset-filters)

---

## Overview & Basics

```bash
tcpdump [options] [capture filter expression]
```

- **Options** control how and where you capture, and how packets are displayed.  
- The **filter expression** controls what traffic is matched (using BPF syntax).  

tcpdump typically uses:

- **Promiscuous mode** to see packets not directly addressed to the host.  
- **Raw sockets** so it receives packets with full headers.  
- A compiled **BPF program** attached to the socket so non-matching packets are dropped in the kernel.


---

## Installation

```bash
# CentOS / RHEL
sudo yum install tcpdump

# Fedora
sudo dnf install tcpdump

# Ubuntu / Debian / Linux Mint
sudo apt-get install tcpdump
```


---

## How tcpdump Works (Conceptual)

High-level pipeline:

1. NIC receives a frame (often in **promiscuous mode**).  
2. Kernel delivers it to a **raw socket** used by libpcap/tcpdump.  
3. A compiled **BPF filter** (attached via `SO_ATTACH_FILTER`) accepts or drops the packet.  
4. Accepted packets are delivered to **libpcap**, which hands them to **tcpdump**.  
5. tcpdump formats and prints or writes them to a capture file.


---

## Command-Line Options

### Packet-Capturing Options

| Switch | Example | Description |
|--------|---------|-------------|
| `-i any` | `tcpdump -i any` | Capture from **all** interfaces. |
| `-i eth0` | `tcpdump -i eth0` | Capture from a specific interface. |
| `-c <count>` | `tcpdump -i eth0 -c 10` | Stop after capturing `<count>` packets. |
| `-D` | `tcpdump -D` | List available capture interfaces. |
| `-A` | `tcpdump -i eth0 -A` | Print each packet's payload in ASCII. |
| `-s <len>` | `tcpdump -i eth0 -s 0` | Snap length in bytes; `0` = entire packet. |
| `-G <n>` | `tcpdump -i eth0 -G 60 -w 'out-%s.pcap'` | Rotate dump file every `<n>` seconds. |
| `-F <file>` | `tcpdump -F filter.txt` | Read the filter expression from a file. |
| `-I` | `tcpdump -I -i wlan0` | Put wireless interface into monitor mode (where supported). |
| `-L` | `tcpdump -L` | List the datalink (DLT) types for the selected interface. |
| `-N` | `tcpdump -N` | Do not print domain names (strip domain part from host names). |
| `-K` | `tcpdump -K` | Do not verify TCP checksums. |
| `-n` | `tcpdump -n` | Do not resolve host names (numeric IPs). |
| `-nn` | `tcpdump -nn` | Do not resolve host or port names (numeric IPs/ports). |
| `-p` | `tcpdump -p` | Do not put the interface into promiscuous mode. |
| `ip` | `tcpdump ip` | Capture only IPv4 packets. |
| `ip6` | `tcpdump ip6` | Capture only IPv6 packets. |
| `tcp` | `tcpdump tcp` | Capture only TCP packets. |
| `udp` | `tcpdump udp` | Capture only UDP packets. |


### Display / Output Options

| Switch | Description |
|--------|-------------|
| `-q` | "Quick" output; less verbose packet info. |
| `-t` | Do not print timestamps. |
| `-v` | Verbose output. |
| `-vv` | More verbose. |
| `-vvv` | Most verbose. |
| `-e` | Print link-layer (Ethernet) header on each line. |
| `-x` | Print packet data (payload) in hex. |
| `-xx` | Print hex including link-layer header. |
| `-X` | Print packet data in hex **and** ASCII. |
| `-XX` | Print hex and ASCII including link-layer header. |
| `-S` | Print absolute TCP sequence numbers. |


### File-Based Capture & Analysis

```bash
# Capture live traffic and write to a file (no stdout printing)
tcpdump -w capture.pcap

# Capture on a specific interface and write to file
tcpdump -i eth0 -w capture.pcap

# Read and analyze packets from an existing capture file
tcpdump -r capture.pcap
```

- `-w` writes raw packets to a pcap file for later analysis (e.g., in Wireshark).  
- `-r` reads packets from a file instead of capturing on the wire.


---

## Capture Filter Primitives

### Hosts & Networks

```bash
[src|dst] host <host>          # Match by IP source, destination, or either
ether [src|dst] host <ehost>  # Match by Ethernet MAC source/dest
gateway host <host>           # Packets that used <host> as a gateway
[src|dst] net <network>/<len> # Match by subnet in CIDR form
```

Examples:

```bash
tcpdump host 10.0.0.5
tcpdump src host 10.0.0.1 and dst host 10.0.0.2
tcpdump ether src host aa:bb:cc:dd:ee:ff
tcpdump net 192.168.1.0/24
```

### Ports & Services

```bash
[tcp|udp] [src|dst] port <port>
[tcp|udp] [src|dst] portrange <p1>-<p2>
<service>                   # e.g. http, ssh, dns (using /etc/services)
```

Examples:

```bash
tcpdump tcp port 80
tcpdump udp src port 53
tcpdump portrange 21-125
tcpdump http
```

### Length, Protocol, Broadcast, VLAN, MPLS

```bash
less <length>                          # length <= value
greater <length>                       # length >= value
(ether|ip|ip6) proto <protocol>        # protocol number or name
(ether|ip) broadcast                   # Ethernet or IPv4 broadcast
(ether|ip|ip6) multicast               # Ethernet/IPv4/IPv6 multicast
vlan [<vlan>]                          # 802.1Q VLAN frames (optional VLAN ID)
mpls [<label>]                         # MPLS packets (optional label)
type (mgt|ctl|data) [subtype <sub>]   # 802.11 (Wi-Fi) frame type/subtype
```

### Protocol Keywords

These can be used alone or combined:

```text
arp  ether  fddi  icmp  ip  ip6  link  ppp  radio  rarp  slip  tcp  tr  udp  wlan
```

Examples:

```bash
tcpdump icmp
tcpdump ip6 and tcp
tcpdump arp or rarp
```


---

## Logical & Comparison Operators

| Operator | Syntax | Example | Description |
|----------|--------|---------|-------------|
| AND | `and`, `&&` | `tcpdump src 192.168.1.1 and dst port 21` | Both conditions must match. |
| OR | `or`, `||` | `tcpdump dst 10.1.1.1 or icmp` | Either condition can match. |
| NOT | `not`, `!` | `tcpdump dst 10.1.1.1 and not icmp` | Negation. |
| LESS | `<` | `tcpdump <32` | Packet length < 32 bytes. |
| GREATER | `>` | `tcpdump >32` | Packet length > 32 bytes. |


---

## Simple Examples

```bash
tcpdump ether               # All Ethernet traffic
tcpdump arp                 # All ARP packets
tcpdump icmp                # All ICMP packets
tcpdump 'icmp[icmptype] = icmp-echo'       # ICMP echo-request (ping)
tcpdump 'icmp[icmptype] = icmp-echoreply'  # ICMP echo-reply
tcpdump host 192.168.1.1                  # To or from 192.168.1.1
tcpdump src host 192.168.1.1              # From 192.168.1.1
tcpdump dst host 192.168.1.1              # To 192.168.1.1
tcpdump net 192.168.1.0/24                # Any host in subnet
tcpdump src net 192.168.1.0/24            # Source in subnet
tcpdump dst net 192.168.1.0/24            # Destination in subnet
tcpdump ip                                # All IPv4 packets
tcpdump ip6                               # All IPv6 packets
tcpdump tcp                               # All TCP packets
tcpdump udp                               # All UDP packets
tcpdump tcp port 22                       # TCP traffic on port 22 (SSH)
tcpdump tcp src port 22                   # Packets leaving TCP 22
tcpdump tcp dst port 22                   # Packets arriving at TCP 22
tcpdump port 53                           # TCP or UDP traffic on port 53 (DNS)
tcpdump 'tcp[tcpflags] & tcp-ack != 0'    # Packets where ACK flag is set
```


---

## Complex Examples

```bash
# Traffic between 192.168.1.1 and either 10.1.1.1 or 10.1.1.2
tcpdump 'host 192.168.1.1 and (10.1.1.1 or 10.1.1.2)'

# All IP packets between 10.1.1.1 and any host except 10.1.1.2
tcpdump 'ip host 10.1.1.1 and not 10.1.1.2'

# All traffic between local hosts and hosts at Berkeley
tcpdump 'net ucb-ether'

# All FTP traffic through internet gateway 192.168.1.1
tcpdump 'gateway 192.168.1.1 and (port ftp or ftp-data)'

# IP traffic neither sourced from nor destined for local hosts
tcpdump 'ip and not net localnet'

# Start/end packets (SYN and FIN) of each TCP conversation with a non-local host
tcpdump 'tcp[tcpflags] & (tcp-syn|tcp-fin) != 0 and not src and dst net localnet'

# TCP packets with both RST and ACK flags set
tcpdump 'tcp[tcpflags] & (tcp-rst|tcp-ack) == (tcp-rst|tcp-ack)'

# IPv4 HTTP packets to/from port 80 that actually contain data
tcpdump 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'

# IP packets longer than 576 bytes sent through gateway 192.168.1.1
tcpdump 'gateway 192.168.1.1 and ip[2:2] > 576'

# IP broadcast or multicast packets not sent via Ethernet broadcast/multicast
tcpdump 'ether[0] & 1 = 0 and ip[16] >= 224'

# All ICMP packets that are not echo requests/replies (non-ping ICMP)
tcpdump 'icmp[icmptype] != icmp-echo and icmp[icmptype] != icmp-echoreply'
```


---

## Advanced BPF / Byte-Offset Filters

These use the `proto[offset:length]` syntax to look at raw header bytes.

### Ethernet / Data-Link Layer

```bash
# Broadcast destination MAC ff:ff:ff:ff:ff:ff
tcpdump -i eth0 'ether[0:4] = 0xffffffff and ether[4:2] = 0xffff'

# Specific source MAC fa:16:3e:f0:ca:fc
tcpdump -i eth0 'ether[6:4] = 0xfa163ef0 and ether[10:2] = 0xcafc'

# Unicast vs multicast bit on destination and source MAC
tcpdump -i eth0 'ether[0] & 0x01 = 0x00'   # dest unicast
tcpdump -i eth0 'ether[0] & 0x01 = 0x01'   # dest multicast
tcpdump -i eth0 'ether[6] & 0x01 = 0x00'   # src unicast
tcpdump -i eth0 'ether[6] & 0x01 = 0x01'   # src multicast

# EtherType matches
tcpdump -i eth0 'ether[12:2] = 0x0800'     # IPv4
tcpdump -i eth0 'ether[12:2] = 0x0806'     # ARP
tcpdump -i eth0 'ether[12:2] = 0x8100'     # 802.1Q VLAN
tcpdump -i eth0 'ether[12:2] = 0x86dd'     # IPv6

# VLAN ID 100 on tagged packets
tcpdump -i eth0 'ether[12:2] = 0x8100 and ether[14:2] & 0x0fff = 0x0064'

# Double-tagged VLAN hopping (outer VLAN 1, inner VLAN 999)
tcpdump -i eth0 'ether[12:4] & 0xffff0fff = 0x81000001 && ether[16:4] & 0xffff0fff = 0x810003E7'

# ARP opcode: request (1) or reply (2)
tcpdump -i eth0 'arp[6:2] = 0x0001'        # request
tcpdump -i eth0 'arp[6:2] = 0x0002'        # reply
```

### IPv4 Header Fields

```bash
# IP header length (IHL) > 5 -> IP options present
tcpdump -i eth0 'ip[0] & 0x0f > 0x05'

# DSCP = 16
tcpdump -i eth0 'ip[1] >> 2 = 16'

# Fragment flags: DF and MF bits
tcpdump -i eth0 'ip[6] & 0x40 = 0x40'      # DF set
tcpdump -i eth0 'ip[6] & 0x20 = 0x20'      # MF set

# Fragment offset > 0 (non-first fragments)
tcpdump -i eth0 'ip[6:2] & 0x1fff > 0'

# TTL constraints
tcpdump -i eth0 'ip[8] = 128'              # TTL exactly 128
tcpdump -i eth0 'ip[8] < 128'              # TTL less than 128

# Protocol field: ICMP, TCP, UDP
tcpdump -i eth0 'ip[9] = 0x01'             # ICMP
tcpdump -i eth0 'ip[9] = 0x06'             # TCP
tcpdump -i eth0 'ip[9] = 0x11'             # UDP

# Source / destination IPv4 address 10.1.1.1
tcpdump -i eth0 'ip[12:4] = 0x0a010101'    # source
tcpdump -i eth0 'ip[16:4] = 0x0a010101'    # destination
```

### IPv6 Header Fields

```bash
# Traffic Class non-zero
tcpdump -i eth0 'ip6[0:2] & 0x0ff0 != 0'

# Flow Label non-zero
tcpdump -i eth0 'ip6[0:4] & 0x000fffff != 0'

# Next Header: ICMPv6, TCP, UDP
tcpdump -i eth0 'ip6[6] = 0x3a'            # ICMPv6
tcpdump -i eth0 'ip6[6] = 0x06'            # TCP
tcpdump -i eth0 'ip6[6] = 0x11'            # UDP

# Hop Limit constraints
tcpdump -i eth0 'ip6[7] = 128'
tcpdump -i eth0 'ip6[7] < 128'
```

### ICMPv4 Example

```bash
# Destination Unreachable, code 9 (network administratively prohibited)
tcpdump -i eth0 'icmp[0] = 3 and icmp[1] = 9'
```

### TCP Flag Experiments (tcp[13])

```bash
# Flags byte exactly 0x11 (SYN+ACK only)
tcpdump 'tcp[13] = 0x11' -r tcpflags.pcap

# SYN and ACK set (other bits may also be set)
tcpdump 'tcp[13] & 0x11 = 0x11' -r tcpflags.pcap

# At least one of SYN or ACK set
tcpdump 'tcp[13] & 0x11 != 0' -r tcpflags.pcap
```

### Inspecting BPF with -d

```bash
# Show compiled BPF for various filters
tcpdump -d 'tcp src port 22'
tcpdump -d 'udp[2:2] = 53'
tcpdump -d 'tcp port 80'
tcpdump -d 'tcp[13] = 17'
tcpdump -d 'tcp[13] & 17 = 17'
tcpdump -d 'tcp[13] & 17 != 0'
```

This sheet consolidates tcpdump options, primitive filters, common examples, complex logic, and advanced BPF-style byte-offset expressions into a single reference.
