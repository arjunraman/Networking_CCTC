# Wireshark Display Filters – Consolidated Cheat Sheet

---

## 1. Logical & Comparison Operators

### 1.1 Logical operators

| Text | Symbol | Meaning | Example |
|------|--------|---------|---------|
| `and` | `&&` | Both conditions must be true. | `ip.addr == 10.10.50.1 and tcp.port == 25` |
| `or`  | `\|\|` | At least one condition is true. | `arp or icmp` |
| `xor` | `^^` | Exactly one condition is true (not both). | `(ip.dst == 192.168.1.1) xor (ip.dst == 192.168.1.2)` |
| `not` | `!` | Negates a condition. | `not multicast` / `!(arp or icmp or stp)` |

> Shorthand: you’ll often see `!(filter)` used to negate a full expression, e.g. `!(arp or icmp or stp)` to hide those protocols.

---

### 1.2 Comparison operators

| Text | Symbol | Meaning | Example |
|------|--------|---------|---------|
| `eq` | `==` | Equal to | `ip.dst == 192.168.1.1` |
| `ne` | `!=` | Not equal to | `ip.dst != 192.168.1.1` |
| `gt` | `>`  | Greater than | `frame.len > 10` |
| `lt` | `<`  | Less than | `frame.len < 10` |
| `ge` | `>=` | Greater than or equal | `frame.len >= 10` |
| `le` | `<=` | Less than or equal | `frame.len <= 10` |

---

### 1.3 Slice & membership operators

| Operator | Syntax | Meaning | Example |
|----------|--------|---------|---------|
| Slice | `field[start:end]` | Match a byte slice / substring of a field. | `(eth.dst[0] & 1) == 1` – test low bit of first MAC byte. |
| Membership | `field in { … }` | Field value is in a set of values. | `tcp.port in {80, 443, 8080}` – common web ports. |

---

## 2. Filter Types

| Type           | Description                                                  |
|----------------|--------------------------------------------------------------|
| Capture filter | Applied **before** capture; limits what is captured.         |
| Display filter | Applied **after** capture; hides/shows packets in the GUI.   |

---

## 2.1 Common Protocol Filters by Layer

You can quickly filter by protocol name alone:

| Layer / Type      | Example filters                                                                 |
|-------------------|----------------------------------------------------------------------------------|
| Layer 2           | `eth`, `arp`, `vlan`, `wlan`                                                     |
| Layer 3           | `ip`, `ipv6`, `icmp`, `icmpv6`                                                   |
| Layer 4           | `tcp`, `udp`                                                                     |
| Session/Other     | `smb`, `socks`, `rpc`                                                            |
| Application (L7)  | `telnet`, `ssh`, `http`, `ssl`, `tls`, `quic`, `dns`, `pop`, `imap`, `dhcp`, `bootp`, `ntp`, `tacplus`, `radius`, `rdp` |
| Routing protocols | `rip`, `ospf`, `bgp`                                                             |

These can be combined with other fields, e.g. `http and ip.addr == 10.0.0.5`.

---

## 3. Ethernet & VLAN

### 3.1 Ethernet fields

```wireshark
eth.addr   # Any MAC (source or destination)
eth.dst    # Destination MAC
eth.src    # Source MAC
```

| Field           | Quick explanation                                           |
|-----------------|-------------------------------------------------------------|
| `eth.len`       | Ethernet payload length field.                              |
| `eth.lg`        | “Locally administered” bit of the MAC address.             |
| `eth.ig`        | “Individual/group” bit (unicast vs multicast).             |
| `eth.multicast` | True if the MAC address is multicast.                      |
| `eth.trailer`   | Ethernet trailer bytes (e.g., padding).                    |
| `eth.type`      | EtherType (e.g., 0x0800 IPv4, 0x86dd IPv6).                |
| `eth.dst == ff:ff:ff:ff:ff:ff` | Ethernet broadcast frames.                 |
| `(eth.dst[0] & 1) == 1` | Group (multicast/broadcast) MAC – low bit set.     |
| `ether host aa:bb:cc:dd:ee:ff` | Capture only traffic to/from that MAC (capture filter). |

---

### 3.2 VLAN (802.1Q)

```wireshark
vlan     # Display only VLAN-tagged frames (any VLAN ID)
```

| Field            | Quick explanation                                           |
|------------------|-------------------------------------------------------------|
| `vlan.id`        | VLAN ID (0–4095).                                          |
| `vlan.priority`  | 802.1p priority / CoS bits.                                |
| `vlan.cfi`       | Canonical Format Indicator bit.                            |
| `vlan.etype`     | Encapsulated EtherType inside the VLAN tag.                |
| `vlan.len`       | Length field in VLAN header (if present).                  |
| `vlan.trailer`   | Any trailing bytes related to VLAN tagging.                |

---

## 4. ARP

### 4.1 ARP core fields

| Field                            | Quick explanation                                                          |
|----------------------------------|----------------------------------------------------------------------------|
| `arp.opcode`                     | ARP operation (1=request, 2=reply).                                       |
| `arp.isgratuitous`              | True for gratuitous ARP (host announcing/refreshing its IP/MAC).          |
| `arp.src.proto_ipv4 == x.x.x.x` | Sender IPv4 address in ARP equals the given IP.                           |
| `arp.dst.hw_mac`                | Destination hardware (MAC) address in the ARP payload.                    |
| `arp.dst.proto_ipv4`            | Destination IPv4 address in the ARP payload.                              |
| `arp.hw.size`                   | Hardware address length in bytes.                                         |
| `arp.hw.type`                   | Hardware type (Ethernet = 1).                                             |
| `arp.proto.size`                | Protocol address length in bytes.                                         |
| `arp.proto.type`                | Protocol type (IPv4 = 0x0800).                                            |
| `arp.src.hw_mac`                | Sender hardware (MAC) address in the ARP payload.                         |
| `arp.src.proto_ipv4`            | Sender IPv4 address in the ARP payload.                                   |

**Examples**

```wireshark
arp.opcode == 1                      # ARP requests only
arp.opcode == 2                      # ARP replies only
arp.isgratuitous                     # Only gratuitous ARP
arp.src.proto_ipv4 == 192.168.1.10   # ARP from a specific IPv4 sender
!(arp or icmp or stp)                # Example: hide ARP/ICMP/STP chatter
```

#### 4.2 Additional ARP examples

| Filter                                                 | Quick explanation                                           |
|--------------------------------------------------------|-------------------------------------------------------------|
| `arp.opcode == 3`                                      | RARP request.                                               |
| `arp.opcode == 4`                                      | RARP reply.                                                 |
| `(arp.opcode == 2) && (eth.dst == ff:ff:ff:ff:ff:ff)` | Classic gratuitous ARP reply sent to the broadcast MAC.     |

---

## 5. IP Layer

### 5.1 IPv4 – basic host & subnet filters

```wireshark
ip                           # IPv4 traffic only
ip.proto == 41               # IPv6-in-IPv4 (tunnel) protocol
```

| Filter | Description |
|--------|-------------|
| `host x.x.x.x` | Packets to or from a specific IPv4 address (capture filter). |
| `host www.example.com and not (port xx or port yy)` | Host traffic excluding specific ports (capture filter). |
| `ip.addr == 10.10.50.1` | Any packet where source or destination IP is `10.10.50.1`. |
| `ip.dst == 10.10.50.1` | Destination IPv4 is `10.10.50.1`. |
| `ip.src == 10.10.50.1` | Source IPv4 is `10.10.50.1`. |
| `!(ip.addr == 10.10.50.1)` | All packets **except** those involving `10.10.50.1`. |
| `ip.addr == 10.10.50.0/24` | Any host in the `10.10.50.0/24` subnet. |
| `ip.addr == 10.0.0.0/24` | Any host in `10.0.0.0/24`. |
| `ip.addr == 10.0.0.1` | Any packet with `10.0.0.1` as source or destination. |
| `ip.addr==10.0.0.1 && ip.addr==10.0.0.2` | Conversation between `10.0.0.1` and `10.0.0.2`. |
| `ip.dst` | Destination IPv4 field (use with `==`, `!=`, etc.). |
| `ip.src` | Source IPv4 field. |
| `ip.host == hostname` | Traffic involving a given resolved hostname. |
| `ip.addr >= 10.10.50.1 and ip.addr <= 10.10.50.100` | IP in range `10.10.50.1–10.10.50.100`. |
| `ip.addr == 10.10.50.1 or ip.addr == 10.10.50.100` | Traffic involving either IP. |

**Exclude-host pattern**

```wireshark
not ip.addr == 10.0.0.1      # Exclude any traffic to or from 10.0.0.1
ip.addr != 10.0.0.1          # Same logic using '!='
```

---

### 5.2 IPv4 header & fragmentation fields

| Field                          | Quick explanation                                                  |
|--------------------------------|--------------------------------------------------------------------|
| `ip.checksum`                  | IPv4 header checksum.                                             |
| `ip.checksum_bad`              | True if checksum is invalid.                                      |
| `ip.checksum_good`             | True if checksum verified ok.                                     |
| `ip.dsfield`                   | DS field (DSCP+ECN combined).                                     |
| `ip.dsfield.ce`                | Congestion Experienced ECN bit.                                   |
| `ip.dsfield.dscp`              | DSCP value.                                                       |
| `ip.dsfield.ect`               | ECN Capable Transport bits.                                       |
| `ip.frag_offset`               | Fragment offset in 8-byte units.                                  |
| `ip.fragment`                  | True for any fragment of a fragmented datagram.                   |
| `ip.fragment.error`            | Fragmentation error detected.                                     |
| `ip.fragment.multipletails`    | Multiple tail fragments seen.                                     |
| `ip.fragment.overlap`          | Overlapping fragments detected.                                   |
| `ip.fragment.overlap_conflict` | Conflicting data in overlapping fragments.                        |
| `ip.fragment.toolongfragment`  | Fragment longer than expected.                                    |
| `ip.fragments`                 | Count/index of fragments.                                         |
| `ip.hdr_len`                   | IPv4 header length.                                               |
| `ip.id`                        | Identification field (used for reassembly).                       |
| `ip.len`                       | Total IPv4 packet length.                                         |
| `ip.proto`                     | Encapsulated protocol number (TCP=6, UDP=17, etc.).               |
| `ip.reassembled_in`            | Frame number where fragments were reassembled.                    |
| `ip.tos`                       | Legacy TOS view of DS field.                                     |
| `ip.tos.cost`                  | TOS “minimize cost” bit.                                         |
| `ip.tos.delay`                 | TOS “minimize delay” bit.                                        |
| `ip.tos.precedence`            | TOS precedence bits.                                             |
| `ip.tos.reliability`           | TOS “maximize reliability” bit.                                  |
| `ip.tos.throughput`            | TOS “maximize throughput” bit.                                   |
| `ip.ttl`                       | Time To Live.                                                     |
| `ip.version`                   | IP version (should be 4).                                        |

#### 5.2.1 IPv4 header examples

| Filter / Field                                        | Quick explanation                                         |
|-------------------------------------------------------|-----------------------------------------------------------|
| `ip.hdr_len == 20`                                    | IPv4 header with no options (20 bytes).                   |
| `ip.hdr_len > 20`                                     | IPv4 header **with** options present.                     |
| `ip.dsfield.dscp > 0`                                 | Packets where DSCP is non-zero (marked QoS).              |
| `ip.dsfield.dscp == 48`                               | DSCP 48 (e.g., EF – Expedited Forwarding).                |
| `ip.dsfield.ecn > 0`                                  | Any ECN-marked traffic.                                   |
| `ip.dsfield.ecn == 2`                                 | Specific ECN value 2.                                     |
| `ip.flags.rb == 1`                                    | Reserved flag bit set (should normally be 0).             |
| `ip.flags.df == 1`                                    | “Don’t Fragment” bit set.                                 |
| `(ip.flags.mf == 1) || (ip.frag_offset > 0)`          | Any fragmented IPv4 packet.                               |
| `ip.ttl == 64` / `ip.ttl == 128`                      | Packets with common initial TTLs (Linux/Unix vs Windows). |
| `ip.ttl <= 64 && ip.ttl > 30 && !(ip.ttl > 64)`       | Example of using a TTL range (roughly 31–64).             |
| `ip.proto == 1` / `ip.proto == 6` / `ip.proto == 17`  | ICMP (1), TCP (6), UDP (17) by protocol number.           |

---

### 5.3 IPv6 – basic host filters

```wireshark
ip6                      # IPv6 traffic only
```

| Field | Quick explanation |
|-------|-------------------|
| `ipv6.addr`      | Any IPv6 address (src or dst).          |
| `ipv6.src`       | Source IPv6 address.                    |
| `ipv6.dst`       | Destination IPv6 address.               |
| `ipv6.src_host`  | Source host (resolved).                 |
| `ipv6.dst_host`  | Destination host (resolved).            |

---

### 5.4 IPv6 header & fragmentation fields

| Field                               | Quick explanation                                                 |
|-------------------------------------|-------------------------------------------------------------------|
| `ipv6.class`                        | Traffic Class (DSCP/ECN equivalent).                             |
| `ipv6.dst_opt`                      | Destination options header.                                      |
| `ipv6.flow`                         | Flow label.                                                       |
| `ipv6.fragment`                     | True for IPv6 fragments.                                         |
| `ipv6.fragment.error`               | Fragmentation error detected.                                    |
| `ipv6.fragment.more`                | “More fragments” flag.                                           |
| `ipv6.fragment.multipletails`       | Multiple tail fragments.                                         |
| `ipv6.fragment.offset`              | Fragment offset.                                                 |
| `ipv6.fragment.overlap`             | Overlapping fragments detected.                                  |
| `ipv6.fragment.overlap_conflict`    | Conflicting data in overlaps.                                    |
| `ipv6.fragment.toolongfragment`     | Fragment longer than expected.                                   |
| `ipv6.fragments`                    | Count/index of fragments.                                        |
| `ipv6.fragment.id`                  | Fragment ID value.                                               |
| `ipv6.hlim`                         | Hop Limit (TTL equivalent).                                      |
| `ipv6.hop_opt`                      | Hop-by-hop options header.                                       |
| `ipv6.mipv6_home_address`          | Mobile IPv6 home address option.                                 |
| `ipv6.mipv6_length`                 | Length of Mobile IPv6 option.                                    |
| `ipv6.mipv6_type`                   | Type of Mobile IPv6 option.                                      |
| `ipv6.nxt`                          | Next Header field (protocol/extension type).                     |
| `ipv6.opt.pad1`                     | 1-byte padding option.                                           |
| `ipv6.opt.padn`                     | N-byte padding option.                                           |
| `ipv6.plen`                         | Payload length.                                                  |
| `ipv6.reassembled_in`               | Frame where IPv6 fragments were reassembled.                     |
| `ipv6.routing_hdr`                  | Routing header.                                                  |
| `ipv6.routing_hdr.addr`             | Addresses in routing header.                                     |
| `ipv6.routing_hdr.left`             | Remaining segments.                                              |
| `ipv6.routing_hdr.type`             | Routing header type.                                             |
| `ipv6.version`                      | IP version (should be 6).                                        |

---

### 5.5 ICMP / ICMPv6

| Filter                    | Description                                                                  |
|---------------------------|------------------------------------------------------------------------------|
| `icmp`                    | ICMPv4 traffic (ping, unreachable, TTL exceeded, etc.).                     |
| `icmp.type == <number>`   | ICMPv4 packets of a specific type.                                          |
| `icmpv6`                  | ICMPv6 traffic (IPv6 echo, neighbor discovery, etc.).                       |
| `icmpv6.type == <number>` | ICMPv6 packets of a specific type.                                          |

**Common ICMPv4**

```wireshark
icmp              # All ICMPv4
icmp.type == 8    # Echo request
icmp.type == 0    # Echo reply
icmp.type == 3    # Destination unreachable
icmp.type == 11   # Time exceeded
```

**Common ICMPv6**

```wireshark
icmpv6             # All ICMPv6
icmpv6.type == 128 # Echo request
icmpv6.type == 129 # Echo reply
```

#### Additional ICMP (IPv4) fields

| Field               | Quick explanation                                            |
|---------------------|--------------------------------------------------------------|
| `icmp.checksum`     | ICMP checksum value.                                         |
| `icmp.checksum_bad` | True if the ICMP checksum is invalid.                        |
| `icmp.code`         | ICMP code field (meaning depends on `icmp.type`).           |
| `icmp.ident`        | Identifier (echo/echo-reply, some other ICMP messages).      |
| `icmp.mtu`          | MTU value carried in “fragmentation needed” messages.        |
| `icmp.redir_gw`     | Gateway address carried in ICMP Redirect messages.          |
| `icmp.seq`          | Echo/echo-reply sequence number.                             |

#### Additional ICMPv6 fields

| Field                              | Quick explanation                                                          |
|------------------------------------|----------------------------------------------------------------------------|
| `icmpv6.all_comp`                  | Composite ICMPv6 status field (rarely used directly as a filter).         |
| `icmpv6.checksum`                  | ICMPv6 checksum value.                                                     |
| `icmpv6.checksum_bad`              | True if ICMPv6 checksum is invalid.                                        |
| `icmpv6.code`                      | ICMPv6 code field.                                                         |
| `icmpv6.comp`                      | Message-specific companion field (varies by ICMPv6 type).                  |
| `icmpv6.haad_ha_addrs`            | Home Agent Address Discovery: list of HA addresses.                        |
| `icmpv6.identifier`                | Identifier (echo/echo-reply and some other ICMPv6 messages).              |
| `icmpv6.option`                    | Generic ICMPv6 option container.                                           |
| `icmpv6.option.cga`                | Cryptographically Generated Address (CGA) option.                          |
| `icmpv6.option.length`             | Length of the current ICMPv6 option.                                      |
| `icmpv6.option.name_type`         | “Name type” field for ICMPv6 name-based options.                           |
| `icmpv6.option.name_type.fqdn`     | Name option where type is FQDN.                                           |
| `icmpv6.option.name_x501`          | Name option where type is X.501 (directory name).                         |
| `icmpv6.option.rsa.key_hash`       | RSA key hash used in Secure Neighbor Discovery options.                   |
| `icmpv6.option.type`               | ICMPv6 option type code.                                                   |
| `icmpv6.ra.cur_hop_limit`          | Router Advertisement: current hop limit for new flows.                     |
| `icmpv6.ra.reachable_time`         | RA: reachability time for neighbors.                                      |
| `icmpv6.ra.retrans_timer`          | RA: neighbor solicitation retransmission timer.                           |
| `icmpv6.ra.router_lifetime`        | RA: router lifetime value.                                                |
| `icmpv6.recursive_dns_serv`        | IPv6 Recursive DNS Server (RDNSS) addresses.                               |

---

## 6. L2 Discovery / Control / FHRP / Routing

### 6.1 Discovery / neighbor / control protocols

| Filter | Description |
|--------|-------------|
| `cdp`  | Cisco Discovery Protocol (L2 neighbor discovery). |
| `lldp` | Link Layer Discovery Protocol (vendor-neutral neighbor discovery). |
| `stp`  | Spanning Tree Protocol BPDUs. |
| `vtp`  | VLAN Trunking Protocol (Cisco VLAN advertisements). |
| `hsrp` | Hot Standby Router Protocol (first-hop redundancy). |
| `vrrp` | Virtual Router Redundancy Protocol (first-hop redundancy). |

**Examples**

```wireshark
cdp                                  # All CDP frames
lldp                                 # All LLDP frames
stp                                  # All STP BPDUs
stp && eth.dst == 01:80:c2:00:00:00  # Classic STP multicast

vtp                                  # All VTP traffic

hsrp                                 # All HSRP
hsrp && ip.dst == 224.0.0.2          # HSRP v1 multicast group
hsrp && ip.dst == 224.0.0.102        # Common HSRP v2 multicast group

vrrp                                 # All VRRP packets
vrrp && ip.dst == 224.0.0.18         # VRRP multicast group
```

---

### 6.2 Routing protocols

| Filter                          | Description |
|---------------------------------|-------------|
| `eigrp`                         | EIGRP (IP protocol 88). |
| `ospf`                          | Open Shortest Path First routing protocol packets. |
| `bgp`                           | Border Gateway Protocol (TCP port 179). |
| `bgp.type`                      | BGP message type (e.g., 2 = UPDATE). |
| `bgp.nlri_prefix`               | IPv4 NLRI prefix in classic UPDATE. |
| `bgp.mp_reach_nlri_ipv4_prefix` | MP-BGP reach IPv4 prefixes. |
| `bgp.mp_unreach_nlri_ipv4_prefix` | MP-BGP unreach IPv4 prefixes (withdrawn). |

#### Additional BGP attributes

| Field                        | Quick explanation                                                   |
|------------------------------|---------------------------------------------------------------------|
| `bgp.aggregator_as`         | AS number of the route aggregator (AGGREGATOR attribute).          |
| `bgp.aggregator_origin`     | Address/ID of the route aggregator.                                |
| `bgp.as_path`               | AS_PATH attribute (sequence of AS numbers).                        |
| `bgp.cluster_identifier`    | Route reflector cluster ID.                                        |
| `bgp.cluster_list`          | List of cluster IDs the route has passed through.                  |
| `bgp.community_as`          | AS component of a BGP COMMUNITY value.                             |
| `bgp.community_value`       | Value component of a BGP COMMUNITY.                                |
| `bgp.local_pref`            | LOCAL_PREF attribute (intra-AS preference).                        |
| `bgp.mp_nlri_tnl_id`        | Tunnel ID associated with MP-BGP NLRI.                             |
| `bgp.multi_exit_disc`       | MULTI_EXIT_DISC (MED) attribute.                                   |
| `bgp.next_hop`              | NEXT_HOP attribute for the route.                                  |
| `bgp.origin`                | ORIGIN attribute (IGP/EGP/INCOMPLETE).                             |
| `bgp.originator_id`         | ORIGINATOR_ID attribute (route reflection).                        |
| `bgp.withdrawn_prefix`      | Prefixes withdrawn in this UPDATE.                                 |

#### RIP fields

| Field               | Quick explanation                                        |
|---------------------|----------------------------------------------------------|
| `rip.auth.passwd`   | RIP authentication password (plain-text auth).          |
| `rip.auth.type`     | RIP authentication type (none, simple, MD5, etc.).      |
| `rip.command`       | RIP command (request/response).                          |
| `rip.family`        | Address family identifier in a route entry.             |
| `rip.ip`            | IPv4 address for a RIP route entry.                     |
| `rip.metric`        | Route metric (hop count).                                |
| `rip.netmask`       | Netmask for the RIP route entry.                         |
| `rip.next_hop`      | Next-hop address advertised for the route.              |
| `rip.route_tag`     | Route tag used to carry extra policy/administrative info.|
| `rip.routing_domain`| Routing domain / process identifier (vendor-specific).   |
| `rip.version`       | RIP protocol version (1 or 2).                           |

---

## 7. TCP / UDP / Ports

### 7.1 Generic / capture-style

```wireshark
tcp         # Only TCP traffic
udp         # Only UDP traffic
port 80     # Any packet with src or dst port 80
port sip    # SIP (VoIP) – capture filter
pppoes      # PPPoE session traffic
```

---

### 7.2 TCP port fields

| Field        | Description                                                                    |
|-------------|---------------------------------------------------------------------------------|
| `tcp.port`  | TCP port; matches when **either** src or dst TCP port has a value.             |
| `tcp.srcport` | TCP source port.                                                              |
| `tcp.dstport` | TCP destination port.                                                         |

**Examples**

```wireshark
tcp.port == 25                          # Any TCP with src or dst port 25 (SMTP)
tcp.port == 53                          # Any TCP with src or dst port 53 (DNS over TCP)
tcp.port in {80, 443, 8080}             # HTTP/HTTPS/alt-HTTP
ip.addr == 10.10.50.1 and tcp.port == 25  # SMTP traffic involving 10.10.50.1
tcp.dstport == 23                       # Telnet server side
tcp.srcport == 1024                     # Source port 1024
```

---

### 7.3 UDP port fields

| Field        | Description                                                                    |
|-------------|---------------------------------------------------------------------------------|
| `udp.port`  | UDP port; matches when **either** src or dst UDP port has a value.             |
| `udp.srcport` | UDP source port.                                                              |
| `udp.dstport` | UDP destination port.                                                         |

**Examples**

```wireshark
udp.port == 53                  # DNS over UDP
udp.port == 68                  # DHCP client-side port
udp.port in {500, 4500}         # IKE / IPsec NAT-T
udp.dstport == 161              # SNMP requests to agents
udp.srcport == 161              # SNMP responses from agents
```

---

### 7.4 TCP header & option fields

| Field                     | Quick explanation                                                     |
|---------------------------|-----------------------------------------------------------------------|
| `tcp.ack`                 | Acknowledgment number.                                               |
| `tcp.checksum`            | TCP checksum value.                                                  |
| `tcp.checksum_bad`        | True if checksum invalid.                                            |
| `tcp.checksum_good`       | True if checksum verified ok.                                        |
| `tcp.continuation_to`     | Frame to which this continuation segment belongs.                    |
| `tcp.flags`               | Full flags field.                                                    |
| `tcp.flags.ack`           | ACK flag.                                                            |
| `tcp.flags.cwr`           | CWR flag.                                                            |
| `tcp.flags.ecn`           | ECN-Echo flag.                                                       |
| `tcp.flags.fin`           | FIN flag.                                                            |
| `tcp.flags.push`          | PSH flag.                                                            |
| `tcp.flags.reset`         | RST flag.                                                            |
| `tcp.flags.syn`           | SYN flag.                                                            |
| `tcp.flags.urg`           | URG flag.                                                            |
| `tcp.hdr_len`             | TCP header length.                                                   |
| `tcp.len`                 | TCP payload length.                                                  |
| `tcp.nxtseq`              | Next expected sequence number.                                       |
| `tcp.options`             | Presence of any options.                                             |
| `tcp.options.cc`          | CC (connection count) option.                                       |
| `tcp.options.ccecho`      | CC echo option.                                                     |
| `tcp.options.ccnew`       | CC new option.                                                      |
| `tcp.options.echo`        | TCP echo option.                                                    |
| `tcp.options.echo_reply`  | TCP echo reply option.                                              |
| `tcp.options.md5`         | TCP MD5 signature option.                                           |
| `tcp.options.mss`         | MSS option present.                                                 |
| `tcp.options.mss_val`     | MSS value.                                                          |
| `tcp.options.qs`          | Quick-Start option.                                                 |
| `tcp.options.sack`        | SACK option present.                                                |
| `tcp.options.sack_le`     | Left edge of a SACK block.                                         |
| `tcp.options.sack_perm`   | SACK permitted option.                                              |
| `tcp.options.sack_re`     | Right edge of a SACK block.                                        |
| `tcp.options.time_stamp`  | Timestamp option present.                                           |
| `tcp.options.wscale`      | Window scale option present.                                       |
| `tcp.options.wscale_val`  | Window scale factor value.                                         |
| `tcp.pdu.last_frame`      | Last frame for this reassembled PDU.                               |
| `tcp.pdu.size`            | Size of the reassembled PDU.                                       |
| `tcp.pdu.time`            | Time to reassemble the PDU.                                        |
| `tcp.reassembled_in`      | Frame where TCP segments were reassembled.                         |
| `tcp.segment`             | True when frame is a TCP segment piece.                            |
| `tcp.segment.error`       | Error during segment reassembly.                                   |
| `tcp.segment.multipletails`| Multiple tail segments detected.                                  |
| `tcp.segment.overlap`     | Overlapping TCP segments.                                          |
| `tcp.segment.overlap_conflict` | Conflicting data in overlaps.                                 |
| `tcp.segment.toolongfragment` | Segment longer than expected.                                  |
| `tcp.segments`            | Count/index of segments in a PDU.                                  |
| `tcp.seq`                 | Sequence number.                                                    |
| `tcp.time_delta`          | Time since previous TCP segment in this flow.                      |
| `tcp.time_relative`       | Time since start of capture/conversation.                          |
| `tcp.urgent_pointer`      | Urgent pointer value.                                              |
| `tcp.window_size`         | TCP window size (possibly unscaled).                               |

**Flag/analysis examples**

```wireshark
tcp.flags.syn == 1                         # SYN set
tcp.flags.syn == 1 and tcp.flags.ack == 0 # Initial SYNs
tcp.flags == 0x012                         # SYN/ACK
tcp.flags.reset == 1                       # RSTs

tcp.analysis.flags && !tcp.analysis.window_update  # Retransmits, dup-ACKs, etc., minus window updates
tcp.time_delta > .250                      # Segments spaced > 250ms
tcp contains "login"                       # TCP payload contains a string
```

---

### 7.5 UDP header fields

| Field               | Quick explanation                   |
|---------------------|-------------------------------------|
| `udp.checksum`      | UDP checksum value.                 |
| `udp.checksum_bad`  | True if checksum invalid.           |
| `udp.checksum_good` | True if checksum verified ok.       |
| `udp.length`        | UDP length (header + payload).      |

---

## 8. Application Protocol Filters

### 8.1 HTTP

| Filter | Description |
|--------|-------------|
| `http.request`          | All HTTP request packets (GET/POST/etc.). |
| `http.response`         | All HTTP response packets. |
| `http.host == "name"`   | Requests whose Host header matches `"name"`. |
| `http.server`           | HTTP Server header. |
| `http.user_agent`       | HTTP User-Agent strings. |
| `http.cookie`           | HTTP Cookie headers. |
| `http.referer`          | HTTP Referer headers. |
| `http.data`             | HTTP message body / payload. |
| `http.authbasic`        | HTTP Basic Authentication. |
| `http.www_authenticate` | HTTP `WWW-Authenticate` header. |
| `http.content_type`     | HTTP Content-Type header. |
| `http.content_length`   | HTTP Content-Length header. |

#### Additional HTTP header / meta fields

| Field                     | Quick explanation                                                    |
|---------------------------|----------------------------------------------------------------------|
| `http.accept`             | HTTP `Accept` header (media types the client will accept).          |
| `http.accept_encoding`    | `Accept-Encoding` header (gzip, deflate, etc.).                     |
| `http.accept_language`    | `Accept-Language` header (preferred languages).                     |
| `http.cache_control`      | `Cache-Control` header (caching directives).                        |
| `http.connection`         | `Connection` header (keep-alive, close, etc.).                      |
| `http.content_encoding`   | `Content-Encoding` header (gzip/deflate/etc. on the body).          |
| `http.date`               | `Date` header (server’s date/time).                                 |
| `http.last_modified`      | `Last-Modified` header (timestamp of resource).                     |
| `http.location`           | `Location` header (redirect target, etc.).                          |
| `http.notification`       | Vendor/extension notification header (rarely used).                 |
| `http.proxy_authenticate` | `Proxy-Authenticate` header (proxy challenges).                     |
| `http.proxy_authorization`| `Proxy-Authorization` header (client creds to proxy).               |
| `http.proxy_connect_host` | Host field for HTTP CONNECT via proxy.                              |
| `http.proxy_connect_port` | Port field for HTTP CONNECT via proxy.                              |
| `http.request.method`     | HTTP request method (GET/POST/PUT/… ).                              |
| `http.request.uri`        | Request URI path.                                                   |
| `http.request.version`    | HTTP version string of the request.                                 |
| `http.response.code`      | Numeric status code (200, 404, 500, etc.).                          |
| `http.set_cookie`         | `Set-Cookie` response headers.                                      |
| `http.transfer_encoding`  | `Transfer-Encoding` header (chunked, etc.).                         |
| `http.x_forwarded_for`    | `X-Forwarded-For` header (client/original IP through proxies).      |

#### HTTP examples

```wireshark
http.request.method == "GET"                    # Show only HTTP GET requests
tcp.port == 443 and ip contains "http"          # Look for cleartext HTTP strings on TCP port 443 (misconfigured HTTPS/proxy)
http contains "login"                           # Any HTTP packet whose payload/headers contain "login"
```

---

### 8.2 DHCP

| Filter                                              | Quick explanation                                  |
|-----------------------------------------------------|----------------------------------------------------|
| `(udp.srcport == 68) && (udp.dstport == 67)`        | DHCP client → server messages.                    |
| `(udp.srcport == 67) && (udp.dstport == 68)`        | DHCP server → client messages.                    |
| `dhcp.option.dhcp == 1`                             | DHCP Discover messages.                           |
| `dhcp.option.dhcp == 2`                             | DHCP Offer messages.                              |
| `dhcp.option.dhcp == 3`                             | DHCP Request messages.                            |
| `dhcp.option.dhcp == 5`                             | DHCP ACK messages.                                |

---

### 8.3 FTP

| Filter / Field                    | Quick explanation                                        |
|-----------------------------------|----------------------------------------------------------|
| `ftp`                             | FTP control channel (commands like USER/PASS/RETR).      |
| `ftp-data`                        | FTP data channel (file transfer streams).                |
| `ftp.request.command`             | Any FTP command request.                                 |
| `ftp.request.command == "USER"`   | FTP username being sent.                                 |
| `ftp.request.command == "PASS"`   | FTP password being sent.                                 |
| `ftp.request.command == "RETR"`   | Client requesting to **download** a file.                |
| `ftp.request.command == "STOR"`   | Client requesting to **upload** a file.                  |
| `ftp.request.command == "PASV"`   | Client switching the server into passive mode.           |
| `ftp.request.command == "LIST"`   | Directory listing commands.                              |
| `ftp.passive.port`                | TCP port advertised by the FTP server for passive-mode data connections. |

---

### 8.4 SMTP

| Filter / Field                      | Quick explanation                                                         |
|-------------------------------------|---------------------------------------------------------------------------|
| `smtp`                              | All SMTP traffic (usually TCP port 25/587/465).                           |
| `smtp.req.command`                  | SMTP request command verb (e.g., `HELO`, `EHLO`, `MAIL`, `RCPT`, `DATA`). |
| `smtp.req.command == "MAIL"`        | Show only SMTP `MAIL FROM` commands.                                      |
| `smtp.req.command == "RCPT"`        | Show only SMTP `RCPT TO` commands.                                        |
| `smtp and ipv6`                     | SMTP traffic carried over IPv6 (any SMTP port on IPv6 packets).           |

---

### 8.5 NTP

| Filter / Field        | Quick explanation                                      |
|-----------------------|--------------------------------------------------------|
| `ntp`                 | All NTP traffic (typically UDP port 123).              |
| `udp.port == 123`     | Any UDP packet using port 123 (usually NTP).          |
| `ntp.flags.li`        | Leap Indicator bits (clock unsynchronized, etc.).     |
| `ntp.stratum`         | NTP stratum (1 = primary server, 2+ = downstream).    |
| `ntp.refid`           | Reference ID describing the upstream time source.     |
| `ntp.org`             | Origin timestamp (client send time).                  |
| `ntp.rec`             | Receive timestamp (server receive time).              |
| `ntp.xmt`             | Transmit timestamp (server send time).                |

**Examples**

```wireshark
ntp and ip.addr == 192.0.2.10     # NTP traffic to/from a specific host
ntp.stratum == 1                  # Only primary time servers
```

---

### 8.6 SSH

| Filter / Field     | Quick explanation                                            |
|--------------------|--------------------------------------------------------------|
| `ssh`              | All SSH traffic (usually TCP port 22).                       |
| `tcp.port == 22`   | Any TCP packet on port 22 (typically SSH).                   |
| `ssh.protocol`     | SSH protocol version (e.g., “2.0”).                          |
| `ssh.kex.alg`      | Key exchange algorithm (diffie-hellman-group14, etc.).      |
| `ssh.host_key.alg` | Host key algorithm (ssh-rsa, ecdsa-sha2-nistp256, etc.).    |
| `ssh.auth.method`  | Authentication method (password, publickey, etc.).          |

**Examples**

```wireshark
ssh and ip.addr == 10.0.0.5       # SSH sessions involving a given host
tcp.port == 22 and !ssh           # TCP/22 that Wireshark didn’t decode as SSH (weird/misuse)
```

---

### 8.7 Telnet

| Filter / Field       | Quick explanation                                |
|----------------------|--------------------------------------------------|
| `telnet`             | All Telnet traffic (usually TCP port 23).        |
| `tcp.port == 23`     | Any TCP packet on port 23 (typically Telnet).    |
| `telnet.auth`        | Telnet authentication sub-negotiation.           |
| `telnet.data`        | Telnet payload data (user input / output).       |

**Examples**

```wireshark
telnet and ip.addr == 192.168.1.50       # Telnet to/from a specific host
telnet.data contains "enable"            # Look for someone sending “enable”
```

---

### 8.8 RADIUS

| Filter / Field            | Quick explanation                                         |
|---------------------------|-----------------------------------------------------------|
| `radius`                  | All RADIUS traffic (usually UDP/1812, 1813, 1645, 1646). |
| `udp.port == 1812`        | Authentication/authorization RADIUS traffic.              |
| `udp.port == 1813`        | Accounting RADIUS traffic.                                |
| `radius.code`             | RADIUS message type (Access-Request, Accept, etc.).      |
| `radius.code == 1`        | Access-Request.                                           |
| `radius.code == 2`        | Access-Accept.                                            |
| `radius.code == 3`        | Access-Reject.                                            |
| `radius.User_Name`        | User-Name attribute.                                      |
| `radius.Calling_Station_Id` | Calling-Station-Id (often client MAC or ID).           |

**Examples**

```wireshark
radius and ip.addr == 10.1.1.10          # RADIUS to/from a specific server
radius.User_Name == "testuser"           # Requests for a specific username
radius.code == 3                         # All Access-Rejects
```

---

### 8.9 TACACS+

| Filter / Field         | Quick explanation                                          |
|------------------------|------------------------------------------------------------|
| `tacacs`               | All TACACS+ traffic (typically TCP port 49).              |
| `tcp.port == 49`       | Any TCP packet on port 49 (usually TACACS+).              |
| `tacacs.type`          | TACACS+ message type (authentication, authorization, etc.).|
| `tacacs.authen.action` | Authentication action (login, enable, etc.).              |
| `tacacs.user`          | TACACS+ username field.                                   |

**Examples**

```wireshark
tacacs and ip.addr == 10.0.0.10          # TACACS+ to/from an AAA server
tacacs.user == "admin"                   # Look for admin logins
```

---

### 8.10 SNMP

| Filter / Field         | Quick explanation                                    |
|------------------------|------------------------------------------------------|
| `snmp`                 | All SNMP traffic (typically UDP port 161/162).      |
| `udp.port == 161`      | SNMP queries/responses.                             |
| `udp.port == 162`      | SNMP traps/informs.                                 |
| `snmp.version == 0`    | SNMPv1 messages.                                    |
| `snmp.version == 1`    | SNMPv2c messages.                                   |
| `snmp.version == 3`    | SNMPv3 messages.                                    |
| `snmp.community`       | Community string for SNMPv1/v2c.                    |
| `snmp.community == "public"` | Cleartext “public” community use.            |
| `snmp.variables`       | SNMP variable bindings (OIDs + values).             |

**Examples**

```wireshark
snmp and ip.addr == 192.168.0.10          # SNMP to/from a specific device
snmp.community == "public"               # Insecure community usage
snmp.version == 3                        # SNMPv3 only
```

---

## 9. Time, Frame & Payload Content

| Filter | Description |
|--------|-------------|
| `frame.time >= "Jun 02, 2019 18:04:00"` | Packets captured at or after that time. |
| `frame contains traffic` | Frame data contains the string `traffic`. |

### 9.2 Payload / string filters

| Filter                        | Quick explanation                                                  |
|-------------------------------|---------------------------------------------------------------------|
| `data contains "String"`      | Search for a string anywhere in the packet payload.                |
| `ip contains "String"`        | Search for a string specifically in the IP payload.                |
| `http contains "String"`      | Search for a string in HTTP payload or headers.                    |
| `file_data`                   | Reassembled file payload data (e.g., exported objects/files).      |

---

## 10. Broadcast / Multicast / Noise Reduction

| Filter | Description |
|--------|-------------|
| `!(arp or icmp or stp)` | Hide ARP, ICMP, and STP to reduce chatter. |
| `not broadcast and not multicast` | Display only **unicast** traffic. |

(Also see `eth.dst == ff:ff:ff:ff:ff:ff` and `(eth.dst[0] & 1) == 1` in the Ethernet section.)

---

## 11. Wi-Fi (802.11)

| Filter | Description |
|--------|-------------|
| `wlan.fc.type eq 0`        | 802.11 management frames.          |
| `wlan.fc.type eq 1`        | 802.11 control frames.             |
| `wlan.fc.type_subtype eq 0`| Association requests.              |
| `wlan.fc.type_subtype eq 2`| Reassociation requests.            |
| `wlan.fc.type_subtype eq 4`| Probe requests.                    |
| `wlan.fc.type_subtype eq 8`| Beacon frames.                     |

---

## 12. Capture Modes (conceptual)

| Concept           | Description |
|-------------------|-------------|
| **Promiscuous mode** | NIC captures all packets on the LAN segment, not just those addressed to it. |
| **Monitor mode**     | Wireless NIC captures all frames it can hear (Linux/Unix only in many cases). |

---

## 13. WAN / MPLS / PPP / Frame Relay / DTP / VTP

### 13.1 Frame Relay fields

| Field                      | Quick explanation                                                  |
|----------------------------|--------------------------------------------------------------------|
| `fr.becn`                  | Backward Explicit Congestion Notification bit.                     |
| `fr.de`                    | Discard Eligibility bit (frame may be dropped under congestion).   |
| `fr.chdlctype`             | Encapsulated protocol type (CHDLC type) over Frame Relay.         |
| `fr.dlci`                  | Data-Link Connection Identifier value.                             |
| `fr.dlcore_control`        | Core Frame Relay DLCI control information.                         |
| `fr.control`               | Frame Relay control byte.                                          |
| `fr.control.f`             | F (final) / poll bit in the control field.                         |
| `fr.control.ftype`         | Frame type field (I/S/U-frame style).                              |
| `fr.control.n_r`           | Receive sequence number N(R).                                      |
| `fr.control.n_s`           | Send sequence number N(S).                                         |
| `fr.control.p`             | P/F (poll/final) bit in the control field.                         |
| `fr.control.s_ftype`       | Supervisory frame type.                                            |
| `fr.control.u_modifier_cmd`| U-frame modifier command bits.                                     |
| `fr.control.u_modifier_resp`| U-frame modifier response bits.                                   |
| `fr.cr`                    | Command/response indicator.                                       |
| `fr.dc`                    | Additional DLCI/control bits (implementation-specific).            |
| `fr.ea`                    | Extended Address (EA) bit in the address field.                    |
| `fr.fecn`                  | Forward Explicit Congestion Notification bit.                      |
| `fr.lower_dlci`            | Lower bits of an extended DLCI value.                              |
| `fr.nlpid`                 | Network Layer Protocol ID field.                                  |
| `fr.second_dlci`           | Second DLCI value (multi-DLCI header).                             |
| `fr.snap.oui`              | SNAP OUI field when using SNAP over Frame Relay.                   |
| `fr.snap.pid`              | SNAP protocol ID field over Frame Relay.                           |
| `fr.snaptype`              | SNAP encapsulated protocol type.                                   |
| `fr.third_dlci`            | Third DLCI value in multi-DLCI scenarios.                          |
| `fr.upper_dlci`            | Upper bits of an extended DLCI value.                              |

---

### 13.2 PPP fields

| Field          | Quick explanation                                      |
|----------------|--------------------------------------------------------|
| `ppp.address`  | PPP address field (usually 0xff in unnumbered mode).   |
| `ppp.control`  | PPP control field (usually 0x03).                       |
| `ppp.direction`| Direction of PPP frame (sent or received).             |
| `ppp.protocol` | PPP protocol field (0x0021=IP, 0x8021=IPCP, etc.).     |

---

### 13.3 MPLS fields

| Field                      | Quick explanation                                                  |
|----------------------------|--------------------------------------------------------------------|
| `mpls.bottom`              | Bottom-of-stack bit for an MPLS label.                             |
| `mpls.cw.control`          | MPLS pseudowire control-word control bits.                         |
| `mpls.cw.res`              | Reserved bits in the MPLS control word.                            |
| `mpls.exp`                 | MPLS EXP/Traffic Class bits (often used for QoS).                  |
| `mpls.label`               | MPLS label value itself.                                           |
| `mpls.oam.bip16`           | BIP-16 error check field in MPLS-TP OAM.                           |
| `mpls.oam.defect_location` | Location associated with an OAM defect.                            |
| `mpls.oam.defect_type`     | Type of OAM defect (e.g., LOC, RDI).                              |
| `mpls.oam.frequency`       | OAM message frequency.                                             |
| `mpls.oam.function_type`   | OAM function type (CC, CV, LM, DM, etc.).                          |
| `mpls.oam.ttsi`            | Trail Termination Source Identifier.                               |
| `mpls.ttl`                 | MPLS Time-to-Live value.                                           |

---

### 13.4 DTP (Dynamic Trunking Protocol)

| Field          | Quick explanation                                     |
|----------------|-------------------------------------------------------|
| `dtp.neighbor` | Neighbor switch information from DTP.                 |
| `dtp.tlv_type` | TLV type used in a DTP message.                       |
| `dtp.tlv_len`  | TLV length field.                                     |
| `dtp.version`  | DTP protocol version.                                 |
| `vtp.neighbor` | VTP/DTP neighbor identifier (shared neighbor info).   |

---

### 13.5 VTP (VLAN Trunking Protocol)

| Field                             | Quick explanation                                              |
|-----------------------------------|----------------------------------------------------------------|
| `vtp.code`                        | VTP message type (summary, subset, advert, etc.).             |
| `vtp.conf_rev_num`               | VTP configuration revision number.                            |
| `vtp.followers`                  | Indicates more subset advertisements follow.                   |
| `vtp.md`                          | VTP management domain name.                                   |
| `vtp.md5_digest`                 | MD5 digest for VTP authentication.                            |
| `vtp.md_len`                     | Length of the management domain name.                         |
| `vtp.seq_num`                    | VTP message sequence number.                                  |
| `vtp.start_value`               | Starting VLAN ID/value in a subset advert.                    |
| `vtp.upd_id`                     | VTP update identifier.                                        |
| `vtp.upd_ts`                     | Timestamp of the VTP update.                                  |
| `vtp.version`                    | VTP protocol version.                                         |
| `vtp.vlan_info.802_1Q_index`    | 802.1Q index associated with this VLAN entry.                 |
| `vtp.vlan_info.isl_vlan_id`     | ISL VLAN identifier value.                                    |
| `vtp.vlan_info.len`             | Length of this VLAN info record.                              |
| `vtp.vlan_info.mtu_size`        | VLAN MTU size.                                                 |
| `vtp.vlan_info.status.vlan_susp`| Flag indicating VLAN is suspended.                             |
| `vtp.vlan_info.tlv_len`         | TLV length for the VLAN info TLV.                             |
| `vtp.vlan_info.tlv_type`        | TLV type for the VLAN info TLV.                               |
| `vtp.vlan_info.vlan_name`       | Configured VLAN name.                                         |
| `vtp.vlan_info.vlan_name_len`   | Length of the VLAN name.                                      |
| `vtp.vlan_info.vlan_type`       | VLAN type (e.g., Ethernet, FDDI, Token Ring).                 |
