#!/usr/bin/env python3
import subprocess, sys, os, site

# Ensure site-packages is available
site_packages_path = os.path.expanduser(
    f"~/.local/lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages")
site.addsitedir(site_packages_path)

# Dependency checker and installer
required_modules = [
    ("ipwhois", "ipwhois"),
    ("requests", "requests"),
    ("dns.resolver", "dnspython")
]

restarted = False
for mod, pkg in required_modules:
    try:
        __import__(mod.split('.')[0])
    except ImportError:
        print(f"Installing missing dependency: {pkg}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--user", pkg])
        restarted = True

# Restart script if new packages were installed
if restarted:
    print("\nDependencies installed. Restarting script...\n")
    os.execv(sys.executable, [sys.executable] + sys.argv)

# Continue with the main program
import socket, ipaddress, dns.resolver, requests
from collections import Counter, defaultdict
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError

# ANSI color codes
C = {
    "header": "\033[95m",
    "blue": "\033[94m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "red": "\033[91m",
    "bold": "\033[1m",
    "end": "\033[0m"
}

# Clear screen
clear_screen = lambda: os.system('cls' if os.name == 'nt' else 'clear')

# Fallback country lookup via ipinfo.io
def fallback_ip_country(ip):
    try:
        return requests.get(f"https://ipinfo.io/{ip}/json", timeout=5).json().get("country")
    except:
        return None

# Repository wrappers
def fetch_url_json(url):
    r = requests.get(url)
    if r.status_code != 200:
        r.raise_for_status()
    return r.json().get("data", {})

# Other RIPEstat calls
def fetch_announced_prefixes(asn):
    return fetch_url_json(f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}").get("prefixes", [])

def fetch_asn_overview(asn):
    return fetch_url_json(f"https://stat.ripe.net/data/as-overview/data.json?resource={asn}")

def fetch_whois_records(asn):
    return fetch_url_json(f"https://stat.ripe.net/data/whois/data.json?resource={asn}").get("records", [])

# DNSBL lookup using Spamhaus XBL
def dnsbl_check(ip):
    try:
        rev = '.'.join(reversed(ip.split('.')))
        dns.resolver.resolve(f"{rev}.xbl.spamhaus.org", 'A')
        return True
    except:
        return False

# Extract contact info
def print_contacts(records):
    contacts = defaultdict(set)
    for rec in records:
        for e in rec:
            k, v = e["key"].lower(), e["value"]
            if "phone" in k:
                contacts["phone"].add(v)
            elif k in ("e-mail", "email"):
                contacts["email"].add(v)
            elif "abuse" in v.lower():
                contacts["abuse_contact"].add(v)
            elif "tech" in v.lower():
                contacts["tech_contact"].add(v)
    for ctype, vals in contacts.items():
        print(f"  {C['yellow']}{ctype.title()}{C['end']}: {', '.join(vals)}")

# ASN metadata display
def print_asn_metadata(asn, prompt_prefixes=True):
    if not asn or asn.upper() == "ASNA":
        print(f"\n{C['header']}[ASN Lookup] {asn}{C['end']}")
        print(f"  {C['red']}No ASN information available.{C['end']}")
        return
    try:
        print(f"\n{C['header']}[ASN Lookup] {asn}{C['end']}")
        info = fetch_asn_overview(asn)
        prefixes_raw = fetch_announced_prefixes(asn)
        prefixes = sorted({p["prefix"].strip() for p in prefixes_raw if p.get("prefix")})
        v4 = [p for p in prefixes if ":" not in p]
        v6 = [p for p in prefixes if ":" in p]

        countries = [p.get("country") for p in prefixes_raw if p.get("country")]
        country = Counter(countries).most_common(1)[0][0] if countries else info.get("country", "N/A")

        print(f"  {C['blue']}Holder{C['end']}       : {info.get('holder','N/A')}")
        print(f"  {C['blue']}Registry{C['end']}     : {info.get('rir','N/A')}")
        print(f"  {C['blue']}ASN Name{C['end']}     : {info.get('as_name','N/A')}")
        print(f"  {C['blue']}Country (BGP prefixes){C['end']} : {country}")

        print_contacts(fetch_whois_records(asn))
        print(f"  {C['blue']}Prefixes Announced{C['end']}: {len(v4)} IPv4, {len(v6)} IPv6")

        if prompt_prefixes and input(f"\n  {C['bold']}→ Show full prefix list? y/n:{C['end']} ").lower() == "y":
            ver = input("    Limit to version (4/6) or Enter: ").strip()
            if ver in ("", "4"):
                print(f"\n  {C['bold']}[IPv4 Prefixes]{C['end']}")
                for p in v4:
                    d = next((x for x in prefixes_raw if x["prefix"].strip() == p), {})
                    print(f"    {p} parent:{d.get('parent','N/A')} origin:{d.get('origin','N/A')}")
            if ver in ("", "6"):
                print(f"\n  {C['bold']}[IPv6 Prefixes]{C['end']}")
                for p in v6:
                    d = next((x for x in prefixes_raw if x["prefix"].strip() == p), {})
                    print(f"    {p} parent:{d.get('parent','N/A')} origin:{d.get('origin','N/A')}")
    except Exception as e:
        print(f"  {C['red']}ASN lookup failed: {e}{C['end']}")

def lookup_ip(ip):
    print(f"\n{C['header']}[IP Lookup] {ip}{C['end']}")
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap()
    except IPDefinedError as e:
        print(f"  {C['red']}Special-use IP (RFC-defined): {e}{C['end']}")
        return
    except Exception as e:
        print(f"  {C['red']}Lookup failed: {e}{C['end']}")
        return

    asn, org = res.get("asn"), res.get("network", {}).get("name", "N/A")
    country = res.get("network", {}).get("country") or fallback_ip_country(ip) or "N/A"
    emails = res.get("network", {}).get("emails", [])
    rir = res.get("nir") or res.get("asn_registry", "N/A")

    print(f"  {C['blue']}ASN{C['end']}              : {asn if asn else 'NA'}")
    print(f"  {C['blue']}Org{C['end']}              : {org}")
    print(f"  {C['blue']}Country (IP){C['end']}     : {country}")
    print(f"  {C['blue']}RIR{C['end']}              : {rir}")
    print(f"  {C['blue']}Contact(s){C['end']}       : {', '.join(emails) if emails else 'N/A'}")

    if ip.count('.') == 3 and dnsbl_check(ip):
        print(f"  {C['red']}Spamhaus XBL     : LISTED{C['end']}")
    if asn and asn.upper() != "NA":
        lookup_asn(f"AS{asn}")
    else:
        print_asn_metadata("ASNA")

def lookup_cidr(cidr):
    net = ipaddress.ip_network(cidr, strict=False)
    print(f"\n{C['header']}[CIDR Info] {cidr}{C['end']}")
    print(f"  {C['blue']}Network Address{C['end']} : {net.network_address}")
    print(f"  {C['blue']}Netmask{C['end']}         : {net.netmask}")
    print(f"  {C['blue']}Num Addresses{C['end']}   : {net.num_addresses}")
    lookup_ip(str(net.network_address))

def lookup_asn(asn):
    print_asn_metadata(asn if asn.upper().startswith("AS") else f"AS{asn}")

def main():
    clear_screen()
    while True:
        t = input("Enter IP, CIDR, or ASN (or 'exit'): ").strip()
        if t.lower() == "exit": break
        clear_screen()
        if "/" in t: lookup_cidr(t)
        elif t.upper().startswith("AS") or t.isdigit(): lookup_asn(t)
        else:
            try:
                ip = socket.gethostbyname(t)
            except:
                print("Failed to resolve."); continue
            lookup_ip(ip)

if __name__ == "__main__":
    main()
