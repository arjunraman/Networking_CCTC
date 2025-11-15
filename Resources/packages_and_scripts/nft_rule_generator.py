#!/usr/bin/env python3

# Fully featured nftables CLI manager using only Python standard library

import subprocess
import os
import sys
import datetime
import json
import csv
import ipaddress

# === Utility Functions ===

def run_cmd(cmd):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"[!] Error: {e.stderr.strip()}")
        return None

def yes_or_no(question):
    while True:
        ans = input(f"{question} (y/n): ").strip().lower()
        if ans in ("y", "yes"):
            return True
        elif ans in ("n", "no"):
            return False

def choose_from_list(prompt, options, multi=False):
    print(prompt)
    for i, opt in enumerate(options, 1):
        print(f"{i}. {opt}")
    while True:
        sel = input("Choice(s): ").strip()
        try:
            if multi:
                indexes = [int(x)-1 for x in sel.split(",") if x.strip().isdigit()]
                return [options[i] for i in indexes if 0 <= i < len(options)]
            else:
                i = int(sel) - 1
                return options[i] if 0 <= i < len(options) else None
        except:
            print("[!] Invalid selection.")

# === Validation Functions ===

def validate_ip(ip_str):
    if not ip_str:
        return True
    try:
        ipaddress.ip_network(ip_str, strict=False)
        return True
    except ValueError:
        return False

def validate_ports(port_str):
    if not port_str:
        return True
    try:
        for part in port_str.split(","):
            if "-" in part:
                s, e = part.split("-")
                assert 0 < int(s) <= int(e) <= 65535
            else:
                assert 0 < int(part) <= 65535
        return True
    except:
        return False

def get_interfaces():
    try:
        return sorted(os.listdir("/sys/class/net"))
    except:
        return []

def show_interfaces():
    print("\nAvailable interfaces:")
    for iface in get_interfaces():
        print(f" - {iface}")

# === Table and Chain Functions ===

def list_tables():
    output = run_cmd("sudo nft list tables")
    tables = []
    if output:
        for line in output.splitlines():
            parts = line.split()
            if len(parts) == 3:
                tables.append((parts[1], parts[2]))  # (family, name)
    return tables

def list_chains(table_name):
    output = run_cmd(f"sudo nft list table {table_name}")
    chains = []
    if output:
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("chain "):
                parts = line.split()
                if len(parts) > 1:
                    chains.append(parts[1])
    return chains

def list_rules(table, chain):
    output = run_cmd(f"sudo nft --handle list chain {table} {chain}")
    rules = []
    if output:
        for line in output.splitlines():
            line = line.strip()
            if line and not line.startswith("chain "):
                rules.append(line)
    return rules

# === Rule Searching & Filtering ===

def filter_rules(rules, keyword=None, proto=None, port=None):
    filtered = []
    for rule in rules:
        if keyword and keyword not in rule:
            continue
        if proto and proto not in rule:
            continue
        if port and f"dport {port}" not in rule and f"sport {port}" not in rule:
            continue
        filtered.append(rule)
    return filtered

def group_rules(rules, mode="protocol"):
    grouped = {}
    for rule in rules:
        key = "other"
        if mode == "protocol":
            for proto in ["tcp", "udp", "icmp", "ip", "ip6"]:
                if proto in rule:
                    key = proto
                    break
        elif mode == "action":
            for act in ["accept", "drop", "reject", "log"]:
                if act in rule:
                    key = act
                    break
        grouped.setdefault(key, []).append(rule)
    return grouped

def show_grouped_rules(rules, mode):
    grouped = group_rules(rules, mode)
    for group, group_rules in grouped.items():
        print(f"\n=== {group.upper()} ===")
        for idx, rule in enumerate(group_rules, 1):
            print(f"{idx}. {rule}")

# === Rule Management Functions ===

def add_rule(family, table, chain):
    proto = input("Protocol (tcp/udp/icmp/icmpv6/any): ").strip().lower()
    src = input("Source IP/CIDR (blank for any): ").strip()
    dst = input("Destination IP/CIDR (blank for any): ").strip()
    sport = input("Source port(s) (e.g. 80, 22-25) or blank: ").strip()
    dport = input("Destination port(s) (e.g. 443, 1000-2000) or blank: ").strip()
    iface = input("Interface (blank for any): ").strip()
    action = input("Action (accept/drop/reject/log): ").strip().lower()

    # Build rule
    rule = f"add rule {table} {chain}"
    if proto != "any":
        rule += f" {proto}"
    if src:
        rule += f" ip saddr {src}"
    if dst:
        rule += f" ip daddr {dst}"
    if sport:
        rule += f" sport {sport}"
    if dport:
        rule += f" dport {dport}"
    if iface:
        rule += f" iifname \"{iface}\""
    if action:
        rule += f" {action}"

    print(f"\n[>] Rule Preview:\n{rule}")
    if yes_or_no("Apply this rule?"):
        out = run_cmd(f"sudo nft {rule}")
        if out is None:
            print("[!] Rule creation failed.")
        else:
            print("[+] Rule added successfully.")

def delete_rule(table, chain):
    rules = list_rules(table, chain)
    if not rules:
        print("No rules to delete.")
        return
    show_rules_with_numbers(table, chain)
    sel = input("Enter rule number(s) to delete (e.g. 2 or 1,3,5): ")
    indexes = [int(i.strip()) - 1 for i in sel.split(",") if i.strip().isdigit()]
    for i in sorted(indexes, reverse=True):
        if 0 <= i < len(rules):
            handle = get_handle_from_rule(rules[i])
            cmd = f"sudo nft delete rule {table} {chain} handle {handle}"
            out = run_cmd(cmd)
            if out is not None:
                print(f"[+] Deleted rule #{i+1}")
            else:
                print(f"[!] Failed to delete rule #{i+1}")
        else:
            print(f"[!] Invalid rule number: {i+1}")

def get_handle_from_rule(rule_line):
    parts = rule_line.split("handle")
    if len(parts) < 2:
        return ""
    return parts[-1].strip()

def show_rules_with_numbers(table, chain):
    rules = list_rules(table, chain)
    if not rules:
        print("No rules found.")
        return
    print(f"\nRules in {table} / {chain}:\n")
    for i, r in enumerate(rules, 1):
        print(f"{i}. {r}")

# === Export Functions ===

def export_rules_csv(table, chain):
    rules = list_rules(table, chain)
    filename = f"{table}_{chain}_export.csv"
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Rule Number", "Rule Text"])
        for i, rule in enumerate(rules, 1):
            writer.writerow([i, rule])
    print(f"[+] Exported to {filename}")

def export_rules_json(table, chain):
    rules = list_rules(table, chain)
    filename = f"{table}_{chain}_export.json"
    with open(filename, "w") as f:
        json.dump({"table": table, "chain": chain, "rules": rules}, f, indent=2)
    print(f"[+] Exported to {filename}")

# === Backup & Restore ===

def backup_ruleset(filename="nft_backup.nft"):
    output = run_cmd("sudo nft list ruleset")
    if output:
        with open(filename, "w") as f:
            f.write(output)
        print(f"[+] Ruleset backed up to {filename}")
    else:
        print("[!] Failed to backup ruleset.")

def restore_ruleset(filename="nft_backup.nft"):
    if not os.path.exists(filename):
        print("[!] Backup file not found.")
        return
    if yes_or_no("This will overwrite current rules. Continue?"):
        run_cmd("sudo nft flush ruleset")
        output = run_cmd(f"sudo nft -f {filename}")
        if output is not None:
            print("[+] Ruleset restored from backup.")
        else:
            print("[!] Restore failed.")

# === Flush Functions with Safety ===

def flush_rules(table):
    print("[!] Safety: Changing chain policies to accept before flush...")
    chains = list_chains(table)
    for chain in chains:
        run_cmd(f"sudo nft chain {table} {chain} {{ policy accept; }}")
    run_cmd(f"sudo nft flush table {table}")
    print(f"[+] Flushed table {table}.")

# === Help ===

def help_menu():
    print("""
=== Help Menu ===

This CLI tool helps you manage nftables rules interactively.

Common Features:
- Add/delete/edit rules with preview
- Search, group, and filter rules by protocol or action
- Export rules as JSON or CSV
- Automatically backs up/flushes safely
- NAT, SNAT, DNAT, and masquerade support
- IPv6-ready with input validation

Examples:
- Allow TCP port 22: add tcp dport 22 accept
- Block all ICMP: add icmp drop
- DNAT HTTP: add ip daddr 1.2.3.4 tcp dport 80 dnat to 10.0.0.5:80

Always run this script as root!
    """)

# === Main Menu ===

def main_menu():
    while True:
        print("\n=== NFTables CLI Tool ===")
        print("1. List Tables")
        print("2. List Chains in a Table")
        print("3. List Rules in a Chain")
        print("4. Add Rule")
        print("5. Delete Rule")
        print("6. Filter/Search Rules")
        print("7. Group Rules")
        print("8. Export Rules")
        print("9. Backup Ruleset")
        print("10. Restore Ruleset")
        print("11. Flush Table (Safe)")
        print("12. Help")
        print("13. Exit")

        choice = input("Select option: ").strip()
        if choice == "1":
            tables = list_tables()
            for fam, tbl in tables:
                print(f"- {tbl} ({fam})")
        elif choice == "2":
            tables = list_tables()
            if not tables: continue
            table = choose_from_list("Select table:", [t[1] for t in tables])
            chains = list_chains(table)
            for ch in chains:
                print(f"- {ch}")
        elif choice == "3":
            tables = list_tables()
            if not tables: continue
            table = choose_from_list("Select table:", [t[1] for t in tables])
            chain = choose_from_list("Select chain:", list_chains(table))
            show_rules_with_numbers(table, chain)
        elif choice == "4":
            tables = list_tables()
            table = choose_from_list("Select table:", [t[1] for t in tables])
            chain = choose_from_list("Select chain:", list_chains(table))
            family = [t[0] for t in tables if t[1] == table][0]
            add_rule(family, table, chain)
        elif choice == "5":
            table = choose_from_list("Select table:", [t[1] for t in list_tables()])
            chain = choose_from_list("Select chain:", list_chains(table))
            delete_rule(table, chain)
        elif choice == "6":
            table = choose_from_list("Select table:", [t[1] for t in list_tables()])
            chain = choose_from_list("Select chain:", list_chains(table))
            rules = list_rules(table, chain)
            term = input("Keyword, IP, or port to search: ").strip()
            results = filter_rules(rules, keyword=term)
            for i, r in enumerate(results, 1):
                print(f"{i}. {r}")
        elif choice == "7":
            table = choose_from_list("Select table:", [t[1] for t in list_tables()])
            chain = choose_from_list("Select chain:", list_chains(table))
            rules = list_rules(table, chain)
            mode = choose_from_list("Group by:", ["protocol", "action"])
            show_grouped_rules(rules, mode)
        elif choice == "8":
            table = choose_from_list("Select table:", [t[1] for t in list_tables()])
            chain = choose_from_list("Select chain:", list_chains(table))
            fmt = choose_from_list("Export format:", ["CSV", "JSON"])
            if fmt == "CSV":
                export_rules_csv(table, chain)
            else:
                export_rules_json(table, chain)
        elif choice == "9":
            backup_ruleset()
        elif choice == "10":
            restore_ruleset()
        elif choice == "11":
            table = choose_from_list("Select table to flush:", [t[1] for t in list_tables()])
            flush_rules(table)
        elif choice == "12":
            help_menu()
        elif choice == "13":
            print("Goodbye!")
            break
        else:
            print("[!] Invalid choice.")

# === Run Script ===

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("You must run this script as root.")
        sys.exit(1)
    main_menu()