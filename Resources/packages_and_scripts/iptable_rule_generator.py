#!/usr/bin/env python3

import os
import subprocess
import ipaddress
import sys

# -------------------------
# Utility functions
# -------------------------

def choose_from_list(prompt, options, multi=False):
    print(f"\n{prompt}")
    for i, opt in enumerate(options):
        print(f"{i + 1}. {opt}")
    choices = input("Enter choice(s) (comma-separated for multiple): ").strip()
    if not choices:
        return [] if multi else ""
    try:
        if multi:
            return [options[int(c) - 1] for c in choices.split(",")]
        else:
            return options[int(choices) - 1]
    except (IndexError, ValueError):
        print("Invalid choice.")
        return choose_from_list(prompt, options, multi)

def yes_or_no(prompt):
    answer = input(f"{prompt} (y/n): ").strip().lower()
    return answer == "y"

def validate_ip(ip):
    if not ip:
        return True
    try:
        ipaddress.ip_network(ip, strict=False)
        return True
    except ValueError:
        return False

def validate_ports(ports):
    if not ports:
        return True
    try:
        for port in ports.split(","):
            p = int(port)
            if p < 0 or p > 65535:
                return False
        return True
    except ValueError:
        return False

def detect_interfaces():
    # Simple auto-detect network interfaces except lo
    try:
        out = subprocess.check_output("ip -o link show | awk -F': ' '{print $2}'", shell=True)
        interfaces = [iface.strip() for iface in out.decode().splitlines() if iface.strip() != "lo"]
        return interfaces
    except Exception:
        return []

# -------------------------
# Rule building with interface filtering and comment support and tagging
# -------------------------

def build_rule(chain_action=None, chain=None, insert_pos=None, interfaces=None):
    if not chain_action:
        chain_action = choose_from_list("Append or Insert rule?", ["-A (Append)", "-I (Insert)"])
    if not chain:
        chain = choose_from_list("Select direction (chain):", ["INPUT", "OUTPUT", "FORWARD"])

    # Interface filtering with auto-detect support
    in_iface = ""
    out_iface = ""
    if interfaces:
        print("\nDetected interfaces:", ", ".join(interfaces))
        if yes_or_no("Filter by incoming interface?"):
            in_iface = choose_from_list("Choose incoming interface:", interfaces)
        if yes_or_no("Filter by outgoing interface?"):
            out_iface = choose_from_list("Choose outgoing interface:", interfaces)
    else:
        in_iface = input("Incoming Interface (-i) (leave blank for any): ").strip()
        out_iface = input("Outgoing Interface (-o) (leave blank for any): ").strip()

    # Input source IP with validation
    while True:
        src_ip = input("Source IP (leave blank for any): ").strip()
        if validate_ip(src_ip):
            break
        print("Invalid IP/network format. Try again.")

    # Input destination IP with validation
    while True:
        dst_ip = input("Destination IP (leave blank for any): ").strip()
        if validate_ip(dst_ip):
            break
        print("Invalid IP/network format. Try again.")

    # Protocol selection
    protocol = choose_from_list("Select protocol:", ["tcp", "udp", "icmp", "all"])

    # Ports only relevant for tcp/udp
    src_port = ""
    dst_port = ""
    if protocol in ["tcp", "udp"]:
        while True:
            src_port = input("Source Port(s) (e.g., 22 or 1000,2000) or leave blank: ").strip()
            if validate_ports(src_port):
                break
            print("Invalid ports. Enter comma-separated integers 0-65535.")

        while True:
            dst_port = input("Destination Port(s) (e.g., 80 or 80,443) or leave blank: ").strip()
            if validate_ports(dst_port):
                break
            print("Invalid ports. Enter comma-separated integers 0-65535.")

    # TCP states option
    tcp_states_option = ""
    if protocol == "tcp" and yes_or_no("Do you want to match TCP connection states?"):
        tcp_states_list = ["NEW", "ESTABLISHED", "RELATED", "INVALID"]
        selected_states = choose_from_list("Select TCP states (comma separated):", tcp_states_list, multi=True)
        if selected_states:
            tcp_states_option = f"-m state --state {','.join(selected_states)} "

    # TCP flags selection as numbered list
    tcp_flags = ""
    if protocol == "tcp" and yes_or_no("Do you want to match TCP flags?"):
        flag_opts = [
            "SYN",
            "ACK",
            "FIN",
            "RST",
            "PSH",
            "URG",
            "ALL",
            "NONE"
        ]
        print("\nSelect TCP flags to match (comma-separated numbers):")
        for i, flag in enumerate(flag_opts, 1):
            print(f"{i}. {flag}")
        flags_input = input("Enter your choice(s): ").strip()
        try:
            selected_flags = [flag_opts[int(num) - 1] for num in flags_input.split(",") if num.strip().isdigit()]
            if selected_flags:
                flags = ",".join(selected_flags)
                tcp_flags = f"--tcp-flags {flags} {flags} "
        except Exception:
            print("Invalid TCP flags selection. Skipping TCP flags match.")
            tcp_flags = ""

    # ICMP type and codes
    icmp_type_code = ""
    if protocol == "icmp" and yes_or_no("Do you want to specify ICMP type and code?"):
        icmp_types = [
            "0 (Echo Reply)",
            "3 (Destination Unreachable)",
            "5 (Redirect)",
            "8 (Echo Request)",
            "11 (Time Exceeded)"
        ]
        selected_icmp_type = choose_from_list("Select ICMP Type:", icmp_types)
        type_num = selected_icmp_type.split(" ")[0]

        icmp_code_map = {
            "3": [
                "0 (Net Unreachable)",
                "1 (Host Unreachable)",
                "2 (Protocol Unreachable)",
                "3 (Port Unreachable)",
                "4 (Fragmentation Needed)",
                "5 (Source Route Failed)",
                "6 (Destination Network Unknown)",
                "7 (Destination Host Unknown)",
                "8 (Source Host Isolated)",
                "9 (Communication with Destination Network Administratively Prohibited)",
                "10 (Communication with Destination Host Administratively Prohibited)",
                "11 (Network Unreachable for Type of Service)",
                "12 (Host Unreachable for Type of Service)",
                "13 (Communication Administratively Prohibited)",
                "14 (Host Precedence Violation)",
                "15 (Precedence cutoff in effect)"
            ],
            "5": ["0 (Network)", "1 (Host)", "2 (TOS Network)", "3 (TOS Host)"],
            "11": ["0 (TTL Expired)", "1 (Fragment Reassembly Timeout)"]
        }

        if type_num in icmp_code_map:
            selected_code = choose_from_list("Select ICMP Code:", icmp_code_map[type_num])
            code_num = selected_code.split(" ")[0]
            icmp_type_code = f"--icmp-type {type_num}/{code_num} "
        else:
            icmp_type_code = f"--icmp-type {type_num} "

    # Action selection
    action = choose_from_list("Select action:", ["ACCEPT", "DROP", "REJECT", "LOG"])

    # Optional comment
    comment = input("Add optional comment for this rule (or leave blank): ").strip()
    comment_str = f'-m comment --comment "{comment}" ' if comment else ""

    # Optional tag (for tagging rules)
    tag = input("Add optional tag for this rule (or leave blank): ").strip()
    tag_str = f"# TAG:{tag}" if tag else ""

    # Build final command
    cmd = f"iptables {chain_action} {chain} "
    if chain_action == "-I" and insert_pos is not None:
        cmd += f"{insert_pos} "

    if in_iface:
        cmd += f"-i {in_iface} "
    if out_iface:
        cmd += f"-o {out_iface} "

    cmd += f"-p {protocol} "
    if src_ip:
        cmd += f"-s {src_ip} "
    if dst_ip:
        cmd += f"-d {dst_ip} "

    if protocol in ["tcp", "udp"]:
        if src_port:
            cmd += f"-m multiport --sports {src_port} " if "," in src_port else f"--sport {src_port} "
        if dst_port:
            cmd += f"-m multiport --dports {dst_port} " if "," in dst_port else f"--dport {dst_port} "

    if tcp_states_option:
        cmd += tcp_states_option
    if tcp_flags:
        cmd += tcp_flags
    if icmp_type_code:
        cmd += icmp_type_code

    cmd += comment_str
    cmd += f"-j {action} {tag_str}".strip()

    return cmd

# -------------------------
# Rule list management and undo/redo
# -------------------------

class RuleManager:
    def __init__(self):
        self.rules = []
        self.undo_stack = []
        self.redo_stack = []

    def save_state(self):
        self.undo_stack.append(list(self.rules))
        self.redo_stack.clear()

    def add_rule(self, rule, position=None):
        self.save_state()
        if position is None:
            self.rules.append(rule)
        else:
            self.rules.insert(position, rule)

    def add_rules_batch(self, rules):
        self.save_state()
        self.rules.extend(rules)

    def delete_rule(self, index):
        if 0 <= index < len(self.rules):
            self.save_state()
            removed = self.rules.pop(index)
            return removed
        return None

    def delete_rules_batch(self, indices):
        self.save_state()
        removed = []
        for i in sorted(indices, reverse=True):
            if 0 <= i < len(self.rules):
                removed.append(self.rules.pop(i))
        return removed

    def list_rules(self):
        if not self.rules:
            print("\n(No rules added yet)")
            return
        print("\n📋 Current Rules:")
        for i, rule in enumerate(self.rules):
            print(f"{i + 1}. {rule}")

    def undo(self):
        if not self.undo_stack:
            print("Nothing to undo.")
            return
        self.redo_stack.append(list(self.rules))
        self.rules = self.undo_stack.pop()
        print("Undo successful.")

    def redo(self):
        if not self.redo_stack:
            print("Nothing to redo.")
            return
        self.undo_stack.append(list(self.rules))
        self.rules = self.redo_stack.pop()
        print("Redo successful.")

    def search_rules(self, keyword):
        results = [(i, r) for i, r in enumerate(self.rules) if keyword.lower() in r.lower()]
        if not results:
            print(f"No rules matching '{keyword}' found.")
            return
        print(f"\nRules matching '{keyword}':")
        for i, rule in results:
            print(f"{i + 1}. {rule}")

    def save_to_file(self, filename, mode="shell"):
        with open(filename, "w") as f:
            if mode == "shell":
                f.write("#!/bin/bash\n\n")
                for rule in self.rules:
                    f.write(rule + "\n")
            elif mode == "iptables-save":
                f.write("*filter\n")
                for rule in self.rules:
                    line = rule.replace("iptables -A", "-A").replace("iptables -I", "-I")
                    f.write(line + "\n")
                f.write("COMMIT\n")
            else:
                print("Unsupported save mode.")
                return
        if mode == "shell":
            os.chmod(filename, 0o755)
        print(f"\n💾 Rules saved to '{filename}' in {mode} format.")

# -------------------------
# Policy management and flush
# -------------------------

def warn_ssh_telnet_block(policy_chain, policy):
    if policy_chain == "INPUT" and policy in ["DROP", "REJECT"]:
        print("\n⚠️ Warning: Setting INPUT policy to DROP or REJECT may block your current SSH/Telnet session!")
        print("If you continue, you may lose remote access unless ports 22 (SSH) or 23 (Telnet) are explicitly allowed.")
        return not yes_or_no("Are you sure you want to proceed?")
    return False

def change_default_policies(rule_manager):
    chains = ["INPUT", "OUTPUT", "FORWARD"]
    policies = ["ACCEPT", "DROP", "REJECT"]

    for chain in chains:
        print(f"\nCurrent policy for {chain} chain:")
        try:
            output = subprocess.check_output(["iptables", "-L", chain, "-n"], stderr=subprocess.DEVNULL).decode()
            for line in output.splitlines():
                if line.startswith("Chain"):
                    parts = line.split()
                    if len(parts) >= 4 and parts[1] == chain:
                        print(f"  {parts[3]}")
                        break
        except Exception:
            print("  (Unable to detect current policy)")

        policy = choose_from_list(f"Select new default policy for {chain}:", policies)
        if warn_ssh_telnet_block(chain, policy):
            print(f"Aborting change of policy for {chain} to avoid lockout.")
            continue

        rule_manager.save_state()
        rule_manager.rules.append(f"iptables -P {chain} {policy}")
        print(f"Set default policy for {chain} to {policy}")

def flush_all_rules(rule_manager):
    print("\n⚠️ You are about to flush all firewall rules and reset default policies to ACCEPT.")
    if not yes_or_no("Are you sure you want to continue?"):
        print("Flush aborted.")
        return
    rule_manager.save_state()
    rule_manager.rules.append("iptables -P INPUT ACCEPT")
    rule_manager.rules.append("iptables -P OUTPUT ACCEPT")
    rule_manager.rules.append("iptables -P FORWARD ACCEPT")
    rule_manager.rules.append("iptables -F")
    print("Flush and policy reset commands added to rules list.")

# -------------------------
# Load rules from file
# -------------------------

def load_rules_from_file(rule_manager):
    filename = input("Enter filename to load rules from: ").strip()
    if not os.path.isfile(filename):
        print("File not found.")
        return
    with open(filename, "r") as f:
        lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    rule_manager.save_state()
    rule_manager.rules.extend(lines)
    print(f"Loaded {len(lines)} rules from {filename}")

# -------------------------
# Insert rule positionally
# -------------------------

def insert_rule_positionally(rule_manager, interfaces):
    if not rule_manager.rules:
        rule = build_rule(chain_action="-A", chain="INPUT", interfaces=interfaces)
        rule_manager.add_rule(rule)
        print("✅ Rule added as the first entry.")
        return

    print("\nWhere do you want to place the new rule?")
    print("1. Append at the end")
    print("2. Insert above a rule")
    print("3. Insert below a rule")
    choice = input("Choose option: ").strip()

    if choice == "1":
        rule = build_rule(chain_action="-A", interfaces=interfaces)
        rule_manager.add_rule(rule)
        print("✅ Rule appended.")
    elif choice in ["2", "3"]:
        rule_manager.list_rules()
        try:
            idx = int(input("Enter target rule number: ")) - 1
            if 0 <= idx < len(rule_manager.rules):
                existing_rule = rule_manager.rules[idx]
                parts = existing_rule.split()
                chain = None
                for p in parts:
                    if p in ("INPUT", "OUTPUT", "FORWARD"):
                        chain = p
                        break
                if not chain:
                    chain = "INPUT"

                pos = idx + 1 if choice == "2" else idx + 2

                rule = build_rule(chain_action="-I", chain=chain, insert_pos=pos, interfaces=interfaces)
                if choice == "2":
                    rule_manager.add_rule(rule, position=idx)
                    print(f"✅ Rule inserted above rule {idx + 1}.")
                else:
                    rule_manager.add_rule(rule, position=idx + 1)
                    print(f"✅ Rule inserted below rule {idx + 1}.")
            else:
                print("❌ Invalid rule number.")
        except ValueError:
            print("❌ Invalid input.")
    else:
        print("❌ Invalid option. Appending by default.")
        rule = build_rule(chain_action="-A", interfaces=interfaces)
        rule_manager.add_rule(rule)
        print("✅ Rule appended.")

# -------------------------
# Batch delete rules by number
# -------------------------

def batch_delete_rules(rule_manager):
    rule_manager.list_rules()
    if not rule_manager.rules:
        return
    choice = input("Enter rule numbers to delete (comma-separated): ").strip()
    try:
        indices = sorted({int(i)-1 for i in choice.split(",") if i.strip().isdigit()}, reverse=True)
        removed = rule_manager.delete_rules_batch(indices)
        if removed:
            print(f"✅ Deleted {len(removed)} rules.")
        else:
            print("No rules deleted.")
    except Exception:
        print("Invalid input.")

# -------------------------
# Dry-run/test mode
# -------------------------

def dry_run_rules(rule_manager):
    print("\n=== Dry-run Mode ===")
    print("Rules will be printed but NOT applied.")
    rule_manager.list_rules()
    print("\nYou can inspect rules before applying them.")

# -------------------------
# Interactive shell mode
# -------------------------

def interactive_shell(rule_manager, interfaces):
    print("\nEntering interactive shell mode (type 'help' for commands, 'exit' to quit)")
    while True:
        cmd = input("firewall> ").strip().lower()
        if cmd in ("exit", "quit"):
            print("Exiting interactive shell mode.")
            break
        elif cmd == "help":
            print("""
Commands:
  add          Add a new rule interactively
  list         List current rules
  del          Delete rule by number
  batchdel     Batch delete rules by numbers
  undo         Undo last change
  redo         Redo last undone change
  save         Save rules to file
  load         Load rules from file
  search       Search rules by keyword
  policies     Change default chain policies
  flush        Flush all rules (safe)
  dryrun       Show rules without applying
  apply        Apply rules immediately
  exit, quit   Exit shell mode
""")
        elif cmd == "add":
            insert_rule_positionally(rule_manager, interfaces)
        elif cmd == "list":
            rule_manager.list_rules()
        elif cmd == "del":
            rule_manager.list_rules()
            try:
                idx = int(input("Enter rule number to delete: ")) - 1
                removed = rule_manager.delete_rule(idx)
                if removed:
                    print(f"❌ Deleted rule: {removed}")
                else:
                    print("Invalid rule number.")
            except ValueError:
                print("Invalid input.")
        elif cmd == "batchdel":
            batch_delete_rules(rule_manager)
        elif cmd == "undo":
            rule_manager.undo()
        elif cmd == "redo":
            rule_manager.redo()
        elif cmd == "save":
            filename = input("Enter filename to save rules to (default firewall_rules.sh): ").strip()
            if not filename:
                filename = "firewall_rules.sh"
            mode = choose_from_list("Select export format:", ["shell script", "iptables-save"])
            mode_key = "shell" if mode == "shell script" else "iptables-save"
            rule_manager.save_to_file(filename, mode=mode_key)
        elif cmd == "load":
            load_rules_from_file(rule_manager)
        elif cmd == "search":
            keyword = input("Enter search keyword: ").strip()
            if keyword:
                rule_manager.search_rules(keyword)
        elif cmd == "policies":
            change_default_policies(rule_manager)
        elif cmd == "flush":
            flush_all_rules(rule_manager)
        elif cmd == "dryrun":
            dry_run_rules(rule_manager)
        elif cmd == "apply":
            print("\n⚠️ This will apply rules immediately using 'iptables-restore'.")
            if not yes_or_no("Are you sure you want to apply?"):
                print("Apply aborted.")
                continue
            tmp_file = "/tmp/firewall_rules_to_apply.rules"
            try:
                with open(tmp_file, "w") as f:
                    f.write("*filter\n")
                    for rule in rule_manager.rules:
                        line = rule.replace("iptables -A", "-A").replace("iptables -I", "-I")
                        f.write(line + "\n")
                    f.write("COMMIT\n")
                ret = subprocess.run(["sudo", "iptables-restore", tmp_file])
                if ret.returncode == 0:
                    print("✅ Rules applied successfully.")
                else:
                    print("❌ Error applying rules.")
            except Exception as e:
                print(f"Exception during apply: {e}")
            finally:
                if os.path.exists(tmp_file):
                    os.remove(tmp_file)
        else:
            print("Unknown command. Type 'help' for available commands.")

# -------------------------
# Main menu
# -------------------------

def firewall_rule_manager():
    rule_manager = RuleManager()
    interfaces = detect_interfaces()

    while True:
        print("\n=== FIREWALL RULE MANAGER ===")
        print("1. Add Rule")
        print("2. List Rules")
        print("3. Delete Rule")
        print("4. Batch Delete Rules")
        print("5. Save Rules to File")
        print("6. Load Rules from File")
        print("7. Undo last change")
        print("8. Redo last undone change")
        print("9. Search Rules")
        print("10. Change default policies (INPUT, OUTPUT, FORWARD)")
        print("11. Flush all rules (reset policies to ACCEPT first)")
        print("12. Preview rules (Dry-run)")
        print("13. Apply rules immediately (requires root)")
        print("14. Enter Interactive Shell Mode")
        print("15. Exit")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            insert_rule_positionally(rule_manager, interfaces)
        elif choice == "2":
            rule_manager.list_rules()
        elif choice == "3":
            rule_manager.list_rules()
            try:
                idx = int(input("Enter rule number to delete: ")) - 1
                removed = rule_manager.delete_rule(idx)
                if removed:
                    print(f"❌ Deleted rule: {removed}")
                else:
                    print("Invalid rule number.")
            except ValueError:
                print("Invalid input.")
        elif choice == "4":
            batch_delete_rules(rule_manager)
        elif choice == "5":
            filename = input("Enter filename to save rules to (default firewall_rules.sh): ").strip()
            if not filename:
                filename = "firewall_rules.sh"
            mode = choose_from_list("Select export format:", ["shell script", "iptables-save"])
            mode_key = "shell" if mode == "shell script" else "iptables-save"
            rule_manager.save_to_file(filename, mode=mode_key)
        elif choice == "6":
            load_rules_from_file(rule_manager)
        elif choice == "7":
            rule_manager.undo()
        elif choice == "8":
            rule_manager.redo()
        elif choice == "9":
            keyword = input("Enter search keyword: ").strip()
            if keyword:
                rule_manager.search_rules(keyword)
        elif choice == "10":
            change_default_policies(rule_manager)
        elif choice == "11":
            flush_all_rules(rule_manager)
        elif choice == "12":
            dry_run_rules(rule_manager)
        elif choice == "13":
            print("\n⚠️ This will apply rules immediately using 'iptables-restore'.")
            if not yes_or_no("Are you sure you want to apply?"):
                print("Apply aborted.")
                continue
            tmp_file = "/tmp/firewall_rules_to_apply.rules"
            try:
                with open(tmp_file, "w") as f:
                    f.write("*filter\n")
                    for rule in rule_manager.rules:
                        line = rule.replace("iptables -A", "-A").replace("iptables -I", "-I")
                        f.write(line + "\n")
                    f.write("COMMIT\n")
                ret = subprocess.run(["sudo", "iptables-restore", tmp_file])
                if ret.returncode == 0:
                    print("✅ Rules applied successfully.")
                else:
                    print("❌ Error applying rules.")
            except Exception as e:
                print(f"Exception during apply: {e}")
            finally:
                if os.path.exists(tmp_file):
                    os.remove(tmp_file)
        elif choice == "14":
            interactive_shell(rule_manager, interfaces)
        elif choice == "15":
            print("Exiting.")
            sys.exit(0)
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    firewall_rule_manager()