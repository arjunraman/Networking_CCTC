#!/usr/bin/python3

import os
import sys

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def color_text(text, color_code):
    return f"\033[{color_code}m{text}\033[0m"

def blue(text): return color_text(text, '34')
def white(text): return color_text(text, '97')

def calculate_fragments_including_original_header(original_packet_size, mtu, ihl_words):
    new_ip_header_size = ihl_words * 4
    payload_to_fragment = original_packet_size  # Treat entire packet as payload

    if mtu <= new_ip_header_size:
        print(color_text("\nError: MTU must be larger than IP header size\n", '31'))
        return

    max_payload_per_fragment = mtu - new_ip_header_size

    print(f"\n{blue('Original Packet Size')}: {white(f'{original_packet_size} bytes')}")
    print(f"{blue('New IP Header Size per Fragment')}: {white(f'{new_ip_header_size} bytes')}")
    print(f"{blue('MTU')}: {white(f'{mtu} bytes')}")
    print(f"{blue('Max Payload per Fragment (pre-alignment)')}: {white(f'{max_payload_per_fragment} bytes')}\n")

    remaining_payload = payload_to_fragment
    fragment_number = 1
    offset = 0
    offset_units = 8

    print(f"{blue('Frag#'):<6} {blue('MF Flag'):<8} {blue('Offset'):<20} {blue('Payload Size'):<14} {blue('Remaining Payload'):<18} {blue('Byte Range'):<20} {blue('Comment')}")
    print("=" * 115)

    while remaining_payload > 0:
        raw_payload_size = min(remaining_payload, max_payload_per_fragment)

        if raw_payload_size < remaining_payload:
            adjusted_payload_size = raw_payload_size - (raw_payload_size % 8)
            comment = f"Adjusted to {adjusted_payload_size} (divisible by 8)" if adjusted_payload_size != raw_payload_size else ""
        else:
            adjusted_payload_size = raw_payload_size
            comment = "Last fragment (may not be divisible by 8)" if adjusted_payload_size % 8 != 0 else ""

        payload_size = adjusted_payload_size
        mf_flag = 1 if remaining_payload > payload_size else 0
        start_byte = offset
        end_byte = offset + payload_size - 1
        byte_range = f"{start_byte}-{end_byte}"

        remaining_payload -= payload_size

        print(f"{fragment_number:<6} {mf_flag:<8} {offset // offset_units:<20} {payload_size:<14} {remaining_payload:<18} {byte_range:<20} {comment}")

        offset += payload_size
        fragment_number += 1

    print(color_text("\nNote: Offset values are in 8-byte units. Only the last fragment may have a payload not divisible by 8.\n", '36'))

if __name__ == "__main__":
    try:
        clear_screen()
        print(color_text("IP Packet Fragmentation Calculator (Original Header Included as Payload)\n", '33'))

        original_packet_size = int(input(blue("Enter original packet size (bytes): ") + white("")))
        mtu = int(input(blue("Enter MTU size (bytes): ") + white("")))
        ihl_words = int(input(blue("Enter IHL (IP header length in 32-bit words, typically 5): ") + white("")))

        if original_packet_size <= 0 or mtu <= 0 or ihl_words <= 0:
            raise ValueError("All values must be positive integers.")

        calculate_fragments_including_original_header(original_packet_size, mtu, ihl_words)

    except ValueError:
        print(color_text("\nInvalid input. Please enter valid positive integers.\n", '31'))
        sys.exit(1)
