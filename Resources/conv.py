#!/usr/bin/env python3
import base64
import os
import sys

# ---------------- Utility Functions ---------------- #
def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def format_binary(bin_str, group_bytes=1):
    bin_str = bin_str.zfill(((len(bin_str) + 7) // 8) * 8)
    groups = [bin_str[i:i+8] for i in range(0, len(bin_str), 8)]
    if group_bytes > 1:
        grouped = []
        for i in range(0, len(groups), group_bytes):
            grouped.append(' '.join(groups[i:i+group_bytes]))
        return '   '.join(grouped)
    return ' '.join(groups)

def to_base64_with_newline(data: bytes) -> str:
    """Mimic Linux base64 tool: append newline before encoding."""
    if not data.endswith(b'\n'):
        data += b'\n'
    return base64.encodebytes(data).decode().rstrip("\n")

# ---------------- Conversion Functions ---------------- #
def decimal_to_all(decimal_value):
    decimal_value = int(decimal_value)
    byte_len = (decimal_value.bit_length() + 7) // 8 or 1
    binary_value = format_binary(bin(decimal_value)[2:], group_bytes=1)
    hex_value = f"0x{decimal_value:0{byte_len*2}x}"
    try:
        ascii_value = decimal_value.to_bytes(byte_len, 'big').decode()
    except:
        ascii_value = "[Non-printable ASCII]"
    base64_value = to_base64_with_newline(str(decimal_value).encode())

    print(f"\nDecimal input: {decimal_value}")
    print(f"Binary: {binary_value}")
    print(f"Hex: {hex_value}")
    print(f"ASCII: {ascii_value}")
    print(f"Base64 (decimal as text with newline): {base64_value}")

def hex_to_all(hex_value):
    if hex_value.lower().startswith("0x"):
        hex_value = hex_value[2:]
    raw_bytes = bytes.fromhex(hex_value)
    decimal_value = int.from_bytes(raw_bytes, 'big')
    binary_value = format_binary(bin(decimal_value)[2:], group_bytes=1)
    hex_value_fmt = f"0x{hex_value}"
    try:
        ascii_value = raw_bytes.decode()
    except:
        ascii_value = "[Non-printable ASCII]"
    base64_value = to_base64_with_newline(str(decimal_value).encode())

    print(f"\nHex input: {hex_value_fmt}")
    print(f"Decimal: {decimal_value}")
    print(f"Binary: {binary_value}")
    print(f"ASCII: {ascii_value}")
    print(f"Base64 (decimal as text with newline): {base64_value}")

def binary_to_all(binary_value):
    decimal_value = int(binary_value, 2)
    byte_len = (len(binary_value) + 7) // 8 or 1
    hex_value = f"0x{decimal_value:0{byte_len*2}x}"
    try:
        ascii_value = decimal_value.to_bytes(byte_len, 'big').decode()
    except:
        ascii_value = "[Non-printable ASCII]"
    base64_value = to_base64_with_newline(str(decimal_value).encode())

    print(f"\nBinary input: {format_binary(binary_value, group_bytes=1)}")
    print(f"Decimal: {decimal_value}")
    print(f"Hex: {hex_value}")
    print(f"ASCII: {ascii_value}")
    print(f"Base64 (decimal as text with newline): {base64_value}")

def ascii_to_all(ascii_value):
    raw_bytes = ascii_value.encode()
    decimal_value = int.from_bytes(raw_bytes, 'big')
    binary_value = format_binary(bin(decimal_value)[2:], group_bytes=1)
    hex_value = f"0x{raw_bytes.hex()}"
    base64_value = to_base64_with_newline(raw_bytes)

    print(f"\nASCII/Text input: {ascii_value}")
    print(f"Decimal: {decimal_value}")
    print(f"Binary: {binary_value}")
    print(f"Hex: {hex_value}")
    print(f"Base64 (ASCII/Text with newline): {base64_value}")

def base64_to_all(base64_value):
    raw_bytes = base64.b64decode(base64_value)
    decimal_value = int.from_bytes(raw_bytes, 'big')
    binary_value = format_binary(bin(decimal_value)[2:], group_bytes=1)
    hex_value = f"0x{raw_bytes.hex()}"
    try:
        ascii_value = raw_bytes.decode()
    except:
        ascii_value = "[Non-printable ASCII]"

    print(f"\nBase64 input: {base64_value}")
    print(f"Decimal: {decimal_value}")
    print(f"Binary: {binary_value}")
    print(f"Hex: {hex_value}")
    print(f"ASCII: {ascii_value}")

# ---------------- Main Program ---------------- #
def main():
    try:
        while True:
            clear_screen()
            print("=== Universal Converter ===")
            print("Select input type:")
            print("1) Decimal")
            print("2) Hex")
            print("3) Binary")
            print("4) ASCII/Text")
            print("5) Base64")
            choice = input("Enter choice (1-5): ").strip()

            user_input = input("Enter the value: ").strip()

            if choice == "1":
                decimal_to_all(user_input)
            elif choice == "2":
                hex_to_all(user_input)
            elif choice == "3":
                binary_to_all(user_input)
            elif choice == "4":
                ascii_to_all(user_input)
            elif choice == "5":
                base64_to_all(user_input)
            else:
                print("Invalid choice.")

            again = input("\nConvert another? (y/n): ").strip().lower()
            if again != "y":
                print("Exiting... Goodbye!")
                break

    except (KeyboardInterrupt, EOFError):
        print("\nExiting... Goodbye!")

if __name__ == "__main__":
    main()
