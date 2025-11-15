#!/usr/bin/python3
import socket
import os
import random

port = 1111
affirmations = [
    "You are awesome!",
    "You are capable of amazing things!",
    "Your potential is limitless!",
    "You are a star in the making!",
    "Keep going, you're doing great!",
    "You bring something special to the world!",
    "You are a force to be reckoned with!",
    "Your creativity knows no bounds!",
    "You are stronger than you think!",
    "You have the power to create change!",
    "You are worthy of success and happiness!",
    "Your dreams are within reach!",
    "You are a beautiful soul, inside and out!",
    "Every step you take brings you closer to greatness!",
    "You radiate positivity and strength!",
    "You are a problem solver, capable of overcoming anything!",
    "You have everything you need to succeed!",
    "Your mind is sharp, and your heart is kind!",
    "You inspire others with your resilience!",
    "You are an unstoppable force of nature!",
    "The world is better with you in it!",
    "Your hard work is paying off!",
    "You are deserving of all the good things coming your way!",
    "You are capable of achieving your wildest dreams!",
    "Your journey is just beginning, and it's full of possibility!",
    "You are a magnet for success and opportunity!",
    "You are brave, you are bold, you are worthy!",
    "You can overcome any challenge that comes your way!",
    "You are a masterpiece in the making!",
    "You have the strength to rise after every fall!",
    "You are an amazing person with endless potential!"
]

# Function to read the list of allowed names from the text file
def load_allowed_names(filename):
    with open(filename, 'r') as file:
        return [line.strip().lower() for line in file.readlines()]  # Convert names to lowercase

# Load allowed names from "allowed_names.txt"
allowed_names = load_allowed_names('allowed_names.txt')

# Create TCP stream socket using IPv4
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)

# This prevents the bind from being stuck in TIME_WAIT state.
# The SO_REUSEADDR flag tells the kernel to reuse a local socket in TIME_WAIT state,
# without waiting for its natural timeout to expire. Will not work if the socket is to the same destination.
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# Bind the socket to address. The socket must not already be bound.
# '' Ties the socket to any IPv4 address on this device
s.bind(('', port))

# Enable a server to accept connections. Listens for 1 request to connect.
s.listen(1)

# Execute the command (a string) in a subshell.
os.system("clear")

print("Waiting for TCP connections\n")

# Initialize a set to keep track of used names
used_names = set()

# Function to display the names in red initially and green when seen
def display_names():
    for name in allowed_names:
        if name in used_names:
            # Print in green when the name has been used
            print(f"\033[32m{name}\033[0m", end=" ")
        else:
            # Print in red initially
            print(f"\033[31m{name}\033[0m", end=" ")
    print()  # Move to next line

# Listens for connections until stopped
while 1:
    # Display allowed names with their updated colors
    print("\nAllowed Names: ", end="")
    display_names()

    conn, addr = s.accept()
    # Accepts connections from clients and creates a new socket.
    # The return value is a pair (conn, address)
    # conn = a new socket object usable to send and receive data on the connection (local)
    # address = the address bound to the socket on the other end of the connection (remote)

    # Receive the message (payload) from the client
    connect = conn.recv(1024)

    # Decode the received message (payload)
    payload = connect.decode().strip().lower()  # Convert payload to lowercase

    # Check if the received payload (name) is in the allowed names list
    if payload not in allowed_names:
        print(f"Connection from '{payload}' denied: Name not in allowed list.")
        conn.close()
        continue

    # If the payload is allowed, process the request
    print(f"Message Received - '{payload}'")  # Prints the received message (payload)

    # Select a random affirmation from the list
    affirmation = random.choice(affirmations)

    # Add two new lines after sending the affirmation
    response = affirmation + "\n\n"  # Append two new lines after the affirmation

    # Sends the randomly chosen affirmation in response with two new lines after it
    conn.sendall(response.encode('utf-8'))

    # Mark the name as used
    used_names.add(payload)

    # Display the updated names with the used name in green
    print(f"\033[32m{payload}\033[0m has been used.")  # Green color

    # Closes the local connection from remote
    conn.close()