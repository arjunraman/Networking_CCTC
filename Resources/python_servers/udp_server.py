#!/usr/bin/python3
import socket
import os
import random

port = 1111
affirmations = [
    "The internet is becoming the town square for the global village of tomorrow. – Bill Gates",
    "Cybersecurity is much more than a matter of IT. – Stephane Nappo",
    "In the world of cybersecurity, there are no absolutes, only degrees of risk. – Bruce Schneier",
    "Security is a process, not a product. – Bruce Schneier",
    "The best way to predict the future is to invent it. – Alan Kay",
    "The Internet is the most powerful tool we have for connecting the world, but it’s also one of the most dangerous. – John McAfee",
    "The challenge of cybersecurity is the constant need to stay ahead of the attackers. – Greg Shipley",
    "It’s not about how good you are at stopping an attack, it’s about how good you are at detecting it. – Unknown",
    "Cybersecurity is an ongoing journey, not a destination. – Unknown",
    "In the cyber world, you must always stay vigilant, as the threats are constant and evolving. – Unknown",
    "The most secure computer is one that’s unplugged. – Unknown",
    "Your network is only as strong as its weakest link. – Unknown",
    "The best defense is a good offense when it comes to cybersecurity. – Unknown",
    "The security of your systems is only as strong as your weakest password. – Unknown",
    "We are not fighting hackers; we are fighting the infrastructure they use. – Unknown",
    "Every device connected to the network is a potential vulnerability. – Unknown",
    "There is no such thing as perfect security, only the best defense. – Unknown",
    "A hacker’s biggest tool is a weak password. – Unknown",
    "The most dangerous thing in cybersecurity is the human element. – Unknown",
    "You can never be too paranoid about cybersecurity. – Unknown",
    "The biggest threat to your network is you, and you’re not even aware of it. – Unknown",
    "Cybersecurity is everyone’s responsibility, not just IT’s. – Unknown",
    "Your firewall is only as strong as the people who manage it. – Unknown",
    "To protect your network, you must understand how it works. – Unknown",
    "The cloud is great, but remember, it’s not as secure as you think. – Unknown",
    "Hackers don’t break into systems; they break into people. – Unknown",
    "It’s not enough to secure your network; you must secure your entire ecosystem. – Unknown",
    "The most important thing to protect in cybersecurity is your data. – Unknown",
    "Cybersecurity isn’t just an IT issue; it’s a business issue. – Unknown",
    "There is no perfect security, but there are better security measures. – Unknown",
    "A good cybersecurity plan includes anticipating the unexpected. – Unknown"
]

# Function to read the list of allowed names from the text file
def load_allowed_names(filename):
    with open(filename, 'r') as file:
        return [line.strip().lower() for line in file.readlines()]  # Convert names to lowercase

# Load allowed names from "allowed_names.txt"
allowed_names = load_allowed_names('allowed_names.txt')

# Create UDP socket using IPv4
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind the socket to any available address on the specified port
s.bind(('', port))

# Execute the command (a string) in a subshell.
os.system("clear")

print("Waiting for UDP connections\n")

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

# Listens for incoming messages
while True:
    # Display allowed names with their updated colors
    print("\nAllowed Names: ", end="")
    display_names()

    # Receive the message (payload) from the client
    data, addr = s.recvfrom(1024)  # Receive data from the client

    # Decode the received message (payload)
    payload = data.decode().strip().lower()  # Convert payload to lowercase

    # Check if the received payload (name) is in the allowed names list
    if payload not in allowed_names:
        print(f"Connection from '{payload}' denied: Name not in allowed list.")
        continue

    # If the payload is allowed, process the request
    print(f"Message Received - '{payload}'")  # Prints the received message (payload)

    # Select a random affirmation from the list
    affirmation = random.choice(affirmations)

    # Add two new lines after sending the affirmation
    response = affirmation + "\n\n"  # Append two new lines after the affirmation

    # Sends the randomly chosen affirmation in response with two new lines after it
    s.sendto(response.encode('utf-8'), addr)

    # Mark the name as used
    used_names.add(payload)

    # Display the updated names with the used name in green
    print(f"\033[32m{payload}\033[0m has been used.")  # Green color