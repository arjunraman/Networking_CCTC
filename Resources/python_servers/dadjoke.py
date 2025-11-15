#!/usr/bin/env python3

import subprocess
import sys
import requests
import os
import shutil

# Function to check if ImageMagick's 'convert' command is available,
# and prompt user to install if missing.
def check_imagemagick():
    if shutil.which("convert") is None:
        print("ImageMagick 'convert' command not found.")
        answer = input("Do you want to install ImageMagick now? (requires sudo) [y/N]: ").strip().lower()
        if answer == 'y':
            try:
                print("Updating package list...")
                subprocess.run(["sudo", "apt", "update"], check=True)
                print("Installing ImageMagick...")
                subprocess.run(["sudo", "apt", "install", "-y", "imagemagick"], check=True)
                print("ImageMagick installed successfully.")
            except subprocess.CalledProcessError:
                print("Failed to install ImageMagick. Please install it manually.")
                sys.exit(1)
        else:
            print("ImageMagick is required to run this script. Exiting.")
            sys.exit(1)

# Ensure ImageMagick is installed before proceeding
check_imagemagick()

# Function to install required dependencies using pip3
def install_dependencies():
    try:
        import requests
    except ImportError:
        print("requests module not found. Installing with pip3...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])

# Ensure required dependencies are installed
install_dependencies()

# Function to create the joke directory if it doesn't exist
def create_joke_directory():
    joke_dir = "joke"
    if not os.path.exists(joke_dir):
        os.makedirs(joke_dir)
        print(f"Directory '{joke_dir}' created.")
    return joke_dir

# Function to get the next available filename in the format "dadjoke<number>.jpg"
def get_next_filename(joke_dir):
    existing_files = os.listdir(joke_dir)
    numbered_files = [f for f in existing_files if f.startswith("dadjoke") and f.endswith(".jpg")]
    file_numbers = []
    for file in numbered_files:
        try:
            number = int(file[len("dadjoke"):-4])
            file_numbers.append(number)
        except ValueError:
            continue
    next_number = 1
    if file_numbers:
        next_number = max(file_numbers) + 1
    return f"dadjoke{next_number}.jpg"

# Function to sanitize joke text by removing quotes
def sanitize_joke_text(dad_joke):
    dad_joke = dad_joke.replace("'", "").replace('"', "")
    return dad_joke

# Your existing wrap_text function here (unchanged)
def wrap_text(text, max_width, font="DejaVu-Sans", font_size=36):
    command = [
        "convert", "-font", font, "-pointsize", str(font_size), "label:" + text, "txt:-"
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"Error wrapping text: {result.stderr}")
    lines = result.stdout.splitlines()
    wrapped_text = []
    current_line = ""
    for word in text.split():
        trial_line = f"{current_line} {word}".strip()
        if len(trial_line) <= max_width:
            current_line = trial_line
        else:
            wrapped_text.append(current_line)
            current_line = word
    if current_line:
        wrapped_text.append(current_line)
    return wrapped_text

# Function to fetch a random dad joke and save it as a JPG image using ImageMagick
def fetch_and_save_dad_joke_as_jpg():
    url = 'https://icanhazdadjoke.com/'
    headers = {'Accept': 'application/json'}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        dad_joke = data['joke']
        sanitized_joke = sanitize_joke_text(dad_joke)
        joke_dir = create_joke_directory()
        filename = get_next_filename(joke_dir)
        save_path = os.path.join(joke_dir, filename)
        wrapped_text = wrap_text(sanitized_joke, max_width=70)
        y_position = 40
        try:
            command = ["convert", "-size", "1920x1024", "xc:white", "-font", "DejaVu-Sans", "-pointsize", "36"]
            for line in wrapped_text:
                command.extend(["-draw", f"text 40,{y_position} '{line}'"])
                y_position += 50
            command.append(save_path)
            subprocess.run(command, check=True)
            print(f"Random dad joke saved as {save_path}")
        except subprocess.CalledProcessError as e:
            print(f"Error creating image with ImageMagick: {e}")
    else:
        print(f"Failed to fetch a dad joke. Status code: {response.status_code}")

# Main execution
fetch_and_save_dad_joke_as_jpg()
