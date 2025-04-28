#!/bin/bash

echo "[+] Starting setup for Information Disclosure Scanner..."

# Update package list
sudo apt update

# Install Nmap
echo "[+] Installing Nmap..."
sudo apt install -y nmap

# Install Python packages
echo "[+] Installing Python libraries (requests, beautifulsoup4, selenium)..."
pip install requests beautifulsoup4 selenium

# Check for Chrome installation
if command -v google-chrome > /dev/null; then
    echo "[+] Google Chrome is already installed."
else
    echo "[!] Please install Google Chrome manually: https://www.google.com/chrome/"
fi

# Reminder for Chromedriver
echo "[!] Make sure you download and match Chromedriver version to your Chrome!"
echo "    Download Chromedriver here: https://sites.google.com/chromium.org/driver/"

echo "[+] Setup completed successfully!"
