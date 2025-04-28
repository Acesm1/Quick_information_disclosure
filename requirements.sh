#!/bin/bash

echo "[+] Starting setup for Information Disclosure Scanner..."

# Update package list
echo "[*] Updating package lists..."
sudo apt update

# Install Nmap
echo "[*] Installing Nmap..."
sudo apt install -y nmap

# Install Python packages
echo "[*] Installing Python libraries (requests, beautifulsoup4, selenium, colorama)..."
pip install requests beautifulsoup4 selenium colorama

# Check if Chrome is installed
if command -v google-chrome > /dev/null; then
    echo "[+] Google Chrome is already installed."
else
    echo "[!] Google Chrome is not installed!"
    echo "[!] Please install it manually: https://www.google.com/chrome/"
fi

# Reminder for Chromedriver
echo "[*] Reminder: Make sure Chromedriver matches your Chrome version."
echo "    Download Chromedriver here: https://sites.google.com/chromium.org/driver/"

echo "[+] Setup completed successfully!"
