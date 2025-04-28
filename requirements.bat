@echo off
echo [+] Starting setup for Information Disclosure Scanner...

:: Install Python packages
echo [*] Installing Python libraries (requests, beautifulsoup4, selenium)...
pip install requests
pip install beautifulsoup4
pip install selenium

:: Reminder for Chrome
echo [!] Make sure you have Google Chrome installed: https://www.google.com/chrome/

:: Reminder for Chromedriver
echo [!] Download Chromedriver that matches your Chrome version: https://sites.google.com/chromium.org/driver/

:: Reminder for Nmap
echo [!] Please install Nmap manually from: https://nmap.org/download.html
echo [!] During Nmap installation, choose to "Add Nmap to PATH".

echo [*] Setup completed successfully!
pause
