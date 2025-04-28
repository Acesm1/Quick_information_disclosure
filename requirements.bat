@echo off
echo [+] Starting setup for Information Disclosure Scanner...

:: Install Python packages
echo [*] Installing Python libraries (requests, beautifulsoup4, selenium, colorama)...
pip install requests
pip install beautifulsoup4
pip install selenium
pip install colorama

:: Reminder for Google Chrome
echo [*] Checking Google Chrome installation...
echo [!] If not installed, download Google Chrome from: https://www.google.com/chrome/

:: Reminder for Chromedriver
echo [*] Reminder: Download the matching Chromedriver for your Chrome version:
echo     https://sites.google.com/chromium.org/driver/

:: Reminder for Nmap
echo [!] Please manually install Nmap from: https://nmap.org/download.html
echo [!] During Nmap installation, make sure to select "Add Nmap to PATH".

echo [+] Setup completed successfully!
pause
