import argparse
import requests
import json
import re
import time
import subprocess
from datetime import datetime

# Try to import optional modules and handle errors
try:
    from bs4 import BeautifulSoup
except ImportError:
    print("[!] BeautifulSoup (bs4) is not installed. Install it using 'pip install beautifulsoup4'")
    exit()

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.common.exceptions import WebDriverException
except ImportError:
    print("[!] Selenium is not installed. Install it using 'pip install selenium'")
    exit()

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    print("[!] Colorama is not installed. Install it using 'pip install colorama'")
    exit()

from requests.exceptions import RequestException

# ====== CONFIGURATION ======
TIMEOUT = 5  # Seconds to wait for loading
HEADLESS = True  # Set to False if you want to see browser
# ============================

# Common sensitive files
sensitive_paths = [
    "robots.txt", "sitemap.xml", ".git/", "backup.zip", "config.php.bak", "db.sql", "admin/", "phpinfo.php"
]

# Bad payloads to trigger errors
payloads = [
    "'", "\"", "`", ";", "<script>", "%00", "../../", "\\", "' OR '1'='1"
]

# Error signatures to detect
error_signatures = [
    "SQL syntax", "mysql_fetch", "ORA-01756", "unexpected token",
    "You have an error in your SQL syntax", "Warning:", "Fatal error", "Stack trace",
    "Undefined index", "System.NullReferenceException", "Traceback (most recent call last)"
]

# Sensitive data patterns
sensitive_patterns = [
    r"[\w\.-]+@[\w\.-]+\.\w+",           # Emails
    r"(token|key|password)[\"']?\s*[:=]\s*[\"']?[a-zA-Z0-9-_\.]+",  # Tokens/Keys/Passwords
    r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", # IP Addresses
    r"Exception|Stack trace|Warning|Error"  # Debug messages
]

# Argument parsing for target URL
def parse_arguments():
    parser = argparse.ArgumentParser(description="Quick Information Disclosure Tool by darknickon")
    parser.add_argument("-u", "--url", required=True, help="Target URL to scan")
    return parser.parse_args()

# Start Selenium browser
def start_browser():
    chrome_options = Options()
    if HEADLESS:
        chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    caps = {'goog:loggingPrefs': {'performance': 'ALL'}}
    driver = webdriver.Chrome(options=chrome_options, desired_capabilities=caps)
    return driver

# Print Banner
def print_banner():
    banner = r"""
  ____             _        _    _ _ _             
 |  _ \  __ _ _ __(_) ___  | |  (_) (_)_ __   __ _ 
 | | | |/ _` | '__| |/ __| | |  | | | | '_ \ / _` |
 | |_| | (_| | |  | | (__  | |__| | | | | | | (_| |
 |____/ \__,_|_|  |_|\___| |____|_|_|_|_| |_|\__, |
                                            |___/ 

          Quick Info Disclosure Scanner
                by ace-Smith001
    """
    print(Fore.BLUE + banner + Style.RESET_ALL)

# Check for sensitive files
def check_sensitive_files():
    print(Fore.BLUE + "\n[+] Checking for sensitive files...\n" + Style.RESET_ALL)
    session = requests.Session()
    for path in sensitive_paths:
        try:
            url = f"{TARGET.rstrip('/')}/{path.lstrip('/')}"
            response = session.get(url, timeout=TIMEOUT)
            if response.status_code == 200:
                print(Fore.BLUE + f"    [!] Found accessible: {url}" + Style.RESET_ALL)
            elif response.status_code in [301, 302]:
                print(Fore.BLUE + f"    [*] Redirected (potentially interesting): {url}" + Style.RESET_ALL)
        except RequestException as e:
            print(Fore.BLUE + f"    [-] Request failed for {url}: {str(e)}" + Style.RESET_ALL)

# Search homepage for HTML comments
def search_html_comments():
    print(Fore.GREEN + "\n[+] Searching HTML source for hidden comments...\n" + Style.RESET_ALL)
    try:
        response = requests.get(TARGET, timeout=TIMEOUT)
        soup = BeautifulSoup(response.text, "html.parser")
        comments = soup.find_all(string=lambda text: isinstance(text, type(soup.comment)))
        if comments:
            for comment in comments:
                print(Fore.BLUE + f"    [!] Comment found: {comment.strip()}" + Style.RESET_ALL)
        else:
            print(Fore.BLUE + "    [-] No comments found." + Style.RESET_ALL)
    except RequestException as e:
        print(Fore.BLUE + f"    [-] Failed to fetch homepage: {str(e)}" + Style.RESET_ALL)

# Try injecting payloads to trigger errors
def trigger_error_messages():
    print(Fore.GREEN + "\n[+] Testing for error message leaks...\n" + Style.RESET_ALL)
    session = requests.Session()
    for payload in payloads:
        try:
            test_url = f"{TARGET.rstrip('/')}/?test={payload}"
            response = session.get(test_url, timeout=TIMEOUT)
            for signature in error_signatures:
                if signature.lower() in response.text.lower():
                    print(Fore.BLUE + f"    [!] Error Leak Detected at {test_url}: {signature}" + Style.RESET_ALL)
                    break
        except RequestException as e:
            print(Fore.GREEN + f"    [-] Request failed for payload {payload}: {str(e)}" + Style.RESET_ALL)

# Analyze network traffic for leaks
def analyze_network_traffic():
    print(Fore.BLUE + "\n[+] Analyzing Network Traffic for sensitive leaks...\n" + Style.RESET_ALL)
    driver = start_browser()
    ip_addresses_found = set()

    try:
        driver.get(TARGET)
        time.sleep(TIMEOUT)

        logs = driver.get_log('performance')

        for entry in logs:
            try:
                message = json.loads(entry['message'])['message']
                if message['method'] == 'Network.responseReceived':
                    request_id = message['params']['requestId']
                    try:
                        response = driver.execute_cdp_cmd('Network.getResponseBody', {'requestId': request_id})
                        body = response.get('body', '')

                        leaks = extract_sensitive_info(body)
                        if leaks:
                            print(Fore.BLUE + f"[!] Leak Detected in Network Response:\n    {leaks}\n" + Style.RESET_ALL)
                            for leak in leaks:
                                if re.match(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", leak):
                                    ip_addresses_found.add(leak)
                    except WebDriverException:
                        pass  # Some responses have no body
            except (json.JSONDecodeError, KeyError):
                pass  # Ignore badly formatted logs

    except WebDriverException as e:
        print(Fore.BLUE + f"    [-] WebDriver error: {str(e)}" + Style.RESET_ALL)
    finally:
        driver.quit()

    # Nmap Scan for leaked IPs
    for ip in ip_addresses_found:
        try:
            run_nmap(ip)
        except Exception as e:
            print(Fore.RED + f"    [!] Failed to scan IP {ip}: {str(e)}" + Style.RESET_ALL)

# Extract sensitive info using regex
def extract_sensitive_info(text):
    findings = []
    for pattern in sensitive_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        findings.extend(matches)
    return findings

# Enhanced Nmap scanner
def run_nmap(ip_address, ports="1-65535", timing="T4", output_file="scan_results.txt"):
    """
    Enhanced Nmap Scan Function
    - Performs a detailed Nmap scan with customizable ports, timing, and output options.
    """
    print(Fore.BLUE + f"\n[+] Running Enhanced Nmap Scan on {ip_address}...\n" + Style.RESET_ALL)
    try:
        # Construct the Nmap command with additional options
        nmap_command = [
            "nmap",
            "-sS",        # SYN Scan
            "-sV",        # Service Version Detection
            "-O",         # OS Detection
            "-p", ports,  # Scan specified ports
            "-T" + timing, # Timing template
            "-oN", output_file,  # Save results to file
            ip_address
        ]
        # Execute the Nmap command and capture output
        result = subprocess.check_output(nmap_command, stderr=subprocess.STDOUT, text=True)
        print(Fore.BLUE + result + Style.RESET_ALL)
        print(Fore.GREEN + f"\n[+] Nmap results saved to '{output_file}'" + Style.RESET_ALL)
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"    [!] Nmap failed: {e.output}" + Style.RESET_ALL)
    except FileNotFoundError:
        print(Fore.RED + "    [!] Nmap is not installed or not found in PATH. Please install Nmap to use this feature." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"    [!] An unexpected error occurred during the Nmap scan: {str(e)}" + Style.RESET_ALL)

# Main function
def main():
    args = parse_arguments()
    global TARGET
    TARGET = args.url  # Set TARGET based on the -u flag

    start_time = datetime.now()

    print_banner()
    print(Fore.BLUE + f"[*] Scan started at: {start_time}" + Style.RESET_ALL)
    check_sensitive_files()
    search_html_comments()
    trigger_error_messages()
    analyze_network_traffic()

    end_time = datetime.now()
    print(Fore.BLUE + f"\n[*] Scan finished at: {end_time}" + Style.RESET_ALL)
    print(Fore.BLUE + f"[*] Total Duration: {end_time - start_time}" + Style.RESET_ALL)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.BLUE + "\n[!] Scan interrupted by user. Exiting..." + Style.RESET_ALL)
