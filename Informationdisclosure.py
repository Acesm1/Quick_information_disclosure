import requests
import json
import re
import time
import subprocess
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import WebDriverException
from requests.exceptions import RequestException

# ====== CONFIGURATION ======
TARGET = input("enter a url to scan")  # <-- Change to your target
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

# Check for sensitive files
def check_sensitive_files():
    print("\n[+] Checking for sensitive files...\n")
    session = requests.Session()
    for path in sensitive_paths:
        try:
            url = f"{TARGET.rstrip('/')}/{path.lstrip('/')}"
            response = session.get(url, timeout=TIMEOUT)
            if response.status_code == 200:
                print(f"    [!] Found accessible: {url}")
            elif response.status_code in [301, 302]:
                print(f"    [*] Redirected (potentially interesting): {url}")
        except RequestException as e:
            print(f"    [-] Request failed for {url}: {str(e)}")

# Search homepage for HTML comments
def search_html_comments():
    print("\n[+] Searching HTML source for hidden comments...\n")
    try:
        response = requests.get(TARGET, timeout=TIMEOUT)
        soup = BeautifulSoup(response.text, "html.parser")
        comments = soup.find_all(string=lambda text: isinstance(text, type(soup.comment)))
        if comments:
            for comment in comments:
                print(f"    [!] Comment found: {comment.strip()}")
        else:
            print("    [-] No comments found.")
    except RequestException as e:
        print(f"    [-] Failed to fetch homepage: {str(e)}")

# Try injecting payloads to trigger errors
def trigger_error_messages():
    print("\n[+] Testing for error message leaks...\n")
    session = requests.Session()
    for payload in payloads:
        try:
            test_url = f"{TARGET.rstrip('/')}/?test={payload}"
            response = session.get(test_url, timeout=TIMEOUT)
            for signature in error_signatures:
                if signature.lower() in response.text.lower():
                    print(f"    [!] Error Leak Detected at {test_url}: {signature}")
                    break
        except RequestException as e:
            print(f"    [-] Request failed for payload {payload}: {str(e)}")

# Analyze network traffic for leaks
def analyze_network_traffic():
    print("\n[+] Analyzing Network Traffic for sensitive leaks...\n")
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
                            print(f"[!] Leak Detected in Network Response:\n    {leaks}\n")
                            for leak in leaks:
                                if re.match(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", leak):
                                    ip_addresses_found.add(leak)
                    except WebDriverException:
                        pass  # Some responses have no body
            except (json.JSONDecodeError, KeyError):
                pass  # Ignore badly formatted logs

    except WebDriverException as e:
        print(f"    [-] WebDriver error: {str(e)}")
    finally:
        driver.quit()

    # Nmap Scan for leaked IPs
    for ip in ip_addresses_found:
        run_nmap(ip)

# Extract sensitive info using regex
def extract_sensitive_info(text):
    findings = []
    for pattern in sensitive_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        findings.extend(matches)
    return findings

# Nmap scanner
def run_nmap(ip_address):
    print(f"\n[+] Running Nmap Scan on {ip_address}...\n")
    try:
        result = subprocess.check_output(["nmap", "-sS", "-T4", ip_address], stderr=subprocess.STDOUT, text=True)
        print(result)
    except subprocess.CalledProcessError as e:
        print(f"    [!] Nmap failed: {e.output}")

# Main function
def main():
    print(f"\n[+] Starting Full Information Disclosure Scan on {TARGET}")
    check_sensitive_files()
    search_html_comments()
    trigger_error_messages()
    analyze_network_traffic()
    print("\n[+] Scan Complete.")

if __name__ == "__main__":
    main()
    
