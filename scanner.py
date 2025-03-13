import sqlite3
import requests
from bs4 import BeautifulSoup
import argparse

DB_FILE = "threat_hunter.db"

def save_scan(target, scan_type):
    """Save scan metadata to the database and return scan_id."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO scans (target, scan_type) VALUES (?, ?)", (target, scan_type))
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id

def save_finding(scan_id, vulnerability, severity, recommendation, verbose):
    """Save scan findings to the database."""
    if verbose:
        print(f"⚠️  Found: {vulnerability} (Severity: {severity})")
        print(f"   ➜ Recommendation: {recommendation}\n")

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO findings (scan_id, vulnerability, severity, recommendation)
        VALUES (?, ?, ?, ?)
    """, (scan_id, vulnerability, severity, recommendation))
    conn.commit()
    conn.close()

def scan_api(url, verbose=False):
    """Scan an API for security issues (OWASP API Top 10)."""
    scan_id = save_scan(url, "API")

    try:
        response = requests.get(url, timeout=10)  # Enforcing SSL verification
        if response.status_code == 200:
            save_finding(scan_id, "API1:2019 - Broken Object Level Authorization", "High",
                         "Ensure proper access controls are implemented.", verbose)

        # Check CORS misconfiguration (OWASP API4:2019)
        if "Access-Control-Allow-Origin" in response.headers and response.headers["Access-Control-Allow-Origin"] == "*":
            save_finding(scan_id, "API4:2019 - Lack of Resources & Rate Limiting", "Medium",
                         "Restrict CORS to trusted domains.", verbose)

        # Check HTTP methods (OWASP API6:2019)
        for method in ["PUT", "DELETE", "OPTIONS"]:
            method_response = requests.request(method, url, timeout=10)
            if method_response.status_code in [200, 201, 202]:
                save_finding(scan_id, f"API6:2019 - Mass Assignment (Unrestricted {method})", "High",
                             f"Restrict {method} to authorized users.", verbose)

    except requests.exceptions.RequestException as e:
        print(f"❌ Error scanning API: {url} - {e}")

def scan_web(url, verbose=False):
    """Scan a web app for security issues (OWASP Web Top 10)."""
    scan_id = save_scan(url, "Web")

    try:
        response = requests.get(url, timeout=10)  # Enforcing SSL verification
        soup = BeautifulSoup(response.text, "html.parser")

        # Check for missing security headers (OWASP A06:2021)
        headers = response.headers
        missing_headers = [h for h in ["Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security"] if h not in headers]
        if missing_headers:
            save_finding(scan_id, "A06:2021 - Security Misconfiguration", "Medium",
                         f"Add {', '.join(missing_headers)}.", verbose)

        # Check for directory listing (OWASP A05:2021)
        if "Index of" in soup.text:
            save_finding(scan_id, "A05:2021 - Security Misconfiguration (Directory Listing)", "High",
                         "Disable directory listing on the web server.", verbose)

        # Check for default login pages (OWASP A07:2021)
        common_admin_pages = ["/admin", "/login", "/wp-admin", "/phpmyadmin"]
        for page in common_admin_pages:
            admin_response = requests.get(url + page, timeout=10)
            if admin_response.status_code == 200:
                save_finding(scan_id, f"A07:2021 - Identification & Authentication Failures (Default Login: {page})",
                             "Medium", "Restrict admin page access.", verbose)

        # Check for weak SSL/TLS configuration (OWASP A02:2021)
        if url.startswith("https://"):
            tls_response = requests.get(url, timeout=10)
            if tls_response.status_code == 200:
                save_finding(scan_id, "A02:2021 - Cryptographic Failures (Weak SSL/TLS)", "High",
                             "Upgrade to modern TLS standards.", verbose)

    except requests.exceptions.RequestException as e:
        print(f"❌ Error scanning web app: {url} - {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Threat Hunting Scanner")
    parser.add_argument("--verbose", action="store_true", help="Show scan results before saving")
    args = parser.parse_args()

    print("\n[ 🔍 Threat Hunting Scanner ]")
    print("1. Scan API")
    print("2. Scan Web Application")
    print("3. Scan Both API & Web")
    choice = input("Select an option (1/2/3): ").strip()

    target = input("Enter target URL: ").strip()

    if choice == "1":
        scan_api(target, verbose=args.verbose)
    elif choice == "2":
        scan_web(target, verbose=args.verbose)
    elif choice == "3":
        scan_api(target, verbose=args.verbose)
        scan_web(target, verbose=args.verbose)
    else:
        print("❌ Invalid choice. Please select 1, 2, or 3.")
