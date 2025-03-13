import sqlite3
import requests
from bs4 import BeautifulSoup

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

def save_finding(scan_id, vulnerability, severity, recommendation):
    """Save scan findings to the database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO findings (scan_id, vulnerability, severity, recommendation)
        VALUES (?, ?, ?, ?)
    """, (scan_id, vulnerability, severity, recommendation))
    conn.commit()
    conn.close()

def scan_api(url):
    """Scan an API for security issues."""
    scan_id = save_scan(url, "API")

    try:
        response = requests.get(url, timeout=10)  # Enforcing SSL verification
        if response.status_code == 200:
            save_finding(scan_id, "Open API Endpoint", "High", "Restrict access with authentication.")

        # Check CORS misconfiguration
        if "Access-Control-Allow-Origin" in response.headers and response.headers["Access-Control-Allow-Origin"] == "*":
            save_finding(scan_id, "CORS Misconfiguration", "Medium", "Restrict CORS to trusted domains.")

        # Check HTTP methods
        for method in ["PUT", "DELETE", "OPTIONS"]:
            method_response = requests.request(method, url, timeout=10)
            if method_response.status_code in [200, 201, 202]:
                save_finding(scan_id, f"Unrestricted {method} Method", "High", f"Restrict {method} to authorized users.")

    except requests.exceptions.RequestException as e:
        print(f"❌ Error scanning API: {url} - {e}")

def scan_web(url):
    """Scan a web app for security issues."""
    scan_id = save_scan(url, "Web")

    try:
        response = requests.get(url, timeout=10)  # Enforcing SSL verification
        soup = BeautifulSoup(response.text, "html.parser")

        # Check for missing security headers
        headers = response.headers
        missing_headers = [h for h in ["Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security"] if h not in headers]
        if missing_headers:
            save_finding(scan_id, "Missing Security Headers", "Medium", f"Add {', '.join(missing_headers)}.")

        # Check for directory listing
        if "Index of" in soup.text:
            save_finding(scan_id, "Directory Listing Enabled", "High", "Disable directory listing.")

        # Check for default login pages
        common_admin_pages = ["/admin", "/login", "/wp-admin", "/phpmyadmin"]
        for page in common_admin_pages:
            admin_response = requests.get(url + page, timeout=10)
            if admin_response.status_code == 200:
                save_finding(scan_id, f"Default Login Page Found: {page}", "Medium", "Restrict admin page access.")

        # Check for weak SSL/TLS (only works on HTTPS)
        if url.startswith("https://"):
            tls_response = requests.get(url, timeout=10)
            if tls_response.status_code == 200:
                save_finding(scan_id, "Weak SSL/TLS Configuration", "High", "Upgrade to modern TLS standards.")

    except requests.exceptions.RequestException as e:
        print(f"❌ Error scanning web app: {url} - {e}")

if __name__ == "__main__":
    print("\n[ 🔍 Threat Hunting Scanner ]")
    print("1. Scan API")
    print("2. Scan Web Application")
    print("3. Scan Both API & Web")
    choice = input("Select an option (1/2/3): ").strip()

    target = input("Enter target URL: ").strip()

    if choice == "1":
        scan_api(target)
    elif choice == "2":
        scan_web(target)
    elif choice == "3":
        scan_api(target)
        scan_web(target)
    else:
        print("❌ Invalid choice. Please select 1, 2, or 3.")
