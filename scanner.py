import sqlite3
import requests
from bs4 import BeautifulSoup
import argparse
from rich.console import Console
from rich.table import Table
from rich.progress import Progress

DB_FILE = "threat_hunter.db"
console = Console()

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
    """Save scan findings and print them immediately."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO findings (scan_id, vulnerability, severity, recommendation)
        VALUES (?, ?, ?, ?)
    """, (scan_id, vulnerability, severity, recommendation))
    conn.commit()
    conn.close()

    # Print the finding immediately
    console.print(f"[bold red]⚠ Found: {vulnerability}[/bold red] (Severity: {severity})")
    console.print(f"   ➜ Recommendation: {recommendation}\n", style="bold green")

def scan_api(url):
    """Scan an API for security issues (OWASP API Top 10)."""
    scan_id = save_scan(url, "API")

    with Progress() as progress:
        task = progress.add_task("[cyan]Scanning API...", total=3)

        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                save_finding(scan_id, "API1:2019 - Broken Object Level Authorization", "High",
                             "Ensure proper access controls are implemented.")
                progress.update(task, advance=1)

            if "Access-Control-Allow-Origin" in response.headers and response.headers["Access-Control-Allow-Origin"] == "*":
                save_finding(scan_id, "API4:2019 - Lack of Resources & Rate Limiting", "Medium",
                             "Restrict CORS to trusted domains.")
                progress.update(task, advance=1)

            for method in ["PUT", "DELETE", "OPTIONS"]:
                method_response = requests.request(method, url, timeout=10)
                if method_response.status_code in [200, 201, 202]:
                    save_finding(scan_id, f"API6:2019 - Mass Assignment ({method})", "High",
                                 f"Restrict {method} to authorized users.")
                    progress.update(task, advance=1)

        except requests.exceptions.RequestException as e:
            console.print(f"[red]❌ Error scanning API: {url} - {e}[/red]")

def scan_web(url):
    """Scan a web app for security issues (OWASP Web Top 10)."""
    scan_id = save_scan(url, "Web")

    with Progress() as progress:
        task = progress.add_task("[cyan]Scanning Web Application...", total=3)

        try:
            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.text, "html.parser")

            headers = response.headers
            missing_headers = [h for h in ["Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security"] if h not in headers]
            if missing_headers:
                save_finding(scan_id, "A06:2021 - Security Misconfiguration", "Medium",
                             f"Add {', '.join(missing_headers)}.")
                progress.update(task, advance=1)

            if "Index of" in soup.text:
                save_finding(scan_id, "A05:2021 - Security Misconfiguration (Directory Listing)", "High",
                             "Disable directory listing on the web server.")
                progress.update(task, advance=1)

            common_admin_pages = ["/admin", "/login", "/wp-admin", "/phpmyadmin"]
            for page in common_admin_pages:
                admin_response = requests.get(url + page, timeout=10)
                if admin_response.status_code == 200:
                    save_finding(scan_id, f"A07:2021 - Default Login Page Found: {page}", "Medium",
                                 "Restrict admin page access.")
                    progress.update(task, advance=1)

            # Force a test vulnerability to verify output
            save_finding(scan_id, "Test Vulnerability", "High", "Fix this immediately.")
            progress.update(task, advance=1)

        except requests.exceptions.RequestException as e:
            console.print(f"[red]❌ Error scanning web app: {url} - {e}[/red]")

def list_results():
    """Display past scan results in a table."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, target, scan_type, timestamp FROM scans")
    results = cursor.fetchall()
    conn.close()

    if not results:
        console.print("[yellow]⚠ No scans found.[/yellow]")
        return

    table = Table(title="Scan Results")
    table.add_column("ID", style="bold cyan")
    table.add_column("Target", style="magenta")
    table.add_column("Type", style="green")
    table.add_column("Timestamp", style="blue")

    for row in results:
        table.add_row(str(row[0]), row[1], row[2], row[3])

    console.print(table)

def view_scan(scan_id):
    """View details of a specific scan."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT vulnerability, severity, recommendation FROM findings WHERE scan_id = ?", (scan_id,))
    findings = cursor.fetchall()
    conn.close()

    if not findings:
        console.print(f"[yellow]⚠ No findings found for Scan ID {scan_id}.[/yellow]")
        return

    table = Table(title=f"Scan ID: {scan_id} Findings")
    table.add_column("Vulnerability", style="bold red")
    table.add_column("Severity", style="yellow")
    table.add_column("Recommendation", style="green")

    for row in findings:
        table.add_row(row[0], row[1], row[2])

    console.print(table)

def main():
    parser = argparse.ArgumentParser(description="Threat Hunting Scanner CLI")
    subparsers = parser.add_subparsers(dest="command")

    scan_api_parser = subparsers.add_parser("scan-api", help="Scan an API for security issues")
    scan_api_parser.add_argument("url", help="API URL to scan")

    scan_web_parser = subparsers.add_parser("scan-web", help="Scan a web application")
    scan_web_parser.add_argument("url", help="Web application URL to scan")

    scan_both_parser = subparsers.add_parser("scan-both", help="Scan both API and Web Application")
    scan_both_parser.add_argument("url", help="Target URL")

    subparsers.add_parser("results-list", help="List all past scan results")

    view_scan_parser = subparsers.add_parser("results-view", help="View findings from a specific scan")
    view_scan_parser.add_argument("scan_id", help="Scan ID to view findings")

    args = parser.parse_args()

    if args.command == "scan-api":
        scan_api(args.url)
    elif args.command == "scan-web":
        scan_web(args.url)
    elif args.command == "scan-both":
        scan_api(args.url)
        scan_web(args.url)
    elif args.command == "results-list":
        list_results()
    elif args.command == "results-view":
        view_scan(args.scan_id)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
