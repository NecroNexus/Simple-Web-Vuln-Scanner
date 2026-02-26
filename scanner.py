import argparse
import requests
import socket
from urllib.parse import urlparse, urljoin
import datetime
import json
import time
import random
import sys

# ==============================================================================
# EDUCATIONAL DISCLAIMER
# ==============================================================================
DISCLAIMER = """
====================================================================
[!] WARNING: ACADEMIC SECURITY RESEARCH TOOL
This tool is explicitly designed for educational purposes and 
authorized security auditing prior to production deployment.
Unauthorized scanning of systems without explicit, written 
consent is strictly illegal. The developer assumes no 
liability for misuse.
====================================================================
"""

# ==============================================================================
# VULNERABILITY CONTEXT & EXPLANATIONS (Educational Component)
# ==============================================================================
EXPLANATIONS = {
    "SQLI": """
[!] SQL Injection (SQLi)
Explanation: SQLi occurs when untrusted user input alters the backend database query.
Risk Level: CRITICAL. Can lead to authentication bypass, data exfiltration, or data loss.
Remediation: Use parameterized queries (Prepared Statements) or ORMs. Never concatenate input.
""",
    "XSS": """
[!] Reflected Cross-Site Scripting (XSS)
Explanation: XSS occurs when user input is reflected in the web page without sanitization.
Risk Level: HIGH. Can lead to session hijacking, defacement, or malicious redirects.
Remediation: Context-aware output encoding. Sanitize all input before rendering in HTML/JS.
""",
    "PORTS": """
[*] Open Port Discovery
Explanation: Open ports represent active services listening for connections.
Risk Level: INFO to HIGH (depending on the service). Unnecessary open ports increase the attack surface.
Remediation: Close unused ports via firewall (e.g., iptables, UFW) and restrict access to management ports.
""",
    "HEADERS": """
[*] Missing Security Headers
Explanation: HTTP Security Headers instruct the browser on how to behave securely.
Risk Level: MEDIUM. Absence can facilitate XSS, clickjacking, and MITM attacks.
Remediation: Configure the web server (Nginx/Apache) to include headers like CSP, HSTS, and X-Frame-Options.
"""
}

# ==============================================================================
# CONFIGURATION & CONSTANTS
# ==============================================================================
COMMON_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.79 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "EduSec-Scanner/1.0 (Academic Project; +https://github.com/student/edusec)"
]

SQLI_PAYLOADS = [
    "'", '"', "1' OR '1'='1", "1\" OR \"1\"=\"1", "') OR ('1'='1", "admin' --"
]
SQLI_ERRORS = [
    "you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark",
    "quoted string not properly terminated", "sql syntax error", "ora-00933",
    "postgresql query failed", "sqlite3.operationalerror"
]

XSS_PAYLOADS = [
    "<script>alert('XSS_Test')</script>",
    "\"><script>alert(1)</script>",
    "<img src=x onerror=alert('XSS')>"
]

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080, 8443]

COMMON_DIRECTORIES = [
    "admin", "login", "css", "js", "images", "api", ".git", "backup", "config", "robots.txt"
]

SECURITY_HEADERS = [
    "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
    "X-Content-Type-Options", "X-XSS-Protection"
]


# ==============================================================================
# SCANNER CORE CLASS
# ==============================================================================
class WebScanner:
    def __init__(self, target_url, delay=1.0, timeout=5, severity_filter="INFO"):
        self.target_url = self._format_url(target_url)
        self.parsed_url = urlparse(self.target_url)
        self.hostname = self.parsed_url.hostname
        self.delay = delay      # Rate limiting (seconds between requests)
        self.timeout = timeout  # Request timeout
        self.severity_filter = severity_filter # Feature expansion: filter results by severity
        
        # Determine base URL without parameters for directory enum
        self.base_url = f"{self.parsed_url.scheme}://{self.hostname}{self.parsed_url.path}"
        
        self.results = {
            "target": self.target_url,
            "timestamp": datetime.datetime.now().isoformat(),
            "findings": []
        }
        
    def _format_url(self, url):
        """Ensures the URL has a valid scheme."""
        if not url.startswith(("http://", "https://")):
            print("[*] Notice: Scheme missing, defaulting to http://")
            return "http://" + url
        return url

    def _get_headers(self):
        """Rotates user agents to simulate realistic academic traffic."""
        return {"User-Agent": random.choice(COMMON_USER_AGENTS)}

    def _make_request(self, url, method="GET", allow_redirects=True):
        """Centralized request handler with rate limiting and error handling."""
        time.sleep(self.delay)  # Rate limiting
        try:
            if method == "GET":
                response = requests.get(url, headers=self._get_headers(), timeout=self.timeout, allow_redirects=allow_redirects)
            elif method == "HEAD":
                response = requests.head(url, headers=self._get_headers(), timeout=self.timeout, allow_redirects=allow_redirects)
            return response
        except requests.exceptions.RequestException as e:
            # We don't print every connection error to keep the console clean, handled by the caller.
            return None

    def log_finding(self, module, severity, title, detail, logic_explanation):
        """Records a finding with structured metadata."""
        finding = {
            "module": module,
            "severity": severity,
            "title": title,
            "detail": detail,
            "explanation": logic_explanation
        }
        self.results["findings"].append(finding)
        self.print_finding(finding)

    def print_finding(self, finding):
        """Outputs a finding cleanly to the console."""
        print(f"\n[+] [{finding['severity']}] {finding['title']}")
        print(f"    Detail: {finding['detail']}")

    # --------------------------------------------------------------------------
    # MODULES
    # --------------------------------------------------------------------------
    
    def check_security_headers(self):
        """
        Analyzes HTTP response headers for missing security configurations.
        """
        print(f"\n[*] Starting Security Header Analysis on: {self.base_url}")
        response = self._make_request(self.base_url, method="HEAD")
        
        if not response:
            print("[-] Could not connect to target to analyze headers.")
            return

        missing_headers = []
        for header in SECURITY_HEADERS:
            # Case-insensitive check for header presence
            if header.lower() not in (h.lower() for h in response.headers.keys()):
                missing_headers.append(header)
                
        if missing_headers:
            self.log_finding(
                module="Headers",
                severity="MEDIUM",
                title="Missing Security Headers",
                detail=f"Headers absent: {', '.join(missing_headers)}",
                logic_explanation=EXPLANATIONS["HEADERS"]
            )
        else:
            print("    [+] All standard security headers are present.")

    def enumerate_directories(self):
        """
        Performs basic endpoint discovery to find hidden or administrative paths.
        """
        print(f"\n[*] Starting Directory/Endpoint Enumeration (Active Scan)")
        print(f"    Base URL matching: {self.base_url}")
        
        found_dirs = []
        for d in COMMON_DIRECTORIES:
            target = urljoin(self.base_url + "/", d)
            # Use HEAD request to save bandwidth since we only care about status codes
            response = self._make_request(target, method="HEAD", allow_redirects=False)
            
            if response and response.status_code in [200, 301, 302, 401, 403]:
                found_dirs.append(f"/{d} (HTTP {response.status_code})")
                print(f"    [+] Found: {target} (Status: {response.status_code})")
                
        if found_dirs:
             self.log_finding(
                module="Enumeration",
                severity="INFO",
                title="Discovered Interesting Endpoints",
                detail=f"Found: {', '.join(found_dirs)}",
                logic_explanation="Hidden directories often contain backup files, admin panels, or configuration data left by developers."
            )
        else:
            print("    [-] No common hidden directories found.")

    def scan_sql_injection(self):
        """
        Advanced SQLi check injecting payloads and analyzing response variance.
        """
        print(f"\n[*] Starting SQL Injection Assessment on: {self.target_url}")
        
        is_vulnerable = False
        for payload in SQLI_PAYLOADS:
            # Determine injection point (existing parameter vs new dummy parameter)
            if "?" in self.target_url:
                target = f"{self.target_url}{payload}"
            else:
                target = f"{self.target_url}?id={payload}"
                
            response = self._make_request(target, method="GET")
            if not response: continue
            
            # Check for generic SQL errors reflecting back in HTML
            for err in SQLI_ERRORS:
                if err in response.text.lower():
                    self.log_finding(
                        module="SQLi",
                        severity="CRITICAL",
                        title="Potential SQL Injection Detected",
                        detail=f"Payload: {payload} | URL: {target}",
                        logic_explanation=EXPLANATIONS["SQLI"]
                    )
                    is_vulnerable = True
                    break # Stop looking at errors for this payload
            
            if is_vulnerable:
                break # Stop sending payloads if we confirmed a vulnerability

        if not is_vulnerable:
            print("    [-] No obvious SQLi vulnerabilities detected based on error reflection.")

    def scan_xss(self):
        """
        Advanced Reflected XSS check verifying if raw payloads are returned unescaped in HTML.
        """
        print(f"\n[*] Starting Reflected XSS Assessment on: {self.target_url}")
        
        is_vulnerable = False
        for payload in XSS_PAYLOADS:
            if "?" in self.target_url:
                target = f"{self.target_url}{payload}"
            else:
                target = f"{self.target_url}?search={payload}"
                
            response = self._make_request(target, method="GET")
            if not response: continue
            
            # If the exact payload appears in response AND content type is HTML
            if response.headers.get("Content-Type", "").startswith("text/html"):
                if payload in response.text:
                    self.log_finding(
                        module="XSS",
                        severity="HIGH",
                        title="Reflected Cross-Site Scripting (XSS) Detected",
                        detail=f"Payload: {payload} | URL: {target}",
                        logic_explanation=EXPLANATIONS["XSS"]
                    )
                    is_vulnerable = True
                    break # Stop testing payloads once confirmed

        if not is_vulnerable:
            print("    [-] No Reflected XSS vulnerabilities detected.")

    def scan_ports(self):
        """
        Socket-based port scanner resolving hostnames to IP addresses.
        """
        print(f"\n[*] Starting TCP Port Discovery on host: {self.hostname}")
        
        try:
            target_ip = socket.gethostbyname(self.hostname)
            print(f"    [*] Resolved {self.hostname} to IP: {target_ip}")
        except socket.gaierror:
            print(f"    [-] Error: Could not resolve hostname '{self.hostname}'")
            return

        open_ports = []
        for port in COMMON_PORTS:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5) # Fast timeout for network scans
            try:
                # 0 means connection succeeded
                if sock.connect_ex((target_ip, port)) == 0:
                    open_ports.append(port)
                    print(f"    [+] Port {port:<4} is OPEN")
            except Exception:
                pass
            finally:
                sock.close()

        if open_ports:
             self.log_finding(
                module="PortScan",
                severity="INFO",
                title="Open Network Ports Discovered",
                detail=f"Ports: {', '.join(map(str, open_ports))}",
                logic_explanation=EXPLANATIONS["PORTS"]
            )
        else:
            print("    [-] All scanned ports appear filtered/closed.")

    # --------------------------------------------------------------------------
    # REPORTING
    # --------------------------------------------------------------------------
    
    def generate_report(self, output_format="txt"):
        """Generates the scan report in either JSON or human-readable text."""
        print("\n==================================================")
        print("                 SCAN SUMMARY                     ")
        print("==================================================")
        
        if not self.results["findings"]:
            print("[+] Scan completed. No vulnerabilities detected.")
        else:
            for f in self.results["findings"]:
                print(f"- [{f['severity']}] {f['module']}: {f['title']}")
        
        # Save to file
        timestamp = datetime.datetime.now().strftime("%Y%md_%H%M%S")
        if output_format.lower() == "json":
            filename = f"scan_report_{timestamp}.json"
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(self.results, f, indent=4)
        else:
            filename = f"scan_report_{timestamp}.txt"
            with open(filename, "w", encoding="utf-8") as f:
                f.write(f"--- EDUCATIONAL SCAN REPORT ---\n")
                f.write(f"Target: {self.results['target']}\n")
                f.write(f"Time: {self.results['timestamp']}\n")
                f.write("-" * 40 + "\n")
                for finding in self.results["findings"]:
                    f.write(f"[{finding['severity']}] {finding['module']} | {finding['title']}\n")
                    f.write(f"Detail: {finding['detail']}\n")
                    f.write(f"Context: {finding['explanation'].strip()}\n")
                    f.write("-" * 40 + "\n")
                    
        print(f"\n[i] Full structured report saved to: {filename}")
        print("[i] Hint: Future extension - Map output JSON structure to a SIEM ingest format or a verifiable Blockchain Logger.")

# ==============================================================================
# CLI ENTRY POINT
# ==============================================================================
def main():
    print(DISCLAIMER)

    # Robust CLI setup with argparse showcasing professional tool design
    parser = argparse.ArgumentParser(
        description="EduSec - Academic Web Vulnerability Scanner",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument("url", nargs="?", help="Target URL (e.g., http://example.com/page.php)")
    
    # Modules
    module_group = parser.add_argument_group("Scanning Modules")
    module_group.add_argument("--sqli", action="store_true", help="Run SQL Injection analysis")
    module_group.add_argument("--xss", action="store_true", help="Run Reflected XSS analysis")
    module_group.add_argument("--ports", action="store_true", help="Run common TCP port discovery")
    module_group.add_argument("--headers", action="store_true", help="Analyze HTTP security headers")
    module_group.add_argument("--enum", action="store_true", help="Enumerate common hidden directories")
    module_group.add_argument("--all", action="store_true", help="Execute all scanning modules (default)")
    
    # Advanced Options
    options_group = parser.add_argument_group("Advanced Settings")
    options_group.add_argument("--delay", type=float, default=1.0, help="Delay between requests in seconds (Rate Limiting)")
    options_group.add_argument("--output", choices=["txt", "json"], default="txt", help="Report format (default: txt)")
    
    args = parser.parse_args()

    # Input validation
    target = args.url
    if not target:
        target = input("Enter target URL: ").strip()
        if not target:
            print("[-] Error: Target URL is required.")
            sys.exit(1)

    # Initialize the scanner using OOP principles
    scanner = WebScanner(target_url=target, delay=args.delay)
    
    print(f"[*] Target initialized: {scanner.target_url}")
    print(f"[*] Rate Limit Delay: {scanner.delay}s")
    print(f"[*] Output Format: {args.output.upper()}")
    
    # Logic to handle module selection. Default to all if none explicitly chosen
    run_all = args.all or not any([args.sqli, args.xss, args.ports, args.headers, args.enum])

    if args.headers or run_all:
        scanner.check_security_headers()
    
    if args.enum or run_all:
        scanner.enumerate_directories()
        
    if args.sqli or run_all:
        scanner.scan_sql_injection()
        
    if args.xss or run_all:
        scanner.scan_xss()
        
    if args.ports or run_all:
        scanner.scan_ports()

    # Consolidate findings
    scanner.generate_report(output_format=args.output)


if __name__ == "__main__":
    main()

