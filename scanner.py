import argparse
import requests
import socket
from urllib.parse import urlparse
import datetime

# --- Vulnerability Explanations ---
SQLI_EXPLANATION = """
[!] SQL Injection (SQLi) Alert!
Explanation: SQL Injection occurs when user input is improperly sanitized before being used 
in a database query. An attacker can input special characters (like quotes) to manipulate 
the query. This could allow them to bypass authentication, access sensitive database information, 
or modify/delete data.
"""

XSS_EXPLANATION = """
[!] Cross-Site Scripting (XSS) Alert!
Explanation: XSS happens when a web application includes untrusted user data in a web page 
without proper validation or escaping. This allows an attacker to inject and execute malicious 
scripts (like JavaScript) in the browser of anyone visiting the compromised page. Attackers 
use this to steal session cookies, deface websites, or redirect users.
"""

PORT_EXPLANATION = """
[*] Port Scanning Context:
Explanation: A port scan checks which network ports are actively listening on a server. 
Open ports indicate running services (e.g., port 80 for normal web traffic, 22 for SSH). 
While web servers need certain ports open, any unnecessary open port increases the "attack surface". 
Hackers often scan for open ports to find outdated or misconfigured services to exploit.
"""

DISCLAIMER = """
==================================================
WARNING: This tool is for educational and authorized 
testing only. Unauthorized scanning is illegal.
==================================================
"""

def log_finding(message):
    """Appends a message to the scan report log."""
    with open("scan_report.txt", "a", encoding="utf-8") as f:
        f.write(message + "\n")

def scan_sql_injection(url):
    """
    Checks for basic SQL Injection vulnerabilities by appending SQL payloads 
    to the URL and checking the webpage response for database error messages.
    """
    print(f"\n[*] Starting SQL Injection scan on: {url}")
    
    # A list of simple SQL injection test payloads
    payloads = [
        "'", 
        "\"", 
        "1' OR '1'='1", 
        "1\" OR \"1\"=\"1"
    ]
    
    # Common database error strings that might leak when a query breaks
    errors = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated",
        "sql syntax error"
    ]
    
    is_vulnerable = False
    
    for payload in payloads:
        # If the URL already has parameters (contains '?'), append the payload.
        # Otherwise, add a dummy parameter '?id=' to test the payload against.
        if "?" in url:
            target_url = f"{url}{payload}"
        else:
            target_url = f"{url}?id={payload}"
            
        try:
            # Send a GET request to the target URL with the payload
            response = requests.get(target_url, timeout=5)
            
            # Check if any common SQL error text appears in the response HTML
            for error in errors:
                if error.lower() in response.text.lower():
                    print(f"\n[+] Vulnerability Found: Potential SQL Injection!")
                    print(f"    Payload used: {payload}")
                    print(f"    Target URL: {target_url}")
                    print(SQLI_EXPLANATION)
                    log_finding(f"[!] SQLi Detected with payload: {payload}")
                    is_vulnerable = True
                    return True # Stop after finding the first one to avoid spam
                    
        except requests.exceptions.RequestException as e:
            print(f"[-] Error connecting to {target_url}: {e}")
            break # Stop trying payloads if the connection fails entirely
            
    if not is_vulnerable:
        print("[-] No basic SQL Injection vulnerabilities found.")
    return False

def scan_xss(url):
    """
    Checks for basic Reflected Cross-Site Scripting (XSS) vulnerabilities by 
    injecting a dummy script payload and checking if it's reflected directly in the HTML.
    """
    print(f"\n[*] Starting XSS scan on: {url}")
    
    # A simple, relatively harmless XSS payload for testing
    payload = "<script>alert('XSS_Test')</script>"
    
    # Append the payload similarly to the SQLi check
    if "?" in url:
        target_url = f"{url}{payload}"
    else:
        target_url = f"{url}?q={payload}"
        
    try:
        response = requests.get(target_url, timeout=5)
        
        # If the exact unescaped script payload appears in the response, 
        # the page might be vulnerable to Reflected XSS.
        if payload in response.text:
            print(f"\n[+] Vulnerability Found: Potential Cross-Site Scripting (XSS)!")
            print(f"    Payload used: {payload}")
            print(f"    Target URL: {target_url}")
            print(XSS_EXPLANATION)
            log_finding(f"[!] XSS Detected with payload: {payload}")
            return True
            
    except requests.exceptions.RequestException as e:
         print(f"[-] Error connecting to {target_url}: {e}")
         
    print("[-] No basic XSS vulnerabilities found.")
    return False

def scan_ports(target_url):
    """
    Performs a basic TCP port scan using Python sockets on common service ports.
    """
    print(f"\n[*] Starting Port Scan...")
    print(PORT_EXPLANATION)
    
    # Extract just the hostname from the URL (e.g., 'http://example.com/page' -> 'example.com')
    parsed_url = urlparse(target_url)
    hostname = parsed_url.hostname or target_url 
    hostname = hostname.replace("http://", "").replace("https://", "")
    
    # A list of common ports to check
    # 21: FTP, 22: SSH, 23: Telnet, 25: SMTP, 53: DNS, 80: HTTP, 110: POP3, 443: HTTPS, 3306: MySQL
    ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 443, 3306, 8080]
    open_ports = []
    
    try:
        # Resolve the human-readable hostname to an IP address
        target_ip = socket.gethostbyname(hostname)
        print(f"[*] Resolved {hostname} to IP: {target_ip}")
    except socket.gaierror:
        print(f"[-] Error: Could not resolve hostname '{hostname}' to an IP address.")
        return open_ports

    for port in ports_to_scan:
        # Create a new socket for each connection attempt using IPv4 (AF_INET) and TCP (SOCK_STREAM)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1) # Fast 1-second timeout so the scan doesn't take forever
        
        try:
            # connect_ex returns 0 if the connection was successful (port open), 
            # and an error indicator otherwise (port closed or filtered)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                print(f"[+] Port {port:<4} is OPEN")
                open_ports.append(port)
            else:
                print(f"[-] Port {port:<4} is CLOSED")
        except socket.error:
            print(f"[-] Port {port:<4} encountered an error.")
        finally:
            sock.close() # Always close the socket to free up resources
        
    if open_ports:
        print(f"\n[!] Warning: Found {len(open_ports)} open port(s).")
        print("    Ensure these services are properly secured and actively maintained.")
    else:
        print("\n[+] All scanned common ports appear to be closed or filtered.")
        
    return open_ports

def main():
    """
    Main program loop. Gathers user input and calls the scanning functions.
    """
    print(DISCLAIMER)
    print("==================================================")
    print("      Beginner-Friendly Web Scanner Project       ")
    print("==================================================\n")
    
    # Setup CLI argument parsing
    parser = argparse.ArgumentParser(description="Basic Web Vulnerability Scanner")
    parser.add_argument("url", nargs="?", help="Target URL to scan (e.g., http://example.com)")
    parser.add_argument("--sqli", action="store_true", help="Scan for SQL Injection")
    parser.add_argument("--xss", action="store_true", help="Scan for Cross-Site Scripting (XSS)")
    parser.add_argument("--ports", action="store_true", help="Scan common open ports")
    parser.add_argument("--all", action="store_true", help="Run all scans (default if no specific flags used)")
    
    args = parser.parse_args()
    
    # Get target from args or prompt the user if not provided
    target = args.url
    if not target:
        target = input("Enter the target URL (e.g., http://testphp.vulnweb.com): ").strip()
    
    # Basic input validation to ensure a protocol is present
    if not target.startswith("http://") and not target.startswith("https://"):
        print("[*] Notice: Missing protocol. Automatically adding 'http://'")
        target = "http://" + target
        
    print(f"\n[*] Target registered: {target}")
    
    # Determine which scans to run
    # If no specific scan block is requested, run all of them
    run_all = args.all or not (args.sqli or args.xss or args.ports)
    
    # Initialize findings dictionary
    findings = {
        "sqli": False,
        "xss": False,
        "open_ports": []
    }
    
    print("[*] Initiating scan sequence...")
    log_finding(f"\n--- New Scan Started: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---")
    log_finding(f"Target: {target}")
    
    # Execute the individual scanning modules based on flags
    if args.sqli or run_all:
        findings["sqli"] = scan_sql_injection(target)
        
    if args.xss or run_all:
        findings["xss"] = scan_xss(target)
        
    if args.ports or run_all:
        findings["open_ports"] = scan_ports(target)
    
    # --- Print and Log Summary ---
    print("\n==================================================")
    print("                 Scan Summary                     ")
    print("==================================================")
    
    sqli_status = "Detected" if findings["sqli"] else "Not Detected"
    xss_status = "Detected" if findings["xss"] else "Not Detected"
    ports_status = ", ".join(map(str, findings["open_ports"])) if findings["open_ports"] else "None"
    
    print(f"- SQL Injection: {sqli_status}")
    print(f"- XSS: {xss_status}")
    print(f"- Open Ports: {ports_status}")
    
    log_finding("\nScan Summary:")
    log_finding(f"- SQL Injection: {sqli_status}")
    log_finding(f"- XSS: {xss_status}")
    log_finding(f"- Open Ports: {ports_status}")
    log_finding("--- Scan Complete ---\n")
    
    print("\n[i] Full report saved to 'scan_report.txt'")
    print("==================================================")

if __name__ == "__main__":
    main()
