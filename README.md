# Beginner-Friendly Web Vulnerability Scanner 🛡️

A flexible, Python-based web vulnerability scanner designed to detect common security flaws and open ports. Built for educational purposes, this tool provides clear, actionable explanations of each vulnerability type as it scans, making it a great learning resource and an excellent addition to a cybersecurity portfolio.

## Key Features ✨

- **SQL Injection (SQLi) Detection**: Tests for basic SQLi vulnerabilities by injecting common payloads and analyzing webpage responses for database syntax errors.
- **Cross-Site Scripting (XSS) Checks**: Scans for reflected XSS by injecting test scripts into URL parameters and checking if the resulting HTML reflects the unescaped script.
- **Port Scanning**: Performs a customized TCP port scan to identify open common service ports (e.g., 80, 443, 22, 21), highlighting potential attack surfaces.
- **Educational Explanations**: Prints out clear, contextual explanations of each vulnerability type when found during the scan.
- **Actionable Summary**: Generates a clean, easy-to-read recruiter-friendly summary at the end of every scan detailing overall findings.
- **Comprehensive Logging**: Automatically logs all scan activities and results to a local `scan_report.txt` file (designed for easy integration with external Audit Loggers, like a Blockchain Immutable Logger).
- **CLI Support (`argparse`)**: Run specific scanning modules using command-line arguments to demonstrate tool-like architecture.

---

## 🚀 Getting Started

### Prerequisites

Ensure you have Python 3.x installed on your system.
Install the required HTTP library (`requests`):

```bash
pip install requests
```

### Usage

You can run the script in interactive mode or utilize the command-line interface (CLI) to specify which scans to perform.

#### Interactive Mode
If you run the script directly, it will prompt you for the target URL and automatically run all available scans:

```bash
python scanner.py
```

#### CLI Mode
Use command-line flags to target specific vulnerability checks. This enables automated scripting and tight integration with other cybersecurity tools:

```bash
# Display the help menu
python scanner.py --help

# Run ALL scans against a specific target
python scanner.py http://example.com --all

# Run ONLY the SQL Injection module
python scanner.py http://example.com --sqli

# Run both the XSS module and the Port Scanner
python scanner.py http://example.com --xss --ports
```

---

## 📝 Example Output

When running a complete scan, the terminal will display real-time progress, educational insights, and conclude with a concise summary:

```text
==================================================
WARNING: This tool is for educational and authorized 
testing only. Unauthorized scanning is illegal.
==================================================
...
[+] Vulnerability Found: Potential Cross-Site Scripting (XSS)!
    Payload used: <script>alert('XSS_Test')</script>
    Target URL: http://testphp.vulnweb.com?q=<script>alert('XSS_Test')</script>

[!] Cross-Site Scripting (XSS) Alert!
Explanation: XSS happens when a web application includes untrusted user data...
...
==================================================
                 Scan Summary                     
==================================================
- SQL Injection: Not Detected
- XSS: Detected
- Open Ports: 25, 80, 110

[i] Full report saved to 'scan_report.txt'
```

---

## 📁 File Structure

- `scanner.py`: The main Python script containing the scanning logic and CLI setup.
- `scan_report.txt`: (Auto-generated) The immutable local text log where all scans and findings are appended and recorded.

---

## ⚠️ Disclaimer

**This tool is strictly for educational and authorized testing purposes only.** 
The creator of this tool assumes no liability and is not responsible for any misuse, damage, or legal consequences caused by its usage. Always ensure you have explicit written permission before scanning any website, server, or network that you do not own.

*Unauthorized network scanning and exploitation is a severe criminal offense.*
