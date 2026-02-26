# EduSec: Academic Web Vulnerability Scanner 🛡️

A Python-based, advanced web vulnerability scanner engineered for academic research, security auditing, and ethical hacking education. This tool demonstrates clean software architecture (OOP) while detecting common security misconfigurations and vulnerabilities.

---

## 🌟 Technical Highlights

This project is built using a professional-grade, modular architecture (`WebScanner` class) showcasing the following capabilities:

### 1. Advanced Vulnerability Detection
- **Smarter SQL Injection (SQLi)**: Uses iterated payload injection and response comparison against known backend database error signatures, minimizing false positives.
- **Reflected XSS Analysis**: Validates if raw payloads survive output encoding by checking `Content-Type` headers alongside payload reflection.

### 2. Infrastructure & Configuration Auditing
- **HTTP Security Header Analysis**: Scans responses for critical missing headers (e.g., `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`).
- **Endpoint & Directory Enumeration**: Performs active discovery of common hidden paths (`/admin`, `/backup`, `/.git`) using low-bandwidth `HEAD` requests.
- **TCP Port Discovery**: Multithreaded socket scanning to map the external attack surface of the host.

### 3. Professional Tool Architecture
- **Evasion & Realism**: Implements automated User-Agent rotation to simulate legitimate browser traffic and bypass basic behavioral filters.
- **Rate Limiting & Safety**: Built-in `--delay` functionality to throttle requests, preventing accidental Denial of Service (DoS) during testing.
- **Structured Reporting**: Exports findings in both human-readable Text and structured JSON formats, enabling easy integration into automated pipelines.
- **Extensible CLI**: Powered by `argparse`, allowing granular control over which scanning modules to execute.

---

## 🚀 Usage Guide

### Installation
Ensure Python 3.x is installed, then install the required `requests` library:
```bash
pip install requests
```

### Command Line Interface (CLI)

The tool provides a modular CLI interface mimicking enterprise scanners. Use `-h` or `--help` to view all options:

```bash
python scanner.py -h
```

**Examples:**

1. **Full Academic Audit (Default)**
   *Runs all modules with default 1-second request delays and outputs a text summary.*
   ```bash
   python scanner.py http://example.com --all
   ```

2. **Targeted Reconnaissance (Headers & Endpoints only)**
   ```bash
   python scanner.py http://example.com --headers --enum
   ```

3. **Intensive Vulnerability Scan with Custom Rate Limiting & JSON Output**
   *Runs SQLi and XSS checks with a 0.5s delay, outputting results to a machine-readable JSON file.*
   ```bash
   python scanner.py http://example.com --sqli --xss --delay 0.5 --output json
   ```

---

## 💼 Resume & Interview Guide

If you are presenting this project in a portfolio or interview, here is how to frame it:

### Suggested Resume Bullet Points
*   **"Architected a scalable, Python-based security auditing tool utilizing Object-Oriented principles, capable of detecting SQL Injection, Reflected XSS, and critical security misconfigurations."**
*   **"Implemented ethical testing guardrails (rate limiting) and evasion techniques (User-Agent rotation) to enable safe, non-disruptive security assessments."**
*   **"Designed an extensible JSON reporting engine to facilitate automated pipeline integration (e.g., SIEM ingestion, Blockchain Audit Logging)."**

### Interview Talking Points
1. **Why Python?**: Contrast Python's rapid prototyping capabilities (built-in `socket` and `urllib` libraries + the powerful `requests` ecosystem) against heavier languages.
2. **Handling False Positives**: Explain how you refined the XSS checker to verify the `Content-Type: text/html` header—ensuring that payloads returned in JSON APIs aren't incorrectly flagged as executable XSS by a browser.
3. **The Importance of JSON Output**: Discuss how modern security is about the "pipeline." Exporting JSON allows the scan results to be cryptographically hashed and stored on a Blockchain or ingested into a SIEM (like Splunk) for immutable auditing.

---

## ⚠️ Academic Disclaimer

**WARNING: ACADEMIC SECURITY RESEARCH TOOL**

This tool is strictly for educational and authorized testing purposes only. The developer assumes no liability and is not responsible for any misuse, damage, or legal consequences caused by its usage. 

Always ensure you have explicit, written consent from the owner before scanning any network, application, or system. Unauthorized network scanning is a severe criminal offense.

