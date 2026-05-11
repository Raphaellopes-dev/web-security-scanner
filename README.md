
                          _ _   _                   ____
                         | | | (_)                 / ___|___ _ __  ___  ___ _ __  ___
                    __ _ | | |_ _  ___  _ __       | |   / __| '_ \/ __|/ _ \ '_ \/ __|
                   / _` || | __| |/ _ \| '_ \      | |__| (__| | | \__ \  __/ | | \__ \
                  | (_| || | |_| | (_) | | | |      \____\___|_| |_|___/\___|_| |_|___/
                   \__,_|_|\__|_|\___/|_| |_|

                    Web Security Scanner — CLI Security Analysis Tool


```

Web Security Scanner
====================

A professional command-line web security scanner that performs basic security
assessments on web applications. It checks security headers, SSL/TLS
certificates, reflected XSS, SQL injection indicators, open ports, and HTML
form detection.

Features
--------

- **Security Headers Analysis** — Checks for X-XSS-Protection, Content-Security-Policy,
  Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, and more.
- **SSL/TLS Certificate Validation** — Verifies certificate validity, issuer, and
  expiration dates.
- **Reflected XSS Detection** — Injects benign payloads into URL parameters and
  checks if they appear unsanitized in the response.
- **SQL Injection (Error-Based) Detection** — Injects common SQLi payloads and
  looks for database error messages in the response.
- **Open Port Scan** — Checks common web ports (80, 443, 8080, 8443) on the
  target host.
- **Form Detection** — Parses HTML responses and lists all `<form>` elements
  with their actions, methods, and input fields.
- **HTML Report Generation** — Produces a styled HTML report with all findings
  organized by category.
- **Colorized Terminal Output** — Clear, color-coded console output using
  colorama.

Installation
------------

```bash
# Clone or copy the project
cd web-security-scanner

# Install dependencies
pip install -r requirements.txt
```

Requires Python 3.7+.

Usage
-----

### Full scan

```bash
python main.py scan https://example.com
```

### Full scan with HTML report

```bash
python main.py scan https://example.com --output report.html
```

### Headers-only check

```bash
python main.py headers https://example.com
```

### Help

```bash
python main.py --help
```

Example Output
--------------

```
[•] Scanning target: https://example.com
[•] Checking security headers...
    [✓] X-XSS-Protection: 1; mode=block
    [✗] Content-Security-Policy: MISSING
[•] Checking SSL/TLS certificate...
    [✓] Certificate valid (expires 2026-06-01)
[•] Testing XSS vulnerabilities...
    [✓] No reflected XSS detected
...
```

Ethical Disclaimer
------------------

**This tool is intended for authorized security assessments only.** You must
have explicit permission from the target owner before scanning any web
application. Unauthorised scanning may violate computer fraud and abuse laws,
privacy regulations, and the target's terms of service.

The authors are not responsible for any misuse or damage caused by this tool.
Use responsibly and at your own risk.
