"""Core scanner module for web security analysis."""

import socket
import ssl
import re
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

import requests


SECURITY_HEADERS = {
    "X-XSS-Protection": "Cross-Site Scripting (XSS) filter",
    "Content-Security-Policy": "Content Security Policy",
    "Strict-Transport-Security": "HTTP Strict Transport Security (HSTS)",
    "X-Frame-Options": "Clickjacking protection",
    "X-Content-Type-Options": "MIME-type sniffing protection",
    "Referrer-Policy": "Referrer information control",
    "Permissions-Policy": "Browser feature permissions",
    "Set-Cookie": "Secure/HttpOnly cookie flags (presence check)",
}

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><script>alert(1)</script>",
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "\" OR \"1\"=\"1",
    "' UNION SELECT NULL--",
    "1; DROP TABLE users--",
]

SQLI_ERROR_PATTERNS = [
    re.compile(r"sql syntax.*mysql", re.IGNORECASE),
    re.compile(r"warning.*mysql", re.IGNORECASE),
    re.compile(r"you have an error in your sql", re.IGNORECASE),
    re.compile(r"unclosed quotation mark", re.IGNORECASE),
    re.compile(r"quoted string not properly terminated", re.IGNORECASE),
    re.compile(r"division by zero.*sql", re.IGNORECASE),
    re.compile(r"unknown column", re.IGNORECASE),
    re.compile(r"pg_query", re.IGNORECASE),
    re.compile(r"sqlite.*error", re.IGNORECASE),
]

COMMON_PORTS = [80, 443, 8080, 8443]

TIMEOUT = 10


class ScanResult:
    """Holds all findings from a security scan."""

    def __init__(self, target_url: str):
        self.target_url = target_url
        self.headers_check: list[dict] = []
        self.ssl_info: dict | None = None
        self.xss_findings: list[dict] = []
        self.sqli_findings: list[dict] = []
        self.open_ports: list[dict] = []
        self.forms: list[dict] = []
        self.errors: list[str] = []


class WebScanner:
    """Main scanner that performs security checks against a target URL."""

    def __init__(self, timeout: int = TIMEOUT):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": (
                    "WebSecurityScanner/1.0 "
                    "(Security Research Tool; +https://example.com)"
                ),
            }
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, url: str) -> ScanResult:
        """Run a full scan against *url* and return a ScanResult."""
        result = ScanResult(url)
        self._check_headers(url, result)
        self._check_ssl(url, result)
        self._check_xss(url, result)
        self._check_sqli(url, result)
        self._scan_ports(url, result)
        self._detect_forms(url, result)
        return result

    def check_headers_only(self, url: str) -> ScanResult:
        """Only check security headers."""
        result = ScanResult(url)
        self._check_headers(url, result)
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get(self, url: str) -> requests.Response | None:
        try:
            resp = self.session.get(url, timeout=self.timeout)
            return resp
        except requests.RequestException as exc:
            return None

    def _check_headers(self, url: str, result: ScanResult) -> None:
        resp = self._get(url)
        if resp is None:
            result.errors.append(f"Failed to reach {url} for header check")
            return

        for header, description in SECURITY_HEADERS.items():
            value = resp.headers.get(header)
            finding = {
                "header": header,
                "description": description,
                "present": value is not None,
                "value": value or "MISSING",
            }
            result.headers_check.append(finding)

    def _check_ssl(self, url: str, result: ScanResult) -> None:
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or 443

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

                    issued_to = cert.get("subject", [])
                    cn = ""
                    for part in issued_to:
                        for key, val in part:
                            if key == "commonName":
                                cn = val

                    issuer = cert.get("issuer", [])
                    issuer_name = ""
                    for part in issuer:
                        for key, val in part:
                            if key == "organizationName":
                                issuer_name = val

                    not_before = cert.get("notBefore", "")
                    not_after = cert.get("notAfter", "")

                    def _parse_asn1_time(t: str) -> str:
                        try:
                            parsed_time = datetime.strptime(t, "%b %d %H:%M:%S %Y %Z")
                            return parsed_time.strftime("%Y-%m-%d %H:%M:%S")
                        except ValueError:
                            return t

                    result.ssl_info = {
                        "hostname": hostname,
                        "port": port,
                        "subject_cn": cn,
                        "issuer": issuer_name,
                        "valid_from": _parse_asn1_time(not_before),
                        "valid_until": _parse_asn1_time(not_after),
                        "valid": True,
                    }
        except Exception as exc:
            result.ssl_info = {
                "hostname": hostname,
                "port": port,
                "error": str(exc),
                "valid": False,
            }

    def _check_xss(self, url: str, result: ScanResult) -> None:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)

        if not query_params:
            # If no existing params, inject a dummy one
            for payload in XSS_PAYLOADS:
                test_url = f"{url}?q={requests.utils.quote(payload)}"
                resp = self._get(test_url)
                if resp is None:
                    continue
                reflected = payload in resp.text
                if reflected:
                    result.xss_findings.append(
                        {"url": test_url, "payload": payload, "reflected": reflected}
                    )
            return

        for param in query_params:
            for payload in XSS_PAYLOADS:
                new_params = query_params.copy()
                new_params[param] = [payload]
                new_query = urlencode(new_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                resp = self._get(test_url)
                if resp is None:
                    continue
                reflected = payload in resp.text
                if reflected:
                    result.xss_findings.append(
                        {"url": test_url, "param": param, "payload": payload, "reflected": True}
                    )

    def _check_sqli(self, url: str, result: ScanResult) -> None:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)

        if not query_params:
            for payload in SQLI_PAYLOADS:
                test_url = f"{url}?id={requests.utils.quote(payload)}"
                resp = self._get(test_url)
                if resp is None:
                    continue
                for pattern in SQLI_ERROR_PATTERNS:
                    if pattern.search(resp.text):
                        result.sqli_findings.append(
                            {
                                "url": test_url,
                                "payload": payload,
                                "pattern": pattern.pattern,
                            }
                        )
                        break
            return

        for param in query_params:
            for payload in SQLI_PAYLOADS:
                new_params = query_params.copy()
                new_params[param] = [payload]
                new_query = urlencode(new_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                resp = self._get(test_url)
                if resp is None:
                    continue
                for pattern in SQLI_ERROR_PATTERNS:
                    if pattern.search(resp.text):
                        result.sqli_findings.append(
                            {
                                "url": test_url,
                                "param": param,
                                "payload": payload,
                                "pattern": pattern.pattern,
                            }
                        )
                        break

    def _scan_ports(self, url: str, result: ScanResult) -> None:
        hostname = urlparse(url).hostname
        for port in COMMON_PORTS:
            sock = None
            try:
                sock = socket.create_connection((hostname, port), timeout=2)
                result.open_ports.append({"port": port, "state": "open"})
            except (socket.timeout, ConnectionRefusedError, OSError):
                result.open_ports.append({"port": port, "state": "closed"})
            finally:
                if sock:
                    sock.close()

    def _detect_forms(self, url: str, result: ScanResult) -> None:
        resp = self._get(url)
        if resp is None:
            return

        html = resp.text
        form_pattern = re.compile(
            r"<form\s[^>]*action\s*=\s*[\"']([^\"']*)[\"'][^>]*>",
            re.IGNORECASE,
        )
        input_pattern = re.compile(
            r"<input\s[^>]*name\s*=\s*[\"']([^\"']*)[\"'][^>]*>",
            re.IGNORECASE,
        )
        method_pattern = re.compile(
            r"<form\s[^>]*method\s*=\s*[\"']([^\"']*)[\"'][^>]*>",
            re.IGNORECASE,
        )

        forms_raw = re.findall(r"(<form\s[^>]*>.*?</form>)", html, re.IGNORECASE | re.DOTALL)
        for form_html in forms_raw:
            action_match = form_pattern.search(form_html)
            method_match = method_pattern.search(form_html)
            action = action_match.group(1) if action_match else "(none)"
            method = method_match.group(1).upper() if method_match else "GET"
            inputs = [m.group(1) for m in input_pattern.finditer(form_html)]

            full_action = urljoin(url, action)

            result.forms.append(
                {
                    "action": full_action,
                    "method": method,
                    "inputs": inputs,
                }
            )
