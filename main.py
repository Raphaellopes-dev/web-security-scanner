#!/usr/bin/env python3
"""CLI entry point for Web Security Scanner."""

import argparse
import sys
from pathlib import Path

from colorama import Fore, Style, init as colorama_init

from webscanner.scanner import WebScanner, ScanResult


colorama_init(autoreset=True)

PASS = Fore.GREEN + Style.BRIGHT + "[✓]" + Style.RESET_ALL
FAIL = Fore.RED + Style.BRIGHT + "[✗]" + Style.RESET_ALL
INFO = Fore.CYAN + Style.BRIGHT + "[•]" + Style.RESET_ALL
WARN = Fore.YELLOW + Style.BRIGHT + "[!]" + Style.RESET_ALL


def _print_banner() -> None:
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}
                          _ _   _                   ____
                         | | | (_)                 / ___|___ _ __  ___  ___ _ __  ___
                    __ _ | | |_ _  ___  _ __       | |   / __| '_ \/ __|/ _ \ '_ \/ __|
                   / _` || | __| |/ _ \| '_ \      | |__| (__| | | \__ \  __/ | | \__ \\
                  | (_| || | |_| | (_) | | | |      \____\___|_| |_|___/\___|_| |_|___/
                   \__,_|_|\__|_|\___/|_| |_|

                    Web Security Scanner — CLI Security Analysis Tool
{Style.RESET_ALL}"""
    print(banner)


def _print_result(result: ScanResult) -> None:
    print(f"\n{INFO} Target: {result.target_url}\n")

    # -- Headers --
    print(f"  {INFO} Security Headers")
    for h in result.headers_check:
        icon = PASS if h["present"] else FAIL
        print(f"    {icon} {h['header']}: {h['value']}")

    # -- SSL --
    print(f"\n  {INFO} SSL / TLS Certificate")
    s = result.ssl_info
    if s:
        if s.get("valid"):
            print(f"    {PASS} Certificate valid until {s.get('valid_until', 'N/A')}")
            print(f"         Issuer: {s.get('issuer', 'N/A')}")
        else:
            print(f"    {FAIL} {s.get('error', 'Certificate invalid')}")
    else:
        print(f"    {WARN} Could not retrieve certificate info")

    # -- XSS --
    print(f"\n  {INFO} Reflected XSS")
    if result.xss_findings:
        for x in result.xss_findings:
            print(f"    {FAIL} Potential XSS in parameter '{x.get('param', 'N/A')}'")
            print(f"         Payload: {x['payload']}")
    else:
        print(f"    {PASS} No reflected XSS detected")

    # -- SQLi --
    print(f"\n  {INFO} SQL Injection (Error Based)")
    if result.sqli_findings:
        for sq in result.sqli_findings:
            print(f"    {FAIL} Potential SQLi in parameter '{sq.get('param', 'N/A')}'")
            print(f"         Payload: {sq['payload']}")
    else:
        print(f"    {PASS} No SQL injection indicators detected")

    # -- Ports --
    print(f"\n  {INFO} Open Ports")
    for p in result.open_ports:
        icon = FAIL if p["state"] == "open" else PASS
        print(f"    {icon} Port {p['port']}: {p['state']}")

    # -- Forms --
    print(f"\n  {INFO} Forms Detected")
    if result.forms:
        for f in result.forms:
            method_colour = Fore.GREEN if f["method"] == "GET" else Fore.YELLOW
            inputs = ", ".join(f["inputs"]) if f["inputs"] else "(none)"
            print(f"    {INFO} {method_colour}{f['method']}{Style.RESET_ALL} {f['action']}")
            print(f"         Inputs: {inputs}")
    else:
        print(f"    {WARN} No forms found")

    # -- Errors --
    if result.errors:
        print(f"\n  {WARN} Errors")
        for err in result.errors:
            print(f"    {FAIL} {err}")

    print()


def _cmd_scan(args: argparse.Namespace) -> None:
    _print_banner()
    scanner = WebScanner()
    result = scanner.scan(args.url)
    _print_result(result)

    if args.output:
        from webscanner.reporter import generate_html_report

        html = generate_html_report(result)
        out_path = Path(args.output)
        out_path.write_text(html, encoding="utf-8")
        print(f"{INFO} HTML report saved to {out_path.resolve()}")


def _cmd_headers(args: argparse.Namespace) -> None:
    _print_banner()
    scanner = WebScanner()
    result = scanner.check_headers_only(args.url)
    _print_result(result)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="webscanner",
        description="Web Security Scanner — CLI Security Analysis Tool",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # Scan command
    scan_p = sub.add_parser("scan", help="Run a full security scan")
    scan_p.add_argument("url", help="Target URL (e.g. https://example.com)")
    scan_p.add_argument(
        "--output", "-o", help="Save HTML report to file", default=None
    )
    scan_p.set_defaults(func=_cmd_scan)

    # Headers command
    head_p = sub.add_parser("headers", help="Check security headers only")
    head_p.add_argument("url", help="Target URL (e.g. https://example.com)")
    head_p.set_defaults(func=_cmd_headers)

    args = parser.parse_args()
    try:
        args.func(args)
    except KeyboardInterrupt:
        print(f"\n{WARN} Scan interrupted by user")
        sys.exit(1)
    except Exception as exc:
        print(f"\n{FAIL} Unexpected error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
