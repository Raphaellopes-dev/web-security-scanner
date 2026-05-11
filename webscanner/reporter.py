"""HTML report generator for scan results."""

from datetime import datetime

from webscanner.scanner import ScanResult

REPORT_CSS = """
body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: #f4f6f9;
    margin: 0;
    padding: 30px;
    color: #333;
}
.container {
    max-width: 1100px;
    margin: 0 auto;
    background: #fff;
    border-radius: 12px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.08);
    padding: 30px 40px;
}
h1 {
    font-size: 28px;
    border-bottom: 3px solid #4a6cf7;
    padding-bottom: 12px;
    margin-top: 0;
    color: #1a1a2e;
}
h2 {
    font-size: 20px;
    margin-top: 30px;
    color: #1a1a2e;
    border-left: 4px solid #4a6cf7;
    padding-left: 10px;
}
.summary {
    background: #f0f4ff;
    border-radius: 8px;
    padding: 16px 20px;
    margin: 20px 0;
    font-size: 15px;
    line-height: 1.7;
}
.summary strong { color: #1a1a2e; }
.pass  { color: #28a745; font-weight: 600; }
.fail  { color: #dc3545; font-weight: 600; }
.warn  { color: #e67e22; font-weight: 600; }
table {
    width: 100%;
    border-collapse: collapse;
    margin: 12px 0 20px;
    font-size: 14px;
}
th {
    background: #4a6cf7;
    color: #fff;
    padding: 10px 12px;
    text-align: left;
    font-weight: 600;
}
td {
    padding: 9px 12px;
    border-bottom: 1px solid #e9ecef;
    vertical-align: top;
}
tr:hover { background: #f8f9ff; }
.badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 12px;
    font-size: 12px;
    font-weight: 600;
}
.badge-green  { background: #d4edda; color: #155724; }
.badge-red    { background: #f8d7da; color: #721c24; }
.badge-yellow { background: #fff3cd; color: #856404; }
ul { margin: 0; padding-left: 18px; }
li { margin-bottom: 4px; }
.footer {
    text-align: center;
    margin-top: 30px;
    font-size: 13px;
    color: #888;
}
"""


def _severity(count: int) -> str:
    if count == 0:
        return "pass"
    return "fail"


def _badge(present: bool) -> str:
    if present:
        return '<span class="badge badge-green">Present</span>'
    return '<span class="badge badge-red">Missing</span>'


def _port_badge(state: str) -> str:
    if state == "open":
        return '<span class="badge badge-red">OPEN</span>'
    return '<span class="badge badge-green">Closed</span>'


def generate_html_report(result: ScanResult) -> str:
    """Return a complete HTML page string with the scan findings."""

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    total_issues = sum(
        [
            len([h for h in result.headers_check if not h["present"]]),
            len(result.xss_findings),
            len(result.sqli_findings),
            0 if result.ssl_info and result.ssl_info.get("valid") else 1,
        ]
    )

    header_issues = [h for h in result.headers_check if not h["present"]]

    def _ssl_badge():
        if result.ssl_info and result.ssl_info.get("valid"):
            return '<span class="badge badge-green">Valid</span>'
        return '<span class="badge badge-red">Invalid / Error</span>'

    rows = ""

    # -- Headers table ---------------------------------------------------
    header_rows = ""
    for h in result.headers_check:
        header_rows += f"""
        <tr>
            <td><code>{h['header']}</code></td>
            <td>{h['description']}</td>
            <td>{_badge(h['present'])}</td>
            <td><code>{h['value']}</code></td>
        </tr>"""

    # -- SSL table -------------------------------------------------------
    ssl_rows = ""
    s = result.ssl_info
    if s:
        ssl_rows = f"""
        <tr><td>Hostname</td><td>{s.get('hostname', 'N/A')}</td></tr>
        <tr><td>Port</td><td>{s.get('port', 'N/A')}</td></tr>
        <tr><td>Subject CN</td><td>{s.get('subject_cn', 'N/A')}</td></tr>
        <tr><td>Issuer</td><td>{s.get('issuer', 'N/A')}</td></tr>
        <tr><td>Valid From</td><td>{s.get('valid_from', 'N/A')}</td></tr>
        <tr><td>Valid Until</td><td>{s.get('valid_until', 'N/A')}</td></tr>
        <tr><td>Status</td><td>{_ssl_badge()}</td></tr>
        """
        if "error" in s:
            ssl_rows += f"""
        <tr><td>Error</td><td class="fail">{s['error']}</td></tr>"""

    # -- XSS table -------------------------------------------------------
    xss_rows = ""
    for x in result.xss_findings:
        xss_rows += f"""
        <tr>
            <td><code>{x.get('param', 'N/A')}</code></td>
            <td><code>{x.get('payload', '').escape()}</code></td>
            <td class="fail">Reflected</td>
        </tr>"""

    # -- SQLi table ------------------------------------------------------
    sqli_rows = ""
    for sq in result.sqli_findings:
        sqli_rows += f"""
        <tr>
            <td><code>{sq.get('param', 'N/A')}</code></td>
            <td><code>{sq.get('payload', '').escape()}</code></td>
            <td><code>{sq.get('pattern', 'N/A')}</code></td>
            <td class="fail">Vulnerable</td>
        </tr>"""

    # -- Ports table -----------------------------------------------------
    port_rows = ""
    for p in result.open_ports:
        port_rows += f"""
        <tr>
            <td>{p['port']}</td>
            <td>{_port_badge(p['state'])}</td>
        </tr>"""

    # -- Forms table -----------------------------------------------------
    form_rows = ""
    for f in result.forms:
        inputs_fmt = ", ".join(f["inputs"]) if f["inputs"] else "(none)"
        form_rows += f"""
        <tr>
            <td><code>{f['action']}</code></td>
            <td>{f['method']}</td>
            <td><code>{inputs_fmt}</code></td>
        </tr>"""

    # -- Errors ----------------------------------------------------------
    error_block = ""
    if result.errors:
        err_lines = "".join(f"<li>{e}</li>" for e in result.errors)
        error_block = f"""
        <h2>Errors</h2>
        <ul>{err_lines}</ul>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Scan Report — {result.target_url}</title>
<style>{REPORT_CSS}</style>
</head>
<body>
<div class="container">
    <h1>Web Security Scan Report</h1>

    <div class="summary">
        <strong>Target:</strong> {result.target_url}<br>
        <strong>Scan Time:</strong> {now}<br>
        <strong>Issues Found:</strong> <span class="{_severity(total_issues)}">{total_issues}</span>
    </div>

    <h2>Security Headers</h2>
    {('<p class="pass">All recommended security headers are present.</p>' if not header_issues else f'<p class="fail">{len(header_issues)} header(s) missing.</p>')}
    <table>
        <thead><tr><th>Header</th><th>Description</th><th>Status</th><th>Value</th></tr></thead>
        <tbody>{header_rows}</tbody>
    </table>

    <h2>SSL / TLS Certificate</h2>
    <table>
        <thead><tr><th>Property</th><th>Value</th></tr></thead>
        <tbody>{ssl_rows}</tbody>
    </table>

    <h2>Reflected XSS</h2>
    {('<p class="pass">No reflected XSS vulnerabilities detected.</p>' if not result.xss_findings else f'<p class="fail">{len(result.xss_findings)} potential XSS reflection(s) found.</p>')}
    {'' if not result.xss_findings else '''
    <table>
        <thead><tr><th>Parameter</th><th>Payload</th><th>Status</th></tr></thead>
        <tbody>''' + xss_rows + '''</tbody>
    </table>'''}

    <h2>SQL Injection (Error Based)</h2>
    {('<p class="pass">No SQL injection indicators detected.</p>' if not result.sqli_findings else f'<p class="fail">{len(result.sqli_findings)} potential SQL injection indicator(s) found.</p>')}
    {'' if not result.sqli_findings else '''
    <table>
        <thead><tr><th>Parameter</th><th>Payload</th><th>Error Pattern</th><th>Status</th></tr></thead>
        <tbody>''' + sqli_rows + '''</tbody>
    </table>'''}

    <h2>Open Ports</h2>
    <table>
        <thead><tr><th>Port</th><th>Status</th></tr></thead>
        <tbody>{port_rows}</tbody>
    </table>

    <h2>Forms Detected</h2>
    {('<p class="warn">No forms found on the page.</p>' if not result.forms else f'<p class="pass">{len(result.forms)} form(s) detected.</p>')}
    {'' if not result.forms else '''
    <table>
        <thead><tr><th>Action</th><th>Method</th><th>Inputs</th></tr></thead>
        <tbody>''' + form_rows + '''</tbody>
    </table>'''}

    {error_block}

    <div class="footer">
        Generated by Web Security Scanner &mdash; {now}
    </div>
</div>
</body>
</html>"""

    return html
