"""
Broken Authentication / Session Management Detection Tool
-----------------------------------------------------------
Author: Member 3 (Individual Contributor)
Purpose: Automates detection of Broken Authentication / Session
         Management issues by pulling alerts from a running OWASP ZAP
         instance and filtering them down to the ones relevant to
         this category.

SCOPE: Authorized lab testing only (OWASP Juice Shop @ localhost:3000).
       Do NOT point this at any system you do not own or have
       explicit written permission to test.

HOW IT WORKS (read this before running):
1. ZAP runs a small local API server (by default on localhost:8080).
2. This script sends a plain HTTP GET request to that API, asking
   for every alert ZAP has found so far for our target.
3. ZAP replies with JSON (the same JSON you saw in your browser).
4. We loop through that JSON and keep only the alerts whose name
   matches keywords related to Authentication/Session Management.
5. We print a table to the screen AND save it to a CSV file so it
   can be attached to your final report.
"""

import requests
import csv
from datetime import datetime

# ---------------------------------------------------------------
# CONFIG — change these if your setup is different
# ---------------------------------------------------------------
ZAP_API_URL = "http://localhost:8080"
API_KEY = "ouu41808q2aaeg13qumfi69nu1"   # from Tools -> Options -> API
TARGET_BASE_URL = "http://localhost:3000"  # authorized lab target only

# List of authorized endpoints we manually exercised during testing.
# (Task requirement: "Processes a controlled list of authorized lab
# URLs/endpoints one by one")
AUTHORIZED_ENDPOINTS = [
    "http://localhost:3000/#/login",
    "http://localhost:3000/#/search",
    "http://localhost:3000/rest/user/login",
    "http://localhost:3000/api/Users/",
    "http://localhost:3000/socket.io/",
]

# Keywords that identify a ZAP alert as Broken Auth / Session Mgmt related.
# (This is our "detection logic" for this specific category.)
RELEVANT_KEYWORDS = [
    "session",
    "cookie",
    "authentication",
    "jwt",
    "auth",
    "login",
]

# Simple remediation notes per keyword, used if ZAP doesn't supply one.
REMEDIATION_MAP = {
    "jwt": "Store tokens in an HttpOnly, Secure cookie instead of "
           "localStorage/sessionStorage so JavaScript (and XSS) cannot "
           "read it.",
    "session": "Never pass session identifiers in the URL. Use secure, "
               "HttpOnly cookies or an Authorization header instead.",
    "cookie": "Set HttpOnly, Secure, and SameSite attributes on all "
              "session cookies.",
    "authentication": "Enforce HTTPS, rate-limiting, and account lockout "
                       "on authentication endpoints.",
    "auth": "Enforce HTTPS, rate-limiting, and account lockout on "
            "authentication endpoints.",
    "login": "Enforce HTTPS and rate-limiting on the login endpoint to "
             "prevent credential exposure and brute-forcing.",
}


def fetch_alerts():
    """Ask ZAP's API for every alert it has recorded in this session.

    Note: we deliberately use core/view/alerts (whole session) instead
    of alert/view/alerts?baseurl=... — the baseurl filter in ZAP's API
    was silently excluding some valid alerts (e.g. cookie-related ones)
    for reasons that weren't obvious from the GUI. Fetching everything
    and filtering by URL ourselves in Python is more reliable.
    """
    endpoint = f"{ZAP_API_URL}/JSON/core/view/alerts/"
    params = {"apikey": API_KEY}
    response = requests.get(endpoint, params=params, timeout=15)
    response.raise_for_status()          # crash loudly if ZAP isn't reachable
    data = response.json()
    all_alerts = data.get("alerts", [])

    # Keep only alerts whose URL actually belongs to our authorized target.
    target_alerts = [
        a for a in all_alerts
        if TARGET_BASE_URL in a.get("url", "")
    ]
    return target_alerts


def is_relevant(alert_name):
    """Return True if this alert's name matches our category keywords."""
    name_lower = alert_name.lower()
    return any(keyword in name_lower for keyword in RELEVANT_KEYWORDS)


def pick_remediation(alert_name, zap_solution, risk):
    """Prefer ZAP's own solution text; fall back to our own notes.

    Bug fix: ZAP sometimes returns a generic placeholder solution
    ("This is an informational alert and no action is necessary.")
    even on alerts whose risk is NOT Informational (e.g. the JWT in
    localStorage alert, which is Medium risk). Trusting that text
    blindly would wrongly tell the reader there's nothing to fix.
    So: only trust ZAP's solution text if it's non-empty AND not that
    generic placeholder on a non-Informational alert. Otherwise fall
    back to our own keyword-based remediation notes.
    """
    solution = (zap_solution or "").strip()
    is_placeholder = "informational alert" in solution.lower()

    if solution and not (is_placeholder and risk.lower() != "informational"):
        return solution

    name_lower = alert_name.lower()
    for keyword, note in REMEDIATION_MAP.items():
        if keyword in name_lower:
            return note
    return "Review manually — no automated remediation note available."


SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "informational": 3}


def build_findings(alerts):
    """Turn raw ZAP alert dicts into our report rows.

    Merges duplicate alerts (same vulnerability name + same evidence,
    e.g. the same session ID showing up across several socket.io
    requests) into a single row that lists all affected endpoints,
    instead of repeating the same finding 2-3 times.
    """
    merged = {}   # key: (name, evidence) -> combined row

    for alert in alerts:
        name = alert.get("name", "")
        if not is_relevant(name):
            continue

        evidence = alert.get("evidence", "") or "(see description)"
        url = alert.get("url", "")
        key = (name, evidence)

        if key in merged:
            if url not in merged[key]["Endpoints"]:
                merged[key]["Endpoints"].append(url)
        else:
            merged[key] = {
                "Vulnerability": name,
                "Detected": "Y",
                "Evidence": evidence,
                "Severity": alert.get("risk", "Unknown"),
                "CWE": alert.get("cweid", "N/A"),
                "Recommendation": pick_remediation(
                    name, alert.get("solution", ""), alert.get("risk", "Unknown")
                ),
                "Endpoints": [url] if url else [],
            }

    findings = []
    for row in merged.values():
        endpoints = row.pop("Endpoints")
        if len(endpoints) > 1:
            row["Endpoint"] = f"{endpoints[0]}  (+{len(endpoints) - 1} more occurrence(s))"
            row["AllEndpoints"] = "; ".join(endpoints)
        else:
            row["Endpoint"] = endpoints[0] if endpoints else ""
            row["AllEndpoints"] = row["Endpoint"]
        findings.append(row)

    # Sort by severity (High -> Medium -> Low -> Informational)
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["Severity"].lower(), 99))

    return findings


def save_csv(findings, filename=None):
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"auth_session_findings_{timestamp}.csv"

    fieldnames = ["Endpoint", "AllEndpoints", "Vulnerability", "Detected",
                  "Evidence", "Severity", "CWE", "Recommendation"]

    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(findings)

    return filename


# Colors used in the HTML report for each severity level.
SEVERITY_COLORS = {
    "high": "#e74c3c",
    "medium": "#e67e22",
    "low": "#f1c40f",
    "informational": "#95a5a6",
}


def save_html(findings, filename=None):
    """Write a polished, self-contained, color-coded HTML report."""
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"auth_session_report_{timestamp}.html"

    # Summary counts per severity, for the top cards
    counts = {"high": 0, "medium": 0, "low": 0, "informational": 0}
    for f in findings:
        counts[f["Severity"].lower()] = counts.get(f["Severity"].lower(), 0) + 1

    rows_html = []
    for f in findings:
        color = SEVERITY_COLORS.get(f["Severity"].lower(), "#bdc3c7")
        rows_html.append(f"""
        <tr>
            <td class="vuln-name">{f['Vulnerability']}</td>
            <td><span class="badge" style="background:{color}">{f['Severity']}</span></td>
            <td class="mono">{f['Endpoint']}</td>
            <td class="mono">{f['Evidence']}</td>
            <td class="center">{f['CWE']}</td>
            <td>{f['Recommendation']}</td>
        </tr>""")

    summary_cards = "".join(f"""
        <div class="card">
          <div class="card-value" style="color:{SEVERITY_COLORS[sev]}">{counts[sev]}</div>
          <div class="card-label">{sev.capitalize()}</div>
        </div>""" for sev in ["high", "medium", "low", "informational"])

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Broken Authentication / Session Management - Findings Report</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{
    font-family: 'Segoe UI', Arial, sans-serif;
    margin: 0;
    background: linear-gradient(135deg, #0f2027 0%, #203a43 45%, #2c5364 100%);
    color: #222;
    min-height: 100vh;
    padding: 40px 20px;
  }}
  .wrap {{ max-width: 1100px; margin: 0 auto; }}
  .header {{
    background: #ffffff;
    border-radius: 12px 12px 0 0;
    padding: 30px 36px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.25);
  }}
  .header h1 {{
    margin: 0 0 6px 0;
    font-size: 24px;
    color: #16222a;
  }}
  .header .sub {{
    color: #607080;
    font-size: 13px;
  }}
  .badge-scope {{
    display: inline-block;
    margin-top: 10px;
    background: #eef6ff;
    color: #1a6fb5;
    border: 1px solid #bfe0ff;
    padding: 4px 10px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 600;
  }}
  .summary {{
    background: #16222a;
    display: flex;
    gap: 0;
    padding: 0;
  }}
  .card {{
    flex: 1;
    text-align: center;
    padding: 18px 10px;
    border-right: 1px solid rgba(255,255,255,0.08);
  }}
  .card:last-child {{ border-right: none; }}
  .card-value {{ font-size: 26px; font-weight: 700; }}
  .card-label {{
    color: #9fb3c8;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-top: 4px;
  }}
  table {{
    border-collapse: collapse;
    width: 100%;
    background: #fff;
    border-radius: 0 0 12px 12px;
    overflow: hidden;
    box-shadow: 0 10px 30px rgba(0,0,0,0.25);
  }}
  th, td {{
    border-bottom: 1px solid #eef1f4;
    padding: 12px 14px;
    text-align: left;
    font-size: 13px;
    vertical-align: top;
  }}
  th {{
    background: #f4f7fa;
    color: #33404d;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }}
  tr:hover {{ background: #fafcff; }}
  .vuln-name {{ font-weight: 600; color: #16222a; }}
  .mono {{ font-family: Consolas, monospace; font-size: 11px; color: #445; word-break: break-all; }}
  .center {{ text-align: center; }}
  .badge {{
    color: #fff;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.3px;
  }}
  .footer {{
    text-align: center;
    margin-top: 16px;
    font-size: 12px;
    color: #cfe3f2;
  }}
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <h1>Broken Authentication / Session Management — Findings Report</h1>
    <div class="sub">
      Target: {TARGET_BASE_URL} &nbsp;•&nbsp;
      Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} &nbsp;•&nbsp;
      Total unique findings: {len(findings)}
    </div>
    <div class="badge-scope">🔒 Authorized lab testing only — OWASP Juice Shop</div>
  </div>
  <div class="summary">
    {summary_cards}
  </div>
  <table>
    <tr>
      <th>Vulnerability</th>
      <th>Severity</th>
      <th>Affected Endpoint</th>
      <th>Evidence</th>
      <th>CWE</th>
      <th>Recommendation</th>
    </tr>
    {''.join(rows_html)}
  </table>
  <div class="footer">
    Generated by auth_session_scanner.py — Member 3, Broken Authentication / Session Management Detection Tool
  </div>
</div>
</body>
</html>"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)

    return filename


def print_report(findings):
    print("\n" + "=" * 90)
    print("BROKEN AUTHENTICATION / SESSION MANAGEMENT — DETECTION REPORT")
    print("Target:", TARGET_BASE_URL, " (authorized lab only)")
    print("=" * 90)

    if not findings:
        print("No Broken Auth / Session Management alerts found.")
        return

    for i, f in enumerate(findings, start=1):
        print(f"\n[{i}] {f['Vulnerability']}")
        print(f"    Endpoint    : {f['Endpoint']}")
        print(f"    Detected    : {f['Detected']}")
        print(f"    Severity    : {f['Severity']}")
        print(f"    Evidence    : {f['Evidence']}")
        print(f"    CWE         : {f['CWE']}")
        print(f"    Remediation : {f['Recommendation']}")

    print("\n" + "-" * 90)
    print(f"Total relevant findings: {len(findings)}")


def main():
    print("Connecting to ZAP API at", ZAP_API_URL, "...")
    try:
        alerts = fetch_alerts()
    except requests.exceptions.ConnectionError:
        print("ERROR: Could not reach ZAP. Is ZAP running, and is the "
              "API enabled under Tools -> Options -> API?")
        return
    except requests.exceptions.HTTPError as e:
        print("ERROR: ZAP API returned an error:", e)
        return

    print(f"Fetched {len(alerts)} total alerts from ZAP.")

    findings = build_findings(alerts)
    print_report(findings)

    if findings:
        csv_filename = save_csv(findings)
        html_filename = save_html(findings)
        print(f"\nSaved CSV report to : {csv_filename}")
        print(f"Saved HTML report to: {html_filename}")


if __name__ == "__main__":
    main()
