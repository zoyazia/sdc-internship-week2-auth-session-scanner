Broken Authentication & Session Management Detection Tool

A Python-based scanner that detects common Broken Authentication and
Session Management weaknesses in web applications, built as part of an
internship security task (SDC Internship — Week 2).

⚠️ Authorized Scope & Legal Notice

This tool was developed and tested exclusively against intentionally
vulnerable, self-hosted lab applications that I own or am explicitly
permitted to test:

OWASP Juice Shop (local instance — http://localhost:3000)
DVWA (Damn Vulnerable Web Application)
OWASP WebGoat
PortSwigger Web Security Academy labs

No testing was performed against any third-party, production, or
unauthorized system.

Using this tool against systems you do not own or do not have written
permission to test is illegal in most jurisdictions. The author accepts
no liability for misuse. You are solely responsible for ensuring you
have authorization before running this tool.

Objective

Identify and report weaknesses in authentication and session handling,
mapped to OWASP Top 10 (A07:2021 – Identification and Authentication
Failures) and relevant CWE identifiers.

Checks Performed
Weak / default credential acceptance
Missing account lockout and rate limiting (brute-force exposure)
Session token not rotated after successful login (session fixation)
Session cookie security flags: HttpOnly, Secure, SameSite
Session token entropy / predictability
Session invalidation on logout
Credentials or tokens transmitted over unencrypted channels
Verbose authentication error messages (user enumeration)
Requirements
Python 3.8+
requests

Install with:

pip install requests
Usage

Run against an authorized lab target:

python auth_session_scanner.py --target http://localhost:3000
Output
File	Description
auth_session_findings_<timestamp>.csv	Machine-readable findings
auth_session_report_<timestamp>.html	Human-readable report

Each finding includes: vulnerability name, severity, affected endpoint,
supporting evidence, CWE reference, and remediation guidance.

Repository Contents
auth_session_scanner.py — the scanner
Final_Report_Broken_Auth_Session_Mgmt.docx — full findings report (methodology, findings table, false-positive review, recommendations)
auth_session_findings_*.csv — raw findings output
auth_session_report_*.html — generated HTML report
Methodology

Findings were produced using a manual baseline (browser + OWASP ZAP
proxy) and then automated with this tool. All automated results were
manually verified to rule out false positives; the verification process
is documented in the final report.

Tools Referenced

OWASP ZAP (proxying and manual exploration), Burp Suite Community
(comparison research), Python requests (tool implementation).

Disclaimer

Educational and authorized-assessment use only.
