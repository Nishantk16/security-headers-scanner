# Security Headers Scanner

A Python CLI tool that scans any website for missing HTTP security headers — helping identify common security misconfigurations (OWASP Top 10 category).

## What it checks
- Content-Security-Policy (XSS protection)
- X-Frame-Options (Clickjacking protection)
- Strict-Transport-Security (HTTPS enforcement)
- X-Content-Type-Options (MIME-sniffing protection)
- Referrer-Policy (Information leakage control)
- Permissions-Policy (Browser feature access control)

## Usage
```bash
pip install requests
python3 scanner.py <url>
```

Example:
```bash
python3 scanner.py example.com
```

## Sample Output
