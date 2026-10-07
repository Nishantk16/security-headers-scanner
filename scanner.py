#!/usr/bin/env python3
"""
Security Headers Scanner v2
- Multiple URLs scan (command line ya file se)
- Header ki value bhi check karta hai (sirf present/missing nahi)
- Score + grade deta hai
- Optional JSON report
"""
import argparse
import json
import re
import sys

import requests

# Security headers aur unka explanation
SECURITY_HEADERS = {
    "Content-Security-Policy": "Rokta hai XSS attacks ko by controlling kaunse scripts/resources load ho sakte hain",
    "X-Frame-Options": "Rokta hai Clickjacking attacks ko (site ko iframe mein load hone se rokta hai)",
    "Strict-Transport-Security": "Force karta hai browser ko sirf HTTPS use karne ke liye",
    "X-Content-Type-Options": "Rokta hai MIME-sniffing attacks ko",
    "Referrer-Policy": "Control karta hai kitni URL info doosri sites ko bheji jaaye",
    "Permissions-Policy": "Control karta hai browser features jaise camera, microphone, location",
}

HSTS_MIN_AGE = 15552000  # 180 din


# ---------- Value checks: har function problems ki list return karta hai ----------

def check_csp(value):
    # CSP ko directives mein todo: {"script-src": ["'self'", ...], ...}
    directives = {}
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        name, *vals = part.split()
        directives[name.lower()] = [v.lower() for v in vals]

    # script-src na ho to default-src apply hota hai
    if "script-src" in directives:
        script_src = directives["script-src"]
    elif "default-src" in directives:
        script_src = directives["default-src"]
    else:
        return ["script-src ya default-src set nahi hai (scripts par koi restriction nahi)"]

    problems = []
    if "'unsafe-inline'" in script_src:
        problems.append("script mein 'unsafe-inline' allowed hai (XSS protection kamzor)")
    if "'unsafe-eval'" in script_src:
        problems.append("script mein 'unsafe-eval' allowed hai")
    if "*" in script_src:
        problems.append("script mein wildcard (*) source allowed hai")
    return problems


def check_hsts(value):
    match = re.search(r"max-age=(\d+)", value.lower())
    if not match:
        return ["max-age missing hai"]
    if int(match.group(1)) < HSTS_MIN_AGE:
        return [f"max-age bahut kam hai ({match.group(1)} sec, kam se kam {HSTS_MIN_AGE} hona chahiye)"]
    return []


def check_xfo(value):
    if value.strip().upper() in ("DENY", "SAMEORIGIN"):
        return []
    return [f"unexpected value '{value}' (DENY ya SAMEORIGIN hona chahiye)"]


def check_xcto(value):
    if value.strip().lower() == "nosniff":
        return []
    return [f"value 'nosniff' hona chahiye, mila '{value}'"]


def check_referrer(value):
    last = value.split(",")[-1].strip().lower()
    if last in ("unsafe-url", "no-referrer-when-downgrade"):
        return [f"'{last}' weak policy hai"]
    return []


def check_permissions(value):
    return []  # present hona hi kaafi maante hain


VALUE_CHECKS = {
    "Content-Security-Policy": check_csp,
    "Strict-Transport-Security": check_hsts,
    "X-Frame-Options": check_xfo,
    "X-Content-Type-Options": check_xcto,
    "Referrer-Policy": check_referrer,
    "Permissions-Policy": check_permissions,
}


def get_grade(percent):
    if percent >= 90:
        return "A"
    if percent >= 75:
        return "B"
    if percent >= 50:
        return "C"
    if percent >= 25:
        return "D"
    return "F"


def normalize_url(url):
    url = url.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    return url


def scan_headers(url, timeout=10):
    """Ek URL scan karta hai aur result dict return karta hai."""
    url = normalize_url(url)
    try:
        response = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": "SecurityHeadersScanner/2.0"},
        )
    except requests.exceptions.RequestException as e:
        return {"url": url, "error": str(e)}

    results = []
    points = 0.0
    for header in SECURITY_HEADERS:
        value = response.headers.get(header)
        if value is None:
            results.append({"header": header, "status": "MISSING", "value": None, "notes": []})
            continue
        problems = VALUE_CHECKS[header](value)
        if problems:
            results.append({"header": header, "status": "WEAK", "value": value, "notes": problems})
            points += 0.5
        else:
            results.append({"header": header, "status": "PASS", "value": value, "notes": []})
            points += 1.0

    total = len(SECURITY_HEADERS)
    percent = round(points / total * 100)
    return {
        "url": url,
        "final_url": response.url,
        "http_status": response.status_code,
        "results": results,
        "score": points,
        "total": total,
        "percent": percent,
        "grade": get_grade(percent),
    }


def print_report(report):
    print("\n" + "=" * 60)
    print(f"[*] Scanning: {report['url']}")
    if "error" in report:
        print(f"[!] Error: Website tak pahunch nahi paya. Reason: {report['error']}")
        return
    print(f"[*] Final URL: {report['final_url']}  (HTTP {report['http_status']})")
    print("=" * 60)

    icons = {"PASS": "✅ PASS", "WEAK": "⚠️  WEAK", "MISSING": "❌ MISSING"}
    for item in report["results"]:
        print(f"[{icons[item['status']]}] {item['header']}")
        if item["status"] == "MISSING":
            print(f"    Risk: {SECURITY_HEADERS[item['header']]}")
        else:
            value = item["value"]
            shown = value if len(value) <= 100 else value[:100] + "..."
            print(f"    Value: {shown}")
            for note in item["notes"]:
                print(f"    Issue: {note}")
        print("-" * 60)

    print(f"[*] Score: {report['score']}/{report['total']} ({report['percent']}%)  Grade: {report['grade']}\n")


def load_urls_from_file(path):
    urls = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
    return urls


def main():
    parser = argparse.ArgumentParser(description="Security Headers Scanner v2")
    parser.add_argument("urls", nargs="*", help="Scan karne wale URL(s)")
    parser.add_argument("-f", "--file", help="File jisme har line mein ek URL ho")
    parser.add_argument("-o", "--output", help="JSON report is file mein save karo")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout seconds (default 10)")
    args = parser.parse_args()

    targets = list(args.urls)
    if args.file:
        try:
            targets += load_urls_from_file(args.file)
        except OSError as e:
            print(f"[!] File padh nahi paya: {e}")
            sys.exit(1)

    if not targets:
        parser.print_usage()
        print("Example: python3 scanner.py example.com")
        print("Example: python3 scanner.py -f targets.txt -o report.json")
        sys.exit(1)

    reports = []
    for target in targets:
        report = scan_headers(target, timeout=args.timeout)
        print_report(report)
        reports.append(report)

    if len(reports) > 1:
        print("=" * 60)
        print("SUMMARY")
        print("=" * 60)
        for r in reports:
            if "error" in r:
                print(f"{r['url']:<40} ERROR")
            else:
                print(f"{r['url']:<40} {r['percent']:>3}%  Grade {r['grade']}")
        print()

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(reports, f, indent=2)
        print(f"[*] JSON report saved: {args.output}")


if __name__ == "__main__":
    main()
