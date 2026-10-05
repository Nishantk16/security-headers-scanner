import requests
import sys

# Security headers jo hum check karenge, aur inka explanation
SECURITY_HEADERS = {
    "Content-Security-Policy": "Rokta hai XSS attacks ko by controlling kaunse scripts/resources load ho sakte hain",
    "X-Frame-Options": "Rokta hai Clickjacking attacks ko (site ko iframe mein load hone se rokta hai)",
    "Strict-Transport-Security": "Force karta hai browser ko sirf HTTPS use karne ke liye",
    "X-Content-Type-Options": "Rokta hai MIME-sniffing attacks ko",
    "Referrer-Policy": "Control karta hai kitni URL info doosri sites ko bheji jaaye",
    "Permissions-Policy": "Control karta hai browser features jaise camera, microphone, location"
}

def scan_headers(url):
    # Agar URL mein http:// ya https:// nahi hai, to https:// add kar do
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    print(f"\n[*] Scanning: {url}\n")
    print("=" * 60)

    try:
        response = requests.get(url, timeout=10)
    except requests.exceptions.RequestException as e:
        print(f"[!] Error: Website tak pahunch nahi paya. Reason: {e}")
        sys.exit(1)

    present_count = 0
    missing_count = 0

    for header, description in SECURITY_HEADERS.items():
        if header in response.headers:
            print(f"[✅ PRESENT] {header}")
            print(f"    Value: {response.headers[header]}")
            present_count += 1
        else:
            print(f"[❌ MISSING] {header}")
            print(f"    Risk: {description}")
            missing_count += 1
        print("-" * 60)

    print(f"\n[*] Scan Complete: {present_count} present, {missing_count} missing\n")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 scanner.py <url>")
        print("Example: python3 scanner.py example.com")
        sys.exit(1)

    target_url = sys.argv[1]
    scan_headers(target_url)
