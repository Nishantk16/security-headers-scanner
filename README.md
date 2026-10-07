# Security Headers Scanner v2

Ek simple Python CLI tool jo kisi bhi website ke HTTP security headers check karta hai, unki value analyze karta hai, aur score + grade deta hai.

## Features

- Multiple URLs ek saath scan (command line ya file se)
- Sirf present/missing nahi, header ki **value bhi check** hoti hai
- Score aur grade (A to F)
- Multi-scan ke baad summary table
- JSON report export
- Unreachable ya galat domain par crash nahi hota, ERROR dikhata hai

## Headers jo check hote hain

| Header | Kya rokta hai |
|---|---|
| Content-Security-Policy | XSS (script sources control karta hai) |
| X-Frame-Options | Clickjacking |
| Strict-Transport-Security | HTTPS downgrade / SSL stripping |
| X-Content-Type-Options | MIME sniffing |
| Referrer-Policy | URL info leak |
| Permissions-Policy | Camera, mic, location jaise browser features |

## Value checks

- **CSP:** script-src (ya default-src) mein `unsafe-inline`, `unsafe-eval` ya wildcard `*` ho to WEAK
- **HSTS:** max-age 15552000 (180 din) se kam ho ya na ho to WEAK
- **X-Frame-Options:** sirf DENY ya SAMEORIGIN sahi maane jaate hain
- **X-Content-Type-Options:** value `nosniff` honi chahiye
- **Referrer-Policy:** `unsafe-url` ya `no-referrer-when-downgrade` to WEAK

## Scoring

- PASS = 1 point, WEAK = 0.5 point, MISSING = 0 point
- Percent = points / 6 x 100
- Grade: A (90+), B (75+), C (50+), D (25+), F (neeche)

## Install

    git clone https://github.com/Nishantk16/security-headers-scanner.git
    cd security-headers-scanner
    pip install -r requirements.txt

## Usage

Ek URL:

    python3 scanner.py github.com

Multiple URLs:

    python3 scanner.py github.com python.org mozilla.org

File se (har line mein ek URL, `#` se comment):

    python3 scanner.py -f targets.txt

JSON report ke saath:

    python3 scanner.py -f targets.txt -o report.json

Options:

    -f, --file      URLs ki file
    -o, --output    JSON report ka path
    -t, --timeout   Request timeout seconds (default 10)

## Example summary

    https://github.com      83%  Grade B
    https://python.org      33%  Grade D
    https://mozilla.org     75%  Grade B

## Note

Ye tool sirf ek normal GET request bhejta hai aur response headers padhta hai. Phir bhi sirf apni ya authorized sites par use karo. Missing header akela aksar low/informational severity hota hai, asli value tab hai jab wo kisi exploitable bug ke saath chain ho.

## Author

Nishant (Nishantk16), 150-day ethical hacking roadmap ka Day 103-104 project.
