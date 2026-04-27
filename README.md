# WebSec Scanner 🔍

A real website security scanning tool that checks for security headers, SQL injection, XSS, directory traversal, and sensitive file exposure.

## Features

- **Security Headers Audit** - Checks CSP, HSTS, X-Frame-Options, X-Content-Type-Options, and more
- **SQL Injection Testing** - Automated parameter injection testing
- **XSS Detection** - Cross-site scripting vulnerability scanning
- **Directory Traversal** - Path traversal attempt detection
- **Sensitive Files** - Exposed config/backup file discovery
- **Server Info** - Technology stack identification

## Quick Start

```bash
# Install
git clone https://github.com/jhonwind2023-sudo/websec-scanner.git
cd websec-scanner
pip install requests

# Run a scan
python3 websec_scanner_pro.py https://example.com
```

## Online Demo

Try it online: [http://103.74.194.42:9090](http://103.74.194.42:9090)

API endpoint: `http://103.74.194.42:8090/scan?url=https://example.com`

## Pricing

| Tier | Price | Features |
|------|-------|----------|
| Free | $0 | Basic scan + headers check |
| Pro | $49 | Deep penetration test + detailed PDF report |
| Enterprise | $149 | Full audit + monitoring + response |

## Support

Contact: jhonwind2023@gmail.com

---

*Built with Python. Results for reference only. Do not use for illegal purposes.*
