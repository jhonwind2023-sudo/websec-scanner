#!/usr/bin/env python3
"""WebSec Scanner - Website Security Vulnerability Scanner"""
import requests, sys, json, socket, ssl, time
from urllib.parse import urlparse
from datetime import datetime

class WebSecScanner:
    def __init__(self, target_url):
        self.target_url = target_url if target_url.startswith(('http://','https://')) else 'https://'+target_url
        self.domain = urlparse(self.target_url).netloc
        self.results = {"vulnerabilities": [], "security_headers": {}}
    
    def scan(self):
        print(f"Scanning {self.target_url}...")
        self.check_security_headers()
        self.check_cors()
        self.check_ssl()
        return self.results
    
    def check_security_headers(self):
        try:
            r = requests.get(self.target_url, timeout=10, verify=False)
            headers = r.headers
            checks = {
                'Strict-Transport-Security': ('HIGH', 'Missing HSTS header'),
                'Content-Security-Policy': ('HIGH', 'Missing CSP header'),
                'X-Frame-Options': ('MEDIUM', 'Missing clickjacking protection'),
                'X-Content-Type-Options': ('MEDIUM', 'Missing MIME sniffing prevention'),
                'X-XSS-Protection': ('MEDIUM', 'Missing XSS protection'),
                'Referrer-Policy': ('LOW', 'Missing referrer policy'),
            }
            for header, (severity, msg) in checks.items():
                if header not in headers:
                    self.results['vulnerabilities'].append({
                        'name': msg, 'severity': severity, 'header': header
                    })
                else:
                    self.results['security_headers'][header] = headers[header]
        except Exception as e:
            self.results['error'] = str(e)

    def check_cors(self):
        try:
            r = requests.get(self.target_url, headers={'Origin': 'https://evil.com'}, timeout=10)
            acao = r.headers.get('Access-Control-Allow-Origin', '')
            acac = r.headers.get('Access-Control-Allow-Credentials', '')
            if acao == 'https://evil.com' and acac == 'true':
                self.results['vulnerabilities'].append({
                    'name': 'CORS Misconfiguration - reflects arbitrary origin with credentials',
                    'severity': 'HIGH'
                })
        except: pass

    def check_ssl(self):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        self.results['ssl_info'] = {
                            'issuer': dict(cert.get('issuer', [])).get('organizationName', 'Unknown'),
                            'expires': cert.get('notAfter', 'Unknown')
                        }
        except: pass

if __name__ == '__main__':
    url = sys.argv[1] if len(sys.argv) > 1 else 'https://example.com'
    scanner = WebSecScanner(url)
    results = scanner.scan()
    print(json.dumps(results, indent=2))
