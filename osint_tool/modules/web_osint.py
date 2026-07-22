"""
Web & Domain OSINT Module
Functions: WHOIS, DNS, IP Geolocation, Reverse IP, SSL, HTTP Headers, etc.
"""
import socket
import ssl
import json
import subprocess
import sys
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
import whois
import dns.resolver
import dns.exception
from bs4 import BeautifulSoup

# Disable SSL warnings for non-validated calls
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WebOSINT:
    """Web & Domain investigation tools."""

    def __init__(self, timeout: int = 10, proxy: Optional[str] = None,
                 tor: bool = False, api_keys: Optional[Dict] = None):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                           'AppleWebKit/537.36 (KHTML, like Gecko) '
                           'Chrome/120.0.0.0 Safari/537.36'),
            'Accept-Language': 'en-US,en;q=0.9',
        })
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        if tor:
            self.session.proxies = {'http': 'socks5://127.0.0.1:9050',
                                    'https': 'socks5://127.0.0.1:9050'}
        self.api_keys = api_keys or {}

    def _extract_domain(self, target: str) -> str:
        """Extract domain from URL or return as-is."""
        parsed = urlparse(target)
        if parsed.netloc:
            return parsed.netloc
        return target.split('/')[0] if '/' in target else target

    # ─────────────────────────────────────────────
    # WHOIS Lookup
    # ─────────────────────────────────────────────
    def whois_lookup(self, domain: str) -> Dict:
        """Perform WHOIS lookup for a domain."""
        domain = self._extract_domain(domain)
        result = {'domain': domain, 'status': 'error', 'data': {}}
        try:
            w = whois.whois(domain)
            result['data'] = {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'updated_date': str(w.updated_date) if w.updated_date else None,
                'name_servers': w.name_servers if w.name_servers else [],
                'registrant_name': w.name,
                'registrant_organization': w.org,
                'registrant_email': w.emails,
                'registrant_country': w.country,
                'registrant_city': w.city,
                'status': w.status,
                'dnssec': w.dnssec,
            }
            result['status'] = 'success'
        except Exception as e:
            result['error'] = str(e)
        return result

    # ─────────────────────────────────────────────
    # DNS Records
    # ─────────────────────────────────────────────
    def dns_lookup(self, domain: str, record_types: Optional[List[str]] = None) -> Dict:
        """Lookup DNS records for a domain."""
        domain = self._extract_domain(domain)
        if record_types is None:
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'CAA']
        result = {'domain': domain, 'status': 'success', 'records': {}}
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                result['records'][rtype] = [str(r) for r in answers]
            except dns.resolver.NoAnswer:
                result['records'][rtype] = []
            except dns.resolver.NXDOMAIN:
                result['status'] = 'error'
                result['error'] = f'Domain {domain} does not exist (NXDOMAIN)'
                break
            except Exception as e:
                result['records'][rtype] = [f'Error: {str(e)}']
        return result

    # ─────────────────────────────────────────────
    # IP Geolocation
    # ─────────────────────────────────────────────
    def ip_geolocation(self, target: str) -> Dict:
        """Get geolocation info for an IP or domain using ip-api.com."""
        domain = self._extract_domain(target)
        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror:
            ip = domain if self._is_ip(domain) else None
        if not ip:
            return {'status': 'error', 'error': 'Could not resolve IP'}
        try:
            resp = self.session.get(f'http://ip-api.com/json/{ip}', timeout=self.timeout)
            data = resp.json()
            if data.get('status') == 'success':
                return {
                    'status': 'success',
                    'ip': ip,
                    'country': data.get('country'),
                    'country_code': data.get('countryCode'),
                    'region': data.get('regionName'),
                    'city': data.get('city'),
                    'zip': data.get('zip'),
                    'lat': data.get('lat'),
                    'lon': data.get('lon'),
                    'isp': data.get('isp'),
                    'org': data.get('org'),
                    'as': data.get('as'),
                    'timezone': data.get('timezone'),
                }
            return {'status': 'error', 'error': data.get('message', 'Unknown error')}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}

    # ─────────────────────────────────────────────
    # Reverse IP Lookup
    # ─────────────────────────────────────────────
    def reverse_ip(self, target: str) -> Dict:
        """Find domains hosted on the same IP (via yougetsignal.com)."""
        domain = self._extract_domain(target)
        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror:
            ip = domain if self._is_ip(domain) else None
        if not ip:
            return {'status': 'error', 'error': 'Could not resolve IP'}
        try:
            resp = self.session.post(
                'https://domains.yougetsignal.com/domains.php',
                data={'remoteAddress': ip, 'key': ''},
                timeout=self.timeout
            )
            data = resp.json()
            if data.get('status') == 'Success':
                return {
                    'status': 'success',
                    'ip': ip,
                    'domain_count': data.get('domainCount', 0),
                    'domains': [d[0] for d in data.get('domainArray', [])],
                }
            return {'status': 'error', 'error': 'No results found'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}

    # ─────────────────────────────────────────────
    # SSL Certificate Checker
    # ─────────────────────────────────────────────
    def ssl_check(self, domain: str, port: int = 443) -> Dict:
        """Check SSL certificate details for a domain."""
        domain = self._extract_domain(domain)
        result = {'domain': domain, 'port': port, 'status': 'error', 'data': {}}
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    result['data'] = {
                        'issuer': dict(cert.get('issuer', [])),
                        'subject': dict(cert.get('subject', [])),
                        'valid_from': cert.get('notBefore'),
                        'valid_to': cert.get('notAfter'),
                        'serial_number': cert.get('serialNumber'),
                        'version': cert.get('version'),
                        'subject_alt_name': [san[1] for san in cert.get('subjectAltName', [])],
                        'ocsp': cert.get('OCSP', 'N/A'),
                        'ca_issuers': cert.get('caIssuers', 'N/A'),
                    }
                    result['status'] = 'success'
        except Exception as e:
            result['error'] = str(e)
        return result

    # ─────────────────────────────────────────────
    # HTTP Headers
    # ─────────────────────────────────────────────
    def http_headers(self, url: str) -> Dict:
        """Fetch and analyze HTTP headers."""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        result = {'url': url, 'status': 'error', 'headers': {}}
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
            result['status_code'] = resp.status_code
            result['final_url'] = resp.url
            result['headers'] = dict(resp.headers)
            # Security headers check
            security_headers = {
                'Strict-Transport-Security': 'HSTS',
                'Content-Security-Policy': 'CSP',
                'X-Frame-Options': 'Clickjacking Protection',
                'X-Content-Type-Options': 'MIME Sniffing Protection',
                'X-XSS-Protection': 'XSS Protection',
            }
            result['security_headers'] = {}
            for hdr, name in security_headers.items():
                result['security_headers'][name] = resp.headers.get(hdr, '❌ Missing')
            result['server'] = resp.headers.get('Server', 'Unknown')
            result['status'] = 'success'
        except Exception as e:
            result['error'] = str(e)
        return result

    # ─────────────────────────────────────────────
    # Website Screenshot (placeholder - needs playwright/selenium)
    # ─────────────────────────────────────────────
    def take_screenshot(self, url: str, output_path: str = 'screenshot.png') -> Dict:
        """Take a screenshot of a website (requires playwright)."""
        result = {'url': url, 'status': 'error'}
        try:
            # Try using playwright first
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(url, wait_until='networkidle', timeout=self.timeout * 1000)
                page.screenshot(path=output_path, full_page=True)
                browser.close()
            result['status'] = 'success'
            result['path'] = output_path
        except ImportError:
            result['error'] = ('Playwright not installed. Install with: '
                               'pip install playwright && playwright install chromium')
        except Exception as e:
            result['error'] = str(e)
        return result

    # ─────────────────────────────────────────────
    # Wayback Machine
    # ─────────────────────────────────────────────
    def wayback_history(self, domain: str, limit: int = 20) -> Dict:
        """Get historical snapshots from the Wayback Machine."""
        domain = self._extract_domain(domain)
        result = {'domain': domain, 'status': 'error', 'snapshots': []}
        try:
            resp = self.session.get(
                f'https://web.archive.org/cdx/search/cdx?url={domain}&output=json&limit={limit}',
                timeout=self.timeout
            )
            data = resp.json()
            if len(data) > 1:
                snapshots = []
                for entry in data[1:]:
                    snapshots.append({
                        'timestamp': entry[1],
                        'original': entry[2],
                        'status_code': entry[4],
                        'archive_url': f'https://web.archive.org/web/{entry[1]}/{entry[2]}',
                    })
                result['snapshots'] = snapshots
                result['status'] = 'success'
        except Exception as e:
            result['error'] = str(e)
        return result

    # ─────────────────────────────────────────────
    # Technology Stack Detection
    # ─────────────────────────────────────────────
    def detect_technologies(self, url: str) -> Dict:
        """Detect technologies used by a website (basic detection)."""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        result = {'url': url, 'status': 'error', 'technologies': []}
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(resp.text, 'lxml')
            html = resp.text.lower()
            headers = resp.headers
            tech = []

            # Server header
            server = headers.get('Server', '')
            if server:
                tech.append({'name': server.split('/')[0], 'version': server.split('/')[1] if '/' in server else '?', 'category': 'Web Server'})
            # X-Powered-By
            powered = headers.get('X-Powered-By', '')
            if powered:
                tech.append({'name': powered, 'category': 'Framework'})
            # Generator meta tag
            gen = soup.find('meta', attrs={'name': 'generator'})
            if gen and gen.get('content'):
                tech.append({'name': gen['content'], 'category': 'CMS/Framework'})
            # Common patterns
            patterns = {
                'jquery': ('jQuery', 'JavaScript Library'),
                'react': ('React', 'JavaScript Framework'),
                'angular': ('Angular', 'JavaScript Framework'),
                'vue.js': ('Vue.js', 'JavaScript Framework'),
                'bootstrap': ('Bootstrap', 'CSS Framework'),
                'tailwind': ('Tailwind CSS', 'CSS Framework'),
                'wordpress': ('WordPress', 'CMS'),
                'joomla': ('Joomla', 'CMS'),
                'drupal': ('Drupal', 'CMS'),
                'shopify': ('Shopify', 'E-commerce'),
                'woocommerce': ('WooCommerce', 'E-commerce'),
                'laravel': ('Laravel', 'PHP Framework'),
                'django': ('Django', 'Python Framework'),
                'flask': ('Flask', 'Python Framework'),
                'express': ('Express.js', 'Node.js Framework'),
                'next.js': ('Next.js', 'React Framework'),
                'nuxt.js': ('Nuxt.js', 'Vue Framework'),
                'google analytics': ('Google Analytics', 'Analytics'),
                'cloudflare': ('Cloudflare', 'CDN/Security'),
            }
            for pattern, (name, category) in patterns.items():
                if pattern in html:
                    if not any(t['name'] == name for t in tech):
                        tech.append({'name': name, 'category': category})

            result['technologies'] = tech
            result['status'] = 'success'
        except Exception as e:
            result['error'] = str(e)
        return result

    # ─────────────────────────────────────────────
    # Google Dorking (via search)
    # ─────────────────────────────────────────────
    def google_dork(self, query: str, dork_type: str = 'standard') -> Dict:
        """Generate Google dork queries or search."""
        dorks = {
            'admin_panels': f'intitle:"login" inurl:/admin {query}',
            'config_files': f'filetype:env OR filetype:cfg "DB_PASSWORD" {query}',
            'directory_listing': f'intitle:"index of" {query}',
            'exposed_docs': f'filetype:pdf OR filetype:docx confidential {query}',
            'error_messages': f'intitle:"Warning" OR intitle:"Error" "PHP" {query}',
            'login_pages': f'inurl:login OR inurl:signin {query}',
            'sql_errors': f'intext:"sql syntax" OR intext:"mysql_fetch" {query}',
            'subdomains': f'site:*.{query} -www',
            'email_addresses': f'@{query} email OR "contact us"',
            'sensitive_files': f'filetype:sql OR filetype:bak OR filetype:old {query}',
        }
        if dork_type == 'all':
            result = {}
            for key, dork in dorks.items():
                result[key] = dork
            return {'status': 'success', 'dork_type': 'all', 'dorks': result}
        elif dork_type in dorks:
            return {'status': 'success', 'dork_type': dork_type, 'query': dorks[dork_type]}
        else:
            return {'status': 'success', 'dork_type': 'custom', 'query': query}

    # ─────────────────────────────────────────────
    # Helper Methods
    # ─────────────────────────────────────────────
    @staticmethod
    def _is_ip(target: str) -> bool:
        try:
            socket.inet_aton(target)
            return True
        except socket.error:
            return False

    @staticmethod
    def get_public_ip() -> str:
        """Get current public IP address."""
        try:
            resp = requests.get('https://api.ipify.org?format=json', timeout=5)
            return resp.json().get('ip', 'Unknown')
        except Exception:
            return 'Could not determine public IP'

