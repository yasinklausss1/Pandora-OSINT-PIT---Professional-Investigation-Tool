"""
Data Analysis & Miscellaneous Tools Module
Functions: Google Dorking automation, Text analysis, etc.
"""
import re
import json
from datetime import datetime
from typing import Dict, List, Optional
from collections import Counter
import requests


class DataAnalysis:
    """Data analysis and miscellaneous OSINT tools."""

    def __init__(self, timeout: int = 10, api_keys: Optional[Dict] = None):
        self.timeout = timeout
        self.session = requests.Session()
        self.api_keys = api_keys or {}

    # ─────────────────────────────────────────────
    # Metadata Extractor
    # ─────────────────────────────────────────────
    @staticmethod
    def extract_metadata_from_text(text: str) -> Dict:
        """Extract potential IOCs and patterns from text."""
        result = {
            'status': 'success',
            'iocs': {
                'ip_addresses': [],
                'domains': [],
                'urls': [],
                'email_addresses': [],
                'phone_numbers': [],
                'social_security': [],
                'crypto_addresses': [],
                'mac_addresses': [],
            }
        }

        # IP Addresses (IPv4)
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, text)
        result['iocs']['ip_addresses'] = list(set(ips))

        # Domains
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        domains = re.findall(domain_pattern, text)
        # Filter out false positives
        domains = [d for d in domains if not d.startswith(('http', 'www')) and '.' in d[1:-1]]
        result['iocs']['domains'] = list(set(domains))

        # URLs
        url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s<>\'"]*'
        urls = re.findall(url_pattern, text)
        result['iocs']['urls'] = list(set(urls))

        # Email addresses
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, text)
        result['iocs']['email_addresses'] = list(set(emails))

        # Phone numbers (basic pattern)
        phone_pattern = r'\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'
        phones = re.findall(phone_pattern, text)
        result['iocs']['phone_numbers'] = list(set(phones))

        # MAC addresses
        mac_pattern = r'(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})'
        macs = re.findall(mac_pattern, text)
        result['iocs']['mac_addresses'] = list(set(macs))

        # Bitcoin addresses
        btc_pattern = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
        btc = re.findall(btc_pattern, text)
        result['iocs']['crypto_addresses'] = {
            'bitcoin': list(set(btc))
        }

        # Ethereum addresses
        eth_pattern = r'\b0x[a-fA-F0-9]{40}\b'
        eth = re.findall(eth_pattern, text)
        if eth:
            result['iocs']['crypto_addresses']['ethereum'] = list(set(eth))

        return result

    # ─────────────────────────────────────────────
    # IP Range Calculator
    # ─────────────────────────────────────────────
    @staticmethod
    def ip_range_calculator(cidr: str) -> Dict:
        """Calculate IP range details from CIDR notation."""
        result = {'cidr': cidr, 'status': 'error'}
        try:
            import ipaddress
            network = ipaddress.ip_network(cidr, strict=False)
            result.update({
                'status': 'success',
                'network_address': str(network.network_address),
                'broadcast_address': str(network.broadcast_address),
                'netmask': str(network.netmask),
                'hostmask': str(network.hostmask),
                'num_addresses': network.num_addresses,
                'prefix_length': network.prefixlen,
                'is_private': network.is_private,
                'is_global': network.is_global,
                'first_host': str(network.network_address + 1) if network.num_addresses > 2 else str(network.network_address),
                'last_host': str(network.broadcast_address - 1) if network.num_addresses > 2 else str(network.broadcast_address),
            })
        except ImportError:
            result['error'] = 'ipaddress module not available'
        except Exception as e:
            result['error'] = str(e)
        return result

    # ─────────────────────────────────────────────
    # User Agent Generator
    # ─────────────────────────────────────────────
    @staticmethod
    def generate_user_agents(count: int = 5) -> Dict:
        """Generate realistic user agent strings."""
        agents = []
        ua_templates = [
            # Chrome on Windows
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version} Safari/537.36',
            # Firefox on Windows
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{version}) Gecko/20100101 Firefox/{version}',
            # Edge on Windows
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_v} Safari/537.36 Edg/{version}',
            # Chrome on macOS
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version} Safari/537.36',
            # Safari on macOS
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{safari_v} Safari/605.1.15',
            # Chrome on Linux
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version} Safari/537.36',
            # Firefox on Linux
            'Mozilla/5.0 (X11; Linux i686; rv:{version}) Gecko/20100101 Firefox/{version}',
        ]
        import random
        for i in range(count):
            template = random.choice(ua_templates)
            ver = f'{random.randint(100, 130)}.0.{random.randint(4000, 6000)}.{random.randint(100, 300)}'
            ff_ver = f'{random.randint(100, 130)}.0'
            safari_v = f'{random.randint(14, 17)}.{random.randint(0, 5)}'
            chrome_v = f'{random.randint(100, 120)}.0.{random.randint(4000, 6000)}.{random.randint(100, 300)}'
            ua = template.format(version=ver, chrome_v=chrome_v, safari_v=safari_v)
            agents.append(ua)
        return {'status': 'success', 'count': count, 'user_agents': agents}

    # ─────────────────────────────────────────────
    # Text Analysis
    # ─────────────────────────────────────────────
    @staticmethod
    def analyze_text(text: str) -> Dict:
        """Analyze text for statistics and patterns."""
        words = text.split()
        sentences = re.split(r'[.!?]+', text)
        sentences = [s.strip() for s in sentences if s.strip()]

        return {
            'status': 'success',
            'statistics': {
                'char_count': len(text),
                'char_no_spaces': len(text.replace(' ', '')),
                'word_count': len(words),
                'sentence_count': len(sentences),
                'avg_word_length': sum(len(w) for w in words) / len(words) if words else 0,
                'avg_sentence_length': len(words) / len(sentences) if sentences else 0,
            },
            'frequent_words': Counter(w.lower().strip('.,!?;:"\'()[]{}') for w in words if len(w) > 3).most_common(10),
            'unique_words': len(set(w.lower() for w in words)),
        }

    # ─────────────────────────────────────────────
    # Reverse Image Search URL (via services)
    # ─────────────────────────────────────────────
    @staticmethod
    def reverse_image_search_urls(image_url: str) -> Dict:
        """Generate search URLs for reverse image search engines."""
        return {
            'status': 'success',
            'image_url': image_url,
            'search_engines': {
                'Google Images': f'https://images.google.com/searchbyimage?image_url={image_url}',
                'TinEye': f'https://www.tineye.com/search?url={image_url}',
                'Yandex': f'https://yandex.com/images/search?url={image_url}&rpt=imageview',
                'Bing': f'https://www.bing.com/images/search?view=detailv2&iss=sbi&form=SBIVSP&sbisrc=UrlPaste&q=imgurl:{image_url}',
                'Saucenao': f'https://saucenao.com/search.php?url={image_url}',
                'ImgOps': f'https://imgops.com/{image_url}',
            }
        }

    # ─────────────────────────────────────────────
    # IP WHOIS (RDAP)
    # ─────────────────────────────────────────────
    def ip_whois_rdap(self, ip: str) -> Dict:
        """Query IP WHOIS via RDAP service."""
        result = {'ip': ip, 'status': 'error'}
        try:
            resp = self.session.get(
                f'https://rdap.db.ripe.net/ip/{ip}',
                timeout=self.timeout,
                headers={'Accept': 'application/json'}
            )
            if resp.status_code == 200:
                data = resp.json()
                entities = data.get('entities', [])
                org_info = {}
                for entity in entities:
                    if 'vcardArray' in entity:
                        vcard = entity['vcardArray'][1] if entity['vcardArray'] else []
                        for item in vcard:
                            if item[0] == 'fn':
                                org_info['name'] = item[3]
                            elif item[0] == 'email' and 'email' not in org_info:
                                org_info['email'] = item[3]
                result.update({
                    'status': 'success',
                    'handle': data.get('handle'),
                    'name': data.get('name'),
                    'type': data.get('type'),
                    'country': data.get('country'),
                    'start_range': data.get('startAddress'),
                    'end_range': data.get('endAddress'),
                    'org': org_info.get('name', 'N/A'),
                    'email': org_info.get('email', 'N/A'),
                })
            else:
                result['error'] = f'RDAP query failed: HTTP {resp.status_code}'
        except Exception as e:
            result['error'] = str(e)
        return result

    # ─────────────────────────────────────────────
    # Check if website is online
    # ─────────────────────────────────────────────
    def is_online(self, url: str) -> Dict:
        """Check if a website is online."""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        result = {'url': url, 'status': 'error'}
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            result.update({
                'status': 'success',
                'online': resp.status_code < 500,
                'status_code': resp.status_code,
                'response_time_ms': resp.elapsed.total_seconds() * 1000,
            })
        except requests.exceptions.ConnectionError:
            result['status'] = 'success'
            result['online'] = False
            result['error'] = 'Connection refused'
        except Exception as e:
            result['error'] = str(e)
        return result

