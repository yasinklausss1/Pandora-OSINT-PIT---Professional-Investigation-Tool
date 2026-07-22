"""
Network & Security Tools Module
Functions: Port scanner, Ping, Traceroute, Shodan, HIBP, URL tools
"""
import socket
import subprocess
import sys
import re
import json
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, unquote

import requests


class NetworkTools:
    """Network investigation and security tools."""

    def __init__(self, timeout: int = 5, api_keys: Optional[Dict] = None):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                           'AppleWebKit/537.36 (KHTML, like Gecko) '
                           'Chrome/120.0.0.0 Safari/537.36'),
        })
        self.api_keys = api_keys or {}

    # ─────────────────────────────────────────────
    # Port Scanner
    # ─────────────────────────────────────────────
    def port_scan(self, target: str, ports: Optional[List[int]] = None,
                  common_only: bool = True) -> Dict:
        """
        Scan common or specified ports on a target host.
        Uses TCP connect scan.
        """
        if ports is None:
            if common_only:
                ports = [
                    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
                    445, 993, 995, 1433, 1521, 2049, 2082, 2083, 2086, 2087,
                    2095, 2096, 2222, 3306, 3389, 5432, 5555, 5900, 5984,
                    5985, 5986, 6379, 7001, 7002, 8000, 8001, 8080, 8081,
                    8443, 8888, 9000, 9001, 9090, 9200, 9300, 9418, 10000,
                    11211, 27017, 27018, 50000, 50070, 50075,
                ]
            else:
                # Top 100 ports
                ports = [
                    7, 9, 13, 21, 22, 23, 25, 26, 37, 53,
                    79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
                    139, 143, 144, 179, 199, 389, 427, 443, 445, 465,
                    513, 514, 515, 543, 544, 548, 554, 587, 631, 646,
                    873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110,
                    1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717,
                    3000, 3128, 3306, 3360, 3386, 3389, 3390, 3986, 4000, 4001,
                    4002, 4333, 4500, 4662, 4899, 5000, 5001, 5002, 5003, 5004,
                    5005, 5009, 5050, 5060, 5101, 5190, 5357, 5432, 5555, 5631,
                    5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8001, 8008,
                    8009, 8080, 8081, 8443, 8888, 9000, 9001, 9090, 9100, 9102,
                    9200, 9800, 9898, 9999, 10000, 10001, 10010, 12345, 20000, 20005,
                    20006, 22222, 27374, 31337, 33434, 37777, 44444, 50000, 65535,
                ]

        # Resolve hostname
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            return {'status': 'error', 'error': f'Could not resolve {target}'}

        result = {
            'target': target,
            'ip': ip,
            'status': 'success',
            'open_ports': [],
            'scan_time': '',
            'ports_scanned': len(ports),
        }

        start_time = datetime.now()
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            try:
                sock.connect((ip, port))
                # Get service banner if possible
                try:
                    sock.send(b'\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                except:
                    banner = ''
                sock.close()
                service = socket.getservbyport(port, 'tcp') if port <= 49151 else 'unknown'
                result['open_ports'].append({
                    'port': port,
                    'service': service,
                    'banner': banner[:100] if banner else '',
                })
            except (socket.timeout, ConnectionRefusedError, OSError):
                pass
            finally:
                sock.close()

        result['scan_time'] = str(datetime.now() - start_time)
        return result

    # ─────────────────────────────────────────────
    # Ping
    # ─────────────────────────────────────────────
    def ping(self, target: str, count: int = 4) -> Dict:
        """Ping a target host."""
        result = {'target': target, 'status': 'error'}
        try:
            # Determine OS and use appropriate ping command
            is_windows = sys.platform.startswith('win')
            if is_windows:
                cmd = ['ping', '-n', str(count), target]
            else:
                cmd = ['ping', '-c', str(count), target]

            resp = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout * count
            )
            result['raw_output'] = resp.stdout + resp.stderr
            result['return_code'] = resp.returncode

            # Parse results
            if is_windows:
                # Windows parsing
                received_match = re.search(r'Received = (\d+)', resp.stdout)
                loss_match = re.search(r'Loss = (\d+)%', resp.stdout)
                time_match = re.search(r'Minimum = (\d+)ms.*Maximum = (\d+)ms.*Average = (\d+)ms', resp.stdout)
                result['received'] = int(received_match.group(1)) if received_match else 0
                result['loss_percent'] = int(loss_match.group(1)) if loss_match else 0
                if time_match:
                    result['min_rtt'] = int(time_match.group(1))
                    result['max_rtt'] = int(time_match.group(2))
                    result['avg_rtt'] = int(time_match.group(3))
            else:
                # Linux/Mac parsing
                stats_match = re.search(r'(\d+) packets transmitted, (\d+) received', resp.stdout)
                time_match = re.search(r'min/avg/max/(?:mdev|stddev) = ([\d.]+)/([\d.]+)/([\d.]+)', resp.stdout)
                if stats_match:
                    result['transmitted'] = int(stats_match.group(1))
                    result['received'] = int(stats_match.group(2))
                    result['loss_percent'] = ((result['transmitted'] - result['received'])
                                              / result['transmitted'] * 100)
                if time_match:
                    result['min_rtt'] = float(time_match.group(1))
                    result['avg_rtt'] = float(time_match.group(2))
                    result['max_rtt'] = float(time_match.group(3))

            result['status'] = 'success'
        except subprocess.TimeoutExpired:
            result['error'] = 'Ping timed out'
        except Exception as e:
            result['error'] = str(e)
        return result

    # ─────────────────────────────────────────────
    # Traceroute
    # ─────────────────────────────────────────────
    def traceroute(self, target: str, max_hops: int = 30) -> Dict:
        """Trace route to target host."""
        result = {'target': target, 'status': 'error', 'hops': []}
        try:
            is_windows = sys.platform.startswith('win')
            if is_windows:
                cmd = ['tracert', '-d', '-h', str(max_hops), target]
            else:
                cmd = ['traceroute', '-n', '-m', str(max_hops), target]

            resp = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self.timeout * max_hops
            )
            result['raw_output'] = resp.stdout + resp.stderr
            result['return_code'] = resp.returncode

            # Parse hops (basic)
            lines = resp.stdout.split('\n')
            for line in lines:
                if is_windows:
                    match = re.search(r'\s*(\d+)\s+<?(\d+)\s+ms\s+<?(\d+)\s+ms\s+<?(\d+)\s+ms\s+(\S+)', line)
                else:
                    match = re.search(r'\s*(\d+)\s+([\d.*]+)\s+([\d.*]+)\s+([\d.*]+)\s+(\S+)', line)
                if match:
                    hop_num = int(match.group(1))
                    hop_ip = match.group(5).strip('()')
                    # Clean time values
                    times = []
                    for g in range(2, 5):
                        t = match.group(g)
                        t = t.replace('<', '').replace('*', '0')
                        try:
                            times.append(float(t))
                        except ValueError:
                            times.append(0)
                    result['hops'].append({
                        'hop': hop_num,
                        'ip': hop_ip if hop_ip != '*' else 'Request timed out',
                        'rtt1': times[0] if times[0] > 0 else None,
                        'rtt2': times[1] if times[1] > 0 else None,
                        'rtt3': times[2] if times[2] > 0 else None,
                    })

            result['status'] = 'success'
            result['total_hops'] = len(result['hops'])
        except subprocess.TimeoutExpired:
            result['error'] = 'Traceroute timed out'
        except Exception as e:
            result['error'] = str(e)
        return result

    # ─────────────────────────────────────────────
    # Shodan Query
    # ─────────────────────────────────────────────
    def shodan_query(self, query: str) -> Dict:
        """Query Shodan API for host/device information."""
        api_key = self.api_keys.get('shodan', '')
        if not api_key:
            return {'status': 'error', 'error': 'No Shodan API key configured'}
        result = {'query': query, 'status': 'error', 'results': []}
        try:
            import shodan
            api = shodan.Shodan(api_key)
            # If it looks like an IP, do host lookup
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', query):
                host = api.host(query)
                result['results'] = [{
                    'ip': host.get('ip_str'),
                    'org': host.get('org'),
                    'isp': host.get('isp'),
                    'os': host.get('os'),
                    'country': host.get('country_name'),
                    'city': host.get('city'),
                    'ports': host.get('ports'),
                    'vulns': host.get('vulns', []),
                    'hostnames': host.get('hostnames', []),
                }]
                result['type'] = 'host'
            else:
                # Search query
                search_results = api.search(query)
                for match in search_results.get('matches', [])[:20]:
                    result['results'].append({
                        'ip': match.get('ip_str'),
                        'port': match.get('port'),
                        'org': match.get('org'),
                        'hostnames': match.get('hostnames', []),
                        'product': match.get('product', ''),
                        'version': match.get('version', ''),
                        'transport': match.get('transport', ''),
                    })
                result['total'] = search_results.get('total', 0)
                result['type'] = 'search'
            result['status'] = 'success'
        except shodan.APIError as e:
            result['error'] = f'Shodan API Error: {str(e)}'
        except ImportError:
            result['error'] = 'Shodan library not installed (pip install shodan)'
        except Exception as e:
            result['error'] = str(e)
        return result

    # ─────────────────────────────────────────────
    # URL Expander / Unshortener
    # ─────────────────────────────────────────────
    def url_expander(self, short_url: str) -> Dict:
        """Expand shortened URLs to their final destination."""
        result = {'original_url': short_url, 'status': 'error'}
        try:
            resp = self.session.head(
                short_url, allow_redirects=True, timeout=self.timeout
            )
            redirect_chain = []
            if resp.history:
                for r in resp.history:
                    redirect_chain.append({
                        'url': r.url,
                        'status_code': r.status_code,
                    })
            result.update({
                'status': 'success',
                'final_url': resp.url,
                'status_code': resp.status_code,
                'redirect_count': len(resp.history),
                'redirect_chain': redirect_chain,
            })
        except Exception as e:
            result['error'] = str(e)
        return result

    # ─────────────────────────────────────────────
    # Hash Generator / Identifier
    # ─────────────────────────────────────────────
    @staticmethod
    def hash_text(text: str, algorithm: str = 'sha256') -> Dict:
        """Generate hash of a text string using specified algorithm."""
        valid_algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha224': hashlib.sha224,
            'sha256': hashlib.sha256,
            'sha384': hashlib.sha384,
            'sha512': hashlib.sha512,
            'blake2b': hashlib.blake2b,
            'blake2s': hashlib.blake2s,
        }
        if algorithm not in valid_algorithms:
            return {
                'status': 'error',
                'error': f'Unsupported algorithm. Choose from: {", ".join(valid_algorithms.keys())}'
            }
        import hashlib
        hash_func = valid_algorithms[algorithm]
        hash_obj = hash_func(text.encode('utf-8'))
        return {
            'status': 'success',
            'text': text,
            'algorithm': algorithm,
            'hash': hash_obj.hexdigest(),
            'hash_type': 'hex',
        }

    @staticmethod
    def identify_hash(hash_string: str) -> Dict:
        """Try to identify the type of hash based on length and pattern."""
        hash_info = {
            '32': ['MD4', 'MD5', 'MD2', 'RIPEMD-128'],
            '40': ['SHA-1', 'RIPEMD-160', 'Haval-160'],
            '56': ['SHA-224', 'SHA3-224', 'BLAKE2s-224'],
            '64': ['SHA-256', 'SHA3-256', 'BLAKE2s-256', 'Skein-256'],
            '96': ['SHA-384', 'SHA3-384', 'BLAKE2b-384'],
            '128': ['SHA-512', 'SHA3-512', 'BLAKE2b-512', 'Skein-512'],
        }

        length = len(hash_string)
        possible_types = hash_info.get(str(length), [])
        # Check if valid hex
        is_hex = all(c in '0123456789abcdefABCDEF' for c in hash_string)

        return {
            'status': 'success',
            'hash': hash_string,
            'length': length,
            'is_hex': is_hex,
            'possible_types': possible_types,
        }

    # ─────────────────────────────────────────────
    # QR Code Generator
    # ─────────────────────────────────────────────
    @staticmethod
    def generate_qr(data: str, output_path: str = 'qrcode.png', 
                    scale: int = 8) -> Dict:
        """Generate a QR code from text/data."""
        result = {'data': data, 'status': 'error'}
        try:
            import pyqrcode
            qr = pyqrcode.create(data)
            qr.png(output_path, scale=scale)
            result['status'] = 'success'
            result['path'] = output_path
            result['size'] = f'{scale * 50}x{scale * 50}px'
        except ImportError:
            result['error'] = 'pyqrcode/pypng not installed (pip install pyqrcode pypng)'
        except Exception as e:
            result['error'] = str(e)
        return result

