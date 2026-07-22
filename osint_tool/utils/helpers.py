"""
Utility helper functions for OSINT Pro Tool.
"""
import re
import os
import json
import csv
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path


def validate_domain(domain: str) -> bool:
    """Validate a domain name format."""
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))


def validate_ip(ip: str) -> bool:
    """Validate an IPv4 address."""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    parts = ip.split('.')
    return all(0 <= int(p) <= 255 for p in parts)


def validate_email(email: str) -> bool:
    """Validate an email address format."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_url(url: str) -> bool:
    """Validate a URL."""
    pattern = r'^https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s<>\'"]*$'
    return bool(re.match(pattern, url))


def format_timestamp(dt: Optional[datetime] = None) -> str:
    """Format a datetime object or current time."""
    if dt is None:
        dt = datetime.now()
    return dt.strftime('%Y-%m-%d %H:%M:%S')


def filename_safe(text: str) -> str:
    """Convert text to a safe filename."""
    return re.sub(r'[^\w\-_\. ]', '_', text)


def bytes_to_human(size_bytes: int) -> str:
    """Convert bytes to human readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024:
            return f'{size_bytes:.2f} {unit}'
        size_bytes /= 1024
    return f'{size_bytes:.2f} PB'


def export_to_json(data: Dict, filepath: Path) -> bool:
    """Export data to JSON file."""
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)
        return True
    except Exception:
        return False


def export_to_csv(data: List[Dict], filepath: Path, 
                  fieldnames: Optional[List[str]] = None) -> bool:
    """Export list of dictionaries to CSV file."""
    try:
        if not data:
            return False
        if fieldnames is None:
            fieldnames = list(data[0].keys())
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)
        return True
    except Exception:
        return False


def export_to_txt(text: str, filepath: Path) -> bool:
    """Export text to a TXT file."""
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(text)
        return True
    except Exception:
        return False


def flatten_dict(d: Dict, parent_key: str = '', sep: str = '.') -> Dict:
    """Flatten a nested dictionary."""
    items = []
    for k, v in d.items():
        new_key = f'{parent_key}{sep}{k}' if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        elif isinstance(v, list):
            items.append((new_key, ', '.join(str(x) for x in v)))
        else:
            items.append((new_key, v))
    return dict(items)


def safe_print(text: str, color: Optional[str] = None):
    """Print text safely (handles encoding issues)."""
    try:
        if color and sys.platform != 'win32':
            # Simple color support for non-Windows
            colors = {
                'red': '\033[91m',
                'green': '\033[92m',
                'yellow': '\033[93m',
                'blue': '\033[94m',
                'magenta': '\033[95m',
                'cyan': '\033[96m',
                'white': '\033[97m',
                'bold': '\033[1m',
                'reset': '\033[0m',
            }
            print(f"{colors.get(color, '')}{text}{colors.get('reset', '')}")
        else:
            print(text)
    except UnicodeEncodeError:
        print(text.encode('ascii', 'ignore').decode())
    except Exception:
        print(str(text))


def truncate_text(text: str, max_length: int = 100) -> str:
    """Truncate text to a maximum length."""
    if len(text) <= max_length:
        return text
    return text[:max_length - 3] + '...'

