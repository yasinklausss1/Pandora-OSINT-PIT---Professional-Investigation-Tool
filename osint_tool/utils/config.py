"""
Configuration management for OSINT Pro Tool.
"""
import os
import json
import sys
from typing import Dict, Optional
from pathlib import Path


class Config:
    """Configuration manager for API keys, settings, etc."""

    CONFIG_DIR = Path.home() / '.osint_pro'
    CONFIG_FILE = CONFIG_DIR / 'config.json'
    REPORTS_DIR = Path(__file__).parent.parent / 'reports'

    DEFAULT_CONFIG = {
        'api_keys': {
            'shodan': '',
            'virustotal': '',
            'huntr': '',
            'github': '',
            'twitter': '',
            'telegram': '',
        },
        'settings': {
            'timeout': 10,
            'max_threads': 5,
            'use_tor': False,
            'tor_proxy': 'socks5://127.0.0.1:9050',
            'http_proxy': '',
            'https_proxy': '',
            'default_export_format': 'html',
            'save_history': True,
            'max_history_items': 100,
        },
        'theme': 'darkly',  # ttkbootstrap theme
    }

    def __init__(self):
        self._config = self.load()

    def load(self) -> Dict:
        """Load configuration from file."""
        try:
            if self.CONFIG_FILE.exists():
                with open(self.CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    # Merge with defaults (fill in missing keys)
                    return self._merge_configs(self.DEFAULT_CONFIG, config)
            return dict(self.DEFAULT_CONFIG)
        except Exception:
            return dict(self.DEFAULT_CONFIG)

    def save(self) -> bool:
        """Save configuration to file."""
        try:
            self.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            with open(self.CONFIG_FILE, 'w') as f:
                json.dump(self._config, f, indent=4)
            return True
        except Exception:
            return False

    def get(self, key: str, default=None):
        """Get a config value using dot notation (e.g., 'api_keys.shodan')."""
        parts = key.split('.')
        value = self._config
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                return default
        return value if value is not None else default

    def set(self, key: str, value) -> bool:
        """Set a config value using dot notation."""
        parts = key.split('.')
        config = self._config
        for part in parts[:-1]:
            if part not in config:
                config[part] = {}
            config = config[part]
        config[parts[-1]] = value
        return self.save()

    def get_all(self) -> Dict:
        """Get full configuration dictionary."""
        return dict(self._config)

    def reset(self) -> bool:
        """Reset configuration to defaults."""
        self._config = dict(self.DEFAULT_CONFIG)
        return self.save()

    @staticmethod
    def _merge_configs(default: Dict, override: Dict) -> Dict:
        """Recursively merge two config dictionaries."""
        result = dict(default)
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = Config._merge_configs(result[key], value)
            else:
                result[key] = value
        return result

    @property
    def reports_dir(self) -> Path:
        """Get reports directory (create if not exists)."""
        self.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        return self.REPORTS_DIR


# Global config instance
config = Config()

