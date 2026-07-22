"""
People & Social OSINT Module
Functions: Username search, Email OSINT, Phone lookup, Social media search
"""
import re
import json
import hashlib
from typing import Dict, List, Optional
import requests
import phonenumbers
from phonenumbers import carrier, geocoder, timezone


class PeopleOSINT:
    """People investigation and social media OSINT tools."""

    def __init__(self, timeout: int = 10, api_keys: Optional[Dict] = None):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                           'AppleWebKit/537.36 (KHTML, like Gecko) '
                           'Chrome/120.0.0.0 Safari/537.36'),
        })
        self.api_keys = api_keys or {}

        # Common social media platforms for username search
        self.social_platforms = {
            'GitHub': 'https://github.com/{username}',
            'Twitter/X': 'https://x.com/{username}',
            'Instagram': 'https://www.instagram.com/{username}',
            'Reddit': 'https://www.reddit.com/user/{username}',
            'LinkedIn': 'https://www.linkedin.com/in/{username}',
            'Facebook': 'https://www.facebook.com/{username}',
            'YouTube': 'https://www.youtube.com/@{username}',
            'TikTok': 'https://www.tiktok.com/@{username}',
            'Pinterest': 'https://www.pinterest.com/{username}',
            'Snapchat': 'https://www.snapchat.com/add/{username}',
            'Telegram': 'https://t.me/{username}',
            'WhatsApp': 'https://wa.me/{username}',
            'Discord': 'https://discord.com/users/{username}',
            'Twitch': 'https://www.twitch.tv/{username}',
            'Medium': 'https://medium.com/@{username}',
            'Dev.to': 'https://dev.to/{username}',
            'Stack Overflow': 'https://stackoverflow.com/users/{username}',
            'Keybase': 'https://keybase.io/{username}',
            'BitBucket': 'https://bitbucket.org/{username}',
            'GitLab': 'https://gitlab.com/{username}',
            'SoundCloud': 'https://soundcloud.com/{username}',
            'Flickr': 'https://www.flickr.com/people/{username}',
            'Behance': 'https://www.behance.net/{username}',
            'Dribbble': 'https://dribbble.com/{username}',
            'Vimeo': 'https://vimeo.com/{username}',
            'DailyMotion': 'https://www.dailymotion.com/{username}',
            'About.me': 'https://about.me/{username}',
            'Steam': 'https://steamcommunity.com/id/{username}',
            'Spotify': 'https://open.spotify.com/user/{username}',
            'Patreon': 'https://www.patreon.com/{username}',
            'Fiverr': 'https://www.fiverr.com/{username}',
        }

    # ─────────────────────────────────────────────
    # Username Search (Sherlock-style)
    # ─────────────────────────────────────────────
    def username_search(self, username: str, platforms: Optional[List[str]] = None) -> Dict:
        """Search for a username across multiple social media platforms."""
        result = {
            'username': username,
            'status': 'success',
            'profiles_found': 0,
            'profiles': {}
        }
        platforms_to_check = self.social_platforms
        if platforms:
            platforms_to_check = {k: v for k, v in self.social_platforms.items()
                                  if k in platforms}

        for platform, url_template in platforms_to_check.items():
            url = url_template.format(username=username)
            try:
                resp = self.session.head(
                    url, timeout=self.timeout, allow_redirects=True
                )
                if resp.status_code == 200:
                    result['profiles'][platform] = {
                        'url': url,
                        'status_code': resp.status_code,
                        'exists': True
                    }
                    result['profiles_found'] += 1
                else:
                    result['profiles'][platform] = {
                        'url': url,
                        'status_code': resp.status_code,
                        'exists': False
                    }
            except requests.exceptions.SSLError:
                # Try HTTP
                try:
                    url_http = url.replace('https://', 'http://')
                    resp = self.session.head(
                        url_http, timeout=self.timeout, allow_redirects=True
                    )
                    result['profiles'][platform] = {
                        'url': url_http,
                        'status_code': resp.status_code,
                        'exists': resp.status_code == 200
                    }
                    if resp.status_code == 200:
                        result['profiles_found'] += 1
                except Exception:
                    result['profiles'][platform] = {
                        'url': url,
                        'status_code': 0,
                        'exists': False,
                        'error': 'Connection failed'
                    }
            except Exception:
                result['profiles'][platform] = {
                    'url': url,
                    'status_code': 0,
                    'exists': False,
                    'error': 'Connection failed'
                }

        return result

    # ─────────────────────────────────────────────
    # Email OSINT
    # ─────────────────────────────────────────────
    def email_osint(self, email: str) -> Dict:
        """Email investigation: verification, domain check, breach check."""
        result = {
            'email': email,
            'status': 'success',
            'valid_format': False,
            'domain': '',
            'domain_mx': False,
            'disposable': False,
            'breaches': [],
            'gravatar': None,
        }

        # Validate email format
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(pattern, email):
            result['status'] = 'error'
            result['error'] = 'Invalid email format'
            return result
        result['valid_format'] = True

        # Extract domain
        domain = email.split('@')[1]
        result['domain'] = domain

        # Check domain MX records
        try:
            import dns.resolver
            mx_records = dns.resolver.resolve(domain, 'MX')
            result['domain_mx'] = len(mx_records) > 0
            result['mx_servers'] = [str(mx.exchange) for mx in mx_records]
        except Exception:
            result['domain_mx'] = False
            result['mx_servers'] = []

        # Check if disposable email
        disposable_domains = [
            'tempmail.com', '10minutemail.com', 'guerrillamail.com',
            'mailinator.com', 'yopmail.com', 'throwaway.email',
            'trashmail.com', 'sharklasers.com', 'maildrop.cc',
            'getairmail.com', 'temp-mail.org', 'fakeinbox.com',
        ]
        result['disposable'] = domain.lower() in disposable_domains

        # Try Gravatar
        try:
            email_hash = hashlib.md5(email.lower().encode()).hexdigest()
            gravatar_url = f'https://www.gravatar.com/avatar/{email_hash}?d=404'
            g_resp = self.session.get(gravatar_url, timeout=self.timeout)
            if g_resp.status_code == 200:
                result['gravatar'] = gravatar_url
        except Exception:
            pass

        # HaveIBeenPwned check (k-anonymity model)
        try:
            sha1_hash = hashlib.sha1(email.lower().encode()).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]
            hibp_resp = self.session.get(
                f'https://api.pwnedpasswords.com/range/{prefix}',
                timeout=self.timeout
            )
            if hibp_resp.status_code == 200:
                hashes = hibp_resp.text.split('\n')
                for line in hashes:
                    if line.startswith(suffix):
                        count = int(line.split(':')[1].strip())
                        if count > 0:
                            result['breaches'].append({
                                'email': email,
                                'breach_count': count,
                                'note': f'Found in {count} known breaches'
                            })
        except Exception:
            result['breaches'] = result.get('breaches', [])

        return result

    # ─────────────────────────────────────────────
    # Phone Number Lookup
    # ─────────────────────────────────────────────
    def phone_lookup(self, phone_number: str, default_region: str = 'US') -> Dict:
        """Lookup phone number information."""
        result = {
            'phone': phone_number,
            'status': 'error',
            'valid': False,
            'data': {}
        }
        try:
            # Parse phone number
            parsed = phonenumbers.parse(phone_number, default_region)
            if not phonenumbers.is_valid_number(parsed):
                result['error'] = 'Invalid phone number'
                return result

            # Get number info
            national = phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.NATIONAL
            )
            international = phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
            )
            e164 = phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.E164
            )

            # Carrier
            carrier_name = carrier.name_for_number(parsed, 'en')
            # Location
            location = geocoder.description_for_number(parsed, 'en')
            # Timezones
            timezones = timezone.time_zones_for_number(parsed)
            # Number type
            num_type = {
                phonenumbers.PhoneNumberType.MOBILE: 'Mobile',
                phonenumbers.PhoneNumberType.FIXED_LINE: 'Fixed Line',
                phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: 'Fixed Line or Mobile',
                phonenumbers.PhoneNumberType.VOIP: 'VoIP',
                phonenumbers.PhoneNumberType.TOLL_FREE: 'Toll Free',
                phonenumbers.PhoneNumberType.PREMIUM_RATE: 'Premium Rate',
                phonenumbers.PhoneNumberType.SHARED_COST: 'Shared Cost',
                phonenumbers.PhoneNumberType.PERSONAL_NUMBER: 'Personal Number',
                phonenumbers.PhoneNumberType.PAGER: 'Pager',
                phonenumbers.PhoneNumberType.UAN: 'UAN',
                phonenumbers.PhoneNumberType.VOICEMAIL: 'Voicemail',
            }.get(phonenumbers.number_type(parsed), 'Unknown')

            # Country code info
            import pycountry
            country_code = parsed.country_code
            region_code = phonenumbers.region_code_for_number(parsed)
            try:
                country_obj = pycountry.countries.get(alpha_2=region_code)
                country_name = country_obj.name if country_obj else region_code
            except Exception:
                country_name = region_code

            result.update({
                'status': 'success',
                'valid': True,
                'national_format': national,
                'international_format': international,
                'e164_format': e164,
                'country_code': f'+{country_code}',
                'country': country_name,
                'region_code': region_code,
                'location': location or 'Unknown',
                'carrier': carrier_name or 'Unknown',
                'line_type': num_type,
                'timezones': list(timezones),
            })
        except Exception as e:
            result['error'] = str(e)
        return result

    # ─────────────────────────────────────────────
    # Email Format Guesser
    # ─────────────────────────────────────────────
    def guess_email_format(self, first_name: str, last_name: str, domain: str) -> Dict:
        """Guess common email formats for a person."""
        fn = first_name.lower().strip()
        ln = last_name.lower().strip()
        formats = [
            f'{fn}.{ln}@{domain}',
            f'{fn}{ln}@{domain}',
            f'{fn}.{ln}@{domain}',
            f'{fn[0]}{ln}@{domain}',
            f'{fn}{ln[0]}@{domain}',
            f'{fn[0]}.{ln}@{domain}',
            f'{fn}.{ln[0]}@{domain}',
            f'{ln}.{fn}@{domain}',
            f'{fn}@{domain}',
            f'{ln}@{domain}',
            f'{fn[0]}{ln[0]}@{domain}',
            f'{fn}_{ln}@{domain}',
            f'{fn}-{ln}@{domain}',
        ]
        return {
            'first_name': first_name,
            'last_name': last_name,
            'domain': domain,
            'guesses': formats,
            'count': len(formats),
        }

