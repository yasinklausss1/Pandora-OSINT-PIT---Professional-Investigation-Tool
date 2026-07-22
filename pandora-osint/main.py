#!/usr/bin/env python3
"""
🕵️ OSINT PIT - Professional Open Source Intelligence Tool

A comprehensive OSINT investigation tool with GUI and CLI interfaces.

Usage:
    python main.py          # Start GUI
    python main.py --cli    # Start CLI (interactive)
    python main.py --help   # Show help
"""

import sys
import os
import argparse
import json
from datetime import datetime

# Ensure we can import modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ─────────────────────────────────────────────
# TEAM IDENTIFIER - Change this to your team name
# ─────────────────────────────────────────────
TEAM_NAME = "PANDORA"


def get_team_banner():
    """Generate ASCII art banner for PANDORA team."""
    art = r"""
    ╔══════════════════════════════════════════════════════╗
    ║                                                     ║
    ║          ██████   █████   ███    ██ ██████           ║
    ║         ██   ██ ██   ██ ████   ██ ██   ██           ║
    ║         ██████  ███████ ██ ██  ██ ██   ██           ║
    ║         ██      ██   ██ ██  ██ ██ ██   ██           ║
    ║         ██      ██   ██ ██   ████ ██████            ║
    ║                                                     ║
    ║              ██████  ██████  ███████  ██████         ║
    ║              ██  ██ ██  ██ ██      ██  ██         ║
    ║              ██████ ██████ █████   ██████         ║
    ║              ██     ██  ██ ██      ██  ██         ║
    ║              ██     ██  ██ ███████ ██  ██         ║
    ║                                                     ║
    ╚══════════════════════════════════════════════════════╝
    """
    return art


def print_banner():
    """Print the OSINT PIT banner with team name."""
    team_art = get_team_banner()
    banner = f"""
{team_art}
    ╔══════════════════════════════════════════════════════╗
    ║              Professional OSINT Tool                 ║
    ║              Open Source Intelligence                ║
    ╚══════════════════════════════════════════════════════╝
    """
    print(banner)
    print(f'  Team: {TEAM_NAME} | OSINT PIT | Version 1.0.0 | Started: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    print('  ' + '=' * 50)
    print()


def run_cli():
    """Run the interactive CLI mode."""
    from modules.web_osint import WebOSINT
    from modules.people_osint import PeopleOSINT
    from modules.network_tools import NetworkTools
    from modules.data_analysis import DataAnalysis
    from modules.reporting import Reporting

    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        from rich.prompt import Prompt
        from rich.syntax import Syntax
        from rich import print as rprint
        use_rich = True
        console = Console()
    except ImportError:
        use_rich = False
        console = None
        print('[!] For better CLI experience: pip install rich')

    # Initialize modules
    web = WebOSINT()
    people = PeopleOSINT()
    network = NetworkTools()
    analysis = DataAnalysis()
    reporting = Reporting()

    def print_result(data: dict, title: str = 'Result'):
        """Print result data."""
        if use_rich:
            json_str = json.dumps(data, indent=2, default=str)
            console.print(Panel(Syntax(json_str, 'json', theme='monokai'),
                          title=f'[bold cyan]{title}[/]', border_style='cyan'))
        else:
            print(f'\n{"="*60}')
            print(f'  {title}')
            print(f'{"="*60}')
            print(json.dumps(data, indent=2, default=str))

    print_banner()
    if use_rich:
        console.print('[bold green]🕵️ OSINT PIT CLI Mode[/]')
        console.print(f'[bold yellow]Team: {TEAM_NAME}[/]')
        console.print('[dim]Type "help" for commands, "quit" to exit[/]\n')
    else:
        print(f'🕵️ OSINT PIT CLI Mode - Team {TEAM_NAME}')
        print('Type "help" for commands, "quit" to exit\n')

    while True:
        try:
            if use_rich:
                cmd = Prompt.ask(f'[bold yellow]{TEAM_NAME}>[/]')
            else:
                cmd = input(f'{TEAM_NAME}> ').strip()

            if not cmd:
                continue
            if cmd.lower() in ('quit', 'exit', 'q'):
                print(f'Goodbye from {TEAM_NAME}!')
                break
            if cmd.lower() == 'help':
                print_help()
                continue
            if cmd.lower() == 'clear':
                os.system('cls' if os.name == 'nt' else 'clear')
                print_banner()
                continue

            parts = cmd.split(' ', 1)
            command = parts[0].lower()
            args = parts[1].strip() if len(parts) > 1 else ''

            if not args and command not in ('help', 'clear', 'quit', 'exit'):
                print('[!] Missing arguments. Usage: <command> <target>')
                continue

            # Web tools
            if command == 'whois':
                print_result(web.whois_lookup(args), f'WHOIS: {args}')
            elif command == 'dns':
                print_result(web.dns_lookup(args), f'DNS Records: {args}')
            elif command == 'geoip':
                print_result(web.ip_geolocation(args), f'IP Geolocation: {args}')
            elif command == 'revip':
                print_result(web.reverse_ip(args), f'Reverse IP: {args}')
            elif command == 'ssl':
                print_result(web.ssl_check(args), f'SSL Certificate: {args}')
            elif command == 'headers':
                print_result(web.http_headers(args), f'HTTP Headers: {args}')
            elif command == 'wayback':
                print_result(web.wayback_history(args), f'Wayback History: {args}')
            elif command == 'tech':
                print_result(web.detect_technologies(args), f'Technologies: {args}')
            elif command == 'dork':
                dork_type = 'all'
                if ' ' in args:
                    parts2 = args.split(' ', 1)
                    dork_type = parts2[0]
                    args = parts2[1]
                print_result(web.google_dork(args, dork_type), f'Google Dorks: {args}')

            # People tools
            elif command == 'username':
                print_result(people.username_search(args), f'Username Search: {args}')
            elif command == 'email':
                print_result(people.email_osint(args), f'Email OSINT: {args}')
            elif command == 'phone':
                region = 'US'
                if ' ' in args:
                    parts2 = args.split(' ', 1)
                    args = parts2[0]
                    region = parts2[1]
                print_result(people.phone_lookup(args, region), f'Phone Lookup: {args}')
            elif command == 'emailguess':
                parts2 = args.split(' ', 2) if ' ' in args else []
                if len(parts2) >= 3:
                    fname, lname, domain = parts2[0], parts2[1], parts2[2]
                    print_result(people.guess_email_format(fname, lname, domain),
                                 f'Email Guesses: {fname} {lname} @ {domain}')
                else:
                    print('[!] Usage: emailguess <first> <last> <domain>')

            # Network tools
            elif command == 'portscan':
                common = 'full' not in args
                target = args.replace(' full', '')
                print_result(network.port_scan(target, common_only=common),
                             f'Port Scan: {target}')
            elif command == 'ping':
                print_result(network.ping(args), f'Ping: {args}')
            elif command == 'traceroute':
                print_result(network.traceroute(args), f'Traceroute: {args}')
            elif command == 'urlexpand':
                print_result(network.url_expander(args), f'URL Expand: {args}')
            elif command == 'hash':
                algo = 'sha256'
                if ' ' in args:
                    parts2 = args.split(' ', 1)
                    algo = parts2[0]
                    text = parts2[1]
                else:
                    text = args
                print_result(network.hash_text(text, algo), f'Hash ({algo}): {text}')
            elif command == 'hashid':
                print_result(network.identify_hash(args), f'Hash Identify: {args}')
            elif command == 'qr':
                result = network.generate_qr(args, 'qrcode_cli.png')
                print_result(result, f'QR Code: {args}')
                if result['status'] == 'success':
                    print(f'  [✓] QR Code saved to: {result["path"]}')

            # Data analysis
            elif command == 'iocs':
                print_result(analysis.extract_metadata_from_text(args), 'IOC Extraction')
            elif command == 'cidr':
                print_result(analysis.ip_range_calculator(args), f'CIDR: {args}')
            elif command == 'online':
                print_result(analysis.is_online(args), f'Online Check: {args}')
            else:
                print(f'[!] Unknown command: {command}')
                print('Type "help" for available commands.')

        except KeyboardInterrupt:
            print(f'\nGoodbye from {TEAM_NAME}!')
            break
        except Exception as e:
            print(f'[!] Error: {str(e)}')


def print_help():
    """Print help information."""
    help_text = f"""
╔══════════════════════════════════════════════════════════════╗
║                 {TEAM_NAME} OSINT PIT - Help                ║
╠══════════════════════════════════════════════════════════════╣
║  GENERAL                                                    ║
║    help           - Show this help                           ║
║    clear          - Clear the screen                          ║
║    quit/exit      - Exit the program                         ║
║                                                            ║
║  WEB & DOMAIN INVESTIGATION                                 ║
║    whois <domain>       - WHOIS lookup                       ║
║    dns <domain>         - DNS records                        ║
║    geoip <ip/domain>    - IP geolocation                     ║
║    revip <ip/domain>    - Reverse IP lookup                  ║
║    ssl <domain>         - SSL certificate check              ║
║    headers <url>        - HTTP headers                       ║
║    wayback <domain>     - Wayback Machine history            ║
║    tech <url>           - Technology stack detection         ║
║    dork [type] <target> - Google dork generator              ║
║                                                            ║
║  PEOPLE & SOCIAL MEDIA                                      ║
║    username <username>  - Search across social platforms     ║
║    email <email>        - Email investigation                ║
║    phone <number> [reg] - Phone number lookup               ║
║    emailguess <f> <l> <d> - Guess email formats             ║
║                                                            ║
║  NETWORK & SECURITY                                         ║
║    portscan <target>    - Scan common ports                  ║
║    ping <target>        - Ping a host                        ║
║    traceroute <target>  - Trace route to host                ║
║    urlexpand <url>      - Expand shortened URL               ║
║    hash [algo] <text>   - Generate hash                      ║
║    hashid <hash>        - Identify hash type                 ║
║    qr <data>            - Generate QR code                   ║
║                                                            ║
║  DATA ANALYSIS                                              ║
║    iocs <text>          - Extract IOCs from text             ║
║    cidr <cidr>          - IP range calculator                ║
║    online <url>         - Check if website is online         ║
╚══════════════════════════════════════════════════════════════╝
    """
    print(help_text)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description=f'🕵️ {TEAM_NAME} OSINT PIT - Professional Open Source Intelligence Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  python main.py              # Start GUI
  python main.py --cli        # Start interactive CLI
  python main.py --help       # Show this help

{TEAM_NAME} CLI Commands:
  whois example.com
  dns example.com
  geoip 8.8.8.8
  username johndoe
  email user@example.com
  portscan example.com
        """
    )
    parser.add_argument('--cli', action='store_true', help='Run in CLI mode')
    parser.add_argument('--command', '-c', type=str, nargs='*',
                        help='Run a single CLI command and exit')

    args = parser.parse_args()

    if args.command:
        print('Single command mode. Use --cli for interactive mode.')
        return

    if args.cli:
        run_cli()
    else:
        # Start GUI
        try:
            from ui.app import OSINTApp
            app = OSINTApp()
            app.run()
        except ImportError as e:
            print(f'[!] Error starting GUI: {e}')
            print('[!] Falling back to CLI mode...')
            run_cli()
        except Exception as e:
            print(f'[!] Error: {e}')
            print('[!] Falling back to CLI mode...')
            run_cli()


if __name__ == '__main__':
    main()
