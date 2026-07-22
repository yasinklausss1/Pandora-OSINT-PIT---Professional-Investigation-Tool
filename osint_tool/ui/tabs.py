"""
Tab definitions for the OSINT Pro GUI application.
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import json
from datetime import datetime
from typing import Dict, Optional


class BaseTab(ttk.Frame):
    """Base class for all OSINT tool tabs."""

    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self.setup_ui()

    def setup_ui(self):
        raise NotImplementedError

    def log(self, message: str, level: str = 'info'):
        """Log a message to the output area."""
        self.app.log(message, level)

    def run_in_thread(self, target, args=(), callback=None):
        """Run a function in a separate thread."""
        thread = threading.Thread(target=self._thread_wrapper, args=(target, args, callback))
        thread.daemon = True
        thread.start()

    def _thread_wrapper(self, target, args, callback):
        try:
            result = target(*args)
            if callback:
                self.after(0, callback, result)
        except Exception as e:
            self.after(0, self.log, f'Error: {str(e)}', 'error')


class WebInvestigationTab(BaseTab):
    """Tab for web/domain investigation tools."""

    def setup_ui(self):
        # Input frame
        input_frame = ttk.LabelFrame(self, text='Target Input', padding=10)
        input_frame.pack(fill='x', padx=10, pady=5)

        ttk.Label(input_frame, text='Domain/IP/URL:').grid(row=0, column=0, sticky='w')
        self.target_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.target_var, width=60).grid(row=0, column=1, padx=5)

        # Tool buttons
        btn_frame = ttk.LabelFrame(self, text='Web Tools', padding=10)
        btn_frame.pack(fill='x', padx=10, pady=5)

        tools = [
            ('🌐 WHOIS Lookup', self.run_whois),
            ('📋 DNS Records', self.run_dns),
            ('📍 IP Geolocation', self.run_geolocation),
            ('🔄 Reverse IP', self.run_reverse_ip),
            ('🔒 SSL Check', self.run_ssl),
            ('📡 HTTP Headers', self.run_headers),
            ('🕰️ Wayback Machine', self.run_wayback),
            ('🔧 Technology Stack', self.run_tech),
        ]
        for i, (label, cmd) in enumerate(tools):
            row, col = divmod(i, 4)
            ttk.Button(btn_frame, text=label, command=cmd, width=20).grid(row=row, column=col, padx=3, pady=3)

        # Output area
        output_frame = ttk.LabelFrame(self, text='Results', padding=10)
        output_frame.pack(fill='both', expand=True, padx=10, pady=5)

        self.output_text = scrolledtext.ScrolledText(
            output_frame, wrap='word', font=('Consolas', 10),
            bg='#1e1e1e', fg='#e0e0e0', insertbackground='white'
        )
        self.output_text.pack(fill='both', expand=True)

    def _get_target(self):
        target = self.target_var.get().strip()
        if not target:
            messagebox.showwarning('Input Required', 'Please enter a domain, IP, or URL.')
            return None
        return target

    def _display_result(self, result):
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, json.dumps(result, indent=2, default=str))
        self.output_text.see(tk.END)

    def run_whois(self):
        target = self._get_target()
        if not target:
            return
        self.log(f'Running WHOIS lookup for {target}...')
        self.run_in_thread(
            self.app.osint.web_osint.whois_lookup, (target,),
            lambda r: self._display_result(r)
        )

    def run_dns(self):
        target = self._get_target()
        if not target:
            return
        self.log(f'Running DNS lookup for {target}...')
        self.run_in_thread(
            self.app.osint.web_osint.dns_lookup, (target,),
            lambda r: self._display_result(r)
        )

    def run_geolocation(self):
        target = self._get_target()
        if not target:
            return
        self.log(f'Running IP geolocation for {target}...')
        self.run_in_thread(
            self.app.osint.web_osint.ip_geolocation, (target,),
            lambda r: self._display_result(r)
        )

    def run_reverse_ip(self):
        target = self._get_target()
        if not target:
            return
        self.log(f'Running reverse IP lookup for {target}...')
        self.run_in_thread(
            self.app.osint.web_osint.reverse_ip, (target,),
            lambda r: self._display_result(r)
        )

    def run_ssl(self):
        target = self._get_target()
        if not target:
            return
        self.log(f'Running SSL check for {target}...')
        self.run_in_thread(
            self.app.osint.web_osint.ssl_check, (target,),
            lambda r: self._display_result(r)
        )

    def run_headers(self):
        target = self._get_target()
        if not target:
            return
        self.log(f'Fetching HTTP headers for {target}...')
        self.run_in_thread(
            self.app.osint.web_osint.http_headers, (target,),
            lambda r: self._display_result(r)
        )

    def run_wayback(self):
        target = self._get_target()
        if not target:
            return
        self.log(f'Fetching Wayback Machine history for {target}...')
        self.run_in_thread(
            self.app.osint.web_osint.wayback_history, (target,),
            lambda r: self._display_result(r)
        )

    def run_tech(self):
        target = self._get_target()
        if not target:
            return
        self.log(f'Detecting technologies for {target}...')
        self.run_in_thread(
            self.app.osint.web_osint.detect_technologies, (target,),
            lambda r: self._display_result(r)
        )


class PeopleInvestigationTab(BaseTab):
    """Tab for people/social media investigation."""

    def setup_ui(self):
        # Notebook for sub-tools
        notebook = ttk.Notebook(self)
        notebook.pack(fill='both', expand=True, padx=5, pady=5)

        # Username search tab
        self._create_username_tab(notebook)
        # Email tab
        self._create_email_tab(notebook)
        # Phone tab
        self._create_phone_tab(notebook)

    def _create_output_area(self, parent):
        text = scrolledtext.ScrolledText(
            parent, wrap='word', font=('Consolas', 10),
            bg='#1e1e1e', fg='#e0e0e0', insertbackground='white'
        )
        text.pack(fill='both', expand=True, padx=5, pady=5)
        return text

    def _display_result(self, text_widget, result):
        text_widget.delete(1.0, tk.END)
        text_widget.insert(tk.END, json.dumps(result, indent=2, default=str))
        text_widget.see(tk.END)

    def _create_username_tab(self, notebook):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text='🔍 Username Search')

        input_frame = ttk.Frame(frame)
        input_frame.pack(fill='x', padx=5, pady=5)

        ttk.Label(input_frame, text='Username:').pack(side='left')
        self.username_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.username_var, width=40).pack(side='left', padx=5)
        ttk.Button(input_frame, text='Search All Platforms', command=self.run_username_search).pack(side='left', padx=2)

        self.username_output = self._create_output_area(frame)

    def _create_email_tab(self, notebook):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text='📧 Email OSINT')

        input_frame = ttk.Frame(frame)
        input_frame.pack(fill='x', padx=5, pady=5)

        ttk.Label(input_frame, text='Email:').pack(side='left')
        self.email_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.email_var, width=40).pack(side='left', padx=5)
        ttk.Button(input_frame, text='Investigate Email', command=self.run_email_osint).pack(side='left', padx=2)

        self.email_output = self._create_output_area(frame)

    def _create_phone_tab(self, notebook):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text='📞 Phone Lookup')

        input_frame = ttk.Frame(frame)
        input_frame.pack(fill='x', padx=5, pady=5)

        ttk.Label(input_frame, text='Phone Number:').pack(side='left')
        self.phone_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.phone_var, width=40).pack(side='left', padx=5)
        ttk.Label(input_frame, text='Region (e.g., US):').pack(side='left', padx=2)
        self.region_var = tk.StringVar(value='US')
        ttk.Entry(input_frame, textvariable=self.region_var, width=5).pack(side='left')
        ttk.Button(input_frame, text='Lookup', command=self.run_phone_lookup).pack(side='left', padx=2)

        self.phone_output = self._create_output_area(frame)

    def run_username_search(self):
        username = self.username_var.get().strip()
        if not username:
            messagebox.showwarning('Input Required', 'Please enter a username.')
            return
        self.log(f'Searching for username: {username}...')
        self.run_in_thread(
            self.app.osint.people_osint.username_search, (username,),
            lambda r: self._display_result(self.username_output, r)
        )

    def run_email_osint(self):
        email = self.email_var.get().strip()
        if not email:
            messagebox.showwarning('Input Required', 'Please enter an email.')
            return
        self.log(f'Investigating email: {email}...')
        self.run_in_thread(
            self.app.osint.people_osint.email_osint, (email,),
            lambda r: self._display_result(self.email_output, r)
        )

    def run_phone_lookup(self):
        phone = self.phone_var.get().strip()
        region = self.region_var.get().strip()
        if not phone:
            messagebox.showwarning('Input Required', 'Please enter a phone number.')
            return
        self.log(f'Looking up phone: {phone}...')
        self.run_in_thread(
            self.app.osint.people_osint.phone_lookup, (phone, region),
            lambda r: self._display_result(self.phone_output, r)
        )


class NetworkToolsTab(BaseTab):
    """Tab for network/security tools."""

    def setup_ui(self):
        notebook = ttk.Notebook(self)
        notebook.pack(fill='both', expand=True, padx=5, pady=5)

        self._create_port_scan_tab(notebook)
        self._create_ping_tab(notebook)
        self._create_misc_tab(notebook)

    def _create_output_area(self, parent):
        text = scrolledtext.ScrolledText(
            parent, wrap='word', font=('Consolas', 10),
            bg='#1e1e1e', fg='#e0e0e0', insertbackground='white'
        )
        text.pack(fill='both', expand=True, padx=5, pady=5)
        return text

    def _display_result(self, text_widget, result):
        text_widget.delete(1.0, tk.END)
        text_widget.insert(tk.END, json.dumps(result, indent=2, default=str))
        text_widget.see(tk.END)

    def _create_port_scan_tab(self, notebook):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text='🔌 Port Scanner')

        input_frame = ttk.Frame(frame)
        input_frame.pack(fill='x', padx=5, pady=5)

        ttk.Label(input_frame, text='Target:').pack(side='left')
        self.port_target_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.port_target_var, width=40).pack(side='left', padx=5)
        ttk.Button(input_frame, text='Scan Common Ports', command=self.run_port_scan).pack(side='left', padx=2)
        ttk.Button(input_frame, text='Scan Top 100', 
                   command=lambda: self.run_port_scan(common_only=False)).pack(side='left', padx=2)

        self.port_output = self._create_output_area(frame)

    def _create_ping_tab(self, notebook):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text='📡 Ping / Traceroute')

        input_frame = ttk.Frame(frame)
        input_frame.pack(fill='x', padx=5, pady=5)

        ttk.Label(input_frame, text='Target:').pack(side='left')
        self.ping_target_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.ping_target_var, width=40).pack(side='left', padx=5)
        ttk.Button(input_frame, text='Ping', command=self.run_ping).pack(side='left', padx=2)
        ttk.Button(input_frame, text='Traceroute', command=self.run_traceroute).pack(side='left', padx=2)

        self.ping_output = self._create_output_area(frame)

    def _create_misc_tab(self, notebook):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text='🔧 Tools')

        # URL Expander
        url_frame = ttk.LabelFrame(frame, text='URL Expander', padding=5)
        url_frame.pack(fill='x', padx=5, pady=5)

        ttk.Label(url_frame, text='Short URL:').pack(side='left')
        self.url_expand_var = tk.StringVar()
        ttk.Entry(url_frame, textvariable=self.url_expand_var, width=40).pack(side='left', padx=5)
        ttk.Button(url_frame, text='Expand', command=self.run_url_expand).pack(side='left')

        # Hash Generator
        hash_frame = ttk.LabelFrame(frame, text='Hash Generator', padding=5)
        hash_frame.pack(fill='x', padx=5, pady=5)

        ttk.Label(hash_frame, text='Text:').pack(side='left')
        self.hash_text_var = tk.StringVar()
        ttk.Entry(hash_frame, textvariable=self.hash_text_var, width=30).pack(side='left', padx=5)
        self.hash_algo_var = tk.StringVar(value='sha256')
        ttk.Combobox(hash_frame, textvariable=self.hash_algo_var,
                      values=['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'],
                      width=10, state='readonly').pack(side='left', padx=2)
        ttk.Button(hash_frame, text='Generate Hash', command=self.run_hash).pack(side='left', padx=2)

        # QR Generator
        qr_frame = ttk.LabelFrame(frame, text='QR Code Generator', padding=5)
        qr_frame.pack(fill='x', padx=5, pady=5)

        ttk.Label(qr_frame, text='Data:').pack(side='left')
        self.qr_data_var = tk.StringVar()
        ttk.Entry(qr_frame, textvariable=self.qr_data_var, width=40).pack(side='left', padx=5)
        ttk.Button(qr_frame, text='Generate QR', command=self.run_qr).pack(side='left')

        self.misc_output = self._create_output_area(frame)

    def run_port_scan(self, common_only=True):
        target = self.port_target_var.get().strip()
        if not target:
            messagebox.showwarning('Input Required', 'Please enter a target.')
            return
        self.log(f'Scanning ports on {target}...')
        self.run_in_thread(
            self.app.osint.network_tools.port_scan, (target,),
            lambda r: self._display_result(self.port_output, r)
        )

    def run_ping(self):
        target = self.ping_target_var.get().strip()
        if not target:
            messagebox.showwarning('Input Required', 'Please enter a target.')
            return
        self.log(f'Pinging {target}...')
        self.run_in_thread(
            self.app.osint.network_tools.ping, (target,),
            lambda r: self._display_result(self.ping_output, r)
        )

    def run_traceroute(self):
        target = self.ping_target_var.get().strip()
        if not target:
            messagebox.showwarning('Input Required', 'Please enter a target.')
            return
        self.log(f'Traceroute to {target}...')
        self.run_in_thread(
            self.app.osint.network_tools.traceroute, (target,),
            lambda r: self._display_result(self.ping_output, r)
        )

    def run_url_expand(self):
        url = self.url_expand_var.get().strip()
        if not url:
            messagebox.showwarning('Input Required', 'Please enter a URL.')
            return
        self.log(f'Expanding URL: {url}...')
        self.run_in_thread(
            self.app.osint.network_tools.url_expander, (url,),
            lambda r: self._display_result(self.misc_output, r)
        )

    def run_hash(self):
        text = self.hash_text_var.get().strip()
        algo = self.hash_algo_var.get()
        if not text:
            messagebox.showwarning('Input Required', 'Please enter text to hash.')
            return
        self.log(f'Generating {algo} hash...')
        result = self.app.osint.network_tools.hash_text(text, algo)
        self._display_result(self.misc_output, result)

    def run_qr(self):
        data = self.qr_data_var.get().strip()
        if not data:
            messagebox.showwarning('Input Required', 'Please enter data for QR code.')
            return
        self.log(f'Generating QR code for: {data}...')
        result = self.app.osint.network_tools.generate_qr(data, 'qrcode.png')
        self._display_result(self.misc_output, result)


class DataAnalysisTab(BaseTab):
    """Tab for data analysis tools."""

    def setup_ui(self):
        notebook = ttk.Notebook(self)
        notebook.pack(fill='both', expand=True, padx=5, pady=5)

        # Text Analysis tab
        text_frame = ttk.Frame(notebook)
        notebook.add(text_frame, text='📝 Text Analysis')

        input_frame = ttk.Frame(text_frame)
        input_frame.pack(fill='x', padx=5, pady=5)

        ttk.Label(input_frame, text='Enter text to analyze:').pack(anchor='w')
        self.text_input = scrolledtext.ScrolledText(
            input_frame, height=6, font=('Consolas', 10)
        )
        self.text_input.pack(fill='x', padx=5, pady=5)

        btn_frame = ttk.Frame(input_frame)
        btn_frame.pack(fill='x')
        ttk.Button(btn_frame, text='🔍 Extract IOCs', command=self.run_extract_iocs).pack(side='left', padx=2)
        ttk.Button(btn_frame, text='📊 Analyze Text', command=self.run_text_analysis).pack(side='left', padx=2)

        self.text_output = scrolledtext.ScrolledText(
            text_frame, wrap='word', font=('Consolas', 10),
            bg='#1e1e1e', fg='#e0e0e0', insertbackground='white'
        )
        self.text_output.pack(fill='both', expand=True, padx=5, pady=5)

        # CIDR / IP Range tab
        cidr_frame = ttk.Frame(notebook)
        notebook.add(cidr_frame, text='🌐 IP Range Calculator')

        cidr_input = ttk.Frame(cidr_frame)
        cidr_input.pack(fill='x', padx=5, pady=5)

        ttk.Label(cidr_input, text='CIDR (e.g., 192.168.1.0/24):').pack(side='left')
        self.cidr_var = tk.StringVar()
        ttk.Entry(cidr_input, textvariable=self.cidr_var, width=30).pack(side='left', padx=5)
        ttk.Button(cidr_input, text='Calculate', command=self.run_cidr).pack(side='left')

        self.cidr_output = scrolledtext.ScrolledText(
            cidr_frame, wrap='word', font=('Consolas', 10),
            bg='#1e1e1e', fg='#e0e0e0', insertbackground='white'
        )
        self.cidr_output.pack(fill='both', expand=True, padx=5, pady=5)

        # User Agent tab
        ua_frame = ttk.Frame(notebook)
        notebook.add(ua_frame, text='🕵️ User-Agent Generator')

        ua_input = ttk.Frame(ua_frame)
        ua_input.pack(fill='x', padx=5, pady=5)

        ttk.Label(ua_input, text='Count:').pack(side='left')
        self.ua_count_var = tk.StringVar(value='5')
        ttk.Spinbox(ua_input, from_=1, to=20, textvariable=self.ua_count_var, width=5).pack(side='left', padx=5)
        ttk.Button(ua_input, text='Generate', command=self.run_ua_generate).pack(side='left')

        self.ua_output = scrolledtext.ScrolledText(
            ua_frame, wrap='word', font=('Consolas', 10),
            bg='#1e1e1e', fg='#e0e0e0', insertbackground='white'
        )
        self.ua_output.pack(fill='both', expand=True, padx=5, pady=5)

    def _display_result(self, text_widget, result):
        text_widget.delete(1.0, tk.END)
        text_widget.insert(tk.END, json.dumps(result, indent=2, default=str))
        text_widget.see(tk.END)

    def run_extract_iocs(self):
        text = self.text_input.get(1.0, tk.END).strip()
        if not text:
            messagebox.showwarning('Input Required', 'Please enter text to analyze.')
            return
        self.log('Extracting IOCs from text...')
        result = self.app.osint.data_analysis.extract_metadata_from_text(text)
        self._display_result(self.text_output, result)

    def run_text_analysis(self):
        text = self.text_input.get(1.0, tk.END).strip()
        if not text:
            messagebox.showwarning('Input Required', 'Please enter text to analyze.')
            return
        self.log('Analyzing text...')
        result = self.app.osint.data_analysis.analyze_text(text)
        self._display_result(self.text_output, result)

    def run_cidr(self):
        cidr = self.cidr_var.get().strip()
        if not cidr:
            messagebox.showwarning('Input Required', 'Please enter a CIDR notation.')
            return
        self.log(f'Calculating IP range for {cidr}...')
        result = self.app.osint.data_analysis.ip_range_calculator(cidr)
        self._display_result(self.cidr_output, result)

    def run_ua_generate(self):
        try:
            count = int(self.ua_count_var.get())
        except ValueError:
            count = 5
        self.log(f'Generating {count} user agents...')
        result = self.app.osint.data_analysis.generate_user_agents(count)
        self._display_result(self.ua_output, result)


class GoogleDorkTab(BaseTab):
    """Tab for Google Dorking."""

    def setup_ui(self):
        input_frame = ttk.LabelFrame(self, text='Google Dork Generator', padding=10)
        input_frame.pack(fill='x', padx=10, pady=5)

        ttk.Label(input_frame, text='Domain/Target:').grid(row=0, column=0, sticky='w')
        self.dork_target_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.dork_target_var, width=50).grid(row=0, column=1, padx=5)

        ttk.Label(input_frame, text='Dork Type:').grid(row=1, column=0, sticky='w', pady=5)
        self.dork_type_var = tk.StringVar(value='all')
        dork_types = [
            'all', 'admin_panels', 'config_files', 'directory_listing',
            'exposed_docs', 'error_messages', 'login_pages', 'sql_errors',
            'subdomains', 'email_addresses', 'sensitive_files', 'custom'
        ]
        dork_combo = ttk.Combobox(input_frame, textvariable=self.dork_type_var,
                                  values=dork_types, width=30, state='readonly')
        dork_combo.grid(row=1, column=1, sticky='w', padx=5)
        dork_combo.bind('<<ComboboxSelected>>', self._on_dork_type_change)

        ttk.Label(input_frame, text='Custom Query:').grid(row=2, column=0, sticky='w', pady=5)
        self.custom_dork_var = tk.StringVar()
        self.custom_dork_entry = ttk.Entry(input_frame, textvariable=self.custom_dork_var, width=50)
        self.custom_dork_entry.grid(row=2, column=1, padx=5)
        self.custom_dork_entry.config(state='disabled')

        ttk.Button(input_frame, text='🔍 Generate Dorks', command=self.run_generate_dorks).grid(row=3, column=0, columnspan=2, pady=10)

        # Output
        output_frame = ttk.LabelFrame(self, text='Generated Dork Queries', padding=10)
        output_frame.pack(fill='both', expand=True, padx=10, pady=5)

        self.output_text = scrolledtext.ScrolledText(
            output_frame, wrap='word', font=('Consolas', 10),
            bg='#1e1e1e', fg='#e0e0e0', insertbackground='white'
        )
        self.output_text.pack(fill='both', expand=True)

    def _on_dork_type_change(self, event):
        if self.dork_type_var.get() == 'custom':
            self.custom_dork_entry.config(state='normal')
        else:
            self.custom_dork_entry.config(state='disabled')

    def run_generate_dorks(self):
        target = self.dork_target_var.get().strip()
        dork_type = self.dork_type_var.get()

        if dork_type == 'custom':
            query = self.custom_dork_var.get().strip()
            if not query:
                messagebox.showwarning('Input Required', 'Please enter a custom dork query.')
                return
        else:
            query = target if target else 'example.com'

        if not query:
            messagebox.showwarning('Input Required', 'Please enter a target domain.')
            return

        self.log(f'Generating {dork_type} dork queries for {query}...')
        result = self.app.osint.web_osint.google_dork(query, dork_type)
        self.output_text.delete(1.0, tk.END)

        if result.get('dork_type') == 'all':
            for name, dork in result.get('dorks', {}).items():
                self.output_text.insert(tk.END, f'🔍 {name.replace("_", " ").title()}\n')
                self.output_text.insert(tk.END, f'   {dork}\n\n')
        else:
            self.output_text.insert(tk.END, json.dumps(result, indent=2, default=str))

        self.output_text.see(tk.END)


class ExportTab(BaseTab):
    """Tab for exporting results."""

    def setup_ui(self):
        main_frame = ttk.Frame(self)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)

        # Info
        info_frame = ttk.LabelFrame(main_frame, text='Export Options', padding=15)
        info_frame.pack(fill='x', pady=10)

        ttk.Label(info_frame, text='📁 Export investigation results to various formats.',
                  font=('', 12)).pack(anchor='w')
        ttk.Label(info_frame, text='Results are saved to the reports/ directory.',
                  font=('', 10)).pack(anchor='w', pady=5)

        # Export format selection
        format_frame = ttk.LabelFrame(main_frame, text='Available Formats', padding=10)
        format_frame.pack(fill='x', pady=10)

        formats = [
            ('HTML', '📄', 'Professional HTML report with styling'),
            ('PDF', '📕', 'PDF document (falls back to HTML if fpdf2 not installed)'),
            ('JSON', '📋', 'Raw JSON data file'),
            ('CSV', '📊', 'Tabular CSV format'),
            ('TXT', '📝', 'Plain text report'),
        ]
        for i, (fmt, icon, desc) in enumerate(formats):
            row = ttk.Frame(format_frame)
            row.pack(fill='x', pady=2)
            ttk.Label(row, text=f'{icon} {fmt}', width=10).pack(side='left')
            ttk.Label(row, text=desc).pack(side='left', padx=10)

        # Quick export section
        quick_frame = ttk.LabelFrame(main_frame, text='Quick Actions', padding=10)
        quick_frame.pack(fill='x', pady=10)

        ttk.Button(quick_frame, text='📄 Export Last Result as HTML',
                   command=self.export_last_html).pack(side='left', padx=5)
        ttk.Button(quick_frame, text='📋 Export Last Result as JSON',
                   command=self.export_last_json).pack(side='left', padx=5)
        ttk.Button(quick_frame, text='📝 Export Last Result as TXT',
                   command=self.export_last_txt).pack(side='left', padx=5)

        # Report history
        history_frame = ttk.LabelFrame(main_frame, text='Report History', padding=10)
        history_frame.pack(fill='both', expand=True, pady=10)

        self.history_text = scrolledtext.ScrolledText(
            history_frame, height=8, font=('Consolas', 10),
            bg='#1e1e1e', fg='#e0e0e0', insertbackground='white'
        )
        self.history_text.pack(fill='both', expand=True)
        self.refresh_history()

    def refresh_history(self):
        """Refresh the report history display."""
        import glob
        from pathlib import Path
        reports_dir = Path(__file__).parent.parent / 'reports'
        reports_dir.mkdir(exist_ok=True)
        
        files = sorted(reports_dir.glob('*'), key=lambda f: f.stat().st_mtime, reverse=True)
        self.history_text.delete(1.0, tk.END)
        
        if not files:
            self.history_text.insert(tk.END, 'No reports generated yet.\n')
            return

        for f in files[:20]:  # Show last 20
            size = f.stat().st_size
            modified = datetime.fromtimestamp(f.stat().st_mtime).strftime('%Y-%m-%d %H:%M')
            self.history_text.insert(
                tk.END,
                f'{f.suffix[1:].upper():5s} | {f.name:40s} | {size:>8d} bytes | {modified}\n'
            )

    def _get_last_data(self):
        """Get the last result from the main app."""
        return getattr(self.app, '_last_result', None)

    def export_last_html(self):
        data = self._get_last_data()
        if not data:
            messagebox.showinfo('No Data', 'No results to export. Run an investigation first.')
            return
        result = self.app.osint.reporting.to_html(data, 'OSINT Export')
        if result['status'] == 'success':
            messagebox.showinfo('Export Successful', f'Report saved to:\n{result["path"]}')
            self.refresh_history()
        else:
            messagebox.showerror('Export Failed', result.get('error', 'Unknown error'))

    def export_last_json(self):
        data = self._get_last_data()
        if not data:
            messagebox.showinfo('No Data', 'No results to export. Run an investigation first.')
            return
        result = self.app.osint.reporting.to_json(data)
        if result['status'] == 'success':
            messagebox.showinfo('Export Successful', f'Data saved to:\n{result["path"]}')
            self.refresh_history()
        else:
            messagebox.showerror('Export Failed', result.get('error', 'Unknown error'))

    def export_last_txt(self):
        data = self._get_last_data()
        if not data:
            messagebox.showinfo('No Data', 'No results to export. Run an investigation first.')
            return
        result = self.app.osint.reporting.to_txt(data, 'OSINT Export')
        if result['status'] == 'success':
            messagebox.showinfo('Export Successful', f'Report saved to:\n{result["path"]}')
            self.refresh_history()
        else:
            messagebox.showerror('Export Failed', result.get('error', 'Unknown error'))

