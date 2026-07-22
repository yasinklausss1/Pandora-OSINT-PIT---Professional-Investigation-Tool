"""
Main GUI Application for OSINT Pro Tool.
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import sys
import os
from datetime import datetime
from typing import Dict, Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class OSINTApp:
    """Main OSINT Pro GUI Application."""

    def __init__(self):
        self.team_name = "PANDORA"
        self.ascii_art = (
            " ▄▄▄· ▄▄▄·  ▐ ▄ ·▄▄▄▄        ▄▄▄   ▄▄▄·\n"
            "▐█ ▄█▐█ ▀█ •█▌▐███▪ ██ ▪     ▀▄ █·▐█ ▀█\n"
            " ██▀·▄█▀▀█ ▐█▐▐▌▐█· ▐█▌ ▄█▀▄ ▐▀▀▄ ▄█▀▀█\n"
            "▐█▪·•▐█ ▪▐▌██▐█▌██. ██ ▐█▌.▐▌▐█•█▌▐█ ▪▐▌\n"
            ".▀    ▀  ▀ ▀▀ █▪▀▀▀▀▀•  ▀█▄▀▪.▀  ▀ ▀  ▀"
        )
        self.root = tk.Tk()
        self.root.title(f'🕵️ {self.team_name} OSINT PIT - Professional Investigation Tool')
        self.root.geometry('1200x800')
        self.root.minsize(900, 600)

        # Set theme
        self.style = ttk.Style()
        try:
            import ttkbootstrap as tb
            self.style = tb.Style(theme='darkly')
            self.root = self.style.master
            self.root.title(f'🕵️ {self.team_name} OSINT PIT - Professional Investigation Tool')
            self.root.geometry('1200x800')
            self.root.minsize(900, 600)
            self.using_ttkbootstrap = True
        except ImportError:
            self.using_ttkbootstrap = False
            available_themes = self.style.theme_names()
            if 'clam' in available_themes:
                self.style.theme_use('clam')

        self._init_osint_engine()
        self._setup_menu()
        self._setup_header()
        self._setup_main_layout()

        self.status_var = tk.StringVar(value=f'{self.team_name} OSINT PIT - Ready')
        status_bar = ttk.Label(self.root, textvariable=self.status_var,
                               relief='sunken', anchor='w', padding=(5, 2))
        status_bar.pack(side='bottom', fill='x')

        self._setup_log_area()
        self._center_window()

    def _setup_header(self):
        """Create header with team branding on left and ASCII art on right."""
        header_frame = ttk.Frame(self.root)
        header_frame.pack(fill='x', padx=10, pady=(5, 0))

        # Left side: Title
        left_frame = ttk.Frame(header_frame)
        left_frame.pack(side='left', fill='x', expand=True)

        title_label = ttk.Label(
            left_frame,
            text=f'🕵️  {self.team_name} OSINT PIT - Professional Investigation Tool',
            font=('Segoe UI', 14, 'bold'),
            foreground='white'
        )
        title_label.pack(anchor='w')

        subtitle_label = ttk.Label(
            left_frame,
            text='Open Source Intelligence Tool for Professional Investigations',
            font=('Segoe UI', 9),
            foreground='white'
        )
        subtitle_label.pack(anchor='w')

        # Right side: ASCII art
        right_frame = ttk.Frame(header_frame)
        right_frame.pack(side='right', padx=(0, 5))

        ascii_label = tk.Label(
            right_frame,
            text=self.ascii_art,
            font=('Consolas', 8),
            fg='white',
            bg='#2d2d2d',
            justify='left'
        )
        ascii_label.pack()

        # Separator
        separator = ttk.Separator(self.root, orient='horizontal')
        separator.pack(fill='x', padx=10, pady=5)

    def _init_osint_engine(self):
        """Initialize the OSINT engine with all modules."""
        from modules.web_osint import WebOSINT
        from modules.people_osint import PeopleOSINT
        from modules.network_tools import NetworkTools
        from modules.data_analysis import DataAnalysis
        from modules.reporting import Reporting

        class OSINTEngine:
            def __init__(self):
                self.web_osint = WebOSINT()
                self.people_osint = PeopleOSINT()
                self.network_tools = NetworkTools()
                self.data_analysis = DataAnalysis()
                self.reporting = Reporting()

        self.osint = OSINTEngine()
        self._last_result = None

    def _setup_menu(self):
        """Create the menu bar."""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label='File', menu=file_menu)
        file_menu.add_command(label='Clear Output', command=self.clear_output, accelerator='Ctrl+L')
        file_menu.add_separator()
        file_menu.add_command(label='Exit', command=self.root.quit, accelerator='Ctrl+Q')

        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label='Tools', menu=tools_menu)
        tools_menu.add_command(label='Clear All Results', command=self.clear_all_tabs)
        tools_menu.add_separator()
        tools_menu.add_command(label='About', command=self.show_about)

        self.root.bind('<Control-l>', lambda e: self.clear_output())
        self.root.bind('<Control-q>', lambda e: self.root.quit())

    def _setup_main_layout(self):
        """Create the main notebook with tabs."""
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=5, pady=5)

        from ui.tabs import (
            WebInvestigationTab, PeopleInvestigationTab, NetworkToolsTab,
            DataAnalysisTab, GoogleDorkTab, ExportTab
        )

        self.tabs = {
            'web': WebInvestigationTab(self.notebook, self),
            'people': PeopleInvestigationTab(self.notebook, self),
            'network': NetworkToolsTab(self.notebook, self),
            'data': DataAnalysisTab(self.notebook, self),
            'dork': GoogleDorkTab(self.notebook, self),
            'export': ExportTab(self.notebook, self),
        }

        self.notebook.add(self.tabs['web'], text='  🌐 Web Investigation  ')
        self.notebook.add(self.tabs['people'], text='  👤 People OSINT  ')
        self.notebook.add(self.tabs['network'], text='  🔌 Network Tools  ')
        self.notebook.add(self.tabs['data'], text='  📊 Data Analysis  ')
        self.notebook.add(self.tabs['dork'], text='  🔍 Google Dorking  ')
        self.notebook.add(self.tabs['export'], text='  📁 Export  ')

    def _setup_log_area(self):
        """Create the log output area at the bottom."""
        log_frame = ttk.LabelFrame(self.root, text=f'{self.team_name} Activity Log', padding=5)
        log_frame.pack(fill='x', padx=10, pady=(0, 5))

        text_frame = ttk.Frame(log_frame)
        text_frame.pack(fill='x', expand=True)

        self.log_text = tk.Text(
            text_frame, height=6, wrap='word',
            font=('Consolas', 9),
            bg='#1a1a2e', fg='#c0c0c0',
            insertbackground='white',
            relief='flat', borderwidth=2
        )
        self.log_text.pack(side='left', fill='x', expand=True)

        scrollbar = ttk.Scrollbar(text_frame, orient='vertical', command=self.log_text.yview)
        scrollbar.pack(side='right', fill='y')
        self.log_text.config(yscrollcommand=scrollbar.set)

        self.log_text.tag_config('info', foreground='#88ccff')
        self.log_text.tag_config('success', foreground='#88ff88')
        self.log_text.tag_config('error', foreground='#ff6666')
        self.log_text.tag_config('warning', foreground='#ffcc66')
        self.log_text.tag_config('timestamp', foreground='#888888')

    def _center_window(self):
        """Center the window on the screen."""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')

    def log(self, message: str, level: str = 'info'):
        """Log a message with timestamp and color coding."""
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.log_text.insert(tk.END, f'[{timestamp}] ', 'timestamp')
        self.log_text.insert(tk.END, f'{message}\n', level)
        self.log_text.see(tk.END)
        self.status_var.set(f'{self.team_name} | {message}')

    def clear_output(self):
        """Clear the log area."""
        self.log_text.delete(1.0, tk.END)
        self.log('Output cleared.')

    def clear_all_tabs(self):
        """Clear all tab output areas."""
        for name, tab in self.tabs.items():
            if hasattr(tab, 'output_text'):
                tab.output_text.delete(1.0, tk.END)
        self.log('All tab results cleared.')

    def show_about(self):
        """Show about dialog."""
        about_text = f"""🕵️ {self.team_name} OSINT PIT - Professional Investigation Tool

Version 1.0.0

Team: {self.team_name}

A comprehensive Open Source Intelligence (OSINT) tool
for professional investigations and research.

Features:
• Web & Domain Investigation
• People & Social Media OSINT
• Network & Security Tools
• Data Analysis & IOC Extraction
• Google Dorking Automation
• Professional Reporting (HTML, PDF, JSON, CSV, TXT)

Created for educational and professional use only.
Use responsibly and in accordance with applicable laws.
        """
        messagebox.showinfo(f'About {self.team_name} OSINT PIT', about_text)

    def run(self):
        """Start the GUI application."""
        self.log(f'🕵️ {self.team_name} OSINT PIT started successfully!', 'success')
        self.log('Select a tab and enter your target to begin investigation.')
        self.root.mainloop()
