"""
Reporting Module - Export results to various formats
Functions: Export to HTML, PDF, CSV, JSON, TXT
"""
import json
import csv
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path


class Reporting:
    """Export investigation results to various formats."""

    def __init__(self, reports_dir: Path = Path('reports')):
        self.reports_dir = reports_dir
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def _get_filename(self, prefix: str, ext: str) -> Path:
        """Generate a unique filename with timestamp."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return self.reports_dir / f'{prefix}_{timestamp}.{ext}'

    # ─────────────────────────────────────────────
    # Export to HTML
    # ─────────────────────────────────────────────
    def to_html(self, data: Dict, title: str = 'OSINT Report',
                filename: Optional[str] = None) -> Dict:
        """Export results to a professional HTML report."""
        filepath = self._get_filename(filename or 'report', 'html')
        try:
            html_content = self._generate_html(data, title)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            return {'status': 'success', 'path': str(filepath), 'format': 'html'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}

    def _generate_html(self, data: Dict, title: str) -> str:
        """Generate HTML content from data dictionary."""
        # Build content sections
        sections = ''
        for key, value in data.items():
            sections += f'''
            <div class="section">
                <h2>{key.replace('_', ' ').title()}</h2>
                <div class="section-content">
                    {self._render_value(value)}
                </div>
            </div>
            '''

        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0f1923;
            color: #e0e0e0;
            line-height: 1.6;
            padding: 20px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{
            background: linear-gradient(135deg, #1a2a3a, #0d1b2a);
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 30px;
            border: 1px solid #2a3a4a;
        }}
        .header h1 {{
            color: #00d4ff;
            font-size: 2em;
            margin-bottom: 10px;
        }}
        .header .meta {{ color: #8899aa; font-size: 0.9em; }}
        .section {{
            background: #1a2a3a;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 20px;
            border: 1px solid #2a3a4a;
        }}
        .section h2 {{
            color: #00d4ff;
            font-size: 1.3em;
            margin-bottom: 15px;
            padding-bottom: 8px;
            border-bottom: 2px solid #2a3a4a;
        }}
        .section-content {{ overflow-x: auto; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
        }}
        th, td {{
            padding: 10px 15px;
            text-align: left;
            border-bottom: 1px solid #2a3a4a;
        }}
        th {{ background: #0d1b2a; color: #00d4ff; font-weight: 600; }}
        tr:hover {{ background: #1d3a4a; }}
        .key-value {{
            display: grid;
            grid-template-columns: 200px 1fr;
            gap: 8px 15px;
        }}
        .key-value .key {{ color: #8899aa; font-weight: 600; }}
        .key-value .value {{ color: #e0e0e0; word-break: break-all; }}
        .badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 0.85em;
            margin: 2px;
        }}
        .badge-success {{ background: #1a4a2a; color: #4caf50; }}
        .badge-error {{ background: #4a1a1a; color: #f44336; }}
        .badge-info {{ background: #1a2a4a; color: #2196f3; }}
        .list {{ list-style: none; padding: 0; }}
        .list li {{
            padding: 6px 10px;
            margin: 4px 0;
            background: #0d1b2a;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }}
        .footer {{
            text-align: center;
            padding: 20px;
            color: #556677;
            font-size: 0.85em;
        }}
        @media (max-width: 768px) {{
            .key-value {{ grid-template-columns: 1fr; }}
            th, td {{ padding: 8px; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🕵️ {title}</h1>
            <div class="meta">
                Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |
                OSINT Professional Tool
            </div>
        </div>
        {sections}
        <div class="footer">
            OSINT Professional Tool • Generated Report • {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </div>
    </div>
</body>
</html>'''

    def _render_value(self, value: Any, depth: int = 0) -> str:
        """Render a value to HTML."""
        if value is None:
            return '<span class="badge badge-error">N/A</span>'
        if isinstance(value, bool):
            cls = 'badge-success' if value else 'badge-error'
            return f'<span class="badge {cls}">{str(value)}</span>'
        if isinstance(value, dict):
            rows = ''
            for k, v in value.items():
                rows += f'<div class="key-value"><span class="key">{k.replace("_", " ").title()}</span><span class="value">{self._render_value(v, depth + 1)}</span></div>'
            return f'<div class="section-content">{rows}</div>'
        if isinstance(value, list):
            if all(isinstance(x, dict) for x in value):
                # Table rendering
                if not value:
                    return '<span class="badge badge-info">No data</span>'
                headers = list(value[0].keys())
                table = '<table><thead><tr>' + ''.join(f'<th>{h.replace("_", " ").title()}</th>' for h in headers) + '</tr></thead><tbody>'
                for row in value:
                    table += '<tr>' + ''.join(f'<td>{str(row.get(h, ""))}</td>' for h in headers) + '</tr>'
                table += '</tbody></table>'
                return table
            else:
                items = ''.join(f'<li>{self._render_value(item, depth + 1)}</li>' for item in value)
                return f'<ul class="list">{items}</ul>'
        # String/number
        return str(value)

    # ─────────────────────────────────────────────
    # Export to PDF
    # ─────────────────────────────────────────────
    def to_pdf(self, data: Dict, title: str = 'OSINT Report',
               filename: Optional[str] = None) -> Dict:
        """Export results to PDF using fpdf2."""
        filepath = self._get_filename(filename or 'report', 'pdf')
        try:
            from fpdf import FPDF

            pdf = FPDF()
            pdf.add_page()

            # Title
            pdf.set_font('Arial', 'B', 20)
            pdf.set_text_color(0, 150, 255)
            pdf.cell(0, 15, title, ln=True, align='C')
            pdf.ln(10)

            # Meta
            pdf.set_font('Arial', 'I', 10)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(0, 8, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', ln=True)
            pdf.ln(10)

            # Content
            pdf.set_text_color(0, 0, 0)
            self._pdf_add_data(pdf, data)

            pdf.output(str(filepath))
            return {'status': 'success', 'path': str(filepath), 'format': 'pdf'}
        except ImportError:
            html_result = self.to_html(data, title, filename)
            return {'status': 'success', 'path': html_result['path'],
                    'format': 'html', 'note': 'PDF not available, exported as HTML'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}

    def _pdf_add_data(self, pdf, data: Dict, depth: int = 0):
        """Recursively add data to PDF."""
        for key, value in data.items():
            if isinstance(value, dict):
                pdf.set_font('Arial', 'B', 12)
                pdf.set_text_color(0, 100, 200)
                pdf.cell(0, 8, f'{key.replace("_", " ").title()}', ln=True)
                pdf.ln(2)
                self._pdf_add_data(pdf, value, depth + 1)
            elif isinstance(value, list):
                pdf.set_font('Arial', 'B', 11)
                pdf.set_text_color(50, 50, 50)
                pdf.cell(0, 7, f'{key.replace("_", " ").title()}:', ln=True)
                for item in value:
                    if isinstance(item, dict):
                        self._pdf_add_data(pdf, item, depth + 1)
                    else:
                        pdf.set_font('Arial', '', 9)
                        pdf.set_text_color(80, 80, 80)
                        pdf.cell(0, 5, f'  - {str(item)}', ln=True)
                pdf.ln(3)
            else:
                pdf.set_font('Arial', '', 10)
                pdf.set_text_color(50, 50, 50)
                pdf.cell(0, 6, f'{key.replace("_", " ").title()}: {str(value)}', ln=True)

    # ─────────────────────────────────────────────
    # Export to JSON
    # ─────────────────────────────────────────────
    def to_json(self, data: Dict, filename: Optional[str] = None) -> Dict:
        """Export results to JSON file."""
        filepath = self._get_filename(filename or 'data', 'json')
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)
            return {'status': 'success', 'path': str(filepath), 'format': 'json'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}

    # ─────────────────────────────────────────────
    # Export to CSV
    # ─────────────────────────────────────────────
    def to_csv(self, data: List[Dict], filename: Optional[str] = None,
               fieldnames: Optional[List[str]] = None) -> Dict:
        """Export list of dictionaries to CSV file."""
        filepath = self._get_filename(filename or 'data', 'csv')
        try:
            if not data:
                return {'status': 'error', 'error': 'No data to export'}
            if fieldnames is None:
                fieldnames = list(data[0].keys())
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(data)
            return {'status': 'success', 'path': str(filepath), 'format': 'csv'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}

    # ─────────────────────────────────────────────
    # Export to TXT
    # ─────────────────────────────────────────────
    def to_txt(self, data: Dict, title: str = 'OSINT Report',
               filename: Optional[str] = None) -> Dict:
        """Export results to a plain text file."""
        filepath = self._get_filename(filename or 'report', 'txt')
        try:
            lines = [
                f'{"="*60}',
                f'{title:^60}',
                f'{"="*60}',
                f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}',
                f'{"="*60}',
                ''
            ]
            self._txt_add_data(data, lines)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines))
            return {'status': 'success', 'path': str(filepath), 'format': 'txt'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}

    def _txt_add_data(self, data: Dict, lines: List[str], indent: int = 0):
        """Recursively add data to text lines."""
        prefix = '  ' * indent
        for key, value in data.items():
            if isinstance(value, dict):
                lines.append(f'{prefix}[{key.replace("_", " ").title()}]')
                self._txt_add_data(value, lines, indent + 1)
            elif isinstance(value, list):
                lines.append(f'{prefix}{key.replace("_", " ").title()}:')
                for item in value:
                    if isinstance(item, dict):
                        self._txt_add_data(item, lines, indent + 1)
                    else:
                        lines.append(f'{prefix}  - {str(item)}')
            else:
                lines.append(f'{prefix}{key.replace("_", " ").title()}: {str(value)}')

    # ─────────────────────────────────────────────
    # Auto-detect format
    # ─────────────────────────────────────────────
    def export(self, data: Any, title: str = 'OSINT Report',
               format: str = 'html', filename: Optional[str] = None) -> Dict:
        """Export data in specified format (auto-detect)."""
        format = format.lower().strip('.')
        exporters = {
            'html': self.to_html,
            'pdf': self.to_pdf,
            'json': self.to_json,
            'csv': self.to_csv,
            'txt': self.to_txt,
        }
        exporter = exporters.get(format)
        if not exporter:
            return {'status': 'error', 'error': f'Unsupported format: {format}'}

        if format == 'csv':
            if isinstance(data, dict):
                # Convert single dict to list for CSV
                data = [data]
            return self.to_csv(data, filename)
        
        return exporter(data, title, filename)

