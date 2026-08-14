"""
Snek Analysis Mx - HTML Reporter
Generates professional HTML reports with interactive visualizations
"""

import os
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import jinja2

logger = logging.getLogger(__name__)


class HTMLReporter:
    """
    Generates HTML reports from memory forensics analysis results
    """
    
    def __init__(self, results: Dict[str, Any]):
        """
        Initialize HTML Reporter
        
        Args:
            results: Analysis results dictionary
        """
        self.results = results
        self.template_dir = self._get_template_dir()
        self.env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(self.template_dir),
            autoescape=jinja2.select_autoescape(['html', 'xml'])
        )
        
    def _get_template_dir(self) -> Path:
        """
        Get template directory path
        
        Returns:
            Path to template directory
        """
        # Try to find templates in package directory
        current_dir = Path(__file__).parent
        template_dir = current_dir / 'templates'
        
        # If templates don't exist in package, create them
        if not template_dir.exists():
            template_dir.mkdir(parents=True, exist_ok=True)
            self._create_default_templates(template_dir)
        
        return template_dir
    
    def _create_default_templates(self, template_dir: Path):
        """
        Create default HTML templates
        
        Args:
            template_dir: Directory to create templates in
        """
        # Base template
        base_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Snek Analysis Mx - Memory Forensics Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0a0e17;
            color: #c8d6e5;
            line-height: 1.6;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: #111927;
            border-radius: 12px;
            padding: 30px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.5);
            border: 1px solid #1a2a3a;
        }
        
        .header {
            text-align: center;
            padding: 30px 0;
            border-bottom: 2px solid #1a2a3a;
            margin-bottom: 30px;
        }
        
        .header h1 {
            font-size: 2.5em;
            background: linear-gradient(135deg, #00d2ff, #3a7bd5);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }
        
        .header .subtitle {
            color: #8899aa;
            font-size: 1.1em;
        }
        
        .header .meta {
            margin-top: 15px;
            display: flex;
            justify-content: center;
            gap: 20px;
            flex-wrap: wrap;
            font-size: 0.9em;
            color: #6688aa;
        }
        
        .header .meta span {
            background: #1a2a3a;
            padding: 5px 15px;
            border-radius: 20px;
            border: 1px solid #2a3a4a;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        
        .summary-card {
            background: #1a2a3a;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border: 1px solid #2a3a4a;
            transition: transform 0.2s;
        }
        
        .summary-card:hover {
            transform: translateY(-5px);
            border-color: #3a7bd5;
        }
        
        .summary-card .number {
            font-size: 2.5em;
            font-weight: bold;
            color: #00d2ff;
            display: block;
        }
        
        .summary-card .label {
            color: #8899aa;
            font-size: 0.9em;
            margin-top: 5px;
        }
        
        .summary-card.critical .number { color: #ff4757; }
        .summary-card.high .number { color: #ff6348; }
        .summary-card.medium .number { color: #ffa502; }
        .summary-card.low .number { color: #2ed573; }
        
        .section {
            margin: 40px 0;
            background: #0d1520;
            border-radius: 8px;
            padding: 25px;
            border: 1px solid #1a2a3a;
        }
        
        .section h2 {
            color: #00d2ff;
            margin-bottom: 20px;
            font-size: 1.8em;
            border-bottom: 2px solid #1a2a3a;
            padding-bottom: 10px;
        }
        
        .section h3 {
            color: #3a7bd5;
            margin: 20px 0 10px 0;
        }
        
        .table-wrapper {
            overflow-x: auto;
            margin: 15px 0;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            background: #0d1520;
        }
        
        th {
            background: #1a2a3a;
            color: #00d2ff;
            padding: 12px;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid #2a3a4a;
        }
        
        td {
            padding: 10px 12px;
            border-bottom: 1px solid #1a2a3a;
            color: #c8d6e5;
        }
        
        tr:hover {
            background: #1a2a3a;
        }
        
        .badge {
            display: inline-block;
            padding: 3px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: 600;
        }
        
        .badge-critical { background: #ff4757; color: white; }
        .badge-high { background: #ff6348; color: white; }
        .badge-medium { background: #ffa502; color: white; }
        .badge-low { background: #2ed573; color: white; }
        .badge-info { background: #1e90ff; color: white; }
        .badge-warning { background: #ffa502; color: white; }
        
        .risk-score {
            display: inline-block;
            padding: 2px 10px;
            border-radius: 12px;
            font-weight: bold;
            font-size: 0.9em;
        }
        
        .risk-critical { background: #ff4757; color: white; }
        .risk-high { background: #ff6348; color: white; }
        .risk-medium { background: #ffa502; color: white; }
        .risk-low { background: #2ed573; color: white; }
        
        .reason-list {
            list-style: none;
            padding: 0;
        }
        
        .reason-list li {
            padding: 4px 0;
            color: #ffa502;
            font-size: 0.9em;
        }
        
        .reason-list li::before {
            content: "⚠️ ";
        }
        
        .alert {
            padding: 15px 20px;
            border-radius: 8px;
            margin: 15px 0;
            border-left: 4px solid;
        }
        
        .alert-danger {
            background: #1a0a0a;
            border-color: #ff4757;
            color: #ff6b81;
        }
        
        .alert-warning {
            background: #1a150a;
            border-color: #ffa502;
            color: #ffbe76;
        }
        
        .alert-info {
            background: #0a1520;
            border-color: #1e90ff;
            color: #70a1ff;
        }
        
        .alert-success {
            background: #0a1a0a;
            border-color: #2ed573;
            color: #7bed9f;
        }
        
        .process-tree {
            font-family: 'Courier New', monospace;
            background: #0d1520;
            padding: 15px;
            border-radius: 8px;
            overflow-x: auto;
            font-size: 0.9em;
            color: #8899aa;
        }
        
        .process-tree .highlight {
            color: #ffa502;
            font-weight: bold;
        }
        
        .footer {
            text-align: center;
            padding: 20px 0;
            border-top: 2px solid #1a2a3a;
            margin-top: 40px;
            color: #6688aa;
            font-size: 0.9em;
        }
        
        .footer .version {
            color: #3a7bd5;
        }
        
        .collapse {
            cursor: pointer;
            user-select: none;
        }
        
        .collapse::after {
            content: " ▼";
            color: #3a7bd5;
        }
        
        .collapse.collapsed::after {
            content: " ▶";
        }
        
        .collapse-content {
            display: block;
            overflow: hidden;
            transition: max-height 0.3s ease;
        }
        
        .collapse-content.hidden {
            display: none;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 15px;
            }
            
            .header h1 {
                font-size: 1.8em;
            }
            
            .summary-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            
            table {
                font-size: 0.85em;
            }
            
            th, td {
                padding: 8px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        {% block content %}{% endblock %}
        <div class="footer">
            <p>Generated by <strong>Snek Analysis Mx</strong> <span class="version">v1.0.0</span></p>
            <p>Memory Forensics Toolkit - Powered by Volatility 3</p>
        </div>
    </div>
    <script>
        // Collapsible sections
        document.querySelectorAll('.collapse').forEach(function(el) {
            el.addEventListener('click', function() {
                this.classList.toggle('collapsed');
                var content = this.nextElementSibling;
                if (content) {
                    content.classList.toggle('hidden');
                }
            });
        });
    </script>
</body>
</html>"""
        
        # Report template
        report_template = """{% extends "base.html" %}

{% block content %}
<div class="header">
    <h1>🐍 SNEK ANALYSIS MX</h1>
    <div class="subtitle">Memory Forensics Analysis Report</div>
    <div class="meta">
        <span>📁 {{ results.memory_file }}</span>
        <span>🖥️ Profile: {{ results.profile }}</span>
        <span>📅 {{ results.timestamp }}</span>
    </div>
</div>

<!-- Summary Cards -->
<div class="summary-grid">
    <div class="summary-card">
        <span class="number">{{ results.processes.total if results.processes else 0 }}</span>
        <span class="label">Total Processes</span>
    </div>
    <div class="summary-card critical">
        <span class="number">{{ results.processes.suspicious|length if results.processes else 0 }}</span>
        <span class="label">Suspicious Processes</span>
    </div>
    <div class="summary-card">
        <span class="number">{{ results.network.total_connections if results.network else 0 }}</span>
        <span class="label">Network Connections</span>
    </div>
    <div class="summary-card high">
        <span class="number">{{ results.network.suspicious|length if results.network else 0 }}</span>
        <span class="label">Suspicious Connections</span>
    </div>
    <div class="summary-card">
        <span class="number">{{ results.dlls.total_dlls if results.dlls else 0 }}</span>
        <span class="label">Total DLLs</span>
    </div>
    <div class="summary-card critical">
        <span class="number">{{ results.dlls.suspicious_dlls|length if results.dlls else 0 }}</span>
        <span class="label">Suspicious DLLs</span>
    </div>
</div>

<!-- Critical Alerts -->
{% if results.processes.suspicious or results.network.suspicious or results.dlls.suspicious_dlls %}
<div class="section">
    <h2>🚨 Critical Alerts</h2>
    {% if results.processes.suspicious %}
        <div class="alert alert-danger">
            <strong>⚠️ {{ results.processes.suspicious|length }} Suspicious Processes Detected!</strong>
            <p>Review the process analysis section for details.</p>
        </div>
    {% endif %}
    {% if results.network.suspicious %}
        <div class="alert alert-danger">
            <strong>⚠️ {{ results.network.suspicious|length }} Suspicious Network Connections Found!</strong>
            <p>Review the network analysis section for details.</p>
        </div>
    {% endif %}
    {% if results.dlls.suspicious_dlls %}
        <div class="alert alert-danger">
            <strong>⚠️ {{ results.dlls.suspicious_dlls|length }} Suspicious DLLs Detected!</strong>
            <p>Review the DLL analysis section for details.</p>
        </div>
    {% endif %}
</div>
{% endif %}

<!-- Process Analysis -->
<div class="section">
    <h2>🕵️ Process Analysis</h2>
    
    <h3>Process Statistics</h3>
    <div class="summary-grid">
        <div class="summary-card">
            <span class="number">{{ results.processes.summary.total_processes if results.processes else 0 }}</span>
            <span class="label">Total Processes</span>
        </div>
        <div class="summary-card">
            <span class="number">{{ results.processes.summary.system_processes if results.processes else 0 }}</span>
            <span class="label">System Processes</span>
        </div>
        <div class="summary-card">
            <span class="number">{{ results.processes.summary.user_processes if results.processes else 0 }}</span>
            <span class="label">User Processes</span>
        </div>
        <div class="summary-card critical">
            <span class="number">{{ results.processes.suspicious|length if results.processes else 0 }}</span>
            <span class="label">Suspicious</span>
        </div>
    </div>
    
    {% if results.processes.suspicious %}
    <h3>Suspicious Processes</h3>
    <div class="table-wrapper">
        <table>
            <thead>
                <tr>
                    <th>PID</th>
                    <th>Process Name</th>
                    <th>PPID</th>
                    <th>Risk Level</th>
                    <th>Reasons</th>
                </tr>
            </thead>
            <tbody>
                {% for proc in results.processes.suspicious %}
                <tr>
                    <td>{{ proc.pid }}</td>
                    <td><strong>{{ proc.name }}</strong></td>
                    <td>{{ proc.ppid }}</td>
                    <td><span class="badge badge-{{ proc.risk_level|lower }}">{{ proc.risk_level }}</span></td>
                    <td>
                        <ul class="reason-list">
                            {% for reason in proc.reasons %}
                            <li>{{ reason }}</li>
                            {% endfor %}
                        </ul>
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    {% endif %}
    
    {% if results.processes.injections %}
    <h3>Potential Process Injections</h3>
    <div class="table-wrapper">
        <table>
            <thead>
                <tr>
                    <th>PID</th>
                    <th>Type</th>
                    <th>Risk</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
                {% for inj in results.processes.injections %}
                <tr>
                    <td>{{ inj.pid }}</td>
                    <td>{{ inj.type }}</td>
                    <td><span class="badge badge-{{ inj.risk|lower }}">{{ inj.risk }}</span></td>
                    <td>Address: {{ inj.address }} | Size: {{ inj.size }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    {% endif %}
    
    {% if results.processes.hidden_processes %}
    <h3>Hidden Processes</h3>
    <div class="alert alert-danger">
        <strong>⚠️ Hidden processes detected!</strong>
        <ul>
            {% for proc in results.processes.hidden_processes %}
            <li>PID {{ proc.pid }}: {{ proc.name }} (detected by {{ proc.detected_by }})</li>
            {% endfor %}
        </ul>
    </div>
    {% endif %}
</div>

<!-- Network Analysis -->
<div class="section">
    <h2>🌐 Network Analysis</h2>
    
    <h3>Network Statistics</h3>
    <div class="summary-grid">
        <div class="summary-card">
            <span class="number">{{ results.network.total_connections if results.network else 0 }}</span>
            <span class="label">Total Connections</span>
        </div>
        <div class="summary-card">
            <span class="number">{{ results.network.active_connections.established|length if results.network else 0 }}</span>
            <span class="label">Established</span>
        </div>
        <div class="summary-card">
            <span class="number">{{ results.network.listening_ports|length if results.network else 0 }}</span>
            <span class="label">Listening Ports</span>
        </div>
        <div class="summary-card critical">
            <span class="number">{{ results.network.suspicious|length if results.network else 0 }}</span>
            <span class="label">Suspicious</span>
        </div>
    </div>
    
    {% if results.network.suspicious %}
    <h3>Suspicious Connections</h3>
    <div class="table-wrapper">
        <table>
            <thead>
                <tr>
                    <th>PID</th>
                    <th>Process</th>
                    <th>Protocol</th>
                    <th>Remote IP</th>
                    <th>Remote Port</th>
                    <th>Risk Level</th>
                    <th>Reasons</th>
                </tr>
            </thead>
            <tbody>
                {% for conn in results.network.suspicious %}
                <tr>
                    <td>{{ conn.pid }}</td>
                    <td><strong>{{ conn.process }}</strong></td>
                    <td>{{ conn.protocol }}</td>
                    <td>{{ conn.remote_ip }}</td>
                    <td>{{ conn.remote_port }}</td>
                    <td><span class="badge badge-{{ conn.risk_level|lower }}">{{ conn.risk_level }}</span></td>
                    <td>
                        <ul class="reason-list">
                            {% for reason in conn.reasons %}
                            <li>{{ reason }}</li>
                            {% endfor %}
                        </ul>
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    {% endif %}
    
    {% if results.network.malicious_ips %}
    <h3>Malicious IP Connections</h3>
    <div class="alert alert-danger">
        <strong>⚠️ Connections to known malicious IPs detected!</strong>
        <ul>
            {% for ip in results.network.malicious_ips %}
            <li>{{ ip.process }} (PID {{ ip.pid }}) → {{ ip.remote_ip }}:{{ ip.remote_port }}</li>
            {% endfor %}
        </ul>
    </div>
    {% endif %}
    
    {% if results.network.data_exfiltration %}
    <h3>Potential Data Exfiltration</h3>
    <div class="alert alert-warning">
        <strong>⚠️ Potential data exfiltration detected!</strong>
        <ul>
            {% for exfil in results.network.data_exfiltration %}
            <li>{{ exfil.process }} → {{ exfil.remote_ip }} ({{ exfil.indicator }})</li>
            {% endfor %}
        </ul>
    </div>
    {% endif %}
    
    <h3>Listening Ports</h3>
    <div class="table-wrapper">
        <table>
            <thead>
                <tr>
                    <th>PID</th>
                    <th>Process</th>
                    <th>Protocol</th>
                    <th>Local Address</th>
                    <th>Port</th>
                </tr>
            </thead>
            <tbody>
                {% for port in results.network.listening_ports[:20] %}
                <tr>
                    <td>{{ port.pid }}</td>
                    <td>{{ port.process }}</td>
                    <td>{{ port.protocol }}</td>
                    <td>{{ port.local_address }}</td>
                    <td>{{ port.local_port }}</td>
                </tr>
                {% endfor %}
                {% if results.network.listening_ports|length > 20 %}
                <tr>
                    <td colspan="5" style="text-align: center; color: #6688aa;">
                        ... and {{ results.network.listening_ports|length - 20 }} more ports
                    </td>
                </tr>
                {% endif %}
            </tbody>
        </table>
    </div>
</div>

<!-- DLL Analysis -->
<div class="section">
    <h2>🔧 DLL Analysis</h2>
    
    <h3>DLL Statistics</h3>
    <div class="summary-grid">
        <div class="summary-card">
            <span class="number">{{ results.dlls.total_dlls if results.dlls else 0 }}</span>
            <span class="label">Total DLLs Loaded</span>
        </div>
        <div class="summary-card">
            <span class="number">{{ results.dlls.summary.unique_dlls if results.dlls else 0 }}</span>
            <span class="label">Unique DLLs</span>
        </div>
        <div class="summary-card">
            <span class="number">{{ results.dlls.summary.processes_analyzed if results.dlls else 0 }}</span>
            <span class="label">Processes Analyzed</span>
        </div>
        <div class="summary-card critical">
            <span class="number">{{ results.dlls.suspicious_dlls|length if results.dlls else 0 }}</span>
            <span class="label">Suspicious DLLs</span>
        </div>
    </div>
    
    {% if results.dlls.suspicious_dlls %}
    <h3>Suspicious DLLs</h3>
    <div class="table-wrapper">
        <table>
            <thead>
                <tr>
                    <th>PID</th>
                    <th>DLL Name</th>
                    <th>Path</th>
                    <th>Risk Level</th>
                    <th>Reasons</th>
                </tr>
            </thead>
            <tbody>
                {% for dll in results.dlls.suspicious_dlls %}
                <tr>
                    <td>{{ dll.pid }}</td>
                    <td><strong>{{ dll.name }}</strong></td>
                    <td style="font-size: 0.85em;">{{ dll.path }}</td>
                    <td><span class="badge badge-{{ dll.risk_level|lower }}">{{ dll.risk_level }}</span></td>
                    <td>
                        <ul class="reason-list">
                            {% for reason in dll.reasons %}
                            <li>{{ reason }}</li>
                            {% endfor %}
                        </ul>
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    {% endif %}
    
    {% if results.dlls.dll_injections %}
    <h3>DLL Injection Detected</h3>
    <div class="alert alert-danger">
        <strong>⚠️ Potential DLL injection detected!</strong>
        <ul>
            {% for inj in results.dlls.dll_injections %}
            <li>PID {{ inj.pid }}: {{ inj.dll_name }} - {{ inj.indicator }}</li>
            {% endfor %}
        </ul>
    </div>
    {% endif %}
    
    {% if results.dlls.orphaned_dlls %}
    <h3>Orphaned DLLs</h3>
    <div class="alert alert-warning">
        <strong>⚠️ Orphaned DLLs found!</strong>
        <ul>
            {% for dll in results.dlls.orphaned_dlls %}
            <li>{{ dll.name }} loaded in {{ dll.loaded_in|length }} processes</li>
            {% endfor %}
        </ul>
    </div>
    {% endif %}
</div>

<!-- Indicators -->
<div class="section">
    <h2>📊 Indicators of Compromise (IOCs)</h2>
    
    {% if results.processes.indicators %}
    <h3>Process IOCs</h3>
    {% if results.processes.indicators.suspicious_process_names %}
    <div class="alert alert-warning">
        <strong>Suspicious Process Names:</strong>
        <ul>
            {% for name in results.processes.indicators.suspicious_process_names %}
            <li>{{ name }}</li>
            {% endfor %}
        </ul>
    </div>
    {% endif %}
    
    {% if results.processes.indicators.suspicious_paths %}
    <div class="alert alert-warning">
        <strong>Suspicious Paths:</strong>
        <ul>
            {% for path in results.processes.indicators.suspicious_paths %}
            <li>{{ path }}</li>
            {% endfor %}
        </ul>
    </div>
    {% endif %}
    
    {% if results.processes.indicators.orphaned_processes %}
    <div class="alert alert-warning">
        <strong>Orphaned Processes:</strong>
        <ul>
            {% for proc in results.processes.indicators.orphaned_processes %}
            <li>PID {{ proc.pid }}: {{ proc.name }}</li>
            {% endfor %}
        </ul>
    </div>
    {% endif %}
    {% endif %}
</div>

<!-- Raw Plugin Output (if any) -->
{% if results.plugins %}
<div class="section">
    <h2>🔌 Custom Plugin Output</h2>
    {% for plugin in results.plugins %}
    <h3>{{ plugin.name }}</h3>
    <pre style="background: #0d1520; padding: 15px; border-radius: 8px; overflow-x: auto; font-size: 0.85em; color: #8899aa; border: 1px solid #1a2a3a;">
{{ plugin.data | tojson(indent=2) }}
    </pre>
    {% endfor %}
</div>
{% endif %}

{% endblock %}"""
        
        # Write templates
        with open(template_dir / 'base.html', 'w') as f:
            f.write(base_template)
        with open(template_dir / 'report.html', 'w') as f:
            f.write(report_template)
        
        logger.info(f"Created default templates in {template_dir}")
    
    def generate(self, output_path: Path) -> str:
        """
        Generate HTML report
        
        Args:
            output_path: Path to save HTML file
            
        Returns:
            Path to generated HTML file
        """
        logger.info(f"Generating HTML report: {output_path}")
        
        try:
            # Prepare template data
            template_data = {
                'results': self.results,
                'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            # Render template
            template = self.env.get_template('report.html')
            html_content = template.render(**template_data)
            
            # Write HTML file
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"HTML report generated: {output_path}")
            return str(output_path)
            
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")
            raise
