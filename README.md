# 🐍 Snek Analysis Mx

**Memory Forensics Toolkit - Volatility 3 Wrapper for Incident Response**

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Volatility 3](https://img.shields.io/badge/volatility-3-orange.svg)](https://github.com/volatilityfoundation/volatility3)

---

## 📌 Overview

Snek Analysis Mx is an automated memory forensics toolkit that wraps Volatility 3 to accelerate incident response and malware analysis. It identifies OS profiles, suspicious processes, network connections, DLL injections, and generates professional HTML reports with interactive visualizations.

### 🎯 Key Features

- 🔍 **Automatic OS Detection** - Identifies Windows, Linux, and macOS profiles with confidence scoring
- 🕵️ **Process Analysis** - Detects suspicious processes, hidden processes, and process injections
- 🌐 **Network Analysis** - Identifies suspicious connections, listening ports, and potential C2 traffic
- 🔧 **DLL Analysis** - Finds suspicious DLLs, injection techniques, and orphaned modules
- 📊 **HTML Reports** - Interactive professional reports with visual indicators
- 📁 **JSON Output** - Structured data for integration with SIEM and threat intelligence tools
- ⚡ **Quick Mode** - Fast triage for large memory dumps
- 🔌 **Plugin Support** - Run any Volatility 3 plugin

---

## 🚀 Quick Start

### Installation

```bash
# Install from PyPI (coming soon)
pip install snek-analysis-mx

# Or install from source
git clone https://github.com/Falconmx1/Snek-analysis-Mx.git
cd Snek-analysis-Mx
pip install -e .

Basic Usage

# Full analysis with HTML report
snek-analyze -f memory.dmp -o report.html

# Quick analysis mode
snek-analyze -f memory.dmp --quick

# Only detect OS profile
snek-analyze -f memory.dmp --detect-os

# JSON output for integration
snek-analyze -f memory.dmp --format json -o results.json

# Run specific Volatility plugins
snek-analyze -f memory.dmp -p windows.cmdline,windows.netscan -o report.html
Python API

from snek_analysis import VolatilityWrapper
from snek_analysis.analyzers import ProcessAnalyzer, NetworkAnalyzer, DLLAnalyzer
from snek_analysis.reporters import HTMLReporter

# Initialize
vol = VolatilityWrapper('memory.dmp')
os_info = vol.detect_os()

# Analyze
processes = ProcessAnalyzer(vol).analyze()
network = NetworkAnalyzer(vol).analyze()
dlls = DLLAnalyzer(vol).analyze()

# Generate report
results = {'processes': processes, 'network': network, 'dlls': dlls}
HTMLReporter(results).generate('report.html')
📊 Example Report
https://docs/report_preview.png

The HTML report includes:

📈 Summary dashboard with risk indicators

🔍 Suspicious processes with detailed reasons

🌐 Network connections with threat intelligence

🔧 DLL analysis with injection detection

📊 Indicators of Compromise (IOCs)
