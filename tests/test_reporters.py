"""
Unit tests for Reporters
"""

import unittest
import tempfile
import json
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from snek_analysis.reporters.html_reporter import HTMLReporter
from snek_analysis.reporters.json_reporter import JSONReporter


class TestHTMLReporter(unittest.TestCase):
    """Test cases for HTMLReporter class"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.results = {
            'memory_file': 'test_memory.dmp',
            'profile': 'Win10x64',
            'timestamp': '2024-01-01T00:00:00',
            'processes': {
                'total': 100,
                'suspicious': [
                    {
                        'pid': 1234,
                        'name': 'suspicious.exe',
                        'ppid': 5678,
                        'reasons': ['Suspicious name'],
                        'risk_score': 75,
                        'risk_level': 'HIGH'
                    }
                ],
                'summary': {
                    'total_processes': 100,
                    'system_processes': 50,
                    'user_processes': 45,
                    'suspicious_count': 1
                }
            },
            'network': {
                'total_connections': 50,
                'suspicious': [
                    {
                        'pid': 1234,
                        'process': 'suspicious.exe',
                        'remote_ip': '192.168.1.100',
                        'remote_port': 4444,
                        'reasons': ['Suspicious port'],
                        'risk_level': 'CRITICAL'
                    }
                ],
                'listening_ports': [
                    {'pid': 1234, 'process': 'suspicious.exe', 'protocol': 'TCP', 'local_port': 4444}
                ]
            },
            'dlls': {
                'total_dlls': 500,
                'suspicious_dlls': [
                    {
                        'pid': 1234,
                        'name': 'malware.dll',
                        'path': 'C:\\Temp\\malware.dll',
                        'reasons': ['Suspicious DLL name'],
                        'risk_level': 'HIGH'
                    }
                ],
                'summary': {
                    'total_dlls_loaded': 500,
                    'unique_dlls': 300,
                    'processes_analyzed': 20
                }
            }
        }
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_generate_html(self):
        """Test HTML report generation"""
        reporter = HTMLReporter(self.results)
        output_path = Path(self.temp_dir) / 'report.html'
        
        result = reporter.generate(output_path)
        
        self.assertTrue(output_path.exists())
        self.assertEqual(result, str(output_path))
        
        # Check HTML content
        with open(output_path, 'r') as f:
            content = f.read()
            self.assertIn('Snek Analysis Mx', content)
            self.assertIn('suspicious.exe', content)
            self.assertIn('malware.dll', content)
            self.assertIn('192.168.1.100', content)
    
    def test_generate_html_with_template(self):
        """Test HTML report generation with custom template"""
        reporter = HTMLReporter(self.results)
        
        # Should create templates automatically
        self.assertTrue(reporter.template_dir.exists())
        self.assertTrue((reporter.template_dir / 'base.html').exists())
        self.assertTrue((reporter.template_dir / 'report.html').exists())


class TestJSONReporter(unittest.TestCase):
    """Test cases for JSONReporter class"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.results = {
            'memory_file': 'test_memory.dmp',
            'profile': 'Win10x64',
            'timestamp': '2024-01-01T00:00:00',
            'processes': {
                'suspicious': [
                    {
                        'pid': 1234,
                        'name': 'suspicious.exe',
                        'reasons': ['Suspicious name'],
                        'risk_score': 75,
                        'risk_level': 'HIGH'
                    }
                ]
            },
            'network': {
                'suspicious': [
                    {
                        'pid': 1234,
                        'process': 'suspicious.exe',
                        'remote_ip': '192.168.1.100',
                        'reasons': ['Suspicious port'],
                        'risk_level': 'CRITICAL'
                    }
                ]
            },
            'dlls': {
                'suspicious_dlls': [
                    {
                        'pid': 1234,
                        'name': 'malware.dll',
                        'reasons': ['Suspicious DLL name'],
                        'risk_level': 'HIGH'
                    }
                ]
            }
        }
    
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_generate_json(self):
        """Test JSON report generation"""
        reporter = JSONReporter(self.results)
        output_path = Path(self.temp_dir) / 'report.json'
        
        result = reporter.generate(output_path)
        
        self.assertTrue(output_path.exists())
        self.assertEqual(result, str(output_path))
        
        # Check JSON content
        with open(output_path, 'r') as f:
            data = json.load(f)
            self.assertIn('metadata', data)
            self.assertIn('summary', data)
            self.assertIn('iocs', data)
            self.assertIn('detailed_results', data)
            
            # Check IOC extraction
            self.assertIn('suspicious_processes', data['iocs'])
            self.assertIn('suspicious_connections', data['iocs'])
            self.assertIn('suspicious_dlls', data['iocs'])
    
    def test_generate_compact_json(self):
        """Test compact JSON report generation"""
        reporter = JSONReporter(self.results)
        output_path = Path(self.temp_dir) / 'report_compact.json'
        
        result = reporter.generate_compact(output_path)
        
        self.assertTrue(output_path.exists())
        
        with open(output_path, 'r') as f:
            data = json.load(f)
            self.assertIn('metadata', data)
            self.assertIn('summary', data)
            self.assertIn('iocs', data)
            self.assertIn('suspicious_count', data)
            
            # Check that detailed results are not included
            self.assertNotIn('detailed_results', data)
    
    def test_generate_misp_format(self):
        """Test MISP format report generation"""
        reporter = JSONReporter(self.results)
        output_path = Path(self.temp_dir) / 'report_misp.json'
        
        result = reporter.generate_misp_format(output_path)
        
        self.assertTrue(output_path.exists())
        
        with open(output_path, 'r') as f:
            data = json.load(f)
            self.assertIn('Event', data)
            self.assertIn('attribute', data['Event'])
            
            # Check MISP attributes
            attributes = data['Event']['attribute']
            self.assertGreater(len(attributes), 0)
            
            # Check for process and network attributes
            found_process = any(a['type'] == 'filename' for a in attributes)
            found_ip = any(a['type'] == 'ip-dst' for a in attributes)
            self.assertTrue(found_process or found_ip)


if __name__ == '__main__':
    unittest.main()
