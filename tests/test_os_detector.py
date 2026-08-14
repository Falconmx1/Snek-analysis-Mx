"""
Unit tests for OS Detector
"""

import unittest
from unittest.mock import Mock, patch
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from snek_analysis.utils.os_detector import OSDetector


class TestOSDetector(unittest.TestCase):
    """Test cases for OSDetector class"""
    
    def setUp(self):
        """Set up test environment"""
        self.mock_volatility = Mock()
    
    def test_detect_windows_from_info(self):
        """Test Windows detection from info plugin"""
        mock_result = {
            'raw_output': '''
            Volatility 3 Framework 2.5.0
            Build Number: 19045
            '''
        }
        self.mock_volatility.run_plugin.return_value = mock_result
        
        detector = OSDetector(self.mock_volatility)
        result = detector._detect_windows()
        
        self.assertIsNotNone(result)
        self.assertEqual(result['os_type'], 'Windows')
        self.assertEqual(result['os_build'], '19045')
        self.assertEqual(result['confidence'], 95)
    
    def test_detect_linux_from_info(self):
        """Test Linux detection from info plugin"""
        mock_result = {
            'raw_output': '''
            Distribution: Ubuntu 22.04 LTS
            '''
        }
        self.mock_volatility.run_plugin.return_value = mock_result
        
        detector = OSDetector(self.mock_volatility)
        result = detector._detect_linux()
        
        self.assertIsNotNone(result)
        self.assertEqual(result['os_type'], 'Linux')
        self.assertIn('Ubuntu', result['os_name'])
    
    def test_detect_os_unknown(self):
        """Test unknown OS detection"""
        self.mock_volatility.run_plugin.return_value = {'error': 'Plugin not found'}
        
        detector = OSDetector(self.mock_volatility)
        result = detector.detect()
        
        # Should fallback to unknown or detect via other methods
        self.assertIsNotNone(result)
    
    def test_get_os_family(self):
        """Test getting OS family"""
        detector = OSDetector(self.mock_volatility)
        detector.detected_os = {'os_type': 'Windows', 'confidence': 95}
        
        self.assertEqual(detector.get_os_family(), 'Windows')
        self.assertTrue(detector.is_windows())
        self.assertFalse(detector.is_linux())
    
    def test_get_volatility_profile(self):
        """Test getting Volatility profile"""
        detector = OSDetector(self.mock_volatility)
        detector.detected_os = {'profile': 'Win10x64_19045'}
        
        self.assertEqual(detector.get_volatility_profile(), 'Win10x64_19045')
    
    def test_get_compatible_plugins_windows(self):
        """Test compatible plugins for Windows"""
        detector = OSDetector(self.mock_volatility)
        detector.detected_os = {'os_type': 'Windows'}
        
        plugins = detector.get_compatible_plugins()
        self.assertIn('windows.pslist', plugins)
        self.assertIn('windows.netscan', plugins)
        self.assertIn('windows.malfind', plugins)
    
    def test_get_compatible_plugins_linux(self):
        """Test compatible plugins for Linux"""
        detector = OSDetector(self.mock_volatility)
        detector.detected_os = {'os_type': 'Linux'}
        
        plugins = detector.get_compatible_plugins()
        self.assertIn('linux.pslist', plugins)
        self.assertIn('linux.netstat', plugins)
    
    def test_get_suggested_plugins_basic(self):
        """Test suggested plugins for basic analysis"""
        detector = OSDetector(self.mock_volatility)
        detector.detected_os = {'os_type': 'Windows'}
        
        plugins = detector.get_suggested_plugins('basic')
        self.assertEqual(len(plugins), 3)
        self.assertIn('windows.pslist', plugins)
    
    def test_get_suggested_plugins_full(self):
        """Test suggested plugins for full analysis"""
        detector = OSDetector(self.mock_volatility)
        detector.detected_os = {'os_type': 'Windows'}
        
        plugins = detector.get_suggested_plugins('full')
        self.assertGreater(len(plugins), 5)
    
    def test_get_os_fingerprint(self):
        """Test OS fingerprint generation"""
        detector = OSDetector(self.mock_volatility)
        detector.detected_os = {
            'os_type': 'Windows',
            'os_name': 'Windows 10 22H2',
            'os_version': '10.0',
            'os_build': '19045',
            'profile': 'Win10x64_19045',
            'confidence': 95
        }
        
        fingerprint = detector.get_os_fingerprint()
        self.assertEqual(fingerprint['os_type'], 'Windows')
        self.assertEqual(fingerprint['os_build'], '19045')
        self.assertIn('fingerprint_hash', fingerprint)


if __name__ == '__main__':
    unittest.main()
