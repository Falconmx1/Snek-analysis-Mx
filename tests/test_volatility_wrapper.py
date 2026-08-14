"""
Unit tests for Volatility Wrapper
"""

import unittest
import os
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from snek_analysis.volatility_wrapper import VolatilityWrapper


class TestVolatilityWrapper(unittest.TestCase):
    """Test cases for VolatilityWrapper class"""
    
    def setUp(self):
        """Set up test environment"""
        # Create a dummy memory file
        self.temp_dir = tempfile.mkdtemp()
        self.memory_file = Path(self.temp_dir) / 'test_memory.dmp'
        self.memory_file.write_bytes(b'\x00' * 1024 * 1024)  # 1MB dummy file
        
    def tearDown(self):
        """Clean up test environment"""
        if self.memory_file.exists():
            self.memory_file.unlink()
        os.rmdir(self.temp_dir)
    
    @patch('snek_analysis.volatility_wrapper.subprocess.run')
    def test_find_volatility_command(self, mock_run):
        """Test finding Volatility as command"""
        mock_run.return_value = Mock(
            stdout='Volatility 3 Framework',
            returncode=0
        )
        
        wrapper = VolatilityWrapper(str(self.memory_file))
        self.assertEqual(wrapper.volatility_path, 'vol')
    
    @patch('snek_analysis.volatility_wrapper.subprocess.run')
    def test_find_volatility_module(self, mock_run):
        """Test finding Volatility as Python module"""
        # First call fails (command not found)
        mock_run.side_effect = [
            FileNotFoundError(),  # vol command not found
            Mock(stdout='Volatility 3 Framework', returncode=0)  # python -m volatility3 works
        ]
        
        wrapper = VolatilityWrapper(str(self.memory_file))
        self.assertEqual(wrapper.volatility_path, sys.executable)
    
    @patch('snek_analysis.volatility_wrapper.subprocess.run')
    def test_detect_os_windows(self, mock_run):
        """Test Windows OS detection"""
        mock_run.return_value = Mock(
            stdout='Build Number: 19045',
            returncode=0
        )
        
        wrapper = VolatilityWrapper(str(self.memory_file))
        profile = wrapper.detect_os()
        self.assertEqual(profile, 'Win10x64_19045')
    
    @patch('snek_analysis.volatility_wrapper.subprocess.run')
    def test_detect_os_linux(self, mock_run):
        """Test Linux OS detection"""
        def side_effect(*args, **kwargs):
            # First call for Windows detection fails
            if 'windows.info' in str(args):
                return Mock(stdout='', returncode=1)
            # Second call for Linux detection succeeds
            elif 'linux.info' in str(args):
                return Mock(stdout='Linux version', returncode=0)
            # Third call for process list succeeds
            elif 'linux.pslist' in str(args):
                return Mock(stdout='Processes:', returncode=0)
            return Mock(stdout='', returncode=0)
        
        mock_run.side_effect = side_effect
        
        wrapper = VolatilityWrapper(str(self.memory_file))
        profile = wrapper.detect_os()
        self.assertEqual(profile, 'Linux')
    
    @patch('snek_analysis.volatility_wrapper.subprocess.run')
    def test_run_plugin_success(self, mock_run):
        """Test running a plugin successfully"""
        mock_run.return_value = Mock(
            stdout='{"Processes": [{"pid": 1234, "name": "test.exe"}]}',
            returncode=0
        )
        
        wrapper = VolatilityWrapper(str(self.memory_file))
        result = wrapper.run_plugin('windows.pslist')
        
        self.assertIn('Processes', result)
        self.assertEqual(len(result['Processes']), 1)
        self.assertEqual(result['Processes'][0]['pid'], 1234)
    
    @patch('snek_analysis.volatility_wrapper.subprocess.run')
    def test_run_plugin_timeout(self, mock_run):
        """Test plugin timeout"""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd='vol', timeout=300)
        
        wrapper = VolatilityWrapper(str(self.memory_file))
        result = wrapper.run_plugin('windows.pslist')
        
        self.assertIn('error', result)
        self.assertEqual(result['error'], 'Timeout')


if __name__ == '__main__':
    unittest.main()
