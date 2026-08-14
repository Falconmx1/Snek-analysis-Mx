"""
Snek Analysis Mx - Volatility 3 Wrapper
Handles Volatility integration, profile detection, and plugin execution
"""

import os
import sys
import json
import subprocess
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
import tempfile

logger = logging.getLogger(__name__)


class VolatilityWrapper:
    """
    Wrapper class for Volatility 3 memory forensics framework
    """
    
    def __init__(self, memory_file: str, profile: Optional[str] = None, 
                 plugin_dir: Optional[str] = None):
        """
        Initialize Volatility wrapper
        
        Args:
            memory_file: Path to memory dump file
            profile: Force specific Volatility profile (optional)
            plugin_dir: Additional plugin directory path (optional)
        """
        self.memory_file = Path(memory_file).absolute()
        self.profile = profile
        self.plugin_dir = plugin_dir
        self.volatility_path = self._find_volatility()
        self._detected_os = None
        self._available_plugins = None
        
        if not self.volatility_path:
            raise ImportError("Volatility 3 not found. Please install: pip install volatility3")
        
        logger.debug(f"Volatility path: {self.volatility_path}")
        logger.debug(f"Memory file: {self.memory_file}")
    
    def _find_volatility(self) -> Optional[str]:
        """
        Find Volatility 3 installation
        
        Returns:
            Path to volatility executable or None if not found
        """
        # Try as command-line tool
        try:
            result = subprocess.run(
                ['vol', '--help'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if 'Volatility 3 Framework' in result.stdout:
                return 'vol'
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        # Try Python module
        try:
            result = subprocess.run(
                [sys.executable, '-m', 'volatility3', '--help'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if 'Volatility 3 Framework' in result.stdout:
                return sys.executable
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        return None
    
    def _run_volatility(self, plugin: str, args: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Run a Volatility plugin and parse results
        
        Args:
            plugin: Plugin name (e.g., 'windows.pslist', 'linux.pslist')
            args: Additional arguments for the plugin
        
        Returns:
            Dictionary with plugin results
        """
        cmd = []
        
        # Build command
        if self.volatility_path == 'vol':
            cmd.extend(['vol', '-f', str(self.memory_file)])
        else:
            cmd.extend([sys.executable, '-m', 'volatility3', '-f', str(self.memory_file)])
        
        # Add profile if specified
        if self.profile:
            cmd.extend(['--profile', self.profile])
        
        # Add plugin
        cmd.append(plugin)
        
        # Add additional arguments
        if args:
            cmd.extend(args)
        
        # Add JSON output
        cmd.extend(['--output', 'json'])
        
        logger.debug(f"Running: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )
            
            if result.returncode != 0:
                logger.error(f"Volatility plugin {plugin} failed with code {result.returncode}")
                logger.error(f"stderr: {result.stderr}")
                return {'error': result.stderr, 'returncode': result.returncode}
            
            # Parse JSON output
            try:
                # Volatility outputs JSON, but might have other text before it
                # Find the actual JSON part
                output = result.stdout
                # Try to find JSON object in output
                json_start = output.find('{')
                if json_start == -1:
                    # Try to find JSON array
                    json_start = output.find('[')
                
                if json_start != -1:
                    json_str = output[json_start:]
                    data = json.loads(json_str)
                    return data
                else:
                    # Fallback: return raw output
                    return {'raw_output': output}
                
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse JSON from plugin {plugin}: {e}")
                return {'raw_output': output, 'stderr': result.stderr}
                
        except subprocess.TimeoutExpired:
            logger.error(f"Plugin {plugin} timed out after 300 seconds")
            return {'error': 'Timeout'}
        except Exception as e:
            logger.error(f"Error running plugin {plugin}: {e}")
            return {'error': str(e)}
    
    def detect_os(self) -> Optional[str]:
        """
        Detect OS profile of memory dump
        
        Returns:
            Detected OS profile string or None if detection failed
        """
        if self.profile:
            logger.debug(f"Using forced profile: {self.profile}")
            self._detected_os = self.profile
            return self.profile
        
        logger.info("Detecting OS from memory dump...")
        
        # Try Windows first
        try:
            result = self._run_volatility('windows.info')
            if 'error' not in result and result.get('raw_output'):
                # Check if output contains Windows indicators
                output = result.get('raw_output', '')
                if 'Windows' in output or 'NT' in output:
                    self._detected_os = self._find_windows_profile()
                    if self._detected_os:
                        logger.info(f"Windows profile detected: {self._detected_os}")
                        return self._detected_os
        except Exception as e:
            logger.debug(f"Windows detection failed: {e}")
        
        # Try Linux
        try:
            result = self._run_volatility('linux.info')
            if 'error' not in result and result.get('raw_output'):
                output = result.get('raw_output', '')
                if 'Linux' in output:
                    self._detected_os = 'Linux'
                    logger.info("Linux profile detected")
                    return self._detected_os
        except Exception as e:
            logger.debug(f"Linux detection failed: {e}")
        
        # Try Mac
        try:
            result = self._run_volatility('mac.info')
            if 'error' not in result and result.get('raw_output'):
                output = result.get('raw_output', '')
                if 'Darwin' in output or 'Mac' in output:
                    self._detected_os = 'Mac'
                    logger.info("Mac profile detected")
                    return self._detected_os
        except Exception as e:
            logger.debug(f"Mac detection failed: {e}")
        
        # Try to guess from the first plugin that works
        test_plugins = ['windows.pslist', 'linux.pslist', 'mac.pslist']
        for plugin in test_plugins:
            try:
                result = self._run_volatility(plugin)
                if 'error' not in result and result.get('raw_output'):
                    os_type = plugin.split('.')[0]
                    self._detected_os = os_type.capitalize()
                    logger.info(f"Detected OS: {self._detected_os}")
                    return self._detected_os
            except Exception:
                continue
        
        logger.error("Failed to detect OS profile")
        return None
    
    def _find_windows_profile(self) -> Optional[str]:
        """
        Try to find specific Windows profile
        
        Returns:
            Windows profile string or None
        """
        # Try various Windows plugins
        try:
            # Try to get build number from info
            result = self._run_volatility('windows.info')
            if 'raw_output' in result:
                output = result['raw_output']
                # Look for build number
                import re
                build_match = re.search(r'Build Number\s*:\s*(\d+)', output)
                if build_match:
                    build = build_match.group(1)
                    # Map build to profile (simplified)
                    build_profiles = {
                        '10240': 'Win10x64_10240',
                        '10586': 'Win10x64_10586',
                        '14393': 'Win10x64_14393',
                        '15063': 'Win10x64_15063',
                        '16299': 'Win10x64_16299',
                        '17134': 'Win10x64_17134',
                        '17763': 'Win10x64_17763',
                        '18362': 'Win10x64_18362',
                        '18363': 'Win10x64_18363',
                        '19041': 'Win10x64_19041',
                        '19042': 'Win10x64_19042',
                        '19043': 'Win10x64_19043',
                        '19044': 'Win10x64_19044',
                        '19045': 'Win10x64_19045',
                    }
                    if build in build_profiles:
                        return build_profiles[build]
        except Exception as e:
            logger.debug(f"Failed to find Windows profile: {e}")
        
        # Default Windows profile
        return 'Win10x64'
    
    def run_plugin(self, plugin: str, args: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Run any Volatility plugin
        
        Args:
            plugin: Plugin name
            args: Additional arguments
            
        Returns:
            Plugin results as dictionary
        """
        logger.info(f"Running plugin: {plugin}")
        return self._run_volatility(plugin, args)
    
    def get_processes(self) -> List[Dict[str, Any]]:
        """
        Get list of processes from memory dump
        
        Returns:
            List of process dictionaries
        """
        if self._detected_os == 'Windows':
            plugin = 'windows.pslist'
        elif self._detected_os == 'Linux':
            plugin = 'linux.pslist'
        elif self._detected_os == 'Mac':
            plugin = 'mac.pslist'
        else:
            # Try Windows first, then Linux, then Mac
            for p in ['windows.pslist', 'linux.pslist', 'mac.pslist']:
                try:
                    result = self._run_volatility(p)
                    if 'error' not in result:
                        plugin = p
                        break
                except:
                    continue
            else:
                logger.error("Could not determine process list plugin")
                return []
        
        result = self._run_volatility(plugin)
        
        if 'error' in result:
            logger.error(f"Failed to get process list: {result['error']}")
            return []
        
        # Parse processes from result
        processes = []
        try:
            if 'Processes' in result:
                processes = result['Processes']
            elif 'raw_output' in result:
                # Try to parse raw output
                output = result['raw_output']
                lines = output.strip().split('\n')
                if len(lines) > 2:  # Skip header
                    for line in lines[2:]:
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 3:
                                proc = {
                                    'pid': parts[0],
                                    'name': parts[1],
                                    'ppid': parts[2] if len(parts) > 2 else '0'
                                }
                                processes.append(proc)
        except Exception as e:
            logger.warning(f"Failed to parse processes: {e}")
        
        return processes
    
    def get_network_connections(self) -> List[Dict[str, Any]]:
        """
        Get network connections from memory dump
        
        Returns:
            List of network connection dictionaries
        """
        plugin = 'windows.netscan' if self._detected_os == 'Windows' else 'linux.netstat'
        
        try:
            result = self._run_volatility(plugin)
            if 'error' in result:
                logger.warning(f"Network scan failed: {result['error']}")
                return []
            
            connections = []
            if 'Connections' in result:
                connections = result['Connections']
            elif 'raw_output' in result:
                # Parse raw output
                output = result['raw_output']
                lines = output.strip().split('\n')
                if len(lines) > 1:
                    for line in lines[1:]:
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 5:
                                conn = {
                                    'protocol': parts[0],
                                    'local_addr': parts[1],
                                    'local_port': parts[2],
                                    'remote_addr': parts[3],
                                    'remote_port': parts[4]
                                }
                                connections.append(conn)
            
            return connections
        except Exception as e:
            logger.warning(f"Failed to get network connections: {e}")
            return []
    
    def get_dlls(self, pid: int) -> List[Dict[str, Any]]:
        """
        Get DLLs loaded by a specific process
        
        Args:
            pid: Process ID
            
        Returns:
            List of DLL dictionaries
        """
        plugin = 'windows.dlldump' if self._detected_os == 'Windows' else 'linux.lsobj'
        
        try:
            result = self._run_volatility(plugin, ['--pid', str(pid)])
            if 'error' in result:
                return []
            
            dlls = []
            if 'DLLs' in result:
                dlls = result['DLLs']
            elif 'raw_output' in result:
                output = result['raw_output']
                lines = output.strip().split('\n')
                if len(lines) > 1:
                    for line in lines[1:]:
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 2:
                                dll = {
                                    'name': parts[0],
                                    'path': parts[1] if len(parts) > 1 else ''
                                }
                                dlls.append(dll)
            
            return dlls
        except Exception as e:
            logger.warning(f"Failed to get DLLs for PID {pid}: {e}")
            return []
    
    def get_available_plugins(self) -> List[str]:
        """
        Get list of available Volatility plugins
        
        Returns:
            List of plugin names
        """
        if self._available_plugins:
            return self._available_plugins
        
        try:
            # Use vol command to list plugins
            result = self._run_volatility('--help')
            if 'raw_output' in result:
                output = result['raw_output']
                import re
                # Find plugin names
                plugins = re.findall(r'([a-z]+)\.[a-z]+', output)
                self._available_plugins = list(set(plugins))
                return self._available_plugins
        except Exception as e:
            logger.warning(f"Failed to list available plugins: {e}")
        
        return []
