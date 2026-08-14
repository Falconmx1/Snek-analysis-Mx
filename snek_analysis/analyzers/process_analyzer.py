"""
Snek Analysis Mx - Process Analyzer
Detects suspicious processes, injections, and anomalies in memory
"""

import re
import logging
from typing import Dict, List, Any, Optional, Set
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger(__name__)


class ProcessAnalyzer:
    """
    Analyzes processes from memory dump for suspicious activity
    """
    
    # Known suspicious process names (malware, tools, etc.)
    SUSPICIOUS_NAMES = {
        # Malware families
        'cobaltstrike', 'beacon', 'mimikatz', 'wce', 'psexec', 
        'powershell.exe', 'cmd.exe', 'rundll32.exe', 'regsvr32.exe',
        'wmic.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe',
        'powershell_ise.exe', 'pwsh.exe', 'bash.exe', 'sh.exe',
        # Hacktools
        'nmap', 'masscan', 'hydra', 'john', 'hashcat', 'sqlmap',
        'metasploit', 'msfconsole', 'msfvenom', 'nc.exe', 'netcat',
        'plink', 'putty', 'vnc', 'radmin', 'teamviewer', 'anydesk',
        # Ransomware related
        'ransom', 'crypt', 'encrypt', 'decrypt', 'locker',
        # Miners
        'xmrig', 'ccminer', 'claymore', 'ethminer', 'miner',
        # Remote access
        'ssh.exe', 'sshd.exe', 'telnet.exe', 'rdesktop',
        # Living off the land
        'bitsadmin.exe', 'certutil.exe', 'findstr.exe', 'ftp.exe',
        'net.exe', 'net1.exe', 'nltest.exe', 'ping.exe', 'systeminfo.exe',
        'tasklist.exe', 'wget.exe', 'curl.exe'
    }
    
    # Suspicious process name patterns (regex)
    SUSPICIOUS_PATTERNS = [
        r'.*\.tmp$',           # Temp executables
        r'.*[0-9]{4,}\.exe$',  # Random numbered executables
        r'.*\.vbe$',           # VBScript encoded
        r'.*\.jse$',           # JScript encoded
        r'.*\.wsf$',           # Windows Script File
        r'.*\.ps1$',           # PowerShell scripts
        r'.*\.bat$',           # Batch files
        r'.*\.com$',           # COM executables
        r'.*[^a-zA-Z0-9]\.exe$', # Special chars in name
        r'^[a-z]{8,}\.exe$',   # Random 8+ chars
    ]
    
    # Known legitimate system processes (to reduce false positives)
    LEGITIMATE_SYSTEM_PROCESSES = {
        'system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe',
        'lsass.exe', 'svchost.exe', 'winlogon.exe', 'explorer.exe',
        'taskhost.exe', 'spoolsv.exe', 'dwm.exe', 'conhost.exe',
        'ctfmon.exe', 'sihost.exe', 'fontdrvhost.exe', 'wininit.exe',
        'winlogon.exe', 'lsm.exe', 'msmpeng.exe', 'dasHost.exe',
        'searchindexer.exe', 'wlanext.exe', 'audiodg.exe',
        'wmpnetwk.exe', 'igfxcuiservice.exe'
    }
    
    def __init__(self, volatility_wrapper):
        """
        Initialize Process Analyzer
        
        Args:
            volatility_wrapper: VolatilityWrapper instance
        """
        self.volatility = volatility_wrapper
        self.processes = []
        self.suspicious_processes = []
        self.process_tree = {}
        self.indicators = {}
        
    def analyze(self) -> Dict[str, Any]:
        """
        Perform comprehensive process analysis
        
        Returns:
            Dictionary with analysis results
        """
        logger.info("🕵️ Analyzing processes...")
        
        # Get process list from Volatility
        processes = self.volatility.get_processes()
        self.processes = processes
        
        if not processes:
            logger.warning("No processes found in memory dump")
            return {
                'total': 0,
                'processes': [],
                'suspicious': [],
                'tree': {},
                'summary': {
                    'total_processes': 0,
                    'suspicious_count': 0,
                    'unique_parents': 0
                }
            }
        
        # Build process tree
        self.process_tree = self._build_process_tree(processes)
        
        # Detect suspicious processes
        self.suspicious_processes = self.detect_suspicious(processes)
        
        # Find process injections
        injections = self._detect_injections()
        
        # Find hidden processes
        hidden = self._find_hidden_processes()
        
        # Detect processes with network connections
        processes_with_network = self._get_processes_with_network()
        
        # Calculate process statistics
        stats = self._calculate_statistics(processes)
        
        # Generate indicators
        self.indicators = self._generate_indicators(processes)
        
        return {
            'total': len(processes),
            'processes': processes,
            'suspicious': self.suspicious_processes,
            'tree': self.process_tree,
            'injections': injections,
            'hidden_processes': hidden,
            'network_connections': processes_with_network,
            'indicators': self.indicators,
            'summary': stats
        }
    
    def detect_suspicious(self, processes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Detect suspicious processes based on various indicators
        
        Args:
            processes: List of process dictionaries
            
        Returns:
            List of suspicious processes with reasons
        """
        suspicious = []
        
        for proc in processes:
            reasons = []
            risk_score = 0
            name = proc.get('name', '').lower()
            path = proc.get('path', '').lower()
            pid = proc.get('pid', 0)
            ppid = proc.get('ppid', 0)
            
            # Skip legitimate system processes
            if name in self.LEGITIMATE_SYSTEM_PROCESSES:
                continue
            
            # Check against suspicious names
            if name in self.SUSPICIOUS_NAMES:
                reasons.append(f"Suspicious process name: {name}")
                risk_score += 30
            
            # Check against suspicious patterns
            for pattern in self.SUSPICIOUS_PATTERNS:
                if re.match(pattern, name, re.IGNORECASE):
                    reasons.append(f"Suspicious name pattern: {name}")
                    risk_score += 25
                    break
            
            # Check for unusual paths
            if path and self._is_suspicious_path(path):
                reasons.append(f"Suspicious execution path: {path}")
                risk_score += 20
            
            # Check for processes running from temp directories
            if path and ('temp' in path or 'tmp' in path or 'cache' in path):
                reasons.append(f"Running from temp directory: {path}")
                risk_score += 15
            
            # Check for unsigned processes (if available)
            if proc.get('signed', False) is False and name not in self.LEGITIMATE_SYSTEM_PROCESSES:
                reasons.append("Unsigned process")
                risk_score += 10
            
            # Check for suspicious parent-child relationships
            if self._is_suspicious_parent_relation(proc, processes):
                reasons.append("Suspicious parent-child relationship")
                risk_score += 20
            
            # Check for processes with no parents (orphaned)
            if ppid == 0 and name not in ['system', 'smss.exe']:
                reasons.append("Orphaned process (no parent)")
                risk_score += 15
            
            # Check for duplicate names with different PIDs (possible process hollowing)
            same_name = [p for p in processes if p.get('name', '').lower() == name and p.get('pid') != pid]
            if len(same_name) > 1 and name not in self.LEGITIMATE_SYSTEM_PROCESSES:
                reasons.append(f"Multiple instances of {name} ({len(same_name)+1} instances)")
                risk_score += 10
            
            # Check for suspicious command line arguments
            cmdline = proc.get('cmdline', '')
            if cmdline and self._has_suspicious_args(cmdline):
                reasons.append(f"Suspicious command line arguments: {cmdline}")
                risk_score += 20
            
            # Check for hidden processes (not in pslist)
            if proc.get('hidden', False):
                reasons.append("Hidden process (detected via psscan)")
                risk_score += 35
            
            if reasons:
                suspicious.append({
                    'pid': pid,
                    'name': name,
                    'ppid': ppid,
                    'path': path,
                    'reasons': reasons,
                    'risk_score': min(100, risk_score),
                    'risk_level': self._calculate_risk_level(risk_score)
                })
        
        # Sort by risk score (highest first)
        suspicious.sort(key=lambda x: x['risk_score'], reverse=True)
        
        logger.info(f"Found {len(suspicious)} suspicious processes")
        return suspicious
    
    def _build_process_tree(self, processes: List[Dict[str, Any]]) -> Dict[int, List[int]]:
        """
        Build parent-child process tree
        
        Args:
            processes: List of process dictionaries
            
        Returns:
            Dictionary with parent PID as key and list of child PIDs as value
        """
        tree = defaultdict(list)
        
        for proc in processes:
            pid = proc.get('pid')
            ppid = proc.get('ppid', 0)
            if pid:
                tree[ppid].append(pid)
        
        return dict(tree)
    
    def _detect_injections(self) -> List[Dict[str, Any]]:
        """
        Detect potential process injections using VAD (Virtual Address Descriptor)
        analysis or other techniques
        
        Returns:
            List of injection indicators
        """
        injections = []
        
        try:
            # Try to use Windows VAD analysis for injection detection
            if self.volatility._detected_os == 'Windows':
                result = self.volatility.run_plugin('windows.vadinfo')
                
                if 'error' not in result:
                    # Look for VAD regions with suspicious flags
                    vad_entries = result.get('VADs', [])
                    for entry in vad_entries:
                        protection = entry.get('protection', '').lower()
                        pid = entry.get('pid')
                        
                        # Detect executable regions with unusual protections
                        if 'execute' in protection and 'write' in protection:
                            # RX or RWX regions - potential shellcode
                            injections.append({
                                'pid': pid,
                                'type': 'Executable memory region with write access',
                                'address': entry.get('start'),
                                'size': entry.get('size'),
                                'protection': protection,
                                'risk': 'HIGH'
                            })
                        elif 'execute' in protection and pid not in self.LEGITIMATE_SYSTEM_PROCESSES:
                            # Executable region in non-system process
                            injections.append({
                                'pid': pid,
                                'type': 'Executable memory region in user process',
                                'address': entry.get('start'),
                                'size': entry.get('size'),
                                'protection': protection,
                                'risk': 'MEDIUM'
                            })
            
            # Check for thread injection indicators (processes with many threads)
            for proc in self.suspicious_processes:
                pid = proc.get('pid')
                if pid:
                    # Count threads for this process
                    threads = self.volatility.run_plugin('windows.threads', ['--pid', str(pid)])
                    if 'Threads' in threads:
                        thread_count = len(threads['Threads'])
                        if thread_count > 100:  # Arbitrary threshold
                            injections.append({
                                'pid': pid,
                                'type': 'Process with excessive threads',
                                'thread_count': thread_count,
                                'risk': 'HIGH'
                            })
        
        except Exception as e:
            logger.debug(f"Injection detection failed: {e}")
        
        return injections
    
    def _find_hidden_processes(self) -> List[Dict[str, Any]]:
        """
        Find hidden processes using psscan or other techniques
        
        Returns:
            List of hidden processes
        """
        hidden = []
        
        try:
            # Use psscan to find hidden processes
            result = self.volatility.run_plugin('windows.psscan')
            
            if 'error' not in result:
                psscan_procs = result.get('Processes', [])
                pslist_pids = {p.get('pid') for p in self.processes if p.get('pid')}
                
                for proc in psscan_procs:
                    pid = proc.get('pid')
                    if pid and pid not in pslist_pids:
                        hidden.append({
                            'pid': pid,
                            'name': proc.get('name'),
                            'detected_by': 'psscan'
                        })
                        
                        # Add to suspicious processes if not already there
                        self.suspicious_processes.append({
                            'pid': pid,
                            'name': proc.get('name'),
                            'reasons': ['Hidden process (detected via psscan)'],
                            'risk_score': 50,
                            'risk_level': 'CRITICAL'
                        })
        
        except Exception as e:
            logger.debug(f"Hidden process detection failed: {e}")
        
        return hidden
    
    def _get_processes_with_network(self) -> Dict[int, List[Dict[str, Any]]]:
        """
        Get processes that have network connections
        
        Returns:
            Dictionary with PID as key and list of connections as value
        """
        network_map = defaultdict(list)
        
        try:
            # Get network connections
            connections = self.volatility.get_network_connections()
            
            for conn in connections:
                pid = conn.get('pid')
                if pid:
                    network_map[pid].append(conn)
        
        except Exception as e:
            logger.debug(f"Network connection mapping failed: {e}")
        
        return dict(network_map)
    
    def _calculate_statistics(self, processes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate process statistics
        
        Args:
            processes: List of process dictionaries
            
        Returns:
            Dictionary with statistics
        """
        # Count processes by type
        system_count = 0
        user_count = 0
        service_count = 0
        
        for proc in processes:
            name = proc.get('name', '').lower()
            if name in self.LEGITIMATE_SYSTEM_PROCESSES:
                system_count += 1
            elif 'service' in name or 'svchost' in name:
                service_count += 1
            else:
                user_count += 1
        
        # Count unique parents
        unique_parents = len(self.process_tree.keys())
        
        # Calculate average children per parent
        total_children = sum(len(children) for children in self.process_tree.values())
        avg_children = total_children / unique_parents if unique_parents > 0 else 0
        
        return {
            'total_processes': len(processes),
            'system_processes': system_count,
            'user_processes': user_count,
            'service_processes': service_count,
            'suspicious_count': len(self.suspicious_processes),
            'unique_parents': unique_parents,
            'avg_children_per_parent': round(avg_children, 2),
            'processes_by_user': self._count_processes_by_user(processes)
        }
    
    def _count_processes_by_user(self, processes: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Count processes by user
        
        Args:
            processes: List of process dictionaries
            
        Returns:
            Dictionary with username as key and count as value
        """
        user_count = defaultdict(int)
        
        for proc in processes:
            user = proc.get('user', 'unknown')
            user_count[user] += 1
        
        return dict(user_count)
    
    def _generate_indicators(self, processes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate IOCs (Indicators of Compromise) from process analysis
        
        Args:
            processes: List of process dictionaries
            
        Returns:
            Dictionary with generated indicators
        """
        indicators = {
            'suspicious_process_names': [],
            'suspicious_paths': [],
            'orphaned_processes': [],
            'process_hashes': []
        }
        
        for proc in self.suspicious_processes:
            indicators['suspicious_process_names'].append(proc.get('name'))
            
            path = proc.get('path')
            if path:
                indicators['suspicious_paths'].append(path)
        
        # Find orphaned processes
        for proc in processes:
            pid = proc.get('pid')
            ppid = proc.get('ppid', 0)
            if pid and ppid == 0 and proc.get('name', '').lower() not in ['system', 'smss.exe']:
                indicators['orphaned_processes'].append({
                    'pid': pid,
                    'name': proc.get('name')
                })
        
        # Collect process hashes (if available)
        for proc in processes:
            if proc.get('hash'):
                indicators['process_hashes'].append({
                    'pid': proc.get('pid'),
                    'name': proc.get('name'),
                    'hash': proc.get('hash')
                })
        
        return indicators
    
    def _is_suspicious_path(self, path: str) -> bool:
        """
        Check if execution path is suspicious
        
        Args:
            path: File path
            
        Returns:
            True if path is suspicious
        """
        suspicious_paths = [
            '\\users\\public\\',
            '\\programdata\\',
            '\\windows\\temp\\',
            '\\recycle.bin\\',
            '\\appdata\\local\\temp\\',
            '\\windows\\appcompat\\',
            '\\windows\\installer\\'
        ]
        
        path_lower = path.lower()
        
        # Check if path contains suspicious directories
        for sus_path in suspicious_paths:
            if sus_path in path_lower:
                return True
        
        # Check for paths with multiple dots (possible file extension spoofing)
        if path.count('.') > 2:
            return True
        
        return False
    
    def _is_suspicious_parent_relation(self, proc: Dict[str, Any], 
                                     processes: List[Dict[str, Any]]) -> bool:
        """
        Check if process has suspicious parent-child relationship
        
        Args:
            proc: Process dictionary
            processes: List of all processes
            
        Returns:
            True if parent relationship is suspicious
        """
        pid = proc.get('pid')
        ppid = proc.get('ppid', 0)
        
        if pid is None:
            return False
        
        # Find parent process
        parent = next((p for p in processes if p.get('pid') == ppid), None)
        if not parent:
            return False
        
        parent_name = parent.get('name', '').lower()
        child_name = proc.get('name', '').lower()
        
        # Check suspicious parent-child pairs
        suspicious_pairs = [
            ('cmd.exe', 'powershell.exe'),
            ('cmd.exe', 'wmic.exe'),
            ('powershell.exe', 'rundll32.exe'),
            ('explorer.exe', 'cmd.exe'),
            ('svchost.exe', 'rundll32.exe'),
            ('services.exe', 'cmd.exe'),
        ]
        
        for parent_p, child_p in suspicious_pairs:
            if parent_name == parent_p and child_name == child_p:
                return True
        
        # Check if parent is system process but child is not
        if parent_name in self.LEGITIMATE_SYSTEM_PROCESSES and child_name not in self.LEGITIMATE_SYSTEM_PROCESSES:
            return True
        
        return False
    
    def _has_suspicious_args(self, cmdline: str) -> bool:
        """
        Check if command line arguments contain suspicious patterns
        
        Args:
            cmdline: Command line string
            
        Returns:
            True if suspicious arguments found
        """
        cmdline_lower = cmdline.lower()
        
        suspicious_args = [
            '-enc', '-e ', '-encodedcommand',  # PowerShell encoded commands
            '-nop', '-noprofile',              # PowerShell bypass
            '-w hidden', '-windowstyle hidden', # Hidden windows
            'bypass', 'unrestricted',           # Execution policy bypass
            'downloadstring',                   # Download cradle
            'invoke-expression', 'iex',         # Execute command
            ' -c ', '-command',                 # Execute command
            ' -f ', '-file',                    # Run script
            '|', ';', '&&',                     # Command chaining
            '$', '{%', '{{'                     # Template injection
        ]
        
        for arg in suspicious_args:
            if arg in cmdline_lower:
                return True
        
        return False
    
    def _calculate_risk_level(self, score: int) -> str:
        """
        Calculate risk level based on score
        
        Args:
            score: Risk score (0-100)
            
        Returns:
            Risk level string
        """
        if score >= 70:
            return 'CRITICAL'
        elif score >= 50:
            return 'HIGH'
        elif score >= 30:
            return 'MEDIUM'
        else:
            return 'LOW'
