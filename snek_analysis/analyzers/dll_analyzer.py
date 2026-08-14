"""
Snek Analysis Mx - DLL Analyzer
Analyzes DLLs loaded by processes, detects injections and suspicious modules
"""

import re
import logging
from typing import Dict, List, Any, Optional, Set
from collections import defaultdict

logger = logging.getLogger(__name__)


class DLLAnalyzer:
    """
    Analyzes DLLs and modules loaded in processes
    """
    
    # Known suspicious DLLs
    SUSPICIOUS_DLLS = {
        # Malware-related
        'mimikatz.dll', 'pwdump.dll', 'fgdump.dll', 'hashdump.dll',
        'cobaltstrike.dll', 'beacon.dll', 'meterpreter.dll',
        'ncrypt.dll', 'secur32.dll', 'kerberos.dll',
        
        # Injection techniques
        'reflective_inject.dll', 'inject.dll', 'shellcode.dll',
        
        # Persistence mechanisms
        'appinit_dlls.dll', 'shim.dll', 'gpedit.dll',
        
        # Keyloggers
        'keylog.dll', 'keylogger.dll', 'logger.dll',
        
        # Rootkits
        'rootkit.dll', 'hide.dll', 'stealth.dll',
        
        # Common malware DLLs
        'wow64log.dll', 'wmi.dll', 'wmic.dll',
        'dllhost32.exe', 'dllhost64.exe',
        'suspicious.dll', 'malware.dll', 'trojan.dll'
    }
    
    # Known legitimate system DLLs (to reduce false positives)
    LEGITIMATE_DLLS = {
        'ntdll.dll', 'kernel32.dll', 'kernelbase.dll', 'advapi32.dll',
        'user32.dll', 'gdi32.dll', 'shell32.dll', 'ole32.dll',
        'comctl32.dll', 'msvcrt.dll', 'ucrtbase.dll', 'vcruntime.dll',
        'wow64.dll', 'wow64cpu.dll', 'wow64win.dll',
        'ctfmon.dll', 'imm32.dll', 'winmm.dll', 'ws2_32.dll',
        'sechost.dll', 'shlwapi.dll', 'combase.dll', 'winspool.drv',
        'iertutil.dll', 'urlmon.dll', 'wininet.dll', 'mshtml.dll',
        'msimg32.dll', 'winhttp.dll', 'uxtheme.dll', 'dwmapi.dll',
        'dwrite.dll', 'dxgi.dll', 'msxml3.dll', 'rasapi32.dll',
        'wintrust.dll', 'crypt32.dll', 'ncrypt.dll', 'bcrypt.dll'
    }
    
    def __init__(self, volatility_wrapper):
        """
        Initialize DLL Analyzer
        
        Args:
            volatility_wrapper: VolatilityWrapper instance
        """
        self.volatility = volatility_wrapper
        self.dlls = {}
        self.suspicious_dlls = []
        
    def analyze(self, target_pids: Optional[List[int]] = None) -> Dict[str, Any]:
        """
        Perform comprehensive DLL analysis
        
        Args:
            target_pids: List of PIDs to analyze (all if None)
            
        Returns:
            Dictionary with analysis results
        """
        logger.info("🔧 Analyzing DLLs...")
        
        results = {
            'total_dlls': 0,
            'processes_analyzed': [],
            'suspicious_dlls': [],
            'dll_injections': [],
            'orphaned_dlls': [],
            'dll_loaded_in_multiple': [],
            'summary': {}
        }
        
        # Get processes if target not specified
        if not target_pids:
            processes = self.volatility.get_processes()
            target_pids = [p.get('pid') for p in processes if p.get('pid')]
        
        # Analyze each process
        all_dlls = []
        suspicious_by_process = defaultdict(list)
        
        for pid in target_pids:
            try:
                dlls = self.volatility.get_dlls(pid)
                if dlls:
                    self.dlls[pid] = dlls
                    all_dlls.extend(dlls)
                    
                    # Check for suspicious DLLs
                    suspicious = self._check_suspicious_dlls(dlls, pid)
                    if suspicious:
                        suspicious_by_process[pid] = suspicious
                        self.suspicious_dlls.extend(suspicious)
                    
                    # Check for DLL injection
                    injection = self._detect_dll_injection(dlls, pid)
                    if injection:
                        results['dll_injections'].append(injection)
                    
                    results['processes_analyzed'].append(pid)
                    
            except Exception as e:
                logger.debug(f"Failed to analyze DLLs for PID {pid}: {e}")
                continue
        
        # Find orphaned DLLs (loaded but not in typical locations)
        orphaned = self._find_orphaned_dlls(all_dlls)
        results['orphaned_dlls'] = orphaned
        
        # Find DLLs loaded in multiple processes (possible shared malicious code)
        multi_loaded = self._find_dlls_in_multiple_processes(all_dlls)
        results['dll_loaded_in_multiple'] = multi_loaded
        
        # Get unique suspicious DLLs
        unique_suspicious = []
        seen = set()
        for dll in self.suspicious_dlls:
            name = dll.get('name')
            if name and name not in seen:
                seen.add(name)
                unique_suspicious.append(dll)
        
        results['suspicious_dlls'] = unique_suspicious
        
        # Calculate statistics
        total_unique = len(set(dll.get('name') for dll in all_dlls if dll.get('name')))
        results['total_dlls'] = len(all_dlls)
        results['summary'] = {
            'total_dlls_loaded': len(all_dlls),
            'unique_dlls': total_unique,
            'processes_analyzed': len(target_pids),
            'suspicious_dlls_found': len(unique_suspicious),
            'dll_injections_found': len(results['dll_injections'])
        }
        
        logger.info(f"Found {len(unique_suspicious)} suspicious DLLs")
        return results
    
    def _check_suspicious_dlls(self, dlls: List[Dict[str, Any]], 
                               pid: int) -> List[Dict[str, Any]]:
        """
        Check DLLs for suspicious indicators
        
        Args:
            dlls: List of DLL dictionaries
            pid: Process ID
            
        Returns:
            List of suspicious DLLs with reasons
        """
        suspicious = []
        
        for dll in dlls:
            name = dll.get('name', '').lower()
            path = dll.get('path', '').lower()
            base = dll.get('base_address')
            
            reasons = []
            risk_score = 0
            
            # Check against suspicious DLL list
            if name in self.SUSPICIOUS_DLLS:
                reasons.append(f"Suspicious DLL name: {name}")
                risk_score += 35
            
            # Check for DLLs loaded from suspicious locations
            if path:
                if self._is_suspicious_path(path):
                    reasons.append(f"Loaded from suspicious path: {path}")
                    risk_score += 20
                
                # Check for DLLs loaded from temp directories
                if 'temp' in path or 'tmp' in path or 'cache' in path:
                    reasons.append(f"Loaded from temp directory: {path}")
                    risk_score += 15
            
            # Check for known malicious DLL patterns
            if self._has_suspicious_pattern(name):
                reasons.append(f"Suspicious DLL name pattern: {name}")
                risk_score += 25
            
            # Check if DLL is loaded from non-system path but has system name
            if path and 'system32' not in path and 'syswow64' not in path:
                if name in self.LEGITIMATE_DLLS:
                    reasons.append(f"System DLL loaded from non-system path: {path}")
                    risk_score += 20
            
            # Check for unusually large number of DLLs (potential injection)
            if len(dlls) > 100:  # Arbitrary threshold
                if not any(name in self.LEGITIMATE_DLLS for name in [d.get('name', '') for d in dlls[:10]]):
                    reasons.append(f"Excessive DLLs loaded ({len(dlls)} modules)")
                    risk_score += 10
            
            if reasons:
                suspicious.append({
                    'pid': pid,
                    'name': name,
                    'path': path,
                    'base_address': base,
                    'reasons': reasons,
                    'risk_score': min(100, risk_score),
                    'risk_level': self._calculate_risk_level(risk_score)
                })
        
        return suspicious
    
    def _detect_dll_injection(self, dlls: List[Dict[str, Any]], 
                              pid: int) -> Optional[Dict[str, Any]]:
        """
        Detect potential DLL injection
        
        Args:
            dlls: List of DLL dictionaries
            pid: Process ID
            
        Returns:
            Injection indicator if found
        """
        # Check for known injection indicators
        for dll in dlls:
            name = dll.get('name', '').lower()
            path = dll.get('path', '').lower()
            
            # Check if DLL is loaded from atypical location
            if path and 'system32' not in path and 'syswow64' not in path:
                # Check if it's a known system DLL (would indicate injection)
                if name in self.LEGITIMATE_DLLS:
                    return {
                        'pid': pid,
                        'dll_name': name,
                        'path': path,
                        'indicator': 'System DLL loaded from non-system path (possible injection)',
                        'risk': 'HIGH'
                    }
        
        # Check for DLLs with unusual base addresses
        for dll in dlls:
            base = dll.get('base_address')
            if base:
                # Typical DLLs load at specific addresses
                # This is a simplified check
                if isinstance(base, int) and base < 0x10000000:
                    # Very low address might indicate injection
                    return {
                        'pid': pid,
                        'dll_name': dll.get('name'),
                        'base_address': hex(base),
                        'indicator': 'DLL loaded at unusually low address (possible injection)',
                        'risk': 'MEDIUM'
                    }
        
        return None
    
    def _find_orphaned_dlls(self, dlls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Find orphaned DLLs (not associated with legitimate processes)
        
        Args:
            dlls: List of all DLL dictionaries
            
        Returns:
            List of orphaned DLLs
        """
        orphaned = []
        
        # Group DLLs by name
        dll_groups = defaultdict(list)
        for dll in dlls:
            name = dll.get('name')
            if name:
                dll_groups[name].append(dll)
        
        # Check each group
        for name, dll_list in dll_groups.items():
            # Check if DLL is found in multiple processes but not in system32
            if len(dll_list) >= 3 and name not in self.LEGITIMATE_DLLS:
                # Check if any instance is in system32
                in_system32 = any(
                    'system32' in dll.get('path', '').lower() or 
                    'syswow64' in dll.get('path', '').lower()
                    for dll in dll_list
                )
                
                if not in_system32:
                    orphaned.append({
                        'name': name,
                        'loaded_in': [dll.get('pid') for dll in dll_list],
                        'indicator': 'DLL loaded in multiple processes outside system directory'
                    })
        
        return orphaned
    
    def _find_dlls_in_multiple_processes(self, 
                                       dlls: List[Dict[str, Any]]) -> Dict[str, List[int]]:
        """
        Find DLLs loaded in multiple processes
        
        Args:
            dlls: List of all DLL dictionaries
            
        Returns:
            Dictionary with DLL name as key and list of PIDs as value
        """
        dll_process_map = defaultdict(set)
        
        for dll in dlls:
            name = dll.get('name')
            pid = dll.get('pid')
            if name and pid:
                dll_process_map[name].add(pid)
        
        # Convert sets to lists
        return {name: list(pids) for name, pids in dll_process_map.items() if len(pids) > 1}
    
    def _is_suspicious_path(self, path: str) -> bool:
        """
        Check if file path is suspicious
        
        Args:
            path: File path
            
        Returns:
            True if path is suspicious
        """
        suspicious_paths = [
            '\\users\\public\\',
            '\\programdata\\',
            '\\windows\\temp\\',
            '\\appdata\\local\\temp\\',
            '\\recycle.bin\\',
            '\\system32\\tasks\\',
            '\\windows\\installer\\',
            '\\program files\\common files\\',
            '\\windows\\system32\\drivers\\etc\\'
        ]
        
        path_lower = path.lower()
        
        for sus_path in suspicious_paths:
            if sus_path in path_lower:
                return True
        
        # Check for paths with multiple file extensions
        if '\\' in path:
            filename = path.split('\\')[-1]
            if filename.count('.') > 1:
                return True
        
        return False
    
    def _has_suspicious_pattern(self, name: str) -> bool:
        """
        Check if DLL name has suspicious pattern
        
        Args:
            name: DLL name
            
        Returns:
            True if suspicious pattern found
        """
        # Check for random-looking names
        if re.match(r'^[a-f0-9]{8,}\.dll$', name, re.IGNORECASE):
            return True
        
        # Check for temp-like names
        if re.match(r'.*\.tmp\.dll$', name, re.IGNORECASE):
            return True
        
        # Check for unusual characters
        if re.search(r'[^a-zA-Z0-9_\-\.]', name):
            return True
        
        # Check for double extensions
        if name.count('.') > 1:
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
