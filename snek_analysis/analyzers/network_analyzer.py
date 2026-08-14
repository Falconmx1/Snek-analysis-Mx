"""
Snek Analysis Mx - Network Analyzer
Analyzes network connections, listening ports, and suspicious network activity
"""

import re
import logging
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
import ipaddress

logger = logging.getLogger(__name__)


class NetworkAnalyzer:
    """
    Analyzes network connections from memory dump
    """
    
    # Known malicious IP ranges (examples - expand with threat intelligence)
    MALICIOUS_IP_RANGES = [
        ('10.0.0.0', '10.255.255.255'),      # Private (not malicious, but suspicious for C2)
        ('172.16.0.0', '172.31.255.255'),     # Private
        ('192.168.0.0', '192.168.255.255'),   # Private
        ('127.0.0.0', '127.255.255.255'),     # Localhost
    ]
    
    # Suspicious ports
    SUSPICIOUS_PORTS = {
        21: 'FTP (data exfiltration)',
        22: 'SSH (possible remote access)',
        23: 'Telnet (insecure)',
        25: 'SMTP (email exfiltration)',
        80: 'HTTP (possible C2)',
        443: 'HTTPS (possible C2)',
        445: 'SMB (lateral movement)',
        1433: 'MSSQL (data exfiltration)',
        3306: 'MySQL (data exfiltration)',
        3389: 'RDP (remote access)',
        5432: 'PostgreSQL (data exfiltration)',
        5900: 'VNC (remote access)',
        6379: 'Redis (data exfiltration)',
        8080: 'HTTP Proxy (possible C2)',
        4444: 'Metasploit Meterpreter',
        5555: 'Android ADB (mobile)',
        6666: 'IRC (malware C2)',
        7777: 'Common malware C2',
        8888: 'Common malware C2',
        9999: 'Common malware C2'
    }
    
    # Known legitimate services (to reduce false positives)
    LEGITIMATE_SERVICES = {
        'svchost.exe': [53, 80, 443, 135, 445, 3389, 49152],
        'lsass.exe': [88, 389, 445, 636, 3268, 3269],
        'services.exe': [135, 445],
        'msdtc.exe': [135],
        'spoolsv.exe': [445],
        'dns.exe': [53],
        'w3wp.exe': [80, 443, 8080],
        'system': [445]
    }
    
    def __init__(self, volatility_wrapper):
        """
        Initialize Network Analyzer
        
        Args:
            volatility_wrapper: VolatilityWrapper instance
        """
        self.volatility = volatility_wrapper
        self.connections = []
        self.suspicious_connections = []
        
    def analyze(self) -> Dict[str, Any]:
        """
        Perform comprehensive network analysis
        
        Returns:
            Dictionary with analysis results
        """
        logger.info("🌐 Analyzing network connections...")
        
        # Get network connections from Volatility
        connections = self.volatility.get_network_connections()
        self.connections = connections
        
        if not connections:
            logger.info("No network connections found")
            return {
                'total_connections': 0,
                'active_connections': [],
                'listening_ports': [],
                'suspicious': [],
                'connections_by_protocol': {},
                'connections_by_process': {}
            }
        
        # Classify connections
        active_connections = self._classify_connections(connections)
        listening_ports = self._find_listening_ports(connections)
        
        # Detect suspicious connections
        self.suspicious_connections = self._detect_suspicious_connections(connections)
        
        # Group by protocol
        by_protocol = self._group_by_protocol(connections)
        
        # Group by process
        by_process = self._group_by_process(connections)
        
        # Find connections to known malicious IPs (if any)
        malicious_ips = self._check_malicious_ips(connections)
        
        # Detect potential data exfiltration patterns
        data_exfil = self._detect_data_exfiltration(connections)
        
        return {
            'total_connections': len(connections),
            'active_connections': active_connections,
            'listening_ports': listening_ports,
            'suspicious': self.suspicious_connections,
            'malicious_ips': malicious_ips,
            'data_exfiltration': data_exfil,
            'connections_by_protocol': by_protocol,
            'connections_by_process': by_process
        }
    
    def _classify_connections(self, connections: List[Dict[str, Any]]) -> Dict[str, List]:
        """
        Classify connections by state
        
        Args:
            connections: List of connection dictionaries
            
        Returns:
            Dictionary with classified connections
        """
        classified = {
            'established': [],
            'listening': [],
            'time_wait': [],
            'close_wait': [],
            'syn_sent': [],
            'syn_recv': [],
            'other': []
        }
        
        for conn in connections:
            state = conn.get('state', '').lower()
            
            if 'established' in state:
                classified['established'].append(conn)
            elif 'listen' in state:
                classified['listening'].append(conn)
            elif 'time_wait' in state:
                classified['time_wait'].append(conn)
            elif 'close_wait' in state:
                classified['close_wait'].append(conn)
            elif 'syn_sent' in state:
                classified['syn_sent'].append(conn)
            elif 'syn_recv' in state:
                classified['syn_recv'].append(conn)
            else:
                classified['other'].append(conn)
        
        return classified
    
    def _find_listening_ports(self, connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Find listening ports
        
        Args:
            connections: List of connection dictionaries
            
        Returns:
            List of listening ports with process info
        """
        listening = []
        
        for conn in connections:
            state = conn.get('state', '').lower()
            if 'listen' in state or 'listening' in state:
                listening.append({
                    'pid': conn.get('pid'),
                    'process': conn.get('process', 'unknown'),
                    'protocol': conn.get('protocol', 'TCP'),
                    'local_port': conn.get('local_port'),
                    'local_address': conn.get('local_address', '0.0.0.0'),
                    'state': 'LISTENING'
                })
        
        return listening
    
    def _detect_suspicious_connections(self, connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Detect suspicious network connections
        
        Args:
            connections: List of connection dictionaries
            
        Returns:
            List of suspicious connections with reasons
        """
        suspicious = []
        
        for conn in connections:
            reasons = []
            risk_score = 0
            pid = conn.get('pid')
            process = conn.get('process', '').lower()
            protocol = conn.get('protocol', 'TCP').upper()
            local_port = conn.get('local_port')
            remote_port = conn.get('remote_port')
            remote_ip = conn.get('remote_ip')
            state = conn.get('state', '')
            
            # Skip established connections for now
            if state and 'listening' in state.lower():
                continue
            
            # Check for suspicious remote ports
            if remote_port and remote_port in self.SUSPICIOUS_PORTS:
                reasons.append(f"Connection to suspicious port {remote_port}: {self.SUSPICIOUS_PORTS[remote_port]}")
                risk_score += 25
            
            # Check for connections to private IPs (potential C2)
            if remote_ip and self._is_private_ip(remote_ip):
                reasons.append(f"Connection to private IP: {remote_ip}")
                risk_score += 15
            
            # Check for connections from suspicious processes
            if process and process in ProcessAnalyzer.SUSPICIOUS_NAMES:
                reasons.append(f"Suspicious process {process} has network connection")
                risk_score += 30
            
            # Check for outbound connections from system processes (anomaly)
            if process and process in ProcessAnalyzer.LEGITIMATE_SYSTEM_PROCESSES:
                if remote_port and remote_port not in self.LEGITIMATE_SERVICES.get(process, []):
                    reasons.append(f"Unusual connection from system process {process} on port {remote_port}")
                    risk_score += 15
            
            # Check for connections to public IPs from internal process (possible data exfil)
            if remote_ip and not self._is_private_ip(remote_ip) and remote_port:
                if remote_port in [21, 25, 80, 443, 8080]:  # Common exfil ports
                    reasons.append(f"Potential data exfiltration: {process} -> {remote_ip}:{remote_port}")
                    risk_score += 20
            
            # Check for multiple outbound connections (beaconing)
            if self._is_potential_beacon(conn, connections):
                reasons.append("Potential beaconing activity detected")
                risk_score += 20
            
            # Check for suspicious protocol usage
            if protocol == 'UDP' and remote_port and remote_port < 1024:
                if process and process not in ProcessAnalyzer.LEGITIMATE_SYSTEM_PROCESSES:
                    reasons.append(f"Unusual UDP connection from {process}")
                    risk_score += 10
            
            if reasons:
                suspicious.append({
                    'pid': pid,
                    'process': process,
                    'protocol': protocol,
                    'local_port': local_port,
                    'remote_ip': remote_ip,
                    'remote_port': remote_port,
                    'state': state,
                    'reasons': reasons,
                    'risk_score': min(100, risk_score),
                    'risk_level': self._calculate_risk_level(risk_score)
                })
        
        # Sort by risk score
        suspicious.sort(key=lambda x: x['risk_score'], reverse=True)
        
        logger.info(f"Found {len(suspicious)} suspicious network connections")
        return suspicious
    
    def _group_by_protocol(self, connections: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Group connections by protocol
        
        Args:
            connections: List of connection dictionaries
            
        Returns:
            Dictionary with protocol as key and count as value
        """
        protocol_count = defaultdict(int)
        
        for conn in connections:
            protocol = conn.get('protocol', 'TCP').upper()
            protocol_count[protocol] += 1
        
        return dict(protocol_count)
    
    def _group_by_process(self, connections: List[Dict[str, Any]]) -> Dict[str, List]:
        """
        Group connections by process
        
        Args:
            connections: List of connection dictionaries
            
        Returns:
            Dictionary with process name as key and list of connections as value
        """
        by_process = defaultdict(list)
        
        for conn in connections:
            process = conn.get('process', 'unknown')
            by_process[process].append(conn)
        
        return dict(by_process)
    
    def _check_malicious_ips(self, connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Check for connections to known malicious IPs
        
        Args:
            connections: List of connection dictionaries
            
        Returns:
            List of connections to malicious IPs
        """
        malicious = []
        
        for conn in connections:
            remote_ip = conn.get('remote_ip')
            if remote_ip:
                if self._is_malicious_ip(remote_ip):
                    malicious.append({
                        'pid': conn.get('pid'),
                        'process': conn.get('process', 'unknown'),
                        'remote_ip': remote_ip,
                        'remote_port': conn.get('remote_port'),
                        'detection': 'Known malicious IP'
                    })
        
        return malicious
    
    def _detect_data_exfiltration(self, connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Detect potential data exfiltration patterns
        
        Args:
            connections: List of connection dictionaries
            
        Returns:
            List of data exfiltration indicators
        """
        exfiltration = []
        
        # Group connections by process and remote IP
        process_ip_map = defaultdict(list)
        for conn in connections:
            key = (conn.get('process'), conn.get('remote_ip'))
            if conn.get('remote_ip'):
                process_ip_map[key].append(conn)
        
        # Look for processes with multiple connections to external IPs
        for (process, ip), conns in process_ip_map.items():
            if len(conns) >= 5:
                # Check if connections are to different ports
                ports = {c.get('remote_port') for c in conns}
                if len(ports) >= 3:
                    exfiltration.append({
                        'process': process,
                        'remote_ip': ip,
                        'connection_count': len(conns),
                        'ports': list(ports),
                        'indicator': 'Multiple connections to same IP on different ports'
                    })
        
        # Look for large amount of outbound traffic (if traffic volume available)
        for conn in connections:
            if conn.get('bytes_sent', 0) > 10 * 1024 * 1024:  # 10MB threshold
                exfiltration.append({
                    'pid': conn.get('pid'),
                    'process': conn.get('process', 'unknown'),
                    'remote_ip': conn.get('remote_ip'),
                    'bytes_sent': conn.get('bytes_sent'),
                    'indicator': 'Large outbound data transfer'
                })
        
        return exfiltration
    
    def _is_private_ip(self, ip: str) -> bool:
        """
        Check if IP address is private
        
        Args:
            ip: IP address string
            
        Returns:
            True if IP is private
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast
        except ValueError:
            return False
    
    def _is_malicious_ip(self, ip: str) -> bool:
        """
        Check if IP is known malicious
        
        Args:
            ip: IP address string
            
        Returns:
            True if IP is malicious
        """
        # This is a placeholder - in production,
