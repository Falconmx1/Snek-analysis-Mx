"""
Snek Analysis Mx - JSON Reporter
Generates JSON reports for integration with other tools
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
import hashlib

logger = logging.getLogger(__name__)


class JSONReporter:
    """
    Generates JSON reports from memory forensics analysis results
    """
    
    def __init__(self, results: Dict[str, Any]):
        """
        Initialize JSON Reporter
        
        Args:
            results: Analysis results dictionary
        """
        self.results = results
        self._sanitize_results()
    
    def _sanitize_results(self):
        """
        Sanitize results for JSON serialization
        Remove non-serializable objects and handle special types
        """
        # Convert any non-serializable objects
        self.results = self._make_serializable(self.results)
    
    def _make_serializable(self, obj: Any) -> Any:
        """
        Recursively convert object to JSON-serializable format
        
        Args:
            obj: Object to convert
            
        Returns:
            JSON-serializable object
        """
        if isinstance(obj, dict):
            return {k: self._make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._make_serializable(item) for item in obj]
        elif isinstance(obj, (datetime,)):
            return obj.isoformat()
        elif isinstance(obj, (Path,)):
            return str(obj)
        elif isinstance(obj, (int, float, str, bool)):
            return obj
        elif obj is None:
            return None
        else:
            # Try to convert to string
            try:
                return str(obj)
            except:
                return None
    
    def _add_metadata(self) -> Dict[str, Any]:
        """
        Add metadata to the report
        
        Returns:
            Dictionary with metadata
        """
        return {
            'generated_at': datetime.now().isoformat(),
            'version': '1.0.0',
            'tool': 'Snek Analysis Mx',
            'memory_file': self.results.get('memory_file'),
            'profile': self.results.get('profile'),
            'analysis_time': self.results.get('timestamp')
        }
    
    def _generate_iocs(self) -> Dict[str, Any]:
        """
        Extract and format IOCs from results
        
        Returns:
            Dictionary with IOCs
        """
        iocs = {
            'suspicious_processes': [],
            'suspicious_connections': [],
            'suspicious_dlls': [],
            'malicious_ips': [],
            'orphaned_processes': [],
            'orphaned_dlls': []
        }
        
        # Extract from process analysis
        if 'processes' in self.results:
            process_data = self.results['processes']
            
            # Suspicious processes
            if 'suspicious' in process_data:
                for proc in process_data['suspicious']:
                    iocs['suspicious_processes'].append({
                        'pid': proc.get('pid'),
                        'name': proc.get('name'),
                        'reasons': proc.get('reasons', []),
                        'risk_score': proc.get('risk_score'),
                        'risk_level': proc.get('risk_level')
                    })
            
            # Orphaned processes
            if 'indicators' in process_data and 'orphaned_processes' in process_data['indicators']:
                iocs['orphaned_processes'] = process_data['indicators']['orphaned_processes']
        
        # Extract from network analysis
        if 'network' in self.results:
            network_data = self.results['network']
            
            # Suspicious connections
            if 'suspicious' in network_data:
                for conn in network_data['suspicious']:
                    iocs['suspicious_connections'].append({
                        'pid': conn.get('pid'),
                        'process': conn.get('process'),
                        'remote_ip': conn.get('remote_ip'),
                        'remote_port': conn.get('remote_port'),
                        'reasons': conn.get('reasons', []),
                        'risk_level': conn.get('risk_level')
                    })
            
            # Malicious IPs
            if 'malicious_ips' in network_data:
                iocs['malicious_ips'] = network_data['malicious_ips']
        
        # Extract from DLL analysis
        if 'dlls' in self.results:
            dll_data = self.results['dlls']
            
            # Suspicious DLLs
            if 'suspicious_dlls' in dll_data:
                for dll in dll_data['suspicious_dlls']:
                    iocs['suspicious_dlls'].append({
                        'pid': dll.get('pid'),
                        'name': dll.get('name'),
                        'path': dll.get('path'),
                        'reasons': dll.get('reasons', []),
                        'risk_level': dll.get('risk_level')
                    })
            
            # Orphaned DLLs
            if 'orphaned_dlls' in dll_data:
                iocs['orphaned_dlls'] = dll_data['orphaned_dlls']
        
        return iocs
    
    def _generate_risk_summary(self) -> Dict[str, Any]:
        """
        Generate risk summary
        
        Returns:
            Dictionary with risk summary
        """
        risk_summary = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'total_risks': 0
        }
        
        # Count risks from processes
        if 'processes' in self.results and 'suspicious' in self.results['processes']:
            for proc in self.results['processes']['suspicious']:
                level = proc.get('risk_level', 'low').lower()
                if level in risk_summary:
                    risk_summary[level] += 1
        
        # Count risks from network
        if 'network' in self.results and 'suspicious' in self.results['network']:
            for conn in self.results['network']['suspicious']:
                level = conn.get('risk_level', 'low').lower()
                if level in risk_summary:
                    risk_summary[level] += 1
        
        # Count risks from DLLs
        if 'dlls' in self.results and 'suspicious_dlls' in self.results['dlls']:
            for dll in self.results['dlls']['suspicious_dlls']:
                level = dll.get('risk_level', 'low').lower()
                if level in risk_summary:
                    risk_summary[level] += 1
        
        risk_summary['total_risks'] = sum(risk_summary.values())
        
        return risk_summary
    
    def generate(self, output_path: Path) -> str:
        """
        Generate JSON report
        
        Args:
            output_path: Path to save JSON file
            
        Returns:
            Path to generated JSON file
        """
        logger.info(f"Generating JSON report: {output_path}")
        
        try:
            # Build report structure
            report = {
                'metadata': self._add_metadata(),
                'summary': self._generate_risk_summary(),
                'iocs': self._generate_iocs(),
                'detailed_results': self.results
            }
            
            # Add report hash for integrity
            report_str = json.dumps(report, sort_keys=True)
            report['metadata']['hash'] = hashlib.sha256(report_str.encode()).hexdigest()
            
            # Write JSON file
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            logger.info(f"JSON report generated: {output_path}")
            return str(output_path)
            
        except Exception as e:
            logger.error(f"Failed to generate JSON report: {e}")
            raise
    
    def generate_compact(self, output_path: Path) -> str:
        """
        Generate compact JSON report (minimal size)
        
        Args:
            output_path: Path to save JSON file
            
        Returns:
            Path to generated JSON file
        """
        logger.info(f"Generating compact JSON report: {output_path}")
        
        try:
            # Create compact report with only essential information
            compact = {
                'metadata': self._add_metadata(),
                'summary': self._generate_risk_summary(),
                'iocs': self._generate_iocs(),
                'suspicious_count': {
                    'processes': len(self.results.get('processes', {}).get('suspicious', [])),
                    'connections': len(self.results.get('network', {}).get('suspicious', [])),
                    'dlls': len(self.results.get('dlls', {}).get('suspicious_dlls', []))
                }
            }
            
            # Write compact JSON
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(compact, f, separators=(',', ':'), ensure_ascii=False)
            
            logger.info(f"Compact JSON report generated: {output_path}")
            return str(output_path)
            
        except Exception as e:
            logger.error(f"Failed to generate compact JSON report: {e}")
            raise
    
    def generate_misp_format(self, output_path: Path) -> str:
        """
        Generate MISP-compatible JSON format
        
        Args:
            output_path: Path to save JSON file
            
        Returns:
            Path to generated JSON file
        """
        logger.info(f"Generating MISP format report: {output_path}")
        
        try:
            # Build MISP event structure
            misp_event = {
                'Event': {
                    'info': f"Snek Analysis Mx - Memory Forensics Findings",
                    'date': datetime.now().strftime('%Y-%m-%d'),
                    'analysis': '2',  # Completed
                    'distribution': '1',  # This community only
                    'threat_level_id': '2',  # Medium
                    'attribute': []
                }
            }
            
            # Add IOCs as MISP attributes
            iocs = self._generate_iocs()
            
            # Suspicious processes
            for proc in iocs.get('suspicious_processes', []):
                misp_event['Event']['attribute'].append({
                    'category': 'Process',
                    'type': 'filename',
                    'value': proc.get('name', ''),
                    'comment': f"PID: {proc.get('pid')} - Risk: {proc.get('risk_level', 'unknown')} - Reasons: {', '.join(proc.get('reasons', []))}",
                    'to_ids': True
                })
            
            # Malicious IPs
            for ip in iocs.get('malicious_ips', []):
                misp_event['Event']['attribute'].append({
                    'category': 'Network activity',
                    'type': 'ip-dst',
                    'value': ip.get('remote_ip', ''),
                    'comment': f"Process: {ip.get('process', 'unknown')} (PID: {ip.get('pid')})",
                    'to_ids': True
                })
            
            # Suspicious connections
            for conn in iocs.get('suspicious_connections', []):
                if conn.get('remote_ip'):
                    misp_event['Event']['attribute'].append({
                        'category': 'Network activity',
                        'type': 'ip-dst',
                        'value': conn.get('remote_ip'),
                        'comment': f"Port: {conn.get('remote_port')} - Process: {conn.get('process')} - Risk: {conn.get('risk_level')}",
                        'to_ids': True
                    })
            
            # Suspicious DLLs
            for dll in iocs.get('suspicious_dlls', []):
                misp_event['Event']['attribute'].append({
                    'category': 'Process',
                    'type': 'filename',
                    'value': dll.get('name', ''),
                    'comment': f"PID: {dll.get('pid')} - Path: {dll.get('path')} - Risk: {dll.get('risk_level')}",
                    'to_ids': True
                })
            
            # Write MISP JSON
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(misp_event, f, indent=2, ensure_ascii=False)
            
            logger.info(f"MISP format report generated: {output_path}")
            return str(output_path)
            
        except Exception as e:
            logger.error(f"Failed to generate MISP format report: {e}")
            raise
