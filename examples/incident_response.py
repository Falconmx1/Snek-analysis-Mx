#!/usr/bin/env python3
"""
Incident Response Example - Snek Analysis Mx
Focused analysis for incident response scenarios
"""

import sys
import logging
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

from snek_analysis import VolatilityWrapper
from snek_analysis.analyzers import ProcessAnalyzer, NetworkAnalyzer, DLLAnalyzer
from snek_analysis.reporters import HTMLReporter, JSONReporter
from snek_analysis.utils import OSDetector

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def main():
    """Run incident response focused analysis"""
    memory_file = sys.argv[1] if len(sys.argv) > 1 else 'memory.dmp'
    
    if not Path(memory_file).exists():
        logger.error(f"Memory file not found: {memory_file}")
        sys.exit(1)
    
    logger.info(f"🚨 Incident Response Analysis: {memory_file}")
    logger.info(f"⏰ Started at: {datetime.now().isoformat()}")
    
    try:
        vol = VolatilityWrapper(memory_file)
        
        # Detect OS
        os_detector = OSDetector(vol)
        os_info = os_detector.detect()
        
        if os_info['os_type'] == 'Unknown':
            logger.error("Could not detect OS")
            sys.exit(1)
        
        logger.info(f"📋 OS: {os_info['os_name']}")
        
        # Run critical analyses
        results = {
            'memory_file': memory_file,
            'profile': os_info.get('profile', 'Unknown'),
            'timestamp': datetime.now().isoformat()
        }
        
        # Process analysis
        logger.info("🔍 Analyzing processes...")
        process_analyzer = ProcessAnalyzer(vol)
        process_results = process_analyzer.analyze()
        results['processes'] = process_results
        
        # Network analysis
        logger.info("🌐 Analyzing network connections...")
        network_analyzer = NetworkAnalyzer(vol)
        network_results = network_analyzer.analyze()
        results['network'] = network_results
        
        # Generate quick report
        html_reporter = HTMLReporter(results)
        report_file = f"incident_response_{Path(memory_file).stem}.html"
        html_reporter.generate(report_file)
        
        logger.info(f"📊 Report generated: {report_file}")
        
        # Critical alerts
        suspicious_count = len(process_results.get('suspicious', []))
        network_suspicious = len(network_results.get('suspicious', []))
        
        logger.info("\n" + "="*50)
        logger.info("🚨 INCIDENT SUMMARY")
        logger.info("="*50)
        logger.info(f"  Suspicious Processes: {suspicious_count}")
        logger.info(f"  Suspicious Connections: {network_suspicious}")
        
        if process_results.get('hidden_processes'):
            logger.info(f"  Hidden Processes: {len(process_results['hidden_processes'])}")
        
        if network_results.get('malicious_ips'):
            logger.info(f"  Malicious IPs: {len(network_results['malicious_ips'])}")
        
        if suspicious_count > 0 or network_suspicious > 0:
            logger.info("\n⚠️  INDICATORS OF COMPROMISE FOUND!")
            logger.info("   Review the HTML report for detailed findings.")
        else:
            logger.info("\n✅ No immediate indicators of compromise detected.")
        logger.info("="*50)
        
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
