#!/usr/bin/env python3
"""
Basic Analysis Example - Snek Analysis Mx
Simple memory analysis with HTML report generation
"""

import sys
import logging
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from snek_analysis import VolatilityWrapper
from snek_analysis.analyzers import ProcessAnalyzer, NetworkAnalyzer, DLLAnalyzer
from snek_analysis.reporters import HTMLReporter, JSONReporter
from snek_analysis.utils import OSDetector

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    """Run basic analysis"""
    # Memory dump file
    memory_file = sys.argv[1] if len(sys.argv) > 1 else 'memory.dmp'
    
    if not Path(memory_file).exists():
        logger.error(f"Memory file not found: {memory_file}")
        logger.info("Usage: python examples/basic_analysis.py <memory_file>")
        sys.exit(1)
    
    logger.info(f"Analyzing memory dump: {memory_file}")
    
    try:
        # Initialize Volatility wrapper
        vol = VolatilityWrapper(memory_file)
        
        # Detect OS using advanced detector
        os_detector = OSDetector(vol)
        os_info = os_detector.detect()
        
        if os_info['os_type'] == 'Unknown':
            logger.error("Failed to detect OS")
            sys.exit(1)
        
        logger.info(f"Detected: {os_info['os_name']} (confidence: {os_info['confidence']}%)")
        logger.info(f"Profile: {os_detector.get_volatility_profile()}")
        
        # Initialize analyzers
        process_analyzer = ProcessAnalyzer(vol)
        network_analyzer = NetworkAnalyzer(vol)
        dll_analyzer = DLLAnalyzer(vol)
        
        # Run analyses
        logger.info("Running process analysis...")
        process_results = process_analyzer.analyze()
        
        logger.info("Running network analysis...")
        network_results = network_analyzer.analyze()
        
        logger.info("Running DLL analysis...")
        dll_results = dll_analyzer.analyze()
        
        # Compile results
        results = {
            'memory_file': memory_file,
            'profile': os_info.get('profile', 'Unknown'),
            'timestamp': os_info.get('timestamp', ''),
            'processes': process_results,
            'network': network_results,
            'dlls': dll_results
        }
        
        # Generate reports
        output_name = Path(memory_file).stem
        
        # HTML Report
        html_reporter = HTMLReporter(results)
        html_file = f"{output_name}_report.html"
        html_reporter.generate(html_file)
        logger.info(f"HTML report generated: {html_file}")
        
        # JSON Report
        json_reporter = JSONReporter(results)
        json_file = f"{output_name}_report.json"
        json_reporter.generate(json_file)
        logger.info(f"JSON report generated: {json_file}")
        
        # Summary
        suspicious_count = len(process_results.get('suspicious', []))
        if suspicious_count > 0:
            logger.warning(f"⚠️ Found {suspicious_count} suspicious processes!")
        else:
            logger.info("✅ No suspicious processes detected")
        
        logger.info("Analysis complete!")
        
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
