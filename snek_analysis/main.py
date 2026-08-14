#!/usr/bin/env python3
"""
Snek Analysis Mx - Main CLI Entry Point
Memory Forensics Automation Tool
"""

import argparse
import sys
import os
import logging
from pathlib import Path
from datetime import datetime
from colorama import init, Fore, Style
import json

from .volatility_wrapper import VolatilityWrapper
from .analyzers.process_analyzer import ProcessAnalyzer
from .analyzers.network_analyzer import NetworkAnalyzer
from .analyzers.dll_analyzer import DLLAnalyzer
from .reporters.html_reporter import HTMLReporter
from .reporters.json_reporter import JSONReporter

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Snek Analysis Mx - Memory Forensics Toolkit (Volatility 3 Wrapper)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  snek-analyze -f memory.dmp -o report.html
  snek-analyze -f memory.dmp --quick -o quick_report.html
  snek-analyze -f memory.dmp --detect-os
  snek-analyze -f memory.dmp -p windows.cmdline,windows.netscan -o report.html
  snek-analyze -f memory.dmp --format json -o report.json
        """
    )
    
    parser.add_argument(
        '-f', '--file',
        required=True,
        help='Path to memory dump file'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='snek_report.html',
        help='Output file path (default: snek_report.html)'
    )
    
    parser.add_argument(
        '--format',
        choices=['html', 'json', 'both'],
        default='html',
        help='Output format: html, json, or both (default: html)'
    )
    
    parser.add_argument(
        '--quick',
        action='store_true',
        help='Quick analysis mode (only processes and network)'
    )
    
    parser.add_argument(
        '--detect-os',
        action='store_true',
        help='Only detect OS and profile, then exit'
    )
    
    parser.add_argument(
        '-p', '--plugins',
        help='Comma-separated list of Volatility plugins to run'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--profile',
        help='Force specific Volatility profile (auto-detection by default)'
    )
    
    parser.add_argument(
        '--plugin-dir',
        help='Additional directory for Volatility plugins'
    )
    
    return parser.parse_args()


def display_banner():
    """Display ASCII banner"""
    banner = f"""
{Fore.GREEN}{Style.BRIGHT}╔═══════════════════════════════════════════════════════════╗
║                                                       ║
║  {Fore.YELLOW}🐍 SNEK ANALYSIS MX {Fore.CYAN}v{__import__('snek_analysis').__version__} {Fore.GREEN}║
║  {Fore.WHITE}Memory Forensics Toolkit - Volatility 3 Wrapper  {Fore.GREEN}║
║  {Fore.RED}🔍 Incident Response & Malware Analysis        {Fore.GREEN}║
║                                                       ║
╚═══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)


def validate_memory_file(file_path):
    """Validate if memory dump file exists and is readable"""
    path = Path(file_path)
    
    if not path.exists():
        logger.error(f"Memory dump file not found: {file_path}")
        return False
    
    if not path.is_file():
        logger.error(f"Path is not a file: {file_path}")
        return False
    
    # Check file size (at least 10MB)
    file_size = path.stat().st_size
    if file_size < 10 * 1024 * 1024:
        logger.warning(f"File size is only {file_size / (1024*1024):.2f} MB. "
                      f"This might not be a valid memory dump.")
    
    logger.info(f"Memory dump file: {path} ({file_size / (1024*1024):.2f} MB)")
    return True


def main():
    """Main entry point"""
    display_banner()
    
    args = parse_arguments()
    
    # Configure logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Validate input file
    if not validate_memory_file(args.file):
        sys.exit(1)
    
    logger.info("Initializing Snek Analysis Mx...")
    start_time = datetime.now()
    
    try:
        # Initialize Volatility wrapper
        volatility = VolatilityWrapper(
            memory_file=args.file,
            profile=args.profile,
            plugin_dir=args.plugin_dir
        )
        
        # Detect OS profile
        logger.info("🔍 Detecting OS profile...")
        profile = volatility.detect_os()
        if not profile:
            logger.error("Failed to detect OS profile. Please specify with --profile")
            sys.exit(1)
        
        logger.info(f"✅ Detected profile: {profile}")
        
        if args.detect_os:
            logger.info("OS detection complete. Exiting...")
            return
        
        # Initialize analyzers
        process_analyzer = ProcessAnalyzer(volatility)
        network_analyzer = NetworkAnalyzer(volatility)
        dll_analyzer = DLLAnalyzer(volatility)
        
        # Collect analysis results
        results = {
            'timestamp': start_time.isoformat(),
            'memory_file': args.file,
            'profile': profile,
            'plugins': []
        }
        
        # Run analyses based on mode
        if args.quick:
            logger.info("⚡ Running quick analysis mode...")
            results['processes'] = process_analyzer.analyze()
            results['network'] = network_analyzer.analyze()
        else:
            logger.info("🕵️ Running full analysis mode...")
            results['processes'] = process_analyzer.analyze()
            results['network'] = network_analyzer.analyze()
            results['dlls'] = dll_analyzer.analyze()
            
            # Add suspicious process detection
            results['suspicious'] = process_analyzer.detect_suspicious(results['processes'])
        
        # Run custom plugins if specified
        if args.plugins:
            logger.info(f"🔌 Running custom plugins: {args.plugins}")
            plugins = [p.strip() for p in args.plugins.split(',')]
            for plugin in plugins:
                try:
                    plugin_results = volatility.run_plugin(plugin)
                    results['plugins'].append({
                        'name': plugin,
                        'data': plugin_results
                    })
                except Exception as e:
                    logger.error(f"Failed to run plugin {plugin}: {e}")
        
        # Generate reports
        logger.info("📊 Generating reports...")
        
        output_path = Path(args.output)
        output_dir = output_path.parent
        output_dir.mkdir(parents=True, exist_ok=True)
        
        if args.format in ['html', 'both']:
            html_reporter = HTMLReporter(results)
            html_file = output_path if args.format == 'html' else output_path.with_suffix('.html')
            html_reporter.generate(html_file)
            logger.info(f"✅ HTML report saved to: {html_file}")
        
        if args.format in ['json', 'both']:
            json_reporter = JSONReporter(results)
            json_file = output_path.with_suffix('.json') if args.format == 'json' else output_path.with_suffix('.json')
            json_reporter.generate(json_file)
            logger.info(f"✅ JSON report saved to: {json_file}")
        
        # Summary
        elapsed_time = datetime.now() - start_time
        logger.info(f"✅ Analysis completed in {elapsed_time.total_seconds():.2f} seconds")
        
        if 'suspicious' in results and results['suspicious']:
            suspicious_count = len(results['suspicious'])
            logger.warning(f"⚠️ Found {suspicious_count} suspicious processes!")
            logger.info("Review the report for detailed findings.")
        else:
            logger.info("No suspicious processes detected.")
        
    except ImportError as e:
        logger.error(f"Failed to import Volatility: {e}")
        logger.error("Please ensure Volatility 3 is installed: pip install volatility3")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
