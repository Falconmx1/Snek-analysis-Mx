"""
Snek Analysis Mx - OS Detector
Advanced OS detection for memory dumps with fingerprinting
"""

import re
import logging
import subprocess
from typing import Dict, Any, Optional, List, Tuple
from pathlib import Path
import json
import hashlib

logger = logging.getLogger(__name__)


class OSDetector:
    """
    Advanced OS detection for memory dumps with multiple detection methods
    """
    
    # Windows version signatures
    WINDOWS_SIGNATURES = {
        'windows_10_1507': {
            'build': '10240',
            'name': 'Windows 10 1507 (Threshold 1)',
            'version': '10.0',
            'release_date': '2015-07-29'
        },
        'windows_10_1511': {
            'build': '10586',
            'name': 'Windows 10 1511 (Threshold 2)',
            'version': '10.0',
            'release_date': '2015-11-10'
        },
        'windows_10_1607': {
            'build': '14393',
            'name': 'Windows 10 1607 (Anniversary Update)',
            'version': '10.0',
            'release_date': '2016-08-02'
        },
        'windows_10_1703': {
            'build': '15063',
            'name': 'Windows 10 1703 (Creators Update)',
            'version': '10.0',
            'release_date': '2017-04-05'
        },
        'windows_10_1709': {
            'build': '16299',
            'name': 'Windows 10 1709 (Fall Creators Update)',
            'version': '10.0',
            'release_date': '2017-10-17'
        },
        'windows_10_1803': {
            'build': '17134',
            'name': 'Windows 10 1803 (April 2018 Update)',
            'version': '10.0',
            'release_date': '2018-04-30'
        },
        'windows_10_1809': {
            'build': '17763',
            'name': 'Windows 10 1809 (October 2018 Update)',
            'version': '10.0',
            'release_date': '2018-11-13'
        },
        'windows_10_1903': {
            'build': '18362',
            'name': 'Windows 10 1903 (May 2019 Update)',
            'version': '10.0',
            'release_date': '2019-05-21'
        },
        'windows_10_1909': {
            'build': '18363',
            'name': 'Windows 10 1909 (November 2019 Update)',
            'version': '10.0',
            'release_date': '2019-11-12'
        },
        'windows_10_2004': {
            'build': '19041',
            'name': 'Windows 10 2004 (May 2020 Update)',
            'version': '10.0',
            'release_date': '2020-05-27'
        },
        'windows_10_20H2': {
            'build': '19042',
            'name': 'Windows 10 20H2 (October 2020 Update)',
            'version': '10.0',
            'release_date': '2020-10-20'
        },
        'windows_10_21H1': {
            'build': '19043',
            'name': 'Windows 10 21H1 (May 2021 Update)',
            'version': '10.0',
            'release_date': '2021-05-18'
        },
        'windows_10_21H2': {
            'build': '19044',
            'name': 'Windows 10 21H2 (November 2021 Update)',
            'version': '10.0',
            'release_date': '2021-11-16'
        },
        'windows_10_22H2': {
            'build': '19045',
            'name': 'Windows 10 22H2 (2022 Update)',
            'version': '10.0',
            'release_date': '2022-10-18'
        },
        'windows_11_21H2': {
            'build': '22000',
            'name': 'Windows 11 21H2 (Initial Release)',
            'version': '10.0',
            'release_date': '2021-10-04'
        },
        'windows_11_22H2': {
            'build': '22621',
            'name': 'Windows 11 22H2 (2022 Update)',
            'version': '10.0',
            'release_date': '2022-09-20'
        },
        'windows_11_23H2': {
            'build': '22631',
            'name': 'Windows 11 23H2 (2023 Update)',
            'version': '10.0',
            'release_date': '2023-10-31'
        },
        'windows_server_2016': {
            'build': '14393',
            'name': 'Windows Server 2016',
            'version': '10.0',
            'release_date': '2016-10-12'
        },
        'windows_server_2019': {
            'build': '17763',
            'name': 'Windows Server 2019',
            'version': '10.0',
            'release_date': '2018-11-13'
        },
        'windows_server_2022': {
            'build': '20348',
            'name': 'Windows Server 2022',
            'version': '10.0',
            'release_date': '2021-08-18'
        },
        'windows_7': {
            'build': '7601',
            'name': 'Windows 7 SP1',
            'version': '6.1',
            'release_date': '2011-02-22'
        },
        'windows_8': {
            'build': '9200',
            'name': 'Windows 8',
            'version': '6.2',
            'release_date': '2012-10-26'
        },
        'windows_8_1': {
            'build': '9600',
            'name': 'Windows 8.1',
            'version': '6.3',
            'release_date': '2013-10-17'
        },
        'windows_vista': {
            'build': '6002',
            'name': 'Windows Vista SP2',
            'version': '6.0',
            'release_date': '2009-05-26'
        },
        'windows_xp': {
            'build': '2600',
            'name': 'Windows XP SP3',
            'version': '5.1',
            'release_date': '2008-04-21'
        }
    }
    
    # Linux distribution signatures (simplified)
    LINUX_SIGNATURES = {
        'ubuntu_20_04': {
            'name': 'Ubuntu 20.04 LTS (Focal Fossa)',
            'version': '20.04',
            'release_date': '2020-04-23'
        },
        'ubuntu_22_04': {
            'name': 'Ubuntu 22.04 LTS (Jammy Jellyfish)',
            'version': '22.04',
            'release_date': '2022-04-21'
        },
        'ubuntu_24_04': {
            'name': 'Ubuntu 24.04 LTS (Noble Numbat)',
            'version': '24.04',
            'release_date': '2024-04-25'
        },
        'centos_7': {
            'name': 'CentOS 7',
            'version': '7',
            'release_date': '2014-07-07'
        },
        'centos_8': {
            'name': 'CentOS 8',
            'version': '8',
            'release_date': '2019-09-24'
        },
        'rhel_7': {
            'name': 'Red Hat Enterprise Linux 7',
            'version': '7',
            'release_date': '2014-06-10'
        },
        'rhel_8': {
            'name': 'Red Hat Enterprise Linux 8',
            'version': '8',
            'release_date': '2019-05-07'
        },
        'rhel_9': {
            'name': 'Red Hat Enterprise Linux 9',
            'version': '9',
            'release_date': '2022-05-17'
        },
        'debian_10': {
            'name': 'Debian 10 (Buster)',
            'version': '10',
            'release_date': '2019-07-06'
        },
        'debian_11': {
            'name': 'Debian 11 (Bullseye)',
            'version': '11',
            'release_date': '2021-08-14'
        },
        'debian_12': {
            'name': 'Debian 12 (Bookworm)',
            'version': '12',
            'release_date': '2023-06-10'
        },
        'fedora_38': {
            'name': 'Fedora 38',
            'version': '38',
            'release_date': '2023-04-18'
        },
        'fedora_39': {
            'name': 'Fedora 39',
            'version': '39',
            'release_date': '2023-11-07'
        },
        'fedora_40': {
            'name': 'Fedora 40',
            'version': '40',
            'release_date': '2024-04-23'
        },
        'arch_linux': {
            'name': 'Arch Linux',
            'version': 'rolling',
            'release_date': 'N/A'
        }
    }
    
    # macOS signatures (simplified)
    MAC_SIGNATURES = {
        'macos_10_15': {
            'name': 'macOS 10.15 Catalina',
            'version': '10.15',
            'release_date': '2019-10-07'
        },
        'macos_11': {
            'name': 'macOS 11 Big Sur',
            'version': '11.0',
            'release_date': '2020-11-12'
        },
        'macos_12': {
            'name': 'macOS 12 Monterey',
            'version': '12.0',
            'release_date': '2021-10-25'
        },
        'macos_13': {
            'name': 'macOS 13 Ventura',
            'version': '13.0',
            'release_date': '2022-10-24'
        },
        'macos_14': {
            'name': 'macOS 14 Sonoma',
            'version': '14.0',
            'release_date': '2023-09-26'
        },
        'macos_15': {
            'name': 'macOS 15 Sequoia',
            'version': '15.0',
            'release_date': '2024-09-16'
        }
    }
    
    def __init__(self, volatility_wrapper=None):
        """
        Initialize OS Detector
        
        Args:
            volatility_wrapper: VolatilityWrapper instance (optional)
        """
        self.volatility = volatility_wrapper
        self.detected_os = None
        self.detection_method = None
        self.confidence = 0
        self.details = {}
        
    def detect(self, force_method: Optional[str] = None) -> Dict[str, Any]:
        """
        Detect OS from memory dump using multiple methods
        
        Args:
            force_method: Force specific detection method ('windows', 'linux', 'mac')
            
        Returns:
            Dictionary with detection results
        """
        logger.info("🔍 Starting OS detection...")
        
        results = {
            'os_type': None,
            'os_name': None,
            'os_version': None,
            'os_build': None,
            'detection_method': None,
            'confidence': 0,
            'details': {},
            'profile': None
        }
        
        # Try each detection method
        detection_methods = [
            ('windows', self._detect_windows),
            ('linux', self._detect_linux),
            ('mac', self._detect_mac),
            ('volatility', self._detect_with_volatility)
        ]
        
        # If force method is specified, try only that
        if force_method:
            for method_name, method_func in detection_methods:
                if method_name == force_method.lower():
                    result = method_func()
                    if result:
                        results.update(result)
                        results['detection_method'] = method_name
                        break
        else:
            # Try all methods
            for method_name, method_func in detection_methods:
                result = method_func()
                if result:
                    results.update(result)
                    results['detection_method'] = method_name
                    self.confidence = results.get('confidence', 0)
                    
                    # If high confidence, stop trying
                    if self.confidence >= 80:
                        break
        
        # If no OS detected, try fallback
        if not results['os_type']:
            results = self._detect_fallback()
        
        self.detected_os = results
        self._log_detection_results(results)
        
        return results
    
    def _detect_windows(self) -> Optional[Dict[str, Any]]:
        """
        Detect Windows OS from memory dump
        
        Returns:
            Dictionary with Windows detection results
        """
        logger.debug("Trying Windows detection...")
        
        try:
            # Try to get Windows info from Volatility
            if self.volatility:
                result = self.volatility.run_plugin('windows.info')
                if 'error' not in result and result.get('raw_output'):
                    output = result.get('raw_output', '')
                    
                    # Extract build number
                    build_match = re.search(r'Build Number\s*:\s*(\d+)', output)
                    if build_match:
                        build = build_match.group(1)
                        
                        # Match with known Windows versions
                        for key, info in self.WINDOWS_SIGNATURES.items():
                            if info['build'] == build:
                                return {
                                    'os_type': 'Windows',
                                    'os_name': info['name'],
                                    'os_version': info['version'],
                                    'os_build': build,
                                    'confidence': 95,
                                    'profile': key,
                                    'details': {
                                        'build_number': build,
                                        'release_date': info['release_date']
                                    }
                                }
                        
                        # Unknown build but still Windows
                        return {
                            'os_type': 'Windows',
                            'os_name': f'Windows (Build {build})',
                            'os_version': 'Unknown',
                            'os_build': build,
                            'confidence': 70,
                            'profile': f'Win10x64_{build}',
                            'details': {
                                'build_number': build,
                                'note': 'Unknown Windows build'
                            }
                        }
            
            # Try to find Windows-specific processes
            if self.volatility:
                try:
                    processes = self.volatility.get_processes()
                    windows_processes = ['csrss.exe', 'winlogon.exe', 'lsass.exe', 'services.exe', 'svchost.exe']
                    found = [p for p in processes if p.get('name', '').lower() in [w.lower() for w in windows_processes]]
                    
                    if len(found) >= 3:
                        return {
                            'os_type': 'Windows',
                            'os_name': 'Windows (detected by system processes)',
                            'os_version': 'Unknown',
                            'os_build': 'Unknown',
                            'confidence': 60,
                            'profile': 'Win10x64',
                            'details': {
                                'detected_processes': [p.get('name') for p in found[:5]]
                            }
                        }
                except:
                    pass
        
        except Exception as e:
            logger.debug(f"Windows detection failed: {e}")
        
        return None
    
    def _detect_linux(self) -> Optional[Dict[str, Any]]:
        """
        Detect Linux OS from memory dump
        
        Returns:
            Dictionary with Linux detection results
        """
        logger.debug("Trying Linux detection...")
        
        try:
            if self.volatility:
                result = self.volatility.run_plugin('linux.info')
                if 'error' not in result and result.get('raw_output'):
                    output = result.get('raw_output', '')
                    
                    # Try to find distribution info
                    distro_match = re.search(r'Distribution\s*:\s*(.+)', output)
                    if distro_match:
                        distro = distro_match.group(1).strip()
                        
                        # Match with known distributions
                        for key, info in self.LINUX_SIGNATURES.items():
                            if info['name'].lower() in distro.lower():
                                return {
                                    'os_type': 'Linux',
                                    'os_name': info['name'],
                                    'os_version': info['version'],
                                    'os_build': 'N/A',
                                    'confidence': 90,
                                    'profile': key,
                                    'details': {
                                        'distribution': distro,
                                        'release_date': info['release_date']
                                    }
                                }
                        
                        # Unknown distribution
                        return {
                            'os_type': 'Linux',
                            'os_name': f'Linux ({distro})',
                            'os_version': 'Unknown',
                            'os_build': 'N/A',
                            'confidence': 70,
                            'profile': 'Linux',
                            'details': {
                                'distribution': distro
                            }
                        }
            
            # Try to find Linux-specific processes
            if self.volatility:
                try:
                    processes = self.volatility.get_processes()
                    linux_processes = ['systemd', 'init', 'kthreadd', 'udevd', 'cron']
                    found = [p for p in processes if p.get('name', '').lower() in linux_processes]
                    
                    if len(found) >= 2:
                        return {
                            'os_type': 'Linux',
                            'os_name': 'Linux (detected by system processes)',
                            'os_version': 'Unknown',
                            'os_build': 'N/A',
                            'confidence': 60,
                            'profile': 'Linux',
                            'details': {
                                'detected_processes': [p.get('name') for p in found[:5]]
                            }
                        }
                except:
                    pass
        
        except Exception as e:
            logger.debug(f"Linux detection failed: {e}")
        
        return None
    
    def _detect_mac(self) -> Optional[Dict[str, Any]]:
        """
        Detect macOS from memory dump
        
        Returns:
            Dictionary with macOS detection results
        """
        logger.debug("Trying macOS detection...")
        
        try:
            if self.volatility:
                result = self.volatility.run_plugin('mac.info')
                if 'error' not in result and result.get('raw_output'):
                    output = result.get('raw_output', '')
                    
                    # Try to extract version
                    version_match = re.search(r'Version\s*:\s*(\d+\.\d+)', output)
                    if version_match:
                        version = version_match.group(1)
                        
                        # Match with known macOS versions
                        for key, info in self.MAC_SIGNATURES.items():
                            if info['version'] == version:
                                return {
                                    'os_type': 'macOS',
                                    'os_name': info['name'],
                                    'os_version': info['version'],
                                    'os_build': 'N/A',
                                    'confidence': 90,
                                    'profile': key,
                                    'details': {
                                        'release_date': info['release_date']
                                    }
                                }
                        
                        # Unknown version
                        return {
                            'os_type': 'macOS',
                            'os_name': f'macOS {version}',
                            'os_version': version,
                            'os_build': 'N/A',
                            'confidence': 70,
                            'profile': 'Mac',
                            'details': {
                                'note': 'Unknown macOS version'
                            }
                        }
            
            # Try to find macOS-specific processes
            if self.volatility:
                try:
                    processes = self.volatility.get_processes()
                    mac_processes = ['launchd', 'WindowServer', 'loginwindow', 'kernel_task']
                    found = [p for p in processes if p.get('name', '').lower() in [m.lower() for m in mac_processes]]
                    
                    if len(found) >= 2:
                        return {
                            'os_type': 'macOS',
                            'os_name': 'macOS (detected by system processes)',
                            'os_version': 'Unknown',
                            'os_build': 'N/A',
                            'confidence': 60,
                            'profile': 'Mac',
                            'details': {
                                'detected_processes': [p.get('name') for p in found[:5]]
                            }
                        }
                except:
                    pass
        
        except Exception as e:
            logger.debug(f"macOS detection failed: {e}")
        
        return None
    
    def _detect_with_volatility(self) -> Optional[Dict[str, Any]]:
        """
        Use Volatility's own detection capabilities
        
        Returns:
            Dictionary with detection results
        """
        logger.debug("Trying Volatility detection...")
        
        if not self.volatility:
            return None
        
        try:
            # Try to detect using Volatility's built-in detection
            result = self.volatility.run_plugin('banners')
            if 'error' not in result and result.get('raw_output'):
                output = result.get('raw_output', '')
                
                # Look for OS signatures in banners
                if 'Windows' in output:
                    return {
                        'os_type': 'Windows',
                        'os_name': 'Windows (detected by Volatility)',
                        'os_version': 'Unknown',
                        'os_build': 'Unknown',
                        'confidence': 50,
                        'profile': 'Win10x64',
                        'details': {
                            'banner': output[:200]
                        }
                    }
                elif 'Linux' in output:
                    return {
                        'os_type': 'Linux',
                        'os_name': 'Linux (detected by Volatility)',
                        'os_version': 'Unknown',
                        'os_build': 'N/A',
                        'confidence': 50,
                        'profile': 'Linux',
                        'details': {
                            'banner': output[:200]
                        }
                    }
                elif 'Darwin' in output or 'Mac' in output:
                    return {
                        'os_type': 'macOS',
                        'os_name': 'macOS (detected by Volatility)',
                        'os_version': 'Unknown',
                        'os_build': 'N/A',
                        'confidence': 50,
                        'profile': 'Mac',
                        'details': {
                            'banner': output[:200]
                        }
                    }
        
        except Exception as e:
            logger.debug(f"Volatility detection failed: {e}")
        
        return None
    
    def _detect_fallback(self) -> Dict[str, Any]:
        """
        Fallback detection method using file signatures
        
        Returns:
            Dictionary with fallback detection results
        """
        logger.warning("Using fallback detection method...")
        
        if not self.volatility:
            return {
                'os_type': 'Unknown',
                'os_name': 'Unknown',
                'os_version': 'Unknown',
                'os_build': 'Unknown',
                'confidence': 0,
                'profile': 'Unknown',
                'details': {
                    'error': 'No volatility wrapper available'
                }
            }
        
        # Try to detect by trying plugins
        test_plugins = {
            'windows.pslist': 'Windows',
            'linux.pslist': 'Linux',
            'mac.pslist': 'macOS'
        }
        
        for plugin, os_type in test_plugins.items():
            try:
                result = self.volatility.run_plugin(plugin)
                if 'error' not in result:
                    return {
                        'os_type': os_type,
                        'os_name': f'{os_type} (detected by plugin test)',
                        'os_version': 'Unknown',
                        'os_build': 'Unknown',
                        'confidence': 30,
                        'profile': os_type,
                        'details': {
                            'detected_plugin': plugin
                        }
                    }
            except:
                continue
        
        return {
            'os_type': 'Unknown',
            'os_name': 'Unknown',
            'os_version': 'Unknown',
            'os_build': 'Unknown',
            'confidence': 0,
            'profile': 'Unknown',
            'details': {
                'error': 'All detection methods failed'
            }
        }
    
    def _log_detection_results(self, results: Dict[str, Any]):
        """
        Log detection results
        
        Args:
            results: Detection results dictionary
        """
        if results.get('os_type') and results['os_type'] != 'Unknown':
            logger.info(f"✅ OS Detected: {results['os_name']}")
            logger.info(f"   Method: {results.get('detection_method', 'unknown')}")
            logger.info(f"   Confidence: {results.get('confidence', 0)}%")
            if results.get('profile'):
                logger.info(f"   Profile: {results['profile']}")
        else:
            logger.warning("❌ Failed to detect OS")
    
    def get_volatility_profile(self) -> Optional[str]:
        """
        Get the best Volatility profile for the detected OS
        
        Returns:
            Volatility profile string
        """
        if self.detected_os:
            return self.detected_os.get('profile')
        return None
    
    def get_os_type(self) -> Optional[str]:
        """
        Get detected OS type
        
        Returns:
            OS type string ('Windows', 'Linux', 'macOS', or None)
        """
        if self.detected_os:
            return self.detected_os.get('os_type')
        return None
    
    def is_windows(self) -> bool:
        """
        Check if detected OS is Windows
        
        Returns:
            True if Windows
        """
        return self.get_os_type() == 'Windows'
    
    def is_linux(self) -> bool:
        """
        Check if detected OS is Linux
        
        Returns:
            True if Linux
        """
        return self.get_os_type() == 'Linux'
    
    def is_mac(self) -> bool:
        """
        Check if detected OS is macOS
        
        Returns:
            True if macOS
        """
        return self.get_os_type() == 'macOS'
    
    def get_os_family(self) -> str:
        """
        Get OS family (Windows, Linux, macOS, Unknown)
        
        Returns:
            OS family string
        """
        if self.detected_os:
            return self.detected_os.get('os_type', 'Unknown')
        return 'Unknown'
    
    def get_detailed_info(self) -> Dict[str, Any]:
        """
        Get detailed OS information
        
        Returns:
            Dictionary with detailed OS info
        """
        if self.detected_os:
            return {
                'type': self.detected_os.get('os_type'),
                'name': self.detected_os.get('os_name'),
                'version': self.detected_os.get('os_version'),
                'build': self.detected_os.get('os_build'),
                'confidence': self.detected_os.get('confidence'),
                'detection_method': self.detected_os.get('detection_method'),
                'profile': self.detected_os.get('profile'),
                'details': self.detected_os.get('details', {})
            }
        return {
            'type': 'Unknown',
            'name': 'Unknown',
            'version': 'Unknown',
            'build': 'Unknown',
            'confidence': 0,
            'detection_method': 'none',
            'profile': 'Unknown',
            'details': {}
        }
    
    def get_os_fingerprint(self) -> Dict[str, Any]:
        """
        Generate a fingerprint of the detected OS
        
        Returns:
            Dictionary with OS fingerprint
        """
        fingerprint = {
            'os_type': self.get_os_type(),
            'os_name': self.detected_os.get('os_name') if self.detected_os else None,
            'os_version': self.detected_os.get('os_version') if self.detected_os else None,
            'os_build': self.detected_os.get('os_build') if self.detected_os else None,
            'profile': self.get_volatility_profile(),
            'detection_confidence': self.detected_os.get('confidence') if self.detected_os else 0,
            'timestamp': None  # Would need to get from memory dump
        }
        
        # Add hash for uniqueness
        fingerprint_str = json.dumps(fingerprint, sort_keys=True)
        fingerprint['fingerprint_hash'] = hashlib.md5(fingerprint_str.encode()).hexdigest()
        
        return fingerprint
    
    def get_compatible_plugins(self) -> List[str]:
        """
        Get list of compatible Volatility plugins for detected OS
        
        Returns:
            List of plugin names
        """
        os_type = self.get_os_type()
        
        if os_type == 'Windows':
            return [
                'windows.pslist', 'windows.psscan', 'windows.dlllist',
                'windows.handles', 'windows.malfind', 'windows.netscan',
                'windows.ldrmodules', 'windows.svcscan', 'windows.mutantscan',
                'windows.envars', 'windows.cmdline', 'windows.vadinfo'
            ]
        elif os_type == 'Linux':
            return [
                'linux.pslist', 'linux.psscan', 'linux.lsmod',
                'linux.netstat', 'linux.lsof', 'linux.mount',
                'linux.envars', 'linux.cmdline', 'linux.bash'
            ]
        elif os_type == 'macOS':
            return [
                'mac.pslist', 'mac.netstat', 'mac.lsmod',
                'mac.malfind', 'mac.dmesg'
            ]
        else:
            return []
    
    def get_suggested_plugins(self, analysis_type: str = 'basic') -> List[str]:
        """
        Get suggested plugins based on analysis type
        
        Args:
            analysis_type: 'basic', 'malware', 'incident_response', 'full'
            
        Returns:
            List of suggested plugins
        """
        os_type = self.get_os_type()
        
        if os_type == 'Windows':
            basic_plugins = ['windows.pslist', 'windows.cmdline', 'windows.netscan']
            malware_plugins = ['windows.malfind', 'windows.ldrmodules', 'windows.dlllist', 'windows.handles']
            incident_plugins = ['windows.psscan', 'windows.svcscan', 'windows.mutantscan', 'windows.envars']
            full_plugins = basic_plugins + malware_plugins + incident_plugins
            
            if analysis_type == 'basic':
                return basic_plugins
            elif analysis_type == 'malware':
                return malware_plugins
            elif analysis_type == 'incident_response':
                return incident_plugins
            else:  # full
                return full_plugins
                
        elif os_type == 'Linux':
            basic_plugins = ['linux.pslist', 'linux.cmdline', 'linux.netstat']
            malware_plugins = ['linux.lsmod', 'linux.lsof', 'linux.mount']
            incident_plugins = ['linux.psscan', 'linux.bash', 'linux.envars']
            full_plugins = basic_plugins + malware_plugins + incident_plugins
            
            if analysis_type == 'basic':
                return basic_plugins
            elif analysis_type == 'malware':
                return malware_plugins
            elif analysis_type == 'incident_response':
                return incident_plugins
            else:  # full
                return full_plugins
                
        elif os_type == 'macOS':
            return ['mac.pslist', 'mac.netstat', 'mac.lsmod', 'mac.malfind']
        else:
            return []
