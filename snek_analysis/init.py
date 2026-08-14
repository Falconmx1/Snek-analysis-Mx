"""
Snek Analysis Mx - Memory Forensics Toolkit
Volatility 3 Wrapper for Automated Memory Analysis
"""

__version__ = "0.1.0"
__author__ = "Falconmx1"
__description__ = "Automated memory forensics tool for incident response"

from .main import main
from .volatility_wrapper import VolatilityWrapper

__all__ = ['main', 'VolatilityWrapper']
