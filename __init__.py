"""
VulnScan Pro - Adaptive Vulnerability Scanner
A professional-grade security scanning tool with real-time output
"""

__version__ = "2.0.0"
__author__ = "HackSurge"

from .scanner import VulnScanner, main
from .core.finding import Finding

__all__ = ['VulnScanner', 'Finding', 'main']
