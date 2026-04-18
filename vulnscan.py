"""
VulnScan Pro - Adaptive Vulnerability Scanner
"""

from .scanner import VulnScanner, main
from .core.finding import Finding

__version__ = "2.0.0"
__all__ = ["VulnScanner", "Finding", "main", "__version__"]
