"""
ngtcp2-python: Python bindings for ngtcp2 QUIC library
"""

__version__ = "0.1.0"
__author__ = "Your Name"
__email__ = "your-email@example.com"

from .core import *
from .version import (
    get_version_info,
    is_supported_version
)

__all__ = [
    "get_version_info",
    "is_supported_version",   
    "NGTCP2FFI",
] 