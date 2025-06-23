"""
Setup script for ngtcp2-python
"""

from setuptools import setup
import os

if __name__ == "__main__":
    # Only build FFI if we're actually installing/building
    import sys
    if len(sys.argv) > 1 and sys.argv[1] in ['build', 'build_ext', 'install', 'develop']:
        try:
            # Test if we can import the build function
            from ngtcp2_python._build_ffi import build_ffi
            setup_kwargs = {
                'cffi_modules': ['ngtcp2_python/_build_ffi.py:build_ffi']
            }
        except Exception as e:
            print(f"Warning: Could not build FFI extension: {e}")
            print("You may need to install ngtcp2 development libraries first.")
            setup_kwargs = {}
    else:
        setup_kwargs = {}
    
    setup(**setup_kwargs) 