"""
Setup script for ngtcp2-python
"""

from setuptools import setup
import os

def build_ffi():
    """Build the FFI extension"""
    from ngtcp2_python._build_ffi import build_ffi
    ffibuilder = build_ffi()
    return ffibuilder

if __name__ == "__main__":
    # Only build FFI if we're actually installing/building
    import sys
    if len(sys.argv) > 1 and sys.argv[1] in ['build', 'build_ext', 'install', 'develop']:
        try:
            ffibuilder = build_ffi()
        except Exception as e:
            print(f"Warning: Could not build FFI extension: {e}")
            print("You may need to install ngtcp2 development libraries first.")
            ffibuilder = None
    else:
        ffibuilder = None
    
    setup_kwargs = {}
    if ffibuilder:
        setup_kwargs['cffi_modules'] = [ffibuilder]
    
    setup(**setup_kwargs) 