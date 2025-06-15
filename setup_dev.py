#!/usr/bin/env python3
"""
Development setup script for ngtcp2-python
"""

import os
import sys
import subprocess

def main():
    print("=== ngtcp2-python Development Setup ===\n")
    
    # Check if we're in the right directory
    if not os.path.exists('ngtcp2_python'):
        print("Error: This script should be run from the ngtcp2_python directory")
        sys.exit(1)
    
    try:
        # 1. Build the FFI extension
        print("1. Building FFI extension...")
        result = subprocess.run([
            sys.executable, '-m', 'ngtcp2_python._build_ffi'
        ], capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"   ❌ FFI build failed: {result.stderr}")
            return False
        else:
            print("   ✅ FFI extension built successfully")
        
        # 2. Test the installation
        print("\n2. Testing installation...")
        result = subprocess.run([
            sys.executable, 'examples/basic_usage.py'
        ], capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"   ❌ Tests failed: {result.stderr}")
            return False
        else:
            print("   ✅ Basic functionality test passed")
        
        # 3. Run pytest if available
        print("\n3. Running test suite...")
        try:
            result = subprocess.run([
                sys.executable, '-m', 'pytest', 'tests/', '-v'
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                print("   ✅ All tests passed")
            else:
                print(f"   ⚠️  Some tests failed: {result.stderr}")
        except FileNotFoundError:
            print("   ⚠️  pytest not installed, skipping tests")
        
        print("\n=== Setup completed successfully! ===")
        print("\nYou can now use ngtcp2-python:")
        print("  import ngtcp2_python")
        print("  ngtcp2 = ngtcp2_python.NGTCP2FFI()")
        print("  version = ngtcp2.get_version()")
        
        return True
        
    except Exception as e:
        print(f"Error during setup: {e}")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 