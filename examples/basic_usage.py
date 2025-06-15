#!/usr/bin/env python3
"""
Basic usage example for ngtcp2-python
"""

import sys
import os

# Add the parent directory to the path so we can import ngtcp2_python
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

try:
    import ngtcp2_python
    
    def main():
        print("=== ngtcp2 Python Bindings Demo ===\n")
        
        # 1. Get version information
        print("1. Getting ngtcp2 version information:")
        try:
            version_info = ngtcp2_python.get_version_info()
            print(f"   Age: {version_info['age']}")
            print(f"   Version Number: {version_info['version_num']}")
            print(f"   Version String: {version_info['version_str']}")
        except Exception as e:
            print(f"   Error: {e}")
            return
        
        print()
        
        # 2. Create FFI instance
        print("2. Creating ngtcp2 FFI instance:")
        try:
            ngtcp2 = ngtcp2_python.NGTCP2FFI()
            print("   ✓ FFI instance created successfully")
        except Exception as e:
            print(f"   Error: {e}")
            return
        
        print()
        
        # 3. Work with Connection IDs
        print("3. Working with Connection IDs:")
        try:
            # Create some connection IDs
            cid1 = ngtcp2.create_cid(b"hello")
            cid2 = ngtcp2.create_cid(b"hello")  # Same data
            cid3 = ngtcp2.create_cid(b"world")  # Different data
            cid4 = ngtcp2.create_cid()  # Random data
            
            print("   ✓ Created 4 connection IDs")
            
            # Compare connection IDs
            print(f"   cid1 == cid2 (same data): {ngtcp2.compare_cids(cid1, cid2)}")
            print(f"   cid1 == cid3 (different data): {ngtcp2.compare_cids(cid1, cid3)}")
            print(f"   cid1 == cid4 (random data): {ngtcp2.compare_cids(cid1, cid4)}")
            
        except Exception as e:
            print(f"   Error: {e}")
            return
        
        print()
        
        # 4. Test error handling
        print("4. Testing error handling:")
        try:
            # Test error string conversion
            error_msg = ngtcp2.strerror(0)  # 0 is usually success
            print(f"   Error code 0: {error_msg}")
            
            error_msg = ngtcp2.strerror(-1)  # -1 is likely an error
            print(f"   Error code -1: {error_msg}")
            
            # Test fatal error checking
            is_fatal = ngtcp2.is_fatal_error(-1)
            print(f"   Error code -1 is fatal: {is_fatal}")
            
        except Exception as e:
            print(f"   Error: {e}")
        
        print()
        print("=== Demo completed successfully! ===")
    
    if __name__ == "__main__":
        main()

except ImportError as e:
    print(f"Error importing ngtcp2_python: {e}")
    print("\nMake sure to build the FFI extension first:")
    print("cd ngtcp2_python && python -m ngtcp2_python._build_ffi")
    sys.exit(1) 