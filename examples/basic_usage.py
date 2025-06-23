#!/usr/bin/env python3
"""
Basic usage example for ngtcp2 Python bindings
"""

import os
import sys

# Add the parent directory to the path so we can import ngtcp2_python
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from ngtcp2_python.core import get_ngtcp2, NGTCP2Error, NGTCP2ConnectionInfo


def demonstrate_basic_functionality():
    """Demonstrate basic ngtcp2 functionality"""
    print("=== Basic ngtcp2 Python Bindings Demo ===\n")
    
    try:
        # Get the ngtcp2 FFI instance
        ngtcp2 = get_ngtcp2()
        print("✓ Successfully loaded ngtcp2 FFI")
        
        # Show version information
        version_info = ngtcp2.get_version()
        print(f"✓ ngtcp2 version: {version_info}")
        
        # Access constants
        constants = ngtcp2.constants
        print(f"✓ QUIC v1 version: 0x{constants.PROTO_VER_V1:08x}")
        print(f"✓ QUIC v2 version: 0x{constants.PROTO_VER_V2:08x}")
        print(f"✓ Max CID length: {constants.MAX_CIDLEN}")
        print(f"✓ Stateless reset token length: {constants.STATELESS_RESET_TOKENLEN}")
        
    except Exception as e:
        print(f"✗ Failed to load ngtcp2: {e}")
        return False
    
    return True


def demonstrate_connection_ids():
    """Demonstrate Connection ID operations"""
    print("\n=== Connection ID Operations ===\n")
    
    try:
        ngtcp2 = get_ngtcp2()
        
        # Create Connection IDs
        print("Creating Connection IDs...")
        cid1 = ngtcp2.create_cid(b"test_cid_1")
        cid2 = ngtcp2.create_cid(b"test_cid_2")
        cid3 = ngtcp2.create_cid(b"test_cid_1")  # Same as cid1
        
        print(f"✓ CID 1: {cid1}")
        print(f"✓ CID 2: {cid2}")
        print(f"✓ CID 3: {cid3}")
        
        # Compare Connection IDs
        print(f"✓ CID1 == CID2: {cid1 == cid2}")
        print(f"✓ CID1 == CID3: {cid1 == cid3}")
        
        # Get CID data
        print(f"✓ CID1 data: {cid1.get_data().hex()}")
        print(f"✓ CID1 length: {cid1.get_length()}")
        
        # Create random CID
        random_cid = ngtcp2.create_cid()
        print(f"✓ Random CID: {random_cid}")
        
    except Exception as e:
        print(f"✗ Connection ID demo failed: {e}")
        return False
    
    return True


def demonstrate_version_operations():
    """Demonstrate version negotiation"""
    print("\n=== Version Operations ===\n")
    
    try:
        ngtcp2 = get_ngtcp2()
        constants = ngtcp2.constants
        
        # Check version support
        v1 = constants.PROTO_VER_V1
        v2 = constants.PROTO_VER_V2
        reserved = 0x0a0a0a0a
        
        print(f"✓ QUIC v1 supported: {ngtcp2.is_supported_version(v1)}")
        print(f"✓ QUIC v2 supported: {ngtcp2.is_supported_version(v2)}")
        print(f"✓ Reserved version: {ngtcp2.is_reserved_version(reserved)}")
        
        # Version selection
        preferred = [v2, v1]
        offered = [v1, 0x12345678]
        
        selected = ngtcp2.select_version(preferred, offered)
        print(f"✓ Selected version: 0x{selected:08x}")
        
    except Exception as e:
        print(f"✗ Version operations demo failed: {e}")
        return False
    
    return True


def demonstrate_error_handling():
    """Demonstrate error handling"""
    print("\n=== Error Handling ===\n")
    
    try:
        ngtcp2 = get_ngtcp2()
        constants = ngtcp2.constants
        
        # Test error message lookup
        error_codes = [
            constants.ERR_INVALID_ARGUMENT,
            constants.ERR_NOBUF,
            constants.ERR_PROTO,
            constants.ERR_CRYPTO,
        ]
        
        for err_code in error_codes:
            message = ngtcp2.strerror(err_code)
            is_fatal = ngtcp2.is_fatal_error(err_code)
            transport_code = ngtcp2.infer_quic_transport_error_code(err_code)
            
            print(f"✓ Error {err_code}: {message}")
            print(f"  - Fatal: {is_fatal}")
            print(f"  - Transport code: 0x{transport_code:02x}")
        
        # Demonstrate connection close error
        ccerr = ngtcp2.create_connection_close_error()
        ccerr.set_transport_error(constants.PROTOCOL_VIOLATION, "Test protocol violation")
        
        print(f"✓ Connection close error: {ccerr}")
        print(f"  - Type: {ccerr.error_type}")
        print(f"  - Code: 0x{ccerr.error_code:02x}")
        print(f"  - Reason: {ccerr.reason}")
        
    except Exception as e:
        print(f"✗ Error handling demo failed: {e}")
        return False
    
    return True


def demonstrate_packet_operations():
    """Demonstrate packet operations"""
    print("\n=== Packet Operations ===\n")
    
    try:
        ngtcp2 = get_ngtcp2()
        constants = ngtcp2.constants
        
        # Create a simple version negotiation packet
        dcid = b"dest_cid"
        scid = b"src_cid"
        supported_versions = [constants.PROTO_VER_V1, constants.PROTO_VER_V2]
        
        vn_packet = ngtcp2.write_version_negotiation(dcid, scid, supported_versions)
        if vn_packet:
            print(f"✓ Created version negotiation packet: {len(vn_packet)} bytes")
            print(f"  - First 16 bytes: {vn_packet[:16].hex()}")
        else:
            print("✗ Failed to create version negotiation packet")
        
        # Create a stateless reset packet
        reset_token = os.urandom(constants.STATELESS_RESET_TOKENLEN)
        random_data = os.urandom(100)
        
        reset_packet = ngtcp2.write_stateless_reset(reset_token, random_data)
        if reset_packet:
            print(f"✓ Created stateless reset packet: {len(reset_packet)} bytes")
            print(f"  - Token: {reset_token.hex()}")
        else:
            print("✗ Failed to create stateless reset packet")
        
        # Test stream ID classification
        bidi_client = 0  # Client-initiated bidirectional
        bidi_server = 1  # Server-initiated bidirectional
        uni_client = 2   # Client-initiated unidirectional
        uni_server = 3   # Server-initiated unidirectional
        
        print(f"✓ Stream 0 is bidirectional: {ngtcp2.is_bidi_stream(bidi_client)}")
        print(f"✓ Stream 1 is bidirectional: {ngtcp2.is_bidi_stream(bidi_server)}")
        print(f"✓ Stream 2 is bidirectional: {ngtcp2.is_bidi_stream(uni_client)}")
        print(f"✓ Stream 3 is bidirectional: {ngtcp2.is_bidi_stream(uni_server)}")
        
    except Exception as e:
        print(f"✗ Packet operations demo failed: {e}")
        return False
    
    return True


def demonstrate_connection_info():
    """Demonstrate connection info structure"""
    print("\n=== Connection Info ===\n")
    
    try:
        ngtcp2 = get_ngtcp2()
        
        # Create connection info structure
        conn_info = NGTCP2ConnectionInfo(ngtcp2.ffi)
        print(f"✓ Created connection info: {conn_info}")
        
        # Show initial values (will be zero/default)
        print(f"✓ Latest RTT: {conn_info.latest_rtt}")
        print(f"✓ Min RTT: {conn_info.min_rtt}")
        print(f"✓ Smoothed RTT: {conn_info.smoothed_rtt}")
        print(f"✓ Congestion window: {conn_info.congestion_window}")
        
    except Exception as e:
        print(f"✗ Connection info demo failed: {e}")
        return False
    
    return True


def demonstrate_constants():
    """Demonstrate access to constants"""
    print("\n=== Constants Access ===\n")
    
    try:
        ngtcp2 = get_ngtcp2()
        constants = ngtcp2.constants
        
        print("QUIC Protocol Versions:")
        print(f"  - v1: 0x{constants.PROTO_VER_V1:08x}")
        print(f"  - v2: 0x{constants.PROTO_VER_V2:08x}")
        
        print("\nPacket Types:")
        print(f"  - Initial: 0x{constants.PKT_INITIAL:02x}")
        print(f"  - Handshake: 0x{constants.PKT_HANDSHAKE:02x}")
        print(f"  - 1-RTT: 0x{constants.PKT_1RTT:02x}")
        print(f"  - Version Negotiation: 0x{constants.PKT_VERSION_NEGOTIATION:02x}")
        
        print("\nTransport Error Codes:")
        print(f"  - No Error: 0x{constants.NO_ERROR:02x}")
        print(f"  - Protocol Violation: 0x{constants.PROTOCOL_VIOLATION:02x}")
        print(f"  - Flow Control Error: 0x{constants.FLOW_CONTROL_ERROR:02x}")
        
        print("\nEncryption Levels:")
        print(f"  - Initial: {constants.ENCRYPTION_LEVEL_INITIAL}")
        print(f"  - Handshake: {constants.ENCRYPTION_LEVEL_HANDSHAKE}")
        print(f"  - 1-RTT: {constants.ENCRYPTION_LEVEL_1RTT}")
        print(f"  - 0-RTT: {constants.ENCRYPTION_LEVEL_0RTT}")
        
    except Exception as e:
        print(f"✗ Constants demo failed: {e}")
        return False
    
    return True


def main():
    """Main demo function"""
    print("ngtcp2 Python Bindings - Comprehensive Demo")
    print("=" * 50)
    
    demos = [
        ("Basic Functionality", demonstrate_basic_functionality),
        ("Connection IDs", demonstrate_connection_ids),
        ("Version Operations", demonstrate_version_operations),
        ("Error Handling", demonstrate_error_handling),
        ("Packet Operations", demonstrate_packet_operations),
        ("Connection Info", demonstrate_connection_info),
        ("Constants Access", demonstrate_constants),
    ]
    
    results = []
    for name, demo_func in demos:
        try:
            success = demo_func()
            results.append((name, success))
        except Exception as e:
            print(f"✗ {name} failed with exception: {e}")
            results.append((name, False))
    
    # Summary
    print("\n" + "=" * 50)
    print("DEMO SUMMARY")
    print("=" * 50)
    
    success_count = 0
    for name, success in results:
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"{status} {name}")
        if success:
            success_count += 1
    
    print(f"\nOverall: {success_count}/{len(results)} demos passed")
    
    if success_count == len(results):
        print("🎉 All demos completed successfully!")
        return 0
    else:
        print("⚠️  Some demos failed. Check the output above for details.")
        return 1


if __name__ == "__main__":
    sys.exit(main()) 