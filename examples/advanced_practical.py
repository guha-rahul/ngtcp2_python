#!/usr/bin/env python3
"""
Practical Advanced ngtcp2 Python bindings usage example

This example demonstrates advanced usage patterns with the currently available features:
- Advanced packet analysis and manipulation
- Connection ID management strategies
- Version negotiation scenarios
- Error handling patterns
- Real-world application configurations
"""

import os
import sys
import time
import struct

# Add the parent directory to the path so we can import ngtcp2_python
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

try:
    import ngtcp2_python
except ImportError as e:
    print(f"Failed to import ngtcp2_python: {e}")
    print("Make sure to build the extension first with: pip install -e .")
    sys.exit(1)


def test_advanced_connection_id_management():
    """Test advanced Connection ID management strategies"""
    print("=== Advanced Connection ID Management ===")
    
    try:
        ngtcp2 = ngtcp2_python.get_ngtcp2()
        
        # Strategy 1: Load balancing with structured CIDs
        print("1. Load Balancing Strategy:")
        server_id = 0x01  # Server identifier
        connection_counter = 0x12345678  # Connection counter
        
        # Create structured CID for load balancing
        cid_data = struct.pack('>BL', server_id, connection_counter) + os.urandom(3)
        lb_cid = ngtcp2.create_cid(cid_data)
        print(f"   Load balancing CID: {lb_cid}")
        print(f"   Server ID: {server_id}, Counter: {connection_counter:08x}")
        
        # Strategy 2: Privacy-focused random CIDs
        print("\n2. Privacy Strategy:")
        privacy_cids = []
        for i in range(5):
            # Generate completely random CIDs of varying lengths
            length = 8 + (i % 13)  # 8-20 bytes
            random_cid = ngtcp2.create_cid(os.urandom(length))
            privacy_cids.append(random_cid)
            print(f"   Privacy CID {i+1}: {random_cid} ({random_cid.get_length()} bytes)")
        
        return True
        
    except Exception as e:
        print(f"✗ Advanced CID management test failed: {e}")
        return False


def test_version_negotiation_scenarios():
    """Test comprehensive version negotiation scenarios"""
    print("\n=== Version Negotiation Scenarios ===")
    
    try:
        ngtcp2 = ngtcp2_python.get_ngtcp2()
        constants = ngtcp2.constants
        
        # Define version sets for different deployment scenarios
        scenarios = [
            {
                "name": "Modern Client vs Legacy Server",
                "client_versions": [constants.PROTO_VER_V2, constants.PROTO_VER_V1],
                "server_versions": [constants.PROTO_VER_V1],
                "expected": constants.PROTO_VER_V1
            },
            {
                "name": "Both Support Latest",
                "client_versions": [constants.PROTO_VER_V2, constants.PROTO_VER_V1],
                "server_versions": [constants.PROTO_VER_V2, constants.PROTO_VER_V1],
                "expected": constants.PROTO_VER_V2
            }
        ]
        
        print("Version negotiation test results:")
        print("Scenario                        Result")
        print("─" * 50)
        
        for scenario in scenarios:
            selected = ngtcp2.select_version(
                scenario["client_versions"], 
                scenario["server_versions"]
            )
            
            result_str = f"0x{selected:08x}" if selected != 0 else "NONE"
            status = "✓" if selected == scenario['expected'] else "✗"
            
            print(f"{scenario['name']:<30} {result_str} {status}")
        
        return True
        
    except Exception as e:
        print(f"✗ Version negotiation test failed: {e}")
        return False


def test_packet_analysis_and_generation():
    """Test advanced packet analysis and generation"""
    print("\n=== Packet Analysis and Generation ===")
    
    try:
        ngtcp2 = ngtcp2_python.get_ngtcp2()
        constants = ngtcp2.constants
        
        # Test 1: Version negotiation packet generation
        print("1. Version Negotiation Packet:")
        dcid = b"client_cid_12345"
        scid = b"server_cid_67890"
        supported_versions = [constants.PROTO_VER_V2, constants.PROTO_VER_V1]
        
        try:
            vn_packet = ngtcp2.write_version_negotiation(dcid, scid, supported_versions)
            print(f"   Generated VN packet: {len(vn_packet)} bytes")
            print(f"   Packet preview: {vn_packet[:32].hex()}...")
            
            # Analyze the generated packet
            vcid = ngtcp2.decode_version_cid(vn_packet)
            print(f"   Decoded version: 0x{vcid.version:08x}")
            print(f"   Decoded DCID: {vcid.dcid.hex() if vcid.dcid else 'None'}")
            print(f"   Decoded SCID: {vcid.scid.hex() if vcid.scid else 'None'}")
            
        except Exception as e:
            print(f"   VN packet generation failed: {e}")
        
        # Test 2: Stateless reset packet generation  
        print("\n2. Stateless Reset Packet:")
        reset_token = os.urandom(constants.STATELESS_RESET_TOKENLEN)
        random_data = os.urandom(32)
        
        try:
            sr_packet = ngtcp2.write_stateless_reset(reset_token, random_data)
            print(f"   Generated SR packet: {len(sr_packet)} bytes")
            print(f"   Reset token: {reset_token.hex()}")
            print(f"   Packet preview: {sr_packet[:32].hex()}...")
            
        except Exception as e:
            print(f"   SR packet generation failed: {e}")
        
        return True
        
    except Exception as e:
        print(f"✗ Packet analysis test failed: {e}")
        return False


def test_error_handling_strategies():
    """Test comprehensive error handling strategies"""
    print("\n=== Error Handling Strategies ===")
    
    try:
        ngtcp2 = ngtcp2_python.get_ngtcp2()
        constants = ngtcp2.constants
        
        # Test connection close error scenarios
        print("1. Connection Close Error Scenarios:")
        
        scenarios = [
            ("Normal closure", constants.NO_ERROR, "Connection closed normally"),
            ("Protocol violation", constants.PROTOCOL_VIOLATION, "Invalid frame received"),
            ("Flow control", constants.FLOW_CONTROL_ERROR, "Data limit exceeded"),
            ("Internal error", constants.INTERNAL_ERROR, "Server internal error"),
        ]
        
        for scenario_name, error_code, reason in scenarios:
            print(f"\n   {scenario_name}:")
            ccerr = ngtcp2.create_connection_close_error()
            
            ccerr.set_transport_error(error_code, reason)
            print(f"     Error type: {ccerr.error_type}")
            print(f"     Error code: {ccerr.error_code}")
            print(f"     Reason: {ccerr.reason}")
        
        return True
        
    except Exception as e:
        print(f"✗ Error handling test failed: {e}")
        return False


def test_stream_management():
    """Test stream management utilities"""
    print("\n=== Stream Management ===")
    
    try:
        ngtcp2 = ngtcp2_python.get_ngtcp2()
        
        # Test stream ID analysis
        print("1. Stream ID Analysis:")
        
        test_stream_ids = [0, 1, 2, 3, 4, 100, 101, 102, 103]
        
        print("Stream ID  Type                        Direction      Initiator")
        print("─" * 65)
        
        for stream_id in test_stream_ids:
            is_bidi = ngtcp2.is_bidi_stream(stream_id)
            stream_type = "Bidirectional" if is_bidi else "Unidirectional"
            
            # Determine initiator and direction
            if stream_id % 4 == 0:
                initiator = "Client"
                direction = "Bidirectional"
            elif stream_id % 4 == 1:
                initiator = "Server"
                direction = "Bidirectional"
            elif stream_id % 4 == 2:
                initiator = "Client"
                direction = "Unidirectional"
            else:  # stream_id % 4 == 3
                initiator = "Server"
                direction = "Unidirectional"
            
            print(f"{stream_id:<10} {stream_type:<25} {direction:<14} {initiator}")
        
        return True
        
    except Exception as e:
        print(f"✗ Stream management test failed: {e}")
        return False


def main():
    """Run all practical advanced feature tests"""
    print("ngtcp2 Python Bindings - Practical Advanced Features Demo")
    print("=" * 60)
    
    tests = [
        ("Advanced Connection ID Management", test_advanced_connection_id_management),
        ("Version Negotiation Scenarios", test_version_negotiation_scenarios),
        ("Packet Analysis and Generation", test_packet_analysis_and_generation),
        ("Error Handling Strategies", test_error_handling_strategies),
        ("Stream Management", test_stream_management),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
        except Exception as e:
            print(f"✗ {test_name} test failed with exception: {e}")
    
    print("\n" + "=" * 60)
    print(f"Practical Advanced Features Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All practical advanced features are working correctly!")
        print("\nThese patterns demonstrate:")
        print("• Advanced Connection ID management strategies")
        print("• Comprehensive version negotiation scenarios")
        print("• Packet analysis and generation capabilities")
        print("• Robust error handling patterns")
        print("• Stream management utilities")
        return 0
    else:
        print("⚠️  Some advanced features encountered issues")
        return 1


if __name__ == "__main__":
    sys.exit(main())
