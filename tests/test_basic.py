"""
Basic tests for ngtcp2-python
"""

import pytest
import sys
import os

# Add the parent directory to the path so we can import ngtcp2_python
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

try:
    import ngtcp2_python
    FFI_AVAILABLE = True
except ImportError:
    FFI_AVAILABLE = False

@pytest.mark.skipif(not FFI_AVAILABLE, reason="ngtcp2 FFI not built")
class TestBasicFunctionality:
    """Test basic ngtcp2 functionality"""
    
    def test_version_info(self):
        """Test getting version information"""
        version_info = ngtcp2_python.get_version_info()
        
        assert isinstance(version_info, dict)
        assert 'age' in version_info
        assert 'version_num' in version_info
        assert 'version_str' in version_info
        
        assert isinstance(version_info['age'], int)
        assert isinstance(version_info['version_num'], int)
        assert isinstance(version_info['version_str'], str)
        
        # Check that values are reasonable
        assert version_info['age'] >= 1
        assert version_info['version_num'] > 0
        assert len(version_info['version_str']) > 0
    
    def test_ffi_instance_creation(self):
        """Test creating FFI instance"""
        ngtcp2 = ngtcp2_python.NGTCP2FFI()
        assert ngtcp2 is not None
        assert hasattr(ngtcp2, 'lib')
        assert hasattr(ngtcp2, 'ffi')
    
    def test_connection_id_creation(self):
        """Test creating connection IDs"""
        ngtcp2 = ngtcp2_python.NGTCP2FFI()
        
        # Test with specific data
        cid1 = ngtcp2.create_cid(b"test_data")
        assert cid1 is not None
        
        # Test with string data
        cid2 = ngtcp2.create_cid("test_string")
        assert cid2 is not None
        
        # Test with random data
        cid3 = ngtcp2.create_cid()
        assert cid3 is not None
    
    def test_connection_id_comparison(self):
        """Test comparing connection IDs"""
        ngtcp2 = ngtcp2_python.NGTCP2FFI()
        
        # Create identical CIDs
        cid1 = ngtcp2.create_cid(b"same_data")
        cid2 = ngtcp2.create_cid(b"same_data")
        
        # Create different CID
        cid3 = ngtcp2.create_cid(b"different_data")
        
        # Test comparison
        assert ngtcp2.compare_cids(cid1, cid2) is True
        assert ngtcp2.compare_cids(cid1, cid3) is False
        assert ngtcp2.compare_cids(cid2, cid3) is False
    
    def test_ffi_version_method(self):
        """Test the version method on FFI instance"""
        ngtcp2 = ngtcp2_python.NGTCP2FFI()
        version_info = ngtcp2.get_version()
        
        assert isinstance(version_info, dict)
        assert 'version_str' in version_info
    
    def test_error_handling(self):
        """Test error handling functions"""
        ngtcp2 = ngtcp2_python.NGTCP2FFI()
        
        # Test with a common error code (if we knew specific ones)
        # For now, test with 0 (usually success) and negative values
        error_msg = ngtcp2.strerror(0)
        assert isinstance(error_msg, str)
        assert len(error_msg) > 0
        
        # Test fatal error check
        is_fatal = ngtcp2.is_fatal_error(0)
        assert isinstance(is_fatal, bool)
        
        # Test with a likely error code
        error_msg = ngtcp2.strerror(-1)
        assert isinstance(error_msg, str)

class TestWithoutFFI:
    """Test behavior when FFI is not available"""
    
    @pytest.mark.skipif(FFI_AVAILABLE, reason="FFI is available")  
    def test_import_error_handling(self):
        """Test that appropriate errors are raised when FFI is not built"""
        # This test only runs when FFI is not available
        with pytest.raises(ImportError):
            import ngtcp2_python 