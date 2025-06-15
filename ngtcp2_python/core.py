"""
Core ngtcp2 Python bindings
"""

try:
    from ._ngtcp2_cffi import lib, ffi
except ImportError:
    # FFI not built yet
    lib = None
    ffi = None

class NGTCP2FFI:
    """
    Main class for ngtcp2 FFI operations
    """
    
    def __init__(self):
        if lib is None:
            raise RuntimeError(
                "ngtcp2 FFI not built. Please build it first:\n"
                "cd ngtcp2_python && python -m ngtcp2_python._build_ffi"
            )
        self.lib = lib
        self.ffi = ffi
    
    def get_version(self):
        """Get ngtcp2 version information"""
        from .version import get_version_info
        return get_version_info()
    
    def create_cid(self, data=None):
        """
        Create a new Connection ID
        
        Args:
            data: Optional bytes data for the CID
            
        Returns:
            Connection ID object
        """
        cid = self.ffi.new("ngtcp2_cid *")
        
        if data is not None:
            if isinstance(data, str):
                data = data.encode('utf-8')
            self.lib.ngtcp2_cid_init(cid, data, len(data))
        else:
            # Generate random CID if no data provided
            import os
            random_data = os.urandom(8)  # 8 bytes random CID
            self.lib.ngtcp2_cid_init(cid, random_data, len(random_data))
        
        return cid
    
    def compare_cids(self, cid1, cid2):
        """
        Compare two Connection IDs
        
        Args:
            cid1: First Connection ID
            cid2: Second Connection ID
            
        Returns:
            bool: True if CIDs are equal, False otherwise
        """
        return bool(self.lib.ngtcp2_cid_eq(cid1, cid2))
    
    def strerror(self, error_code):
        """
        Get human-readable error message for ngtcp2 error code
        
        Args:
            error_code: ngtcp2 error code (integer)
            
        Returns:
            str: Error message string
        """
        error_str = self.lib.ngtcp2_strerror(error_code)
        if error_str == self.ffi.NULL:
            return f"Unknown error code: {error_code}"
        return self.ffi.string(error_str).decode('utf-8')
    
    def is_fatal_error(self, error_code):
        """
        Check if an ngtcp2 error code represents a fatal error
        
        Args:
            error_code: ngtcp2 error code (integer)
            
        Returns:
            bool: True if error is fatal, False otherwise
        """
        return bool(self.lib.ngtcp2_err_is_fatal(error_code)) 