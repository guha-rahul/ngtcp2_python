"""
Version information for ngtcp2
"""

try:
    from ._ngtcp2_cffi import lib, ffi
except ImportError:
    # FFI not built yet
    lib = None
    ffi = None

def get_version_info():
    """
    Get ngtcp2 version information
    
    Returns:
        dict: Dictionary containing version information with keys:
            - age: Age of the struct
            - version_num: Version number
            - version_str: Version string
    """
    if lib is None:
        raise RuntimeError("ngtcp2 FFI not built. Run: python -m ngtcp2_python._build_ffi")
    
    version_info = lib.ngtcp2_version(1)
    if version_info == ffi.NULL:
        raise RuntimeError("Failed to get ngtcp2 version info")
    
    return {
        'age': version_info.age,
        'version_num': version_info.version_num,
        'version_str': ffi.string(version_info.version_str).decode('utf-8')
    } 