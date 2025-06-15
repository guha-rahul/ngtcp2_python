"""
CFFI build script for ngtcp2 bindings
"""

import os
from cffi import FFI

def build_ffi():
    """Build the CFFI extension for ngtcp2"""
    
    ffibuilder = FFI()
    
    # Include the header definitions
    ffibuilder.cdef("""
        // Constants
        #define NGTCP2_MAX_CIDLEN 20
        
        // Version info structure
        typedef struct {
            int age;
            int version_num;
            const char *version_str;
        } ngtcp2_info;
        
        // Connection ID structure
        typedef struct {
            size_t datalen;
            uint8_t data[20];  // NGTCP2_MAX_CIDLEN = 20
        } ngtcp2_cid;
        
        // Vector structure (like iovec)
        typedef struct {
            uint8_t *base;
            size_t len;
        } ngtcp2_vec;
        
        // Core functions
        const ngtcp2_info *ngtcp2_version(int least_version);
        
        // CID functions
        void ngtcp2_cid_init(ngtcp2_cid *cid, const uint8_t *data, size_t datalen);
        int ngtcp2_cid_eq(const ngtcp2_cid *a, const ngtcp2_cid *b);
        
        // Error handling functions
        const char *ngtcp2_strerror(int liberr);
        int ngtcp2_err_is_fatal(int liberr);
        
        // Add more function declarations as needed
    """)
    
    # Determine library paths
    ngtcp2_include_dir = os.environ.get('NGTCP2_INCLUDE_DIR', '/usr/local/include')
    ngtcp2_lib_dir = os.environ.get('NGTCP2_LIB_DIR', '/usr/local/lib')
    
    # For local development, use the build directory if it exists
    local_include = "/Users/rahulguha/ngtcp2/build/include"
    local_lib = "/Users/rahulguha/ngtcp2/build/lib"
    
    if os.path.exists(local_include):
        ngtcp2_include_dir = local_include
    if os.path.exists(local_lib):
        ngtcp2_lib_dir = local_lib
    
    ffibuilder.set_source(
        "ngtcp2_python._ngtcp2_cffi",
        """
        #include <ngtcp2/ngtcp2.h>
        """,
        libraries=["ngtcp2"],
        include_dirs=[ngtcp2_include_dir],
        library_dirs=[ngtcp2_lib_dir],
    )
    
    return ffibuilder

if __name__ == "__main__":
    ffibuilder = build_ffi()
    ffibuilder.compile(verbose=True) 