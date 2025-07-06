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
                                        
        typedef enum ngtcp2_pkt_type {
            NGTCP2_PKT_VERSION_NEGOTIATION = 128,
            NGTCP2_PKT_STATELESS_RESET = 129,
            NGTCP2_PKT_INITIAL = 16,
            NGTCP2_PKT_0RTT = 17,
            NGTCP2_PKT_HANDSHAKE = 18,
            NGTCP2_PKT_RETRY = 19,
            NGTCP2_PKT_1RTT = 64
        } ngtcp2_pkt_type;
        
        typedef enum ngtcp2_path_validation_result {
            NGTCP2_PATH_VALIDATION_RESULT_SUCCESS = 0x00,
            NGTCP2_PATH_VALIDATION_RESULT_FAILURE = 0x01,
            NGTCP2_PATH_VALIDATION_RESULT_ABORTED = 0x02
        } ngtcp2_path_validation_result;
        
        typedef enum ngtcp2_cc_algo {
            NGTCP2_CC_ALGO_RENO = 0x00,
            NGTCP2_CC_ALGO_CUBIC = 0x01,
            NGTCP2_CC_ALGO_BBR = 0x02
        } ngtcp2_cc_algo;
                    
        typedef enum ngtcp2_token_type {
            NGTCP2_TOKEN_TYPE_UNKNOWN = 0,
            NGTCP2_TOKEN_TYPE_RETRY = 1,
            NGTCP2_TOKEN_TYPE_NEW_TOKEN = 2,
        } ngtcp2_token_type;
        
        typedef enum ngtcp2_encryption_level {
            NGTCP2_ENCRYPTION_LEVEL_INITIAL = 0,
            NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE = 1,
            NGTCP2_ENCRYPTION_LEVEL_1RTT = 2,    
            NGTCP2_ENCRYPTION_LEVEL_0RTT = 3,
        } ngtcp2_encryption_level;
        
        typedef enum ngtcp2_connection_id_status_type {
            NGTCP2_CONNECTION_ID_STATUS_TYPE_ACTIVATE = 0,
            NGTCP2_CONNECTION_ID_STATUS_TYPE_DEACTIVATE = 1
        } ngtcp2_connection_id_status_type;
        
        typedef enum ngtcp2_ccerr_type {
            NGTCP2_CCERR_TYPE_TRANSPORT = 0,            
            NGTCP2_CCERR_TYPE_APPLICATION = 1,            
            NGTCP2_CCERR_TYPE_VERSION_NEGOTIATION = 2,            
            NGTCP2_CCERR_TYPE_IDLE_CLOSE = 3,            
            NGTCP2_CCERR_TYPE_DROP_CONN = 4,
            NGTCP2_CCERR_TYPE_RETRY = 5,
        } ngtcp2_ccerr_type;
                    
        typedef struct st_ptls_t st_ptls_t;
        typedef struct st_ptls_key_schedule_t st_ptls_key_schedule_t;
        typedef struct ngtcp2_conn ngtcp2_conn;
                    
        #define NGTCP2_MAX_CIDLEN 20
                
        typedef struct ngtcp2_info {
            int age;
            int version_num;
            const char *version_str;
        } ngtcp2_info;
    
        typedef struct ngtcp2_cid {
            size_t datalen;
            uint8_t data[NGTCP2_MAX_CIDLEN];
        } ngtcp2_cid;
        
        typedef struct ngtcp2_vec{
            uint8_t *base;
            size_t len;
        } ngtcp2_vec;
        
        const ngtcp2_info *ngtcp2_version(int least_version);
        int ngtcp2_is_supported_version(uint32_t verision);
        
        void ngtcp2_cid_init(ngtcp2_cid *cid, const uint8_t *data, size_t datalen);
        int ngtcp2_cid_eq(const ngtcp2_cid *a, const ngtcp2_cid *b);
        
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