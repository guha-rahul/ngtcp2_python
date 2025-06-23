"""
CFFI build script for ngtcp2 bindings - Simplified version focusing on working functions
"""

import os
from cffi import FFI

def build_ffi():
    """Build the CFFI extension for ngtcp2"""
    
    ffibuilder = FFI()
    
    # Define C structures and functions - simplified version
    ffibuilder.cdef("""
        // Basic types
        typedef uint64_t ngtcp2_tstamp;
        typedef uint64_t ngtcp2_duration;
        typedef int64_t ngtcp2_ssize;

        // Constants
        #define NGTCP2_MAX_CIDLEN 20
        #define NGTCP2_STATELESS_RESET_TOKENLEN 16
        #define NGTCP2_MIN_STATELESS_RESET_RANDLEN 5

        // QUIC versions
        #define NGTCP2_PROTO_VER_V1 0x00000001U
        #define NGTCP2_PROTO_VER_V2 0x6b3343cfU

        // Basic error codes (only those that exist)
        #define NGTCP2_ERR_INVALID_ARGUMENT -209
        #define NGTCP2_ERR_NOBUF -220
        #define NGTCP2_ERR_NOMEM -221

        // Basic structures
        typedef struct {
            size_t datalen;
            uint8_t data[20];  // NGTCP2_MAX_CIDLEN
        } ngtcp2_cid;

        typedef struct {
            uint8_t *base;
            size_t len;
        } ngtcp2_vec;

        // Version CID structure for packet parsing
        typedef struct {
            ngtcp2_cid dcid;
            ngtcp2_cid scid;
            uint32_t version;
        } ngtcp2_version_cid;

        // Packet header structure (simplified)
        typedef struct {
            ngtcp2_cid dcid;
            ngtcp2_cid scid;
            int64_t pkt_num;
            const uint8_t *token;
            size_t tokenlen;
            size_t pkt_numlen;
            size_t len;
            uint32_t version;
            uint8_t type;
            uint8_t flags;
        } ngtcp2_pkt_hd;

        // Basic functions that we know work
        const char *ngtcp2_version(int least);
        const char *ngtcp2_strerror(int liberr);
        int ngtcp2_err_is_fatal(int liberr);

        // Version negotiation functions
        int ngtcp2_is_supported_version(uint32_t version);
        int ngtcp2_is_reserved_version(uint32_t version);
        uint32_t ngtcp2_select_version(const uint32_t *preferred_versions,
                                      size_t preferred_versionslen,
                                      const uint32_t *offered_versions,
                                      size_t offered_versionslen);

        // Packet functions
        ngtcp2_ssize ngtcp2_pkt_decode_version_cid(ngtcp2_version_cid *dest,
                                                   const uint8_t *data,
                                                   size_t datalen,
                                                   size_t short_dcidlen);

        ngtcp2_ssize ngtcp2_pkt_decode_hd_long(ngtcp2_pkt_hd *dest,
                                              const uint8_t *pkt,
                                              size_t pktlen);

        ngtcp2_ssize ngtcp2_pkt_decode_hd_short(ngtcp2_pkt_hd *dest,
                                               const uint8_t *pkt,
                                               size_t pktlen,
                                               size_t dcidlen);

        ngtcp2_ssize ngtcp2_pkt_write_version_negotiation(
            uint8_t *dest, size_t destlen, uint8_t unused_random,
            const uint8_t *dcid, size_t dcidlen,
            const uint8_t *scid, size_t scidlen,
            const uint32_t *sv, size_t nsv);

        ngtcp2_ssize ngtcp2_pkt_write_stateless_reset(
            uint8_t *dest, size_t destlen,
            const uint8_t *stateless_reset_token,
            const uint8_t *rand, size_t randlen);

        // Stream functions
        int ngtcp2_is_bidi_stream(int64_t stream_id);

        // Connection ID functions
        void ngtcp2_cid_init(ngtcp2_cid *cid, const uint8_t *data, size_t datalen);
        int ngtcp2_cid_eq(const ngtcp2_cid *a, const ngtcp2_cid *b);
    """)

    # Set library and include paths
    ngtcp2_include_dir = os.environ.get('NGTCP2_INCLUDE_DIR', '/Users/rahulguha/ngtcp2/build/include')
    ngtcp2_lib_dir = os.environ.get('NGTCP2_LIB_DIR', '/Users/rahulguha/ngtcp2/build/lib')

    ffibuilder.set_source(
        "ngtcp2_python._ngtcp2_cffi",
        """
        #include <ngtcp2/ngtcp2.h>
        """,
        include_dirs=[ngtcp2_include_dir],
        library_dirs=[ngtcp2_lib_dir],
        libraries=['ngtcp2'],
    )

    return ffibuilder

if __name__ == "__main__":
    build_ffi().compile(verbose=True) 