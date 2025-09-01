"""
CFFI build script for ngtcp2 bindings
"""

import os
from cffi import FFI


def _first_existing_dir(paths):
    for p in paths:
        if p and os.path.isdir(p):
            return p
    return None


def build_ffi():
    """Build the CFFI extension for ngtcp2"""

    ffibuilder = FFI()

    # Minimal, stable subset of declarations required by our Python API
    ffibuilder.cdef(
        """
        typedef struct ngtcp2_info {
            int age;
            int version_num;
            const char *version_str;
        } ngtcp2_info;

        typedef struct ngtcp2_cid {
            size_t datalen;
            unsigned char data[20];
        } ngtcp2_cid;

        typedef struct ngtcp2_conn ngtcp2_conn;  /* opaque */

        typedef enum ngtcp2_pkt_type {
            NGTCP2_PKT_VERSION_NEGOTIATION = 0x80,
            NGTCP2_PKT_STATELESS_RESET = 0x81,
            NGTCP2_PKT_INITIAL = 0x10,
            NGTCP2_PKT_0RTT = 0x11,
            NGTCP2_PKT_HANDSHAKE = 0x12,
            NGTCP2_PKT_RETRY = 0x13,
            NGTCP2_PKT_1RTT = 0x40
        } ngtcp2_pkt_type;

        /* Packet flags */
        enum { NGTCP2_PKT_FLAG_NONE = 0x00u };
        enum { NGTCP2_PKT_FLAG_LONG_FORM = 0x01u };
        enum { NGTCP2_PKT_FLAG_FIXED_BIT_CLEAR = 0x02u };
        enum { NGTCP2_PKT_FLAG_KEY_PHASE = 0x04u };

        /* Common macros exposed as enum constants for CFFI */
        enum { NGTCP2_MAX_CIDLEN = 20 };
        enum { NGTCP2_STATELESS_RESET_TOKENLEN = 16 };
        enum {
            NGTCP2_ERR_INVALID_ARGUMENT = -201,
            NGTCP2_ERR_NOBUF = -202,
            NGTCP2_ERR_PROTO = -203,
            NGTCP2_ERR_INVALID_STATE = -204,
            NGTCP2_ERR_ACK_FRAME = -205,
            NGTCP2_ERR_STREAM_ID_BLOCKED = -206,
            NGTCP2_ERR_STREAM_IN_USE = -207,
            NGTCP2_ERR_STREAM_DATA_BLOCKED = -208,
            NGTCP2_ERR_FLOW_CONTROL = -209,
            NGTCP2_ERR_CONNECTION_ID_LIMIT = -210,
            NGTCP2_ERR_STREAM_LIMIT = -211,
            NGTCP2_ERR_FINAL_SIZE = -212,
            NGTCP2_ERR_CRYPTO = -213,
            NGTCP2_ERR_PKT_NUM_EXHAUSTED = -214,
            NGTCP2_ERR_REQUIRED_TRANSPORT_PARAM = -215,
            NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM = -216,
            NGTCP2_ERR_FRAME_ENCODING = -217,
            NGTCP2_ERR_DECRYPT = -218,
            NGTCP2_ERR_STREAM_SHUT_WR = -219,
            NGTCP2_ERR_STREAM_NOT_FOUND = -220,
            NGTCP2_ERR_STREAM_STATE = -221,
            NGTCP2_ERR_RECV_VERSION_NEGOTIATION = -222,
            NGTCP2_ERR_CLOSING = -223,
            NGTCP2_ERR_DRAINING = -224,
            NGTCP2_ERR_TRANSPORT_PARAM = -225,
            NGTCP2_ERR_DISCARD_PKT = -226,
            NGTCP2_ERR_CONN_ID_BLOCKED = -227,
            NGTCP2_ERR_INTERNAL = -228,
            NGTCP2_ERR_CRYPTO_BUFFER_EXCEEDED = -229,
            NGTCP2_ERR_WRITE_MORE = -230,
            NGTCP2_ERR_RETRY = -231,
            NGTCP2_ERR_DROP_CONN = -232,
            NGTCP2_ERR_AEAD_LIMIT_REACHED = -233,
            NGTCP2_ERR_NO_VIABLE_PATH = -234,
            NGTCP2_ERR_VERSION_NEGOTIATION = -235,
            NGTCP2_ERR_HANDSHAKE_TIMEOUT = -236,
            NGTCP2_ERR_VERSION_NEGOTIATION_FAILURE = -237,
            NGTCP2_ERR_IDLE_CLOSE = -238,
            NGTCP2_ERR_FATAL = -500,
            NGTCP2_ERR_NOMEM = -501,
            NGTCP2_ERR_CALLBACK_FAILURE = -502
        };

        typedef struct ngtcp2_version_cid {
            unsigned int version;
            const unsigned char *dcid;
            size_t dcidlen;
            const unsigned char *scid;
            size_t scidlen;
        } ngtcp2_version_cid;

        typedef struct ngtcp2_pkt_hd {
            ngtcp2_cid dcid;
            ngtcp2_cid scid;
            long long pkt_num;
            const unsigned char *token;
            size_t tokenlen;
            size_t pkt_numlen;
            size_t len;
            unsigned int version;
            unsigned char type;
            unsigned char flags;
        } ngtcp2_pkt_hd;

        const ngtcp2_info *ngtcp2_version(int least_version);
        int ngtcp2_is_supported_version(unsigned int version);
        int ngtcp2_is_reserved_version(unsigned int version);
        unsigned int ngtcp2_select_version(const unsigned int *preferred_versions,
                                           size_t preferred_versionslen,
                                           const unsigned int *offered_versions,
                                           size_t offered_versionslen);

        void ngtcp2_cid_init(ngtcp2_cid *cid, const unsigned char *data, size_t datalen);
        int ngtcp2_cid_eq(const ngtcp2_cid *a, const ngtcp2_cid *b);

        const char *ngtcp2_strerror(int liberr);
        int ngtcp2_err_is_fatal(int liberr);
        unsigned long long ngtcp2_err_infer_quic_transport_error_code(int liberr);
        int ngtcp2_is_bidi_stream(long long stream_id);

        /* Simple connection getters (no complex structs returned by value) */
        unsigned int ngtcp2_conn_get_client_chosen_version(ngtcp2_conn *conn);
        unsigned int ngtcp2_conn_get_negotiated_version(ngtcp2_conn *conn);
        unsigned long long ngtcp2_conn_get_max_data_left(ngtcp2_conn *conn);
        unsigned long long ngtcp2_conn_get_max_stream_data_left(ngtcp2_conn *conn, long long stream_id);
        unsigned long long ngtcp2_conn_get_streams_bidi_left(ngtcp2_conn *conn);
        unsigned long long ngtcp2_conn_get_streams_uni_left(ngtcp2_conn *conn);
        unsigned long long ngtcp2_conn_get_cwnd_left(ngtcp2_conn *conn);
        size_t ngtcp2_conn_get_max_tx_udp_payload_size(ngtcp2_conn *conn);
        size_t ngtcp2_conn_get_send_quantum(ngtcp2_conn *conn);
        size_t ngtcp2_conn_get_stream_loss_count(ngtcp2_conn *conn, long long stream_id);
        int ngtcp2_conn_is_server(ngtcp2_conn *conn);
        int ngtcp2_conn_is_local_stream(ngtcp2_conn *conn, long long stream_id);
        int ngtcp2_conn_in_closing_period(ngtcp2_conn *conn);
        int ngtcp2_conn_in_draining_period(ngtcp2_conn *conn);
        int ngtcp2_conn_get_tls_error(ngtcp2_conn *conn);
        int ngtcp2_conn_after_retry(ngtcp2_conn *conn);
        int ngtcp2_conn_get_handshake_completed(ngtcp2_conn *conn);
        int ngtcp2_conn_tls_early_data_rejected(ngtcp2_conn *conn);
        int ngtcp2_conn_get_tls_early_data_rejected(ngtcp2_conn *conn);

        /* CID getters */
        const ngtcp2_cid *ngtcp2_conn_get_dcid(ngtcp2_conn *conn);
        const ngtcp2_cid *ngtcp2_conn_get_client_initial_dcid(ngtcp2_conn *conn);
        size_t ngtcp2_conn_get_scid(ngtcp2_conn *conn, ngtcp2_cid *dest);

        /* Packet header helpers */
        int ngtcp2_pkt_decode_version_cid(ngtcp2_version_cid *dest,
                                          const unsigned char *data,
                                          size_t datalen,
                                          size_t short_dcidlen);
        long long ngtcp2_pkt_decode_hd_long(ngtcp2_pkt_hd *dest,
                                            const unsigned char *pkt,
                                            size_t pktlen);
        long long ngtcp2_pkt_decode_hd_short(ngtcp2_pkt_hd *dest,
                                             const unsigned char *pkt,
                                             size_t pktlen,
                                             size_t dcidlen);

        /* Path helpers (opaque-safe usage via pointers) */
        typedef struct ngtcp2_path ngtcp2_path;  /* opaque for Python */
        void ngtcp2_path_copy(ngtcp2_path *dest, const ngtcp2_path *src);
        int ngtcp2_path_eq(const ngtcp2_path *a, const ngtcp2_path *b);
        """
    )

    # Determine include and library directories (standalone)
    default_prefix = os.environ.get("NGTCP2_PREFIX", os.path.expanduser("~/.local"))

    env_include = os.environ.get("NGTCP2_INCLUDE_DIR")
    env_lib = os.environ.get("NGTCP2_LIB_DIR")

    # Try pkg-config first if available
    pc_include = None
    pc_libdir = None
    try:
        import subprocess

        cflags = subprocess.check_output(["pkg-config", "--cflags", "libngtcp2"], text=True).strip()
        libs = subprocess.check_output(["pkg-config", "--libs-only-L", "libngtcp2"], text=True).strip()
        for token in cflags.split():
            if token.startswith("-I"):
                pc_include = token[2:]
                break
        for token in libs.split():
            if token.startswith("-L"):
                pc_libdir = token[2:]
                break
    except Exception:
        pass

    candidate_includes = [
        env_include,
        pc_include,
        os.path.join(default_prefix, "include"),
        "/usr/local/include",
        "/opt/homebrew/include",
    ]
    candidate_libs = [
        env_lib,
        pc_libdir,
        os.path.join(default_prefix, "lib"),
        "/usr/local/lib",
        "/opt/homebrew/lib",
    ]

    ngtcp2_include_dir = _first_existing_dir(candidate_includes) or "/usr/local/include"
    ngtcp2_lib_dir = _first_existing_dir(candidate_libs) or "/usr/local/lib"

    extra_link_args = []
    if os.path.isdir(ngtcp2_lib_dir):
        # Embed rpath so the extension can locate libngtcp2 at runtime
        extra_link_args = [f"-Wl,-rpath,{ngtcp2_lib_dir}"]

    ffibuilder.set_source(
        "ngtcp2_python._ngtcp2_cffi",
        """
        #include <ngtcp2/ngtcp2.h>
        """,
        libraries=["ngtcp2"],
        include_dirs=[ngtcp2_include_dir],
        library_dirs=[ngtcp2_lib_dir],
        extra_link_args=extra_link_args,
    )

    return ffibuilder


if __name__ == "__main__":
    ffibuilder = build_ffi()
    ffibuilder.compile(verbose=True)