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

        typedef struct ngtcp2_version_cid {
            unsigned int version;
            const unsigned char *dcid;
            size_t dcidlen;
            const unsigned char *scid;
            size_t scidlen;
        } ngtcp2_version_cid;

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