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

    def infer_quic_transport_error_code(self, lib_error: int) -> int:
        """Map libngtcp2 error code to QUIC transport error code."""
        return int(self.lib.ngtcp2_err_infer_quic_transport_error_code(lib_error))

    def is_bidi_stream(self, stream_id: int) -> bool:
        """Return True if the given stream_id is bidirectional."""
        return bool(self.lib.ngtcp2_is_bidi_stream(stream_id))

    def is_reserved_version(self, version: int) -> bool:
        """Return True if the given QUIC version is reserved."""
        return bool(self.lib.ngtcp2_is_reserved_version(version))

    def select_version(self, preferred_versions: list[int], offered_versions: list[int]) -> int:
        """Select a version from offered set given preferred order.
        Returns 0 if none selected.
        """
        pref_arr = self.ffi.new("unsigned int[]", preferred_versions)
        off_arr = self.ffi.new("unsigned int[]", offered_versions)
        return int(self.lib.ngtcp2_select_version(
            pref_arr, len(preferred_versions), off_arr, len(offered_versions)
        ))

    # --- Simple ngtcp2_conn accessors (accept an opaque pointer) ---
    def conn_get_client_chosen_version(self, conn_ptr) -> int:
        return int(self.lib.ngtcp2_conn_get_client_chosen_version(conn_ptr))

    def conn_get_negotiated_version(self, conn_ptr) -> int:
        return int(self.lib.ngtcp2_conn_get_negotiated_version(conn_ptr))

    def conn_get_max_data_left(self, conn_ptr) -> int:
        return int(self.lib.ngtcp2_conn_get_max_data_left(conn_ptr))

    def conn_get_max_stream_data_left(self, conn_ptr, stream_id: int) -> int:
        return int(self.lib.ngtcp2_conn_get_max_stream_data_left(conn_ptr, stream_id))

    def conn_get_streams_bidi_left(self, conn_ptr) -> int:
        return int(self.lib.ngtcp2_conn_get_streams_bidi_left(conn_ptr))

    def conn_get_streams_uni_left(self, conn_ptr) -> int:
        return int(self.lib.ngtcp2_conn_get_streams_uni_left(conn_ptr))

    def conn_get_cwnd_left(self, conn_ptr) -> int:
        return int(self.lib.ngtcp2_conn_get_cwnd_left(conn_ptr))

    def conn_get_max_tx_udp_payload_size(self, conn_ptr) -> int:
        return int(self.lib.ngtcp2_conn_get_max_tx_udp_payload_size(conn_ptr))

    def conn_get_send_quantum(self, conn_ptr) -> int:
        return int(self.lib.ngtcp2_conn_get_send_quantum(conn_ptr))

    def conn_get_stream_loss_count(self, conn_ptr, stream_id: int) -> int:
        return int(self.lib.ngtcp2_conn_get_stream_loss_count(conn_ptr, stream_id))

    def conn_is_server(self, conn_ptr) -> bool:
        return bool(self.lib.ngtcp2_conn_is_server(conn_ptr))

    def conn_is_local_stream(self, conn_ptr, stream_id: int) -> bool:
        return bool(self.lib.ngtcp2_conn_is_local_stream(conn_ptr, stream_id))

    def conn_in_closing_period(self, conn_ptr) -> bool:
        return bool(self.lib.ngtcp2_conn_in_closing_period(conn_ptr))

    def conn_in_draining_period(self, conn_ptr) -> bool:
        return bool(self.lib.ngtcp2_conn_in_draining_period(conn_ptr))

    def conn_get_handshake_completed(self, conn_ptr) -> bool:
        return bool(self.lib.ngtcp2_conn_get_handshake_completed(conn_ptr))

    def conn_get_tls_error(self, conn_ptr) -> int:
        return int(self.lib.ngtcp2_conn_get_tls_error(conn_ptr))

    def conn_after_retry(self, conn_ptr) -> int:
        return int(self.lib.ngtcp2_conn_after_retry(conn_ptr))

    def conn_tls_early_data_rejected(self, conn_ptr) -> int:
        return int(self.lib.ngtcp2_conn_tls_early_data_rejected(conn_ptr))

    def conn_get_tls_early_data_rejected(self, conn_ptr) -> bool:
        return bool(self.lib.ngtcp2_conn_get_tls_early_data_rejected(conn_ptr))

    # --- CID accessors ---
    def conn_get_dcid_bytes(self, conn_ptr) -> bytes:
        cid_ptr = self.lib.ngtcp2_conn_get_dcid(conn_ptr)
        if cid_ptr == self.ffi.NULL or cid_ptr.datalen == 0:
            return b""
        return bytes(self.ffi.buffer(cid_ptr.data, cid_ptr.datalen))

    def conn_get_client_initial_dcid_bytes(self, conn_ptr) -> bytes:
        cid_ptr = self.lib.ngtcp2_conn_get_client_initial_dcid(conn_ptr)
        if cid_ptr == self.ffi.NULL or cid_ptr.datalen == 0:
            return b""
        return bytes(self.ffi.buffer(cid_ptr.data, cid_ptr.datalen))

    def conn_get_scids(self, conn_ptr) -> list[bytes]:
        # First query count
        count = self.lib.ngtcp2_conn_get_scid(conn_ptr, self.ffi.NULL)
        if count == 0:
            return []
        arr = self.ffi.new("ngtcp2_cid[]", count)
        wrote = self.lib.ngtcp2_conn_get_scid(conn_ptr, arr)
        result: list[bytes] = []
        for i in range(int(wrote)):
            datalen = arr[i].datalen
            if datalen:
                result.append(bytes(self.ffi.buffer(arr[i].data, datalen)))
            else:
                result.append(b"")
        return result

    # --- Path helpers ---
    def path_eq(self, path_a_ptr, path_b_ptr) -> bool:
        return bool(self.lib.ngtcp2_path_eq(path_a_ptr, path_b_ptr))

    # --- Packet header helpers ---
    def pkt_decode_version_cid(self, packet: bytes, short_dcidlen: int = 0):
        """Decode version and CIDs from raw QUIC packet bytes.
        Returns dict with keys: rc, version, dcid (bytes), scid (bytes).
        """
        dest = self.ffi.new("ngtcp2_version_cid *")
        buf = self.ffi.from_buffer(packet)
        rc = self.lib.ngtcp2_pkt_decode_version_cid(dest, buf, len(packet), short_dcidlen)
        version = int(dest.version)
        dcid = bytes(self.ffi.buffer(dest.dcid, dest.dcidlen)) if dest.dcid and dest.dcidlen else b""
        scid = bytes(self.ffi.buffer(dest.scid, dest.scidlen)) if dest.scid and dest.scidlen else b""
        return {"rc": int(rc), "version": version, "dcid": dcid, "scid": scid}

    def pkt_decode_hd_long(self, packet: bytes):
        """Decode QUIC long header. Returns dict with key fields and rc (bytes decoded or <0)."""
        hd = self.ffi.new("ngtcp2_pkt_hd *")
        buf = self.ffi.from_buffer(packet)
        rc = self.lib.ngtcp2_pkt_decode_hd_long(hd, buf, len(packet))
        return {
            "rc": int(rc),
            "version": int(hd.version),
            "type": int(hd.type),
            "flags": int(hd.flags),
            "dcid": bytes(self.ffi.buffer(hd.dcid.data, hd.dcid.datalen)),
            "scid": bytes(self.ffi.buffer(hd.scid.data, hd.scid.datalen)),
            "token": bytes(self.ffi.buffer(hd.token, hd.tokenlen)) if hd.token and hd.tokenlen else b"",
            "pkt_numlen": int(hd.pkt_numlen),
            "len": int(hd.len),
        }

    def pkt_decode_hd_short(self, packet: bytes, dcidlen: int):
        """Decode QUIC short header. Returns dict with key fields and rc (bytes decoded or <0)."""
        hd = self.ffi.new("ngtcp2_pkt_hd *")
        buf = self.ffi.from_buffer(packet)
        rc = self.lib.ngtcp2_pkt_decode_hd_short(hd, buf, len(packet), dcidlen)
        return {
            "rc": int(rc),
            "type": int(hd.type),
            "flags": int(hd.flags),
            "dcid": bytes(self.ffi.buffer(hd.dcid.data, hd.dcid.datalen)),
            "pkt_numlen": int(hd.pkt_numlen),
            "len": int(hd.len),
        } 