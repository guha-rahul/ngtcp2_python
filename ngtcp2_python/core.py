"""
Core ngtcp2 Python bindings
"""

try:
    from ._ngtcp2_cffi import lib, ffi
except ImportError:
    # FFI not built yet
    lib = None
    ffi = None


class NGTCP2Error(Exception):
    """Base exception for ngtcp2 errors"""
    def __init__(self, error_code, message=None):
        self.error_code = error_code
        if message is None and lib is not None:
            error_str = lib.ngtcp2_strerror(error_code)
            if error_str != ffi.NULL:
                message = ffi.string(error_str).decode('utf-8')
            else:
                message = f"Unknown ngtcp2 error: {error_code}"
        super().__init__(message)


class NGTCP2ConnectionID:
    """Wrapper for ngtcp2_cid structure"""
    
    def __init__(self, ffi_obj, data=None):
        self.ffi = ffi_obj
        self._cid = self.ffi.new("ngtcp2_cid *")
        
        if data is not None:
            if isinstance(data, str):
                data = data.encode('utf-8')
            lib.ngtcp2_cid_init(self._cid, data, len(data))
        else:
            # Generate random CID if no data provided
            import os
            random_data = os.urandom(8)  # 8 bytes random CID
            lib.ngtcp2_cid_init(self._cid, random_data, len(random_data))
    
    def __eq__(self, other):
        if not isinstance(other, NGTCP2ConnectionID):
            return False
        return bool(lib.ngtcp2_cid_eq(self._cid, other._cid))
    
    def get_data(self):
        """Get the raw CID data as bytes"""
        return self.ffi.buffer(self._cid.data, self._cid.datalen)[:]
    
    def get_length(self):
        """Get the length of the CID"""
        return self._cid.datalen
    
    def __repr__(self):
        data = self.get_data()
        return f"NGTCP2ConnectionID({data.hex()})"
    
    @classmethod
    def from_ffi(cls, ffi_obj, cid_ptr):
        """Create a ConnectionID from an existing FFI pointer"""
        instance = cls.__new__(cls)
        instance.ffi = ffi_obj
        instance._cid = cid_ptr
        return instance


class NGTCP2PacketHeader:
    """Wrapper for ngtcp2_pkt_hd structure"""
    
    def __init__(self, ffi_obj):
        self.ffi = ffi_obj
        self._hd = self.ffi.new("ngtcp2_pkt_hd *")
    
    @property
    def dcid(self):
        """Destination Connection ID"""
        return NGTCP2ConnectionID.from_ffi(self.ffi, self._hd.dcid)
    
    @property
    def scid(self):
        """Source Connection ID"""
        return NGTCP2ConnectionID.from_ffi(self.ffi, self._hd.scid)
    
    @property
    def packet_number(self):
        """Packet number"""
        return self._hd.pkt_num
    
    @property
    def version(self):
        """QUIC version"""
        return self._hd.version
    
    @property
    def packet_type(self):
        """Packet type"""
        return self._hd.type
    
    @property
    def token(self):
        """Token data (if present)"""
        if self._hd.token == self.ffi.NULL:
            return None
        return self.ffi.buffer(self._hd.token, self._hd.tokenlen)[:]
    
    def __repr__(self):
        return (f"NGTCP2PacketHeader(type={self.packet_type}, "
                f"version=0x{self.version:08x}, pkt_num={self.packet_number})")


class NGTCP2VersionCID:
    """Wrapper for ngtcp2_version_cid structure"""
    
    def __init__(self, ffi_obj):
        self.ffi = ffi_obj
        self._vcid = self.ffi.new("ngtcp2_version_cid *")
    
    @property
    def version(self):
        """QUIC version"""
        return self._vcid.version
    
    @property
    def dcid(self):
        """Destination Connection ID"""
        if self._vcid.dcid == self.ffi.NULL:
            return None
        return self.ffi.buffer(self._vcid.dcid, self._vcid.dcidlen)[:]
    
    @property
    def scid(self):
        """Source Connection ID"""
        if self._vcid.scid == self.ffi.NULL:
            return None
        return self.ffi.buffer(self._vcid.scid, self._vcid.scidlen)[:]
    
    def __repr__(self):
        return f"NGTCP2VersionCID(version=0x{self.version:08x})"


class NGTCP2ConnectionInfo:
    """Wrapper for ngtcp2_conn_info structure"""
    
    def __init__(self, ffi_obj):
        self.ffi = ffi_obj
        self._info = self.ffi.new("ngtcp2_conn_info *")
    
    @property
    def latest_rtt(self):
        """Latest RTT sample"""
        return self._info.latest_rtt
    
    @property
    def min_rtt(self):
        """Minimum RTT observed"""
        return self._info.min_rtt
    
    @property
    def smoothed_rtt(self):
        """Smoothed RTT"""
        return self._info.smoothed_rtt
    
    @property
    def rtt_variance(self):
        """RTT variance"""
        return self._info.rttvar
    
    @property
    def congestion_window(self):
        """Congestion window size"""
        return self._info.cwnd
    
    @property
    def slow_start_threshold(self):
        """Slow start threshold"""
        return self._info.ssthresh
    
    @property
    def bytes_in_flight(self):
        """Bytes in flight"""
        return self._info.bytes_in_flight
    
    def __repr__(self):
        return (f"NGTCP2ConnectionInfo(rtt={self.smoothed_rtt}, "
                f"cwnd={self.congestion_window}, in_flight={self.bytes_in_flight})")


class NGTCP2ConnectionCloseError:
    """Wrapper for ngtcp2_ccerr structure"""
    
    def __init__(self, ffi_obj):
        self.ffi = ffi_obj
        self._ccerr = self.ffi.new("ngtcp2_ccerr *")
        lib.ngtcp2_ccerr_default(self._ccerr)
    
    def set_transport_error(self, error_code, reason=None):
        """Set as transport error"""
        reason_data = None
        reason_len = 0
        if reason:
            if isinstance(reason, str):
                reason = reason.encode('utf-8')
            reason_data = reason
            reason_len = len(reason)
        
        lib.ngtcp2_ccerr_set_transport_error(self._ccerr, error_code, reason_data, reason_len)
    
    def set_application_error(self, error_code, reason=None):
        """Set as application error"""
        reason_data = None
        reason_len = 0
        if reason:
            if isinstance(reason, str):
                reason = reason.encode('utf-8')
            reason_data = reason
            reason_len = len(reason)
        
        lib.ngtcp2_ccerr_set_application_error(self._ccerr, error_code, reason_data, reason_len)
    
    def set_liberr(self, liberr, reason=None):
        """Set from ngtcp2 library error"""
        reason_data = None
        reason_len = 0
        if reason:
            if isinstance(reason, str):
                reason = reason.encode('utf-8')
            reason_data = reason
            reason_len = len(reason)
        
        lib.ngtcp2_ccerr_set_liberr(self._ccerr, liberr, reason_data, reason_len)
    
    @property
    def error_type(self):
        """Error type"""
        return self._ccerr.type
    
    @property
    def error_code(self):
        """Error code"""
        return self._ccerr.error_code
    
    @property
    def frame_type(self):
        """Frame type that caused the error"""
        return self._ccerr.frame_type
    
    @property
    def reason(self):
        """Reason phrase"""
        if self._ccerr.reason == self.ffi.NULL:
            return None
        return self.ffi.buffer(self._ccerr.reason, self._ccerr.reasonlen)[:].decode('utf-8', errors='ignore')
    
    def __repr__(self):
        return f"NGTCP2ConnectionCloseError(type={self.error_type}, code={self.error_code})"


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
    
    # Connection ID functions
    def create_cid(self, data=None):
        """
        Create a new Connection ID
        
        Args:
            data: Optional bytes data for the CID
            
        Returns:
            NGTCP2ConnectionID object
        """
        return NGTCP2ConnectionID(self.ffi, data)
    
    def compare_cids(self, cid1, cid2):
        """
        Compare two Connection IDs
        
        Args:
            cid1: First Connection ID
            cid2: Second Connection ID
            
        Returns:
            bool: True if CIDs are equal, False otherwise
        """
        if isinstance(cid1, NGTCP2ConnectionID) and isinstance(cid2, NGTCP2ConnectionID):
            return cid1 == cid2
        return bool(self.lib.ngtcp2_cid_eq(cid1, cid2))
    
    # Error handling functions
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
    
    def infer_quic_transport_error_code(self, liberr):
        """
        Infer QUIC transport error code from ngtcp2 library error
        
        Args:
            liberr: ngtcp2 library error code
            
        Returns:
            int: QUIC transport error code
        """
        return self.lib.ngtcp2_err_infer_quic_transport_error_code(liberr)
    
    # Version functions
    def select_version(self, preferred_versions, offered_versions):
        """
        Select a QUIC version from preferred and offered versions
        
        Args:
            preferred_versions: List of preferred version numbers
            offered_versions: List of offered version numbers
            
        Returns:
            int: Selected version, or 0 if no common version
        """
        preferred_array = self.ffi.new("uint32_t[]", preferred_versions)
        offered_array = self.ffi.new("uint32_t[]", offered_versions)
        
        return self.lib.ngtcp2_select_version(
            preferred_array, len(preferred_versions),
            offered_array, len(offered_versions)
        )
    
    def is_supported_version(self, version):
        """
        Check if a QUIC version is supported
        
        Args:
            version: QUIC version number
            
        Returns:
            bool: True if supported, False otherwise
        """
        return bool(self.lib.ngtcp2_is_supported_version(version))
    
    def is_reserved_version(self, version):
        """
        Check if a QUIC version number is reserved
        
        Args:
            version: QUIC version number
            
        Returns:
            bool: True if reserved, False otherwise
        """
        return bool(self.lib.ngtcp2_is_reserved_version(version))
    
    # Packet functions
    def decode_version_cid(self, packet_data, short_dcidlen=8):
        """
        Decode version and connection IDs from packet
        
        Args:
            packet_data: Raw packet data (bytes)
            short_dcidlen: Length of destination CID for short packets
            
        Returns:
            NGTCP2VersionCID object or None if decoding failed
        """
        vcid = NGTCP2VersionCID(self.ffi)
        result = self.lib.ngtcp2_pkt_decode_version_cid(
            vcid._vcid, packet_data, len(packet_data), short_dcidlen
        )
        if result == 0:
            return vcid
        return None
    
    def decode_long_header(self, packet_data):
        """
        Decode long packet header
        
        Args:
            packet_data: Raw packet data (bytes)
            
        Returns:
            tuple: (NGTCP2PacketHeader, bytes_consumed) or (None, 0) if failed
        """
        hd = NGTCP2PacketHeader(self.ffi)
        result = self.lib.ngtcp2_pkt_decode_hd_long(hd._hd, packet_data, len(packet_data))
        if result > 0:
            return hd, result
        return None, 0
    
    def decode_short_header(self, packet_data, dcidlen):
        """
        Decode short packet header
        
        Args:
            packet_data: Raw packet data (bytes)
            dcidlen: Length of destination Connection ID
            
        Returns:
            tuple: (NGTCP2PacketHeader, bytes_consumed) or (None, 0) if failed
        """
        hd = NGTCP2PacketHeader(self.ffi)
        result = self.lib.ngtcp2_pkt_decode_hd_short(hd._hd, packet_data, len(packet_data), dcidlen)
        if result > 0:
            return hd, result
        return None, 0
    
    def write_stateless_reset(self, stateless_reset_token, random_data, dest_size=1200):
        """
        Write a stateless reset packet
        
        Args:
            stateless_reset_token: 16-byte stateless reset token
            random_data: Random data for the packet
            dest_size: Size of destination buffer
            
        Returns:
            bytes: Stateless reset packet or None if failed
        """
        dest = self.ffi.new("uint8_t[]", dest_size)
        result = self.lib.ngtcp2_pkt_write_stateless_reset(
            dest, dest_size, stateless_reset_token, random_data, len(random_data)
        )
        if result > 0:
            return self.ffi.buffer(dest, result)[:]
        return None
    
    def write_version_negotiation(self, dcid, scid, supported_versions, dest_size=1200):
        """
        Write a version negotiation packet
        
        Args:
            dcid: Destination Connection ID (bytes)
            scid: Source Connection ID (bytes)
            supported_versions: List of supported version numbers
            dest_size: Size of destination buffer
            
        Returns:
            bytes: Version negotiation packet or None if failed
        """
        dest = self.ffi.new("uint8_t[]", dest_size)
        versions_array = self.ffi.new("uint32_t[]", supported_versions)
        
        result = self.lib.ngtcp2_pkt_write_version_negotiation(
            dest, dest_size, 0x80,  # unused_random
            dcid, len(dcid), scid, len(scid),
            versions_array, len(supported_versions)
        )
        if result > 0:
            return self.ffi.buffer(dest, result)[:]
        return None
    
    def accept_packet(self, packet_data):
        """
        Check if a packet should be accepted by a server
        
        Args:
            packet_data: Raw packet data (bytes)
            
        Returns:
            NGTCP2PacketHeader or None if packet should not be accepted
        """
        hd = NGTCP2PacketHeader(self.ffi)
        result = self.lib.ngtcp2_accept(hd._hd, packet_data, len(packet_data))
        if result == 0:
            return hd
        return None
    
    # Stream functions
    def is_bidi_stream(self, stream_id):
        """
        Check if a stream ID represents a bidirectional stream
        
        Args:
            stream_id: Stream ID
            
        Returns:
            bool: True if bidirectional, False if unidirectional
        """
        return bool(self.lib.ngtcp2_is_bidi_stream(stream_id))
    
    # Connection close error functions
    def create_connection_close_error(self):
        """
        Create a new connection close error object
        
        Returns:
            NGTCP2ConnectionCloseError object
        """
        return NGTCP2ConnectionCloseError(self.ffi)
    
    # Advanced feature functions
    def create_transport_params(self):
        """
        Create a new transport parameters object
        
        Returns:
            NGTCP2TransportParams object
        """
        return NGTCP2TransportParams(self.ffi)
    
    def create_settings(self):
        """
        Create a new settings object
        
        Returns:
            NGTCP2Settings object
        """
        return NGTCP2Settings(self.ffi)
    
    def create_crypto_context(self):
        """
        Create a new crypto context object
        
        Returns:
            NGTCP2CryptoContext object
        """
        return NGTCP2CryptoContext(self.ffi)
    
    # Crypto utility functions
    def crypto_hkdf_extract(self, md_handle, secret, salt):
        """
        Perform HKDF extract operation
        
        Args:
            md_handle: Message digest handle
            secret: Secret key bytes
            salt: Salt bytes
        
        Returns:
            Extracted key bytes
        """
        if not self.lib:
            raise RuntimeError("ngtcp2 library not available")
        
        # Create crypto MD structure
        md = self.ffi.new("ngtcp2_crypto_md *")
        self.lib.ngtcp2_crypto_md_init(md, md_handle)
        
        # Get hash length
        hash_len = self.lib.ngtcp2_crypto_md_hashlen(md)
        
        # Allocate output buffer
        output = self.ffi.new("uint8_t[]", hash_len)
        
        result = self.lib.ngtcp2_crypto_hkdf_extract(
            output, md, secret, len(secret), salt, len(salt)
        )
        
        if result != 0:
            raise NGTCP2Error(result, "HKDF extract failed")
        
        return self.ffi.buffer(output, hash_len)[:]
    
    def crypto_hkdf_expand(self, md_handle, prk, info, length):
        """
        Perform HKDF expand operation
        
        Args:
            md_handle: Message digest handle
            prk: Pseudo-random key bytes
            info: Info bytes
            length: Output length
        
        Returns:
            Expanded key bytes
        """
        if not self.lib:
            raise RuntimeError("ngtcp2 library not available")
        
        # Create crypto MD structure
        md = self.ffi.new("ngtcp2_crypto_md *")
        self.lib.ngtcp2_crypto_md_init(md, md_handle)
        
        # Allocate output buffer
        output = self.ffi.new("uint8_t[]", length)
        
        result = self.lib.ngtcp2_crypto_hkdf_expand(
            output, length, md, prk, len(prk), info, len(info)
        )
        
        if result != 0:
            raise NGTCP2Error(result, "HKDF expand failed")
        
        return self.ffi.buffer(output, length)[:]
    
    def crypto_hkdf(self, md_handle, secret, salt, info, length):
        """
        Perform HKDF operation (extract + expand)
        
        Args:
            md_handle: Message digest handle
            secret: Secret key bytes
            salt: Salt bytes
            info: Info bytes
            length: Output length
        
        Returns:
            Derived key bytes
        """
        if not self.lib:
            raise RuntimeError("ngtcp2 library not available")
        
        # Create crypto MD structure
        md = self.ffi.new("ngtcp2_crypto_md *")
        self.lib.ngtcp2_crypto_md_init(md, md_handle)
        
        # Allocate output buffer
        output = self.ffi.new("uint8_t[]", length)
        
        result = self.lib.ngtcp2_crypto_hkdf(
            output, length, md, secret, len(secret), salt, len(salt), info, len(info)
        )
        
        if result != 0:
            raise NGTCP2Error(result, "HKDF failed")
        
        return self.ffi.buffer(output, length)[:]
    
    def crypto_generate_stateless_reset_token(self, aead_handle, aead_ctx_handle, cid):
        """
        Generate stateless reset token
        
        Args:
            aead_handle: AEAD handle
            aead_ctx_handle: AEAD context handle
            cid: Connection ID object
        
        Returns:
            Stateless reset token bytes
        """
        if not self.lib:
            raise RuntimeError("ngtcp2 library not available")
        
        # Create crypto AEAD structures
        aead = self.ffi.new("ngtcp2_crypto_aead *")
        aead.native_handle = aead_handle
        
        aead_ctx = self.ffi.new("ngtcp2_crypto_aead_ctx *")
        aead_ctx.native_handle = aead_ctx_handle
        
        # Allocate token buffer
        token = self.ffi.new("uint8_t[]", self.constants.STATELESS_RESET_TOKENLEN)
        
        result = self.lib.ngtcp2_crypto_generate_stateless_reset_token(
            token, aead, aead_ctx, cid._cid
        )
        
        if result < 0:
            raise NGTCP2Error(result, "Failed to generate stateless reset token")
        
        return self.ffi.buffer(token, self.constants.STATELESS_RESET_TOKENLEN)[:]
    
    def crypto_write_connection_close(self, version, dcid, scid, error_code, reason=None):
        """
        Write connection close packet with crypto
        
        Args:
            version: QUIC version
            dcid: Destination connection ID bytes
            scid: Source connection ID bytes
            error_code: Error code
            reason: Optional reason string
        
        Returns:
            Connection close packet bytes
        """
        if not self.lib:
            raise RuntimeError("ngtcp2 library not available")
        
        # Create connection IDs
        dcid_obj = self.create_cid(dcid)
        scid_obj = self.create_cid(scid)
        
        # Allocate buffer for the packet
        buffer_size = 1200
        buffer = self.ffi.new("uint8_t[]", buffer_size)
        
        if reason is None:
            reason_ptr = self.ffi.NULL
            reason_len = 0
        else:
            if isinstance(reason, str):
                reason = reason.encode('utf-8')
            reason_ptr = reason
            reason_len = len(reason)
        
        result = self.lib.ngtcp2_crypto_write_connection_close(
            buffer, buffer_size, version, dcid_obj._cid, scid_obj._cid,
            error_code, reason_ptr, reason_len
        )
        
        if result < 0:
            raise NGTCP2Error(result, "Failed to write connection close packet")
        
        return self.ffi.buffer(buffer, result)[:]
    
    def crypto_write_retry(self, version, dcid, scid, odcid, token):
        """
        Write retry packet with crypto
        
        Args:
            version: QUIC version
            dcid: Destination connection ID bytes
            scid: Source connection ID bytes
            odcid: Original destination connection ID bytes
            token: Retry token bytes
        
        Returns:
            Retry packet bytes
        """
        if not self.lib:
            raise RuntimeError("ngtcp2 library not available")
        
        # Create connection IDs
        dcid_obj = self.create_cid(dcid)
        scid_obj = self.create_cid(scid)
        odcid_obj = self.create_cid(odcid)
        
        # Allocate buffer for the packet
        buffer_size = 1200
        buffer = self.ffi.new("uint8_t[]", buffer_size)
        
        if isinstance(token, str):
            token = token.encode('utf-8')
        
        result = self.lib.ngtcp2_crypto_write_retry(
            buffer, buffer_size, version, dcid_obj._cid, scid_obj._cid,
            odcid_obj._cid, token, len(token)
        )
        
        if result < 0:
            raise NGTCP2Error(result, "Failed to write retry packet")
        
        return self.ffi.buffer(buffer, result)[:]
    
    @property
    def constants(self):
        """Get access to ngtcp2 constants"""
        return NGTCP2Constants()


class NGTCP2TransportParams:
    """Wrapper for ngtcp2_transport_params structure"""
    
    def __init__(self, ffi_obj):
        self.ffi = ffi_obj
        self._params = self.ffi.new("ngtcp2_transport_params *")
        # Initialize with default values
        if lib:
            lib.ngtcp2_transport_params_default_versioned(
                lib.NGTCP2_TRANSPORT_PARAMS_VERSION,
                self._params
            )
    
    @property
    def initial_max_stream_data_bidi_local(self):
        """Initial max stream data for bidirectional local streams"""
        return self._params.initial_max_stream_data_bidi_local
    
    @initial_max_stream_data_bidi_local.setter
    def initial_max_stream_data_bidi_local(self, value):
        self._params.initial_max_stream_data_bidi_local = value
    
    @property
    def initial_max_stream_data_bidi_remote(self):
        """Initial max stream data for bidirectional remote streams"""
        return self._params.initial_max_stream_data_bidi_remote
    
    @initial_max_stream_data_bidi_remote.setter
    def initial_max_stream_data_bidi_remote(self, value):
        self._params.initial_max_stream_data_bidi_remote = value
    
    @property
    def initial_max_stream_data_uni(self):
        """Initial max stream data for unidirectional streams"""
        return self._params.initial_max_stream_data_uni
    
    @initial_max_stream_data_uni.setter
    def initial_max_stream_data_uni(self, value):
        self._params.initial_max_stream_data_uni = value
    
    @property
    def initial_max_data(self):
        """Initial max data for the connection"""
        return self._params.initial_max_data
    
    @initial_max_data.setter
    def initial_max_data(self, value):
        self._params.initial_max_data = value
    
    @property
    def initial_max_streams_bidi(self):
        """Initial max bidirectional streams"""
        return self._params.initial_max_streams_bidi
    
    @initial_max_streams_bidi.setter
    def initial_max_streams_bidi(self, value):
        self._params.initial_max_streams_bidi = value
    
    @property
    def initial_max_streams_uni(self):
        """Initial max unidirectional streams"""
        return self._params.initial_max_streams_uni
    
    @initial_max_streams_uni.setter
    def initial_max_streams_uni(self, value):
        self._params.initial_max_streams_uni = value
    
    @property
    def max_idle_timeout(self):
        """Max idle timeout in nanoseconds"""
        return self._params.max_idle_timeout
    
    @max_idle_timeout.setter
    def max_idle_timeout(self, value):
        self._params.max_idle_timeout = value
    
    @property
    def max_udp_payload_size(self):
        """Max UDP payload size"""
        return self._params.max_udp_payload_size
    
    @max_udp_payload_size.setter
    def max_udp_payload_size(self, value):
        self._params.max_udp_payload_size = value
    
    @property
    def active_connection_id_limit(self):
        """Active connection ID limit"""
        return self._params.active_connection_id_limit
    
    @active_connection_id_limit.setter
    def active_connection_id_limit(self, value):
        self._params.active_connection_id_limit = value
    
    @property
    def ack_delay_exponent(self):
        """ACK delay exponent"""
        return self._params.ack_delay_exponent
    
    @ack_delay_exponent.setter
    def ack_delay_exponent(self, value):
        self._params.ack_delay_exponent = value
    
    @property
    def max_ack_delay(self):
        """Max ACK delay in nanoseconds"""
        return self._params.max_ack_delay
    
    @max_ack_delay.setter
    def max_ack_delay(self, value):
        self._params.max_ack_delay = value
    
    @property
    def max_datagram_frame_size(self):
        """Max datagram frame size"""
        return self._params.max_datagram_frame_size
    
    @max_datagram_frame_size.setter
    def max_datagram_frame_size(self, value):
        self._params.max_datagram_frame_size = value
    
    @property
    def disable_active_migration(self):
        """Whether active migration is disabled"""
        return bool(self._params.disable_active_migration)
    
    @disable_active_migration.setter
    def disable_active_migration(self, value):
        self._params.disable_active_migration = int(value)
    
    @property
    def grease_quic_bit(self):
        """Whether QUIC bit greasing is enabled"""
        return bool(self._params.grease_quic_bit)
    
    @grease_quic_bit.setter
    def grease_quic_bit(self, value):
        self._params.grease_quic_bit = int(value)
    
    def encode(self):
        """Encode transport parameters to bytes"""
        if not lib:
            raise RuntimeError("ngtcp2 library not available")
        
        # Allocate a buffer for encoding
        buffer_size = 1024  # Should be enough for most transport parameters
        buffer = self.ffi.new("uint8_t[]", buffer_size)
        
        result = lib.ngtcp2_transport_params_encode_versioned(
            buffer, buffer_size, lib.NGTCP2_TRANSPORT_PARAMS_VERSION, self._params
        )
        
        if result < 0:
            raise NGTCP2Error(result, "Failed to encode transport parameters")
        
        return self.ffi.buffer(buffer, result)[:]
    
    @classmethod
    def decode(cls, ffi_obj, data):
        """Decode transport parameters from bytes"""
        if not lib:
            raise RuntimeError("ngtcp2 library not available")
        
        params = cls(ffi_obj)
        
        result = lib.ngtcp2_transport_params_decode_versioned(
            lib.NGTCP2_TRANSPORT_PARAMS_VERSION,
            params._params,
            data,
            len(data)
        )
        
        if result != 0:
            raise NGTCP2Error(result, "Failed to decode transport parameters")
        
        return params
    
    def __repr__(self):
        return (
            f"NGTCP2TransportParams("
            f"initial_max_data={self.initial_max_data}, "
            f"initial_max_streams_bidi={self.initial_max_streams_bidi}, "
            f"initial_max_streams_uni={self.initial_max_streams_uni}, "
            f"max_idle_timeout={self.max_idle_timeout})"
        )


class NGTCP2Settings:
    """Wrapper for ngtcp2_settings structure"""
    
    def __init__(self, ffi_obj):
        self.ffi = ffi_obj
        self._settings = self.ffi.new("ngtcp2_settings *")
        # Initialize with default values
        if lib:
            lib.ngtcp2_settings_default_versioned(
                lib.NGTCP2_SETTINGS_VERSION,
                self._settings
            )
    
    @property
    def cc_algo(self):
        """Congestion control algorithm"""
        return self._settings.cc_algo
    
    @cc_algo.setter
    def cc_algo(self, value):
        self._settings.cc_algo = value
    
    @property
    def initial_ts(self):
        """Initial timestamp"""
        return self._settings.initial_ts
    
    @initial_ts.setter
    def initial_ts(self, value):
        self._settings.initial_ts = value
    
    @property
    def initial_rtt(self):
        """Initial RTT in nanoseconds"""
        return self._settings.initial_rtt
    
    @initial_rtt.setter
    def initial_rtt(self, value):
        self._settings.initial_rtt = value
    
    @property
    def max_tx_udp_payload_size(self):
        """Maximum transmit UDP payload size"""
        return self._settings.max_tx_udp_payload_size
    
    @max_tx_udp_payload_size.setter
    def max_tx_udp_payload_size(self, value):
        self._settings.max_tx_udp_payload_size = value
    
    @property
    def token_type(self):
        """Token type"""
        return self._settings.token_type
    
    @token_type.setter
    def token_type(self, value):
        self._settings.token_type = value
    
    @property
    def max_window(self):
        """Maximum connection-level flow control window"""
        return self._settings.max_window
    
    @max_window.setter
    def max_window(self, value):
        self._settings.max_window = value
    
    @property
    def max_stream_window(self):
        """Maximum stream-level flow control window"""
        return self._settings.max_stream_window
    
    @max_stream_window.setter
    def max_stream_window(self, value):
        self._settings.max_stream_window = value
    
    @property
    def ack_thresh(self):
        """ACK threshold"""
        return self._settings.ack_thresh
    
    @ack_thresh.setter
    def ack_thresh(self, value):
        self._settings.ack_thresh = value
    
    @property
    def no_tx_udp_payload_size_shaping(self):
        """Whether to disable UDP payload size shaping"""
        return bool(self._settings.no_tx_udp_payload_size_shaping)
    
    @no_tx_udp_payload_size_shaping.setter
    def no_tx_udp_payload_size_shaping(self, value):
        self._settings.no_tx_udp_payload_size_shaping = int(value)
    
    @property
    def handshake_timeout(self):
        """Handshake timeout in nanoseconds"""
        return self._settings.handshake_timeout
    
    @handshake_timeout.setter
    def handshake_timeout(self, value):
        self._settings.handshake_timeout = value
    
    @property
    def original_version(self):
        """Original QUIC version"""
        return self._settings.original_version
    
    @original_version.setter
    def original_version(self, value):
        self._settings.original_version = value
    
    @property
    def no_pmtud(self):
        """Whether to disable Path MTU Discovery"""
        return bool(self._settings.no_pmtud)
    
    @no_pmtud.setter
    def no_pmtud(self, value):
        self._settings.no_pmtud = int(value)
    
    @property
    def initial_pkt_num(self):
        """Initial packet number"""
        return self._settings.initial_pkt_num
    
    @initial_pkt_num.setter
    def initial_pkt_num(self, value):
        self._settings.initial_pkt_num = value
    
    def __repr__(self):
        return (
            f"NGTCP2Settings("
            f"cc_algo={self.cc_algo}, "
            f"initial_rtt={self.initial_rtt}, "
            f"max_tx_udp_payload_size={self.max_tx_udp_payload_size}, "
            f"handshake_timeout={self.handshake_timeout})"
        )


class NGTCP2CryptoContext:
    """Wrapper for ngtcp2_crypto_ctx structure"""
    
    def __init__(self, ffi_obj):
        self.ffi = ffi_obj
        self._ctx = self.ffi.new("ngtcp2_crypto_ctx *")
    
    @property
    def max_encryption(self):
        """Maximum number of encryptions allowed"""
        return self._ctx.max_encryption
    
    @property
    def max_decryption_failure(self):
        """Maximum number of decryption failures allowed"""
        return self._ctx.max_decryption_failure
    
    def init_from_tls(self, tls_handle):
        """Initialize crypto context from TLS handle"""
        if not lib:
            raise RuntimeError("ngtcp2 library not available")
        
        result = lib.ngtcp2_crypto_ctx_tls(self._ctx, tls_handle)
        if result == self.ffi.NULL:
            raise NGTCP2Error(-201, "Failed to initialize crypto context from TLS")
        return result
    
    def init_from_tls_early(self, tls_handle):
        """Initialize crypto context from TLS handle for early data"""
        if not lib:
            raise RuntimeError("ngtcp2 library not available")
        
        result = lib.ngtcp2_crypto_ctx_tls_early(self._ctx, tls_handle)
        if result == self.ffi.NULL:
            raise NGTCP2Error(-201, "Failed to initialize crypto context from TLS early")
        return result
    
    def __repr__(self):
        return (
            f"NGTCP2CryptoContext("
            f"max_encryption={self.max_encryption}, "
            f"max_decryption_failure={self.max_decryption_failure})"
        )


class NGTCP2Constants:
    """Container for ngtcp2 constants"""
    
    # QUIC versions
    PROTO_VER_V1 = 0x00000001
    PROTO_VER_V2 = 0x6b3343cf
    
    # Size limits
    MAX_CIDLEN = 20
    MIN_CIDLEN = 1
    STATELESS_RESET_TOKENLEN = 16
    MAX_UDP_PAYLOAD_SIZE = 65527
    DEFAULT_ACTIVE_CONNECTION_ID_LIMIT = 2
    
    # Version constants
    TRANSPORT_PARAMS_VERSION = 1
    SETTINGS_VERSION = 2
    CONN_INFO_VERSION = 1
    
    # Basic error codes
    ERR_HANDSHAKE_TIMEOUT = -236
    ERR_VERSION_NEGOTIATION = -237
    ERR_REQUIRED_TRANSPORT_PARAM = -201
    ERR_MALFORMED_TRANSPORT_PARAM = -202
    ERR_FRAME_ENCODING = -203
    ERR_DECRYPT = -204
    ERR_ENCRYPT = -205
    ERR_PKT_NUM_EXHAUSTED = -206
    ERR_CALLBACK_FAILURE = -207
    ERR_PROTO = -208
    ERR_INVALID_ARGUMENT = -209
    ERR_INVALID_STATE = -210
    ERR_STREAM_ID_BLOCKED = -211
    ERR_STREAM_IN_USE = -212
    ERR_STREAM_DATA_BLOCKED = -213
    ERR_FLOW_CONTROL = -214
    ERR_CONNECTION_ID_LIMIT = -215
    ERR_STREAM_LIMIT = -216
    ERR_FINAL_SIZE = -217
    ERR_CRYPTO = -218
    ERR_PKT_TOO_SMALL = -219
    ERR_NOBUF = -220
    ERR_NOMEM = -221
    ERR_PATH_VALIDATION_FAILED = -222
    ERR_STREAM_NOT_FOUND = -223
    ERR_STREAM_STATE = -224
    ERR_RECV_VERSION_NEGOTIATION = -225
    ERR_CLOSING = -226
    ERR_DRAINING = -227
    ERR_TRANSPORT_PARAM = -228
    ERR_DISCARD_PKT = -229
    ERR_CONN_ID_BLOCKED = -230
    ERR_INTERNAL = -231
    ERR_CRYPTO_BUFFER_EXCEEDED = -232
    ERR_WRITE_MORE = -233
    ERR_RETRY = -234
    ERR_DROP_CONN = -235
    
    # QUIC transport error codes
    NO_ERROR = 0x00
    INTERNAL_ERROR = 0x01
    CONNECTION_REFUSED = 0x02
    FLOW_CONTROL_ERROR = 0x03
    STREAM_LIMIT_ERROR = 0x04
    STREAM_STATE_ERROR = 0x05
    FINAL_SIZE_ERROR = 0x06
    FRAME_ENCODING_ERROR = 0x07
    TRANSPORT_PARAMETER_ERROR = 0x08
    CONNECTION_ID_LIMIT_ERROR = 0x09
    PROTOCOL_VIOLATION = 0x0a
    INVALID_TOKEN = 0x0b
    APPLICATION_ERROR = 0x0c
    CRYPTO_BUFFER_EXCEEDED = 0x0d
    KEY_UPDATE_ERROR = 0x0e
    AEAD_LIMIT_REACHED = 0x0f
    NO_VIABLE_PATH = 0x10
    VERSION_NEGOTIATION_ERROR = 0x11
    
    # Crypto error codes
    CRYPTO_ERR_INTERNAL = -201
    CRYPTO_ERR_UNREADABLE_TOKEN = -202
    CRYPTO_ERR_VERIFY_TOKEN = -203
    CRYPTO_ERR_NOMEM = -501
    
    # Congestion control algorithms
    CC_ALGO_RENO = 0x00
    CC_ALGO_CUBIC = 0x01
    CC_ALGO_BBR = 0x02
    
    # Token types
    TOKEN_TYPE_UNKNOWN = 0
    TOKEN_TYPE_RETRY = 1
    TOKEN_TYPE_NEW_TOKEN = 2
    
    # Packet types
    PKT_VERSION_NEGOTIATION = 0x80
    PKT_STATELESS_RESET = 0x81
    PKT_INITIAL = 0x10
    PKT_0RTT = 0x11
    PKT_HANDSHAKE = 0x12
    PKT_RETRY = 0x13
    PKT_1RTT = 0x40
    
    # Encryption levels
    ENCRYPTION_LEVEL_INITIAL = 0
    ENCRYPTION_LEVEL_HANDSHAKE = 1
    ENCRYPTION_LEVEL_1RTT = 2
    ENCRYPTION_LEVEL_0RTT = 3
    
    # Connection close error types
    CCERR_TYPE_TRANSPORT = 0
    CCERR_TYPE_APPLICATION = 1
    CCERR_TYPE_VERSION_NEGOTIATION = 2
    CCERR_TYPE_IDLE_CLOSE = 3
    CCERR_TYPE_DROP_CONN = 4
    CCERR_TYPE_RETRY = 5


# Convenience instance for easy access
ngtcp2 = None

def get_ngtcp2():
    """Get the global ngtcp2 FFI instance"""
    global ngtcp2
    if ngtcp2 is None:
        ngtcp2 = NGTCP2FFI()
    return ngtcp2 