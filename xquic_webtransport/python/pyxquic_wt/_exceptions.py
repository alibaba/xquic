"""WebTransport exception hierarchy."""


class WebTransportError(Exception):
    """Base exception for all WebTransport errors."""


class QuicConnectionError(WebTransportError):
    """QUIC connection failed or was lost."""


class SessionClosedError(WebTransportError):
    """Session was closed (locally or by peer)."""

    def __init__(self, error_code: int = 0, reason: str = ""):
        self.error_code = error_code
        self.reason = reason
        msg = f"session closed (code={error_code})"
        if reason:
            msg += f": {reason}"
        super().__init__(msg)


class StreamResetError(WebTransportError):
    """Stream was reset by peer (RESET_STREAM)."""

    def __init__(self, error_code: int = 0):
        self.error_code = error_code
        super().__init__(f"stream reset (code={error_code})")


class StreamStopError(WebTransportError):
    """Peer sent STOP_SENDING on this stream."""

    def __init__(self, error_code: int = 0):
        self.error_code = error_code
        super().__init__(f"stop sending (code={error_code})")


class HandshakeError(WebTransportError):
    """TLS/QUIC handshake failed."""


class SessionRejectedError(WebTransportError):
    """Server rejected the session (e.g. path not found)."""

    def __init__(self, status_code: int = 0):
        self.status_code = status_code
        super().__init__(f"session rejected (status={status_code})")
