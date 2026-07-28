"""
Default configuration values for pyxquic-wt.

Centralised so they can be imported by _client.py, _server.py, _stream.py,
and overridden by users in a single place.
"""

# Network
DEFAULT_PORT = 4443
UDP_RECV_BUF_SIZE = 1500          # max UDP datagram read size

# Polling
POLL_INTERVAL_SEC = 0.02          # 20 ms event-loop tick (active streams)
POLL_IDLE_INTERVAL_SEC = 0.2      # 200 ms tick when no active streams

# Timeouts (seconds)
HANDSHAKE_TIMEOUT = 10.0          # QUIC handshake
SESSION_OPEN_TIMEOUT = 10.0       # wait for session creation after open_session()
STREAM_READ_TIMEOUT = 10.0        # default for read_all() / recv()
STREAM_ITER_TIMEOUT = 5.0         # per-chunk timeout in __anext__
INCOMING_STREAM_TIMEOUT = 1.0     # poll interval for incoming_*_streams()
SERVER_READ_TIMEOUT = 30.0        # server-side read_all() default

# TLS (default paths for development / testing)
DEFAULT_CERT_FILE = "certs/localhost.crt"
DEFAULT_KEY_FILE = "certs/localhost.key"
