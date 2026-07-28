"""
Minimal WebTransport echo server example.

Usage:
    python echo_server.py

Requires TLS certificates in certs/ directory:
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout certs/localhost.key -out certs/localhost.crt \
        -days 14 -nodes -subj "/CN=localhost"
"""

import asyncio
from pyxquic_wt import serve


async def echo_handler(session):
    """Echo all incoming bidi stream data back."""
    async for stream in session.incoming_bidirectional_streams():
        data = await stream.read_all()
        print(f"Echo: {len(data)} bytes")
        await stream.write_all(data, end_stream=True)


async def main():
    print("WebTransport echo server listening on :4443")
    async with serve(echo_handler, port=4443,
                     cert_file="certs/localhost.crt",
                     key_file="certs/localhost.key"):
        await asyncio.Future()  # run forever


if __name__ == "__main__":
    asyncio.run(main())
