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
from pyxquic_wt import WebTransportServer


async def handle_session(session):
    print(f"New session: path={session.path}")

    async for stream in session.incoming_bidi_streams():
        data = await stream.recv()
        print(f"Received: {data}")
        await stream.send(data)  # echo back
        await stream.close()


async def main():
    server = WebTransportServer(
        host="0.0.0.0",
        port=4443,
        cert_file="certs/localhost.crt",
        key_file="certs/localhost.key",
    )
    server.on_session = handle_session
    print("WebTransport echo server listening on :4443")
    await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
