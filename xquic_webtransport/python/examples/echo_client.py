"""
Minimal WebTransport echo client example.

Usage:
    python echo_client.py
"""

import asyncio
from pyxquic_wt import WebTransportClient


async def main():
    async with WebTransportClient("https://localhost:4443/echo") as client:
        # Create a bidirectional stream
        stream = await client.create_bidi_stream()

        # Send a message
        message = b"Hello WebTransport from Python!"
        await stream.send(message, fin=True)
        print(f"Sent: {message}")

        # Receive the echo
        data = await stream.recv()
        print(f"Received: {data}")

        assert data == message, "Echo mismatch!"
        print("Echo test PASSED!")


if __name__ == "__main__":
    asyncio.run(main())
