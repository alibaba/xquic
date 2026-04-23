"""
Minimal WebTransport echo client example.

Usage:
    python echo_client.py

Simple mode (single bidi send+recv):
    Uses connect() context manager for one-shot echo.

Advanced mode (multi-stream):
    Uses open_connection() + session for multiple streams.
"""

import asyncio
from pyxquic_wt import connect, open_connection


async def simple_echo():
    """Simple: connect, send, receive, done."""
    async with connect("https://localhost:4443/echo") as session:
        await session.send_bidi(b"Hello WebTransport!")
        echo = await session.recv()
        print(f"Echo: {echo}")
        assert echo == b"Hello WebTransport!", "Mismatch!"
        print("Simple echo PASSED!")


async def advanced_echo():
    """Advanced: use stream objects for multi-send."""
    async with open_connection("https://localhost:4443") as conn:
        session = await conn.open_session("/echo")

        stream = await session.create_bidirectional_stream()
        await stream.write_all(b"chunk1 ", end_stream=False)
        await stream.write_all(b"chunk2", end_stream=True)

        data = await stream.read_all()
        print(f"Multi-chunk echo: {data}")
        assert data == b"chunk1 chunk2", "Mismatch!"
        print("Advanced echo PASSED!")


async def main():
    await simple_echo()
    await advanced_echo()
    print("All echo tests PASSED!")


if __name__ == "__main__":
    asyncio.run(main())
