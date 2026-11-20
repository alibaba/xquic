#!/usr/bin/env python3
"""Endpoint probe for RFC 9001 Section 8.4 (case 900).

Sends a QUIC v1 Initial packet whose ClientHello carries a non-empty
legacy_session_id (TLS middlebox compatibility mode, prohibited in QUIC)
and expects the server to answer CONNECTION_CLOSE with PROTOCOL_VIOLATION
(0x0a). Initial keys are derived from the public RFC 9001 Section 5.2 salt
and the client-chosen DCID, so no production hook is needed.

Prints "[legacy-session-id-test]|case:900|close_error:0x<code>|" on success
and exits 0; any other outcome exits 1 with a diagnostic line.
"""

import argparse
import socket
import struct
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

INITIAL_SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
DCID = bytes.fromhex("8394c8f03e515708")
MARKER = "[legacy-session-id-test]|case:900|"


def hkdf_expand_label(secret, label, length):
    full_label = b"tls13 " + label
    info = (struct.pack("!H", length) + bytes([len(full_label)])
            + full_label + b"\x00")
    return HKDFExpand(algorithm=hashes.SHA256(), length=length,
                      info=info).derive(secret)


def initial_keys(dcid, role):
    import hmac
    initial_secret = hmac.new(INITIAL_SALT_V1, dcid, "sha256").digest()
    secret = hkdf_expand_label(initial_secret, role + b" in", 32)
    return (hkdf_expand_label(secret, b"quic key", 16),
            hkdf_expand_label(secret, b"quic iv", 12),
            hkdf_expand_label(secret, b"quic hp", 16))


def hp_mask(hp_key, sample):
    enc = Cipher(algorithms.AES(hp_key), modes.ECB()).encryptor()
    return enc.update(sample) + enc.finalize()


def varint(value):
    if value < 64:
        return bytes([value])
    if value < 16384:
        return struct.pack("!H", value | 0x4000)
    if value < 1 << 30:
        return struct.pack("!I", value | 0x80000000)
    return struct.pack("!Q", value | 0xC000000000000000)


def read_varint(buf, pos):
    first = buf[pos]
    size = 1 << (first >> 6)
    value = first & 0x3F
    for i in range(1, size):
        value = (value << 8) | buf[pos + i]
    return value, pos + size


def build_client_hello(sid_len):
    # legacy_version, random, legacy_session_id (the prohibited field)
    body = b"\x03\x03" + b"\x5a" * 32 + bytes([sid_len]) + b"\xa5" * sid_len
    # cipher_suites: TLS_AES_128_GCM_SHA256; compression: null
    body += b"\x00\x02\x13\x01" + b"\x01\x00"
    # extensions: supported_versions advertising TLS 1.3 only
    sv = b"\x00\x2b" + b"\x00\x03\x02\x03\x04"
    body += struct.pack("!H", len(sv)) + sv
    return b"\x01" + struct.pack("!I", len(body))[1:] + body


def build_initial(ch, key, iv, hp):
    crypto_frame = b"\x06" + varint(0) + varint(len(ch)) + ch
    # pad the payload so the whole datagram reaches 1200 bytes
    header_fixed = 1 + 4 + 1 + len(DCID) + 1 + 0 + 1
    pn_len = 4
    payload = crypto_frame
    pad = 1200 - (header_fixed + 2 + pn_len + len(payload) + 16)
    if pad > 0:
        payload += b"\x00" * pad
    length = pn_len + len(payload) + 16
    header = (b"\xc3" + struct.pack("!I", 1)
              + bytes([len(DCID)]) + DCID + b"\x00" + b"\x00"
              + varint(length) + struct.pack("!I", 0))
    pn_offset = len(header) - pn_len
    nonce = bytes(a ^ b for a, b in zip(iv, b"\x00" * 8 + struct.pack("!I", 0)))
    ciphertext = AESGCM(key).encrypt(nonce, payload, header)
    packet = bytearray(header + ciphertext)
    sample = bytes(packet[pn_offset + 4:pn_offset + 20])
    mask = hp_mask(hp, sample)
    packet[0] ^= mask[0] & 0x0F
    for i in range(pn_len):
        packet[pn_offset + i] ^= mask[1 + i]
    return bytes(packet)


def parse_frames(plaintext):
    """Yield (frame_type, fields) for the frames we care about."""
    pos = 0
    while pos < len(plaintext):
        ftype, pos = read_varint(plaintext, pos)
        if ftype == 0x00:  # PADDING
            continue
        if ftype == 0x1c:  # CONNECTION_CLOSE (transport)
            error, pos = read_varint(plaintext, pos)
            _frame_type, pos = read_varint(plaintext, pos)
            reason_len, pos = read_varint(plaintext, pos)
            yield ftype, error
            pos += reason_len
        elif ftype == 0x02 or ftype == 0x03:  # ACK
            _largest, pos = read_varint(plaintext, pos)
            _delay, pos = read_varint(plaintext, pos)
            range_count, pos = read_varint(plaintext, pos)
            _first_range, pos = read_varint(plaintext, pos)
            for _ in range(range_count):
                _gap, pos = read_varint(plaintext, pos)
                _range, pos = read_varint(plaintext, pos)
            if ftype == 0x03:
                for _ in range(3):
                    _ecn, pos = read_varint(plaintext, pos)
        elif ftype == 0x06:  # CRYPTO
            _offset, pos = read_varint(plaintext, pos)
            clen, pos = read_varint(plaintext, pos)
            pos += clen
        else:
            # unknown frame: cannot continue parsing safely
            return


def unprotect_initial(datagram, key, iv, hp):
    """Decrypt the first Initial packet of a datagram, return plaintext."""
    pos = 0
    while pos < len(datagram):
        first = datagram[pos]
        if not first & 0x80:
            return None  # short header: no Initial keys apply
        p = pos + 1 + 4
        dcid_len = datagram[p]
        p += 1 + dcid_len
        scid_len = datagram[p]
        p += 1 + scid_len
        ptype = (first & 0x30) >> 4
        if ptype == 0:  # Initial: token field present
            _token_len, p = read_varint(datagram, p)
        elif ptype != 2:  # Handshake/0-RTT/Retry: skip or stop
            return None
        length, p = read_varint(datagram, p)
        pn_offset = p
        sample = datagram[pn_offset + 4:pn_offset + 20]
        if len(sample) < 16:
            return None
        mask = hp_mask(hp, sample)
        header = bytearray(datagram[pos:pn_offset])
        header[0] ^= mask[0] & 0x0F
        pn_len = (header[0] & 0x03) + 1
        pn_bytes = bytes(datagram[pn_offset + i] ^ mask[1 + i]
                         for i in range(pn_len))
        header += pn_bytes
        pn = int.from_bytes(pn_bytes, "big")
        nonce = bytes(a ^ b for a, b in
                      zip(iv, b"\x00" * (12 - pn_len) + pn_bytes))
        ciphertext = datagram[pn_offset + pn_len:pn_offset + length]
        try:
            return AESGCM(key).decrypt(nonce, ciphertext, bytes(header))
        except Exception:
            return None
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--timeout", type=float, default=3.0)
    args = parser.parse_args()

    cli_key, cli_iv, cli_hp = initial_keys(DCID, b"client")
    svr_key, svr_iv, svr_hp = initial_keys(DCID, b"server")

    ch = build_client_hello(32)
    packet = build_initial(ch, cli_key, cli_iv, cli_hp)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.timeout)
    try:
        sock.sendto(packet, (args.host, args.port))
        datagram, _ = sock.recvfrom(65535)
    except socket.timeout:
        print(MARKER + "no_response|")
        return 1
    finally:
        sock.close()

    plaintext = unprotect_initial(datagram, svr_key, svr_iv, svr_hp)
    if plaintext is None:
        print(MARKER + "decrypt_failed|len:%d|" % len(datagram))
        return 1
    for ftype, error in parse_frames(plaintext):
        if ftype == 0x1c:
            print(MARKER + "close_error:0x%x|" % error)
            return 0 if error == 0x0A else 1
    print(MARKER + "no_connection_close|")
    return 1


if __name__ == "__main__":
    sys.exit(main())