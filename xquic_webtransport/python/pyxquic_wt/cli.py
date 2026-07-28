"""
pyxquic-wt CLI tool.

Usage:
    pyxquic-wt gen-cert                  # self-signed localhost cert (Chrome)
    pyxquic-wt gen-cert --ca             # CA + CA-signed server cert (Safari)
    pyxquic-wt gen-cert --ca --trust     # same + add CA to macOS Keychain
    pyxquic-wt gen-cert --outdir certs/  # output to custom directory
"""

import argparse
import datetime
import ipaddress
import os
import subprocess
import sys


def _gen_cert_cryptography(args):
    """Generate certificates using the cryptography library."""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError:
        print("ERROR: 'cryptography' package required.")
        print("Install it: pip install 'pyxquic-wt[cert]'")
        sys.exit(1)

    outdir = args.outdir
    os.makedirs(outdir, exist_ok=True)

    now = datetime.datetime.now(datetime.timezone.utc)
    expire = now + datetime.timedelta(days=args.days)

    san = x509.SubjectAlternativeName([
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        x509.IPAddress(ipaddress.IPv6Address("::1")),
    ])

    if args.ca:
        # --- Generate CA ---
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pyxquic-wt CA")])
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(expire)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(ca_key, hashes.SHA256())
        )
        ca_crt_path = os.path.join(outdir, "ca.crt")
        ca_key_path = os.path.join(outdir, "ca.key")
        with open(ca_crt_path, "wb") as f:
            f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
        with open(ca_key_path, "wb") as f:
            f.write(ca_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
        print(f"  CA cert:  {ca_crt_path}")
        print(f"  CA key:   {ca_key_path}")

        # --- Generate server cert signed by CA ---
        srv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        srv_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        srv_cert = (
            x509.CertificateBuilder()
            .subject_name(srv_name)
            .issuer_name(ca_name)
            .public_key(srv_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(expire)
            .add_extension(san, critical=False)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .sign(ca_key, hashes.SHA256())
        )
        crt_path = os.path.join(outdir, "server.crt")
        key_path = os.path.join(outdir, "server.key")
        with open(crt_path, "wb") as f:
            f.write(srv_cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, "wb") as f:
            f.write(srv_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
        print(f"  Server cert: {crt_path}")
        print(f"  Server key:  {key_path}")

        # --- Trust CA in macOS Keychain ---
        if args.trust:
            if sys.platform != "darwin":
                print("  --trust is only supported on macOS")
            else:
                print(f"  Adding CA to system keychain (requires sudo)...")
                subprocess.run([
                    "sudo", "security", "add-trusted-cert",
                    "-d", "-r", "trustRoot",
                    "-k", "/Library/Keychains/System.keychain",
                    ca_crt_path,
                ])
                print("  CA trusted!")

        _print_hash(crt_path, "server.crt")

    else:
        # --- Self-signed cert (for Chrome with serverCertificateHashes) ---
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(expire)
            .add_extension(san, critical=False)
            .sign(key, hashes.SHA256())
        )
        crt_path = os.path.join(outdir, "localhost.crt")
        key_path = os.path.join(outdir, "localhost.key")
        with open(crt_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
        print(f"  Cert: {crt_path}")
        print(f"  Key:  {key_path}")
        _print_hash(crt_path, "localhost.crt")


def _print_hash(cert_path, label):
    """Print SHA-256 hash of DER-encoded certificate."""
    import base64
    import hashlib
    with open(cert_path, "rb") as f:
        pem = f.read()
    lines = pem.decode().strip().split("\n")
    der_b64 = "".join(l for l in lines if not l.startswith("-----"))
    der = base64.b64decode(der_b64)
    h = hashlib.sha256(der).hexdigest().upper()
    print(f"\n  SHA-256 hash ({label}):")
    print(f"    {h}")
    print(f"\n  Chrome serverCertificateHashes:")
    print(f'    const hashHex = "{h}";')


def cmd_gen_cert(args):
    """Generate TLS certificates for WebTransport testing."""
    print(f"Generating certificates in {args.outdir}/")
    if args.ca:
        print("  Mode: CA + CA-signed server cert (Safari compatible)")
    else:
        print("  Mode: Self-signed (Chrome with serverCertificateHashes)")
    print(f"  Validity: {args.days} days")
    print()

    _gen_cert_cryptography(args)

    print()
    if not args.ca:
        print("Usage with pyxquic-wt server:")
        print(f'  serve(handler, cert_file="{args.outdir}/localhost.crt",')
        print(f'                 key_file="{args.outdir}/localhost.key")')
        print()
        print("Chrome: enable chrome://flags/#webtransport-developer-mode")
    else:
        print("Usage with pyxquic-wt server:")
        print(f'  serve(handler, cert_file="{args.outdir}/server.crt",')
        print(f'                 key_file="{args.outdir}/server.key")')
        if not args.trust and sys.platform == "darwin":
            print()
            print("Safari: trust the CA certificate:")
            print(f"  sudo security add-trusted-cert -d -r trustRoot \\")
            print(f"    -k /Library/Keychains/System.keychain {args.outdir}/ca.crt")


def main():
    parser = argparse.ArgumentParser(
        prog="pyxquic-wt",
        description="pyxquic-wt: WebTransport tools",
    )
    sub = parser.add_subparsers(dest="command")

    # gen-cert
    cert_parser = sub.add_parser(
        "gen-cert",
        help="Generate TLS certificates for WebTransport",
    )
    cert_parser.add_argument(
        "--ca", action="store_true",
        help="Generate CA + CA-signed cert (required for Safari)",
    )
    cert_parser.add_argument(
        "--trust", action="store_true",
        help="Add CA to macOS system keychain (requires sudo)",
    )
    cert_parser.add_argument(
        "--outdir", default="certs",
        help="Output directory (default: certs/)",
    )
    cert_parser.add_argument(
        "--days", type=int, default=14,
        help="Certificate validity in days (default: 14)",
    )

    args = parser.parse_args()
    if args.command == "gen-cert":
        cmd_gen_cert(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
