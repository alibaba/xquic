#!/usr/bin/env python3
"""Run the XQUIC WebTransport demo with the simulator's environment."""
import os
import re
# Run fixed simulator helpers and role-whitelisted demos without a shell.
import subprocess  # nosec B404
import sys
from urllib.parse import urlsplit


def endpoint_command(env):
    role = env.get("ROLE")
    cases = {"client": ("handshake", "transfer",
                        "transfer-unidirectional-receive",
                        "transfer-bidirectional-receive",
                        "transfer-datagram-receive"),
             "server": ("handshake", "transfer", "transfer-unidirectional-send",
                        "transfer-bidirectional-send",
                        "transfer-datagram-send")}
    if env.get("TESTCASE") not in cases.get(role, ()):
        return None
    args = [f"/usr/local/bin/demo_{role}", "-W", "-C", "-v", "16",
            "-l", "d", "-L", f"/logs/{role}.log",
            "-k", env.get("SSLKEYLOGFILE", "/logs/keys.log")]
    if role == "server":
        return args + ["-A", "-p", "443", "-T", "/certs/cert.pem",
                       "-K", "/certs/priv.key"]
    requests = env.get("REQUESTS", "").split()
    if not requests:
        raise ValueError("REQUESTS is required for the client")
    first = urlsplit(requests[0])
    endpoint = first.path.strip("/").split("/")[0]
    # Bound the shared demo's fixed-size URL fields before its C parser.
    if (first.scheme != "https" or first.query or first.fragment
            or len(first.netloc) >= 128
            or not re.fullmatch(r"[A-Za-z0-9_.-]+(?::[0-9]{1,5})?",
                                first.netloc)
            or not re.fullmatch(r"[A-Za-z0-9_.-]{1,255}", endpoint)
            or endpoint in (".", "..")):
        raise ValueError("REQUESTS needs an HTTPS host and session endpoint")
    port = first.port if first.port is not None else 443
    if port == 0:
        raise ValueError("REQUESTS port must be between 1 and 65535")
    return args + ["-U", f"https://{first.netloc}/{endpoint}", "-p", str(port),
                   "-J", "/certs/ca.pem", "-K", "45"]


def main():
    try:
        args = endpoint_command(os.environ)
        if args is None:
            return 127
        subprocess.run(["/setup.sh"], check=True)  # nosec B603
        if os.environ["ROLE"] == "client":
            subprocess.run(  # nosec B603
                ["/wait-for-it.sh", "sim:57832", "-s", "-t", "30"], check=True)
        os.execv(args[0], args)  # nosec B606
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(f"WebTransport endpoint failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
