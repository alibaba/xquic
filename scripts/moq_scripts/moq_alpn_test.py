#!/usr/bin/env python3
"""Run the demo client with explicit protocols against one dual-ALPN demo."""

from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time


SERVER_CLOSE_TIMEOUT = 5


def run(build, mode):
    work = Path(tempfile.mkdtemp(prefix="moq-demo-alpn-", dir=str(build)))
    for name in ("server.crt", "server.key"):
        shutil.copyfile(str(build / name), str(work / name))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = str(sock.getsockname()[1])
    server_bin = str(build / "moq/demo/moq_demo_server")
    client_bin = str(build / "moq/demo/moq_demo_client")
    with (work / "server.stdout").open("w") as server_log:
        server = subprocess.Popen([server_bin, "-p", port, "-r", "sub", "-l", "e"],
                                  cwd=str(work), stdout=server_log,
                                  stderr=subprocess.STDOUT)
        try:
            time.sleep(0.3)
            assert server.poll() is None, "demo server exited before connection"
            if mode == "coexist":
                expected_alpns = (("moq-quic", 1), ("moqt-22", 0))
                for version, extra in (("05", []), ("22", [])):
                    name = version + ("-fast" if extra else "")
                    client_dir = work / name
                    client_dir.mkdir()
                    cached = ("test_session", "tp_localhost", "xqc_token")
                    if version == "22":
                        for filename in cached:
                            (client_dir / filename).write_bytes(b"legacy-cache")
                    result = subprocess.run(
                        [client_bin, "-p", port, "-v", version, "-r", "pub",
                         "-n", "2", "-1", "-l", "e"] + extra,
                        cwd=str(client_dir), stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT, timeout=15)
                    output = result.stdout.decode(errors="replace")
                    (client_dir / "client.stdout").write_text(output)
                    alpn = "moqt-22" if version == "22" else (
                        "moq-fast-rtt-alpn" if extra else "moq-quic")
                    assert result.returncode == 0, (name, output)
                    marker = "handshake alpn:{} legacy_session:{}".format(
                        alpn, int(version != "22"))
                    assert output.count(marker) == 1, (name, output)
                    assert "conn_err:0," in output, (name, output)
                    if version == "22":
                        assert output.count("moqt ready:client") == 1, output
                        assert "on_server_setup" not in output, output
                        assert "on_session_setup" not in output, output
                        for filename in cached:
                            assert (client_dir / filename).read_bytes() == b"legacy-cache"
                    else:
                        assert "on_session_setup" in output, (name, output)
                # Client exit can precede the server's QUIC close timer.
                # Buffered stdout is checked again after server termination.
                deadline = time.monotonic() + SERVER_CLOSE_TIMEOUT
                while server.poll() is None and time.monotonic() < deadline:
                    output = (work / "server.stdout").read_text()
                    if all("alpn:{},".format(alpn) in output
                           for alpn, _ in expected_alpns):
                        break
                    time.sleep(0.01)
            elif mode == "setup-errors":
                result = subprocess.run(
                    [str(build / "tests/test_moqt_negotiation"), mode, port],
                    cwd=str(work), stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, timeout=10)
                (work / "setup-errors.stdout").write_bytes(result.stdout)
                assert result.returncode == 0, result.stdout
            else:
                result = subprocess.run(
                    [str(build / "tests/test_moqt_negotiation"), "reject", port],
                    cwd=str(work), stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, timeout=10)
                (work / "reject.stdout").write_bytes(result.stdout)
                assert result.returncode == 0, result.stdout
                for options, error in ((["-v", "23"], "protocol version must"),
                                       (["-v", "22", "-F", "1"], "does not support"),
                                       (["-F", "2", "-v", "22"], "does not support")):
                    result = subprocess.run([client_bin] + options, cwd=str(work),
                                            stdout=subprocess.PIPE,
                                            stderr=subprocess.STDOUT, timeout=5)
                    assert result.returncode != 0 and error.encode() in result.stdout
        finally:
            server.terminate()
            server.wait(timeout=SERVER_CLOSE_TIMEOUT)
    assert server.returncode == 0, "demo server crashed: {}".format(work)
    output = (work / "server.stdout").read_text()
    if mode == "coexist":
        for alpn, legacy in expected_alpns:
            assert output.count("handshake alpn:{} legacy_session:{}".format(
                alpn, legacy)) == 1, output
            assert "alpn:{},".format(alpn) in output, output
        assert output.count("moqt ready:server") == 1, output
        assert "on_session_setup" in output, output
        assert "video_len:" in output and "audio_len:" in output, output
    elif mode == "setup-errors":
        assert output.count("handshake alpn:moqt-22 legacy_session:0") == 6, output
        assert "moqt ready:server" not in output, output
        assert "on_session_setup" not in output, output
    else:
        assert "server_refuse" in output, output
        assert "handshake alpn:" not in output, output
        assert "on_session_setup" not in output, output
    print("demo ALPN {} passed: {}".format(mode, work))


if __name__ == "__main__":
    run(Path(sys.argv[1]).resolve(), sys.argv[2])
