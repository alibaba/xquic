"""Real local runner-endpoint checks for WT glue and native regressions."""
from contextlib import contextmanager
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import unittest

import test_cli


class InteropEndpoint(unittest.TestCase):
    @contextmanager
    def server(self, transport, relay=False):
        binary = Path(test_cli.InteropCLI.binary).resolve()
        build = binary.parent.parent
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        env = os.environ.copy()
        env.pop("MOQT_TRANSPORT", None)
        process = subprocess.Popen([str(binary),
            "--relay-server" if relay else "--server", "--transport",
            transport, "--port", str(port), "--cert", str(build / "server.crt"),
            "--key", str(build / "server.key")], env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        try:
            ready, _, _ = select.select([process.stderr], [], [], 5)
            self.assertTrue(ready, "server startup did not finish")
            line = process.stderr.readline()
            self.assertIn(("relay" if relay else "endpoint")
                          + " server moqt-22 transport=" + transport,
                          line)
            yield port
        finally:
            process.terminate()
            try:
                _, errors = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                _, errors = process.communicate()
                self.fail("server failed to shut down: " + errors)
            self.assertEqual(process.returncode, 0, errors)

    def client(self, url, case, *args, **overrides):
        env = os.environ.copy()
        for name in ("RELAY_URL", "TESTCASE", "TLS_DISABLE_VERIFY", "VERBOSE",
                     "MOQT_TRANSPORT"):
            env.pop(name, None)
        env["TLS_DISABLE_VERIFY"] = "1"
        env.update(overrides)
        return subprocess.run([test_cli.InteropCLI.binary, "--relay", url, "--test",
            case, *args], env=env, text=True, capture_output=True, timeout=10)

    def test_wt_setup_and_control(self):
        with self.server("webtransport") as port:
            for case in ("setup-only", "announce-only", "subscribe-error"):
                with self.subTest(case=case):
                    result = self.client(f"https://127.0.0.1:{port}/moq?q=1",
                                         case)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("ok 1 - " + case, result.stdout)
                    self.assertIn("transport: webtransport", result.stdout)
                    self.assertIn("moqt_version: moqt-22", result.stdout)
                    self.assertIn("alpn=h3", result.stderr)

    def test_canonical_wt_uri_and_cli_transport_override(self):
        with self.server("webtransport") as port:
            result = self.client(f"moqt://127.0.0.1:{port}?q=1#local",
                "setup-only", "--transport", "webtransport",
                MOQT_TRANSPORT="quic")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("transport: webtransport", result.stdout)

    def test_certificate_rejection_is_failure(self):
        for transport, scheme in (("webtransport", "https"), ("quic", "moqt")):
            with self.subTest(transport=transport), self.server(transport) as port:
                result = self.client(f"{scheme}://127.0.0.1:{port}", "setup-only",
                                      TLS_DISABLE_VERIFY="0")
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn("not ok 1 - setup-only", result.stdout)
                self.assertNotIn("# SKIP", result.stdout)
                self.assertNotIn("SETUP ready", result.stderr)

    def test_native_setup_regression(self):
        with self.server("quic") as port:
            result = self.client(f"moqt://127.0.0.1:{port}/", "setup-only")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("transport: quic", result.stdout)

    def test_relay_routes_and_request_error_recovery(self):
        for transport, scheme in (("quic", "moqt"),
                                  ("webtransport", "https")):
            with self.subTest(transport=transport), \
                    self.server(transport, relay=True) as port:
                for case in ("namespace-discovery", "data-subgroup-basic",
                             "fetch", "join", "subscribe-error", "announce-only"):
                    result = self.client(f"{scheme}://127.0.0.1:{port}/", case)
                    self.assertEqual(result.returncode, 0,
                                     case + ": " + result.stderr)
                    self.assertIn("ok 1 - " + case, result.stdout)

    def test_origin_objects_and_unknown_track_recovery(self):
        for transport, scheme in (("quic", "moqt"),
                                  ("webtransport", "https")):
            with self.subTest(transport=transport), self.server(transport) as port:
                for case in ("moq-test-subgroup-per-group-eog",
                             "moq-test-datagram", "moq-test-extensions",
                             "subscribe-error"):
                    result = self.client(f"{scheme}://127.0.0.1:{port}/", case,
                                         "--origin")
                    self.assertEqual(result.returncode, 0,
                                     case + ": " + result.stderr)

    def test_dual_relay_and_closed_peer_reclamation(self):
        with self.server("dual", relay=True) as port:
            for index in range(66):
                scheme = "https" if index % 2 else "moqt"
                result = self.client(f"{scheme}://127.0.0.1:{port}/",
                                     "setup-only")
                self.assertEqual(result.returncode, 0, result.stderr)
            result = self.client(f"moqt://127.0.0.1:{port}/", "subscribe-error")
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_media_catalog_decode_render_and_recovery(self):
        for transport, scheme in (("quic", "moqt"),
                                  ("webtransport", "https")):
            with self.subTest(transport=transport), \
                    self.server(transport, relay=True) as port:
                for case, rejected in (
                    ("publish-subscribe-media", None),
                    ("media-catalog-error", "rejected unsupported MSF catalog"),
                    ("media-loc-error", "rejected invalid LOC Timescale"),
                ):
                    result = self.client(f"{scheme}://127.0.0.1:{port}/", case)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("MSF catalog selected Track video", result.stderr)
                    self.assertIn("displayed 3 frames", result.stderr)
                    self.assertEqual(result.stderr.count("media rendered frame"), 3)
                    if rejected:
                        self.assertIn(rejected, result.stderr)

    def test_media_decoder_failure_cannot_pass(self):
        with tempfile.TemporaryDirectory() as directory, \
                self.server("quic", relay=True) as port:
            abnormal = Path(directory) / "abnormal-decoder"
            abnormal.write_text(f"#!{sys.executable}\nimport os\n"
                                "os.write(1, b'\\x00' * 768)\n"
                                "raise SystemExit(1)\n")
            abnormal.chmod(0o755)
            for decoder, message in (
                ("/bin/false", "media decoder failed"),
                ("/nonexistent/xquic-ffmpeg", "media decoder failed"),
                ("/usr/bin/true", "media decoder returned incomplete frames"),
                (str(abnormal), "media decoder failed"),
            ):
                result = self.client(f"moqt://127.0.0.1:{port}/",
                    "publish-subscribe-media", XQC_INTEROP_FFMPEG=decoder)
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn("not ok 1 - publish-subscribe-media", result.stdout)
                self.assertIn(message, result.stderr)
                self.assertNotIn("displayed 3 frames", result.stderr)
            result = self.client(f"moqt://127.0.0.1:{port}/", "setup-only")
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
