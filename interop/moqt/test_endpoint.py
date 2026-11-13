"""Real local runner-endpoint checks for WT glue and native regressions."""
from contextlib import contextmanager
import os
from pathlib import Path
import select
import socket
import subprocess
import unittest

import test_cli


class InteropEndpoint(unittest.TestCase):
    @contextmanager
    def server(self, transport):
        binary = Path(test_cli.InteropCLI.binary).resolve()
        build = binary.parent.parent
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        env = os.environ.copy()
        env.pop("MOQT_TRANSPORT", None)
        process = subprocess.Popen([str(binary), "--server", "--transport",
            transport, "--port", str(port), "--cert", str(build / "server.crt"),
            "--key", str(build / "server.key")], env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        try:
            ready, _, _ = select.select([process.stderr], [], [], 5)
            self.assertTrue(ready, "server startup did not finish")
            line = process.stderr.readline()
            self.assertIn("endpoint server moqt-22 transport=" + transport,
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


if __name__ == "__main__":
    unittest.main()
