"""Black-box unit checks for the runner CLI contract; no network required."""
import os
from pathlib import Path
import subprocess
import unittest


class InteropCLI(unittest.TestCase):
    binary = os.environ.get("XQC_MOQT_INTEROP", str(
        Path(__file__).resolve().parents[2]
        / "build/validation/tests/moqt_interop"))

    def run_cli(self, *args, **overrides):
        env = os.environ.copy()
        for name in ("RELAY_URL", "TESTCASE", "TLS_DISABLE_VERIFY", "VERBOSE",
                     "MOQT_TRANSPORT"):
            env.pop(name, None)
        env.update(overrides)
        return subprocess.run([self.binary, *args], env=env,
                              capture_output=True, text=True, timeout=3)

    def test_capability_discovery(self):
        result = self.run_cli("--list")
        self.assertEqual(result.returncode, 0)
        self.assertIn("setup-only", result.stdout.splitlines())
        self.assertIn("moq-test-datagram", result.stdout.splitlines())
        for name in ("publish-namespace-multi-publisher-retention",
                     "fetch", "join", "namespace-discovery"):
            self.assertIn(name, result.stdout.splitlines())
        for name in ("publish-subscribe-media", "media-catalog-error",
                     "media-loc-error"):
            self.assertIn(name, result.stdout.splitlines())
        self.assertEqual(len(result.stdout.splitlines()), 26)

    def test_origin_capabilities(self):
        result = self.run_cli("--list", "--origin")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(len(result.stdout.splitlines()), 13)
        self.assertIn("moq-test-extensions", result.stdout.splitlines())
        self.assertNotIn("namespace-discovery", result.stdout.splitlines())
        result = self.run_cli("--origin", "--test", "namespace-discovery")
        self.assertEqual(result.returncode, 127)
        self.assertIn("# SKIP", result.stdout)

    def test_history_and_retention_are_supported_cases(self):
        for name in ("publish-namespace-multi-publisher-retention",
                     "fetch", "join"):
            result = self.run_cli("--relay", "invalid", "--test", name)
            self.assertEqual(result.returncode, 1)
            self.assertIn("Bail out!", result.stdout)
            self.assertNotIn("# SKIP", result.stdout)

    def test_unknown_case_is_unsupported(self):
        result = self.run_cli("--test", "unsupported-test")
        self.assertEqual(result.returncode, 127)
        self.assertIn("1..1\n", result.stdout)
        self.assertIn("# SKIP", result.stdout)

    def test_cli_precedence(self):
        result = self.run_cli("--relay", "invalid",
                              "--test", "setup-only",
                              RELAY_URL="https://localhost:4443",
                              TESTCASE="unsupported-test")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Bail out!", result.stdout)
        self.assertNotIn("unsupported #", result.stdout)

    def test_transport_help(self):
        result = self.run_cli("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("--transport quic|webtransport", result.stdout)

    def test_invalid_transport_is_not_a_skip(self):
        for value in ("udp", "https", "dual", ""):
            result = self.run_cli("--transport", value, "--test", "setup-only")
            self.assertEqual(result.returncode, 1)
            self.assertIn("invalid transport", result.stderr)
            self.assertNotIn("# SKIP", result.stdout)

    def test_https_cannot_select_native_quic(self):
        result = self.run_cli("--relay", "https://localhost:4443",
                              "--transport", "quic", "--test", "setup-only")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Bail out! HTTPS requires WebTransport", result.stdout)

    def test_malformed_wt_urls_are_failures(self):
        for url in ("https://", "https://localhost:0/",
                    "https://localhost:65536/", "https://user@localhost/",
                    "https://localhost:/", "http://localhost:4443/"):
            result = self.run_cli("--relay", url, "--test", "setup-only")
            self.assertEqual(result.returncode, 1, url)
            self.assertIn("Bail out!", result.stdout)
            self.assertNotIn("# SKIP", result.stdout)

    def test_invalid_uri_is_a_failure(self):
        result = self.run_cli("--relay", "invalid", "--test", "setup-only")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Bail out!", result.stdout)


if __name__ == "__main__":
    unittest.main()
