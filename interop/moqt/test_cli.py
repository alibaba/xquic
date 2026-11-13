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
        for name in ("RELAY_URL", "TESTCASE", "TLS_DISABLE_VERIFY", "VERBOSE"):
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
                     "fetch", "join"):
            self.assertIn(name, result.stdout.splitlines())
        self.assertNotIn("namespace-discovery", result.stdout.splitlines())

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

    def test_transport_skip_and_cli_precedence(self):
        result = self.run_cli("--relay", "https://localhost:4443",
                              "--test", "setup-only",
                              RELAY_URL="invalid", TESTCASE="unsupported-test")
        self.assertEqual(result.returncode, 127)
        self.assertIn("ok 1 - setup-only # SKIP WebTransport", result.stdout)
        self.assertNotIn("unsupported #", result.stdout)

    def test_invalid_uri_is_a_failure(self):
        result = self.run_cli("--relay", "invalid", "--test", "setup-only")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Bail out!", result.stdout)


if __name__ == "__main__":
    unittest.main()
