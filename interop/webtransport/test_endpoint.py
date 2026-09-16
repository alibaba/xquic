#!/usr/bin/env python3
"""Test container argument mapping and startup failures without networking."""
import unittest
from unittest.mock import patch
import run_endpoint as endpoint


class EndpointTests(unittest.TestCase):
    def test_arguments(self):
        for role, case, request, session, port in [
            ("client", "handshake", "https://server/wt",
             "https://server/wt", "443"),
            ("client", "transfer-unidirectional-receive",
             "https://server:8443/wt/a https://server:8443/wt/b",
             "https://server:8443/wt", "8443"),
            ("client", "transfer", "https://server/wt",
             "https://server/wt", "443"),
            *[("client", f"transfer-{carrier}-receive", "https://server/wt/a",
               "https://server/wt", "443")
              for carrier in ("bidirectional", "datagram")],
            *[("server", case, "wt/a wt/b", None, "443")
              for case in ("handshake", "transfer",
                           "transfer-unidirectional-send",
                           "transfer-bidirectional-send",
                           "transfer-datagram-send")],
        ]:
            with self.subTest(role=role, case=case):
                args = endpoint.endpoint_command(dict(
                    ROLE=role, TESTCASE=case, REQUESTS=request,
                    SSLKEYLOGFILE="/logs/custom.keys"))
                self.assertEqual(args[0], f"/usr/local/bin/demo_{role}")
                self.assertEqual(args[1:4], ["-W", "-v", "16"])
                self.assertEqual("-A" in args, role == "server")
                value_args = [arg for arg in args[4:] if arg != "-A"]
                flags = dict(zip(value_args[::2], value_args[1::2]))
                self.assertEqual(flags["-p"], port)
                self.assertEqual(flags["-k"], "/logs/custom.keys")
                self.assertEqual(flags.get("-U"), session)
                cert = "/certs/ca.pem" if session else "/certs/cert.pem"
                self.assertEqual(flags.get("-J", flags.get("-T")), cert)
                self.assertEqual(flags["-K"],
                                 "45" if session else "/certs/priv.key")

    def test_invalid_urls(self):
        for url in ["", "http://server/wt", "https://user@server/wt",
                    "https://server/", "https://server/../a",
                    "https://server/wt?a", "https://server/wt#f",
                    "https://server:0/wt", "https://server:65536/wt",
                    "https://server:0000443/wt", "https://[::1]/wt",
                    "https://" + "a" * 128 + "/wt",
                    "https://server/" + "a" * 256]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                endpoint.endpoint_command(dict(
                    ROLE="client", TESTCASE="handshake", REQUESTS=url))

    def test_startup(self):
        failure = endpoint.subprocess.CalledProcessError(1, "setup")
        for role, case, error, status, calls in [
            ("client", "unknown", None, 127, 0),
            ("invalid", "handshake", None, 127, 0),
            *[(role, f"transfer-{carrier}-{direction}", None, 127, 0)
              for role, direction in (("client", "send"), ("server", "receive"))
              for carrier in ("unidirectional", "bidirectional", "datagram")],
            ("server", "handshake", failure, 1, 1),
            ("server", "handshake", None, None, 1),
            ("client", "handshake", None, None, 2),
            ("client", "handshake", [None, failure], 1, 2),
        ]:
            with (self.subTest(role=role, error=error),
                  patch.dict(endpoint.os.environ, dict(
                      ROLE=role, TESTCASE=case, REQUESTS="https://server/wt")),
                  patch.object(endpoint.subprocess, "run",
                               side_effect=error) as run,
                  patch.object(endpoint.os, "execv") as execute,
                  patch.object(endpoint.sys, "stderr")):
                self.assertEqual(endpoint.main(), status)
                self.assertEqual(run.call_count, calls)
                self.assertEqual(execute.call_count, int(status is None))
                if calls:
                    run.assert_any_call(["/setup.sh"], check=True)
                if calls == 2:
                    run.assert_any_call(
                        ["/wait-for-it.sh", "sim:57832", "-s", "-t", "30"],
                        check=True)


if __name__ == "__main__":
    unittest.main()
