import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest

from pqc_evidencekit.demo import run_demo, tls_server
from pqc_evidencekit.scanner import HYBRID_GROUPS, file_sha256, inspect_openssl, parse_target, run_probe


@unittest.skipUnless(os.environ.get("PQC_EVIDENCEKIT_INTEGRATION") == "1", "real localhost integration explicitly disabled")
class RealHandshakeTests(unittest.TestCase):
    def _environment(self):
        return inspect_openssl(os.environ.get("PQC_EVIDENCEKIT_OPENSSL", "openssl"))

    def _fresh_certificate(self, environment, private):
        certificate, key = private / "server.pem", private / "server-key.pem"
        creation = subprocess.run(
            [environment["openssl_path"], "req", "-x509", "-newkey", "rsa:2048", "-noenc",
             "-keyout", str(key), "-out", str(certificate), "-days", "1", "-subj", "/CN=localhost",
             "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
            capture_output=True, timeout=20,
        )
        self.assertEqual(creation.returncode, 0, creation.stderr.decode("utf-8", "replace")[:2000])
        return certificate, key

    def test_all_rfc10024_groups_complete_verified_handshakes(self):
        environment = self._environment()
        supported = {group.lower() for group in environment["supported_tls13_groups"]}
        for group in HYBRID_GROUPS:
            with self.subTest(group=group), tempfile.TemporaryDirectory() as temporary:
                self.assertIn(group.lower(), supported, "integration environment must provide every advertised hybrid group")
                private = Path(temporary)
                certificate, key = self._fresh_certificate(environment, private)
                logs = private / "logs"
                logs.mkdir()
                with tls_server(environment["openssl_path"], certificate, key, group) as port:
                    probe = run_probe(
                        parse_target(f"127.0.0.1:{port}", "localhost"),
                        {"id": "forced-hybrid", "label": group, "offered_groups": group},
                        environment, logs, timeout=4, cafile=str(certificate), insecure=False,
                    )
                self.assertEqual(probe["status"], "confirmed", probe["error_detail"])
                self.assertTrue(probe["handshake_completed"])
                self.assertTrue(probe["certificate_verified"])
                self.assertEqual(probe["negotiated_group"], group)
                self.assertEqual(probe["key_establishment_family"], "pq_hybrid")

    def test_refused_connection_is_indeterminate_not_absent_pqc(self):
        environment = self._environment()
        with tempfile.TemporaryDirectory() as temporary, socket.socket() as unavailable:
            # Holding a bound, non-listening socket prevents a competing service
            # from occupying the port while the kernel refuses the connection.
            unavailable.bind(("127.0.0.1", 0))
            port = unavailable.getsockname()[1]
            probe = run_probe(
                parse_target(f"127.0.0.1:{port}", "localhost"),
                {"id": "refused", "label": "refused", "offered_groups": None},
                environment, Path(temporary), timeout=2, cafile=None, insecure=False,
            )
            self.assertEqual(probe["status"], "indeterminate")
            self.assertEqual(probe["error_category"], "network")
            self.assertFalse(probe["handshake_completed"])
            self.assertFalse(probe["certificate_verified"])
            self.assertIsNone(probe["negotiated_group"])

    def test_unresponsive_peer_timeout_is_indeterminate_not_absent_pqc(self):
        environment = self._environment()
        with tempfile.TemporaryDirectory() as temporary, socket.socket() as unresponsive:
            # TCP accepts the connection into its backlog, but this fixture
            # deliberately never accepts it or responds to the ClientHello.
            unresponsive.bind(("127.0.0.1", 0))
            unresponsive.listen(1)
            port = unresponsive.getsockname()[1]
            probe = run_probe(
                parse_target(f"127.0.0.1:{port}", "localhost"),
                {"id": "unresponsive", "label": "unresponsive", "offered_groups": None},
                environment, Path(temporary), timeout=0.5, cafile=None, insecure=False,
            )
            self.assertEqual(probe["status"], "indeterminate")
            self.assertEqual(probe["error_category"], "timeout")
            self.assertTrue(probe["process_timed_out"])
            self.assertFalse(probe["handshake_completed"])
            self.assertFalse(probe["certificate_verified"])
            self.assertIsNone(probe["negotiated_group"])

    def test_disposable_servers_and_negative_cases(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "demo"
            run_demo(output, executable=os.environ.get("PQC_EVIDENCEKIT_OPENSSL", "openssl"))
            result = json.loads((output / "demo-result.json").read_text())
            self.assertEqual(result["passed"], result["total"])
            self.assertGreaterEqual(result["total"], 13)
            self.assertFalse(list(output.rglob("*key.pem")))
            for line in (output / "manifest.sha256").read_text().splitlines():
                digest, name = line.split("  ", 1)
                self.assertEqual(file_sha256(output / name), digest)


if __name__ == "__main__":
    unittest.main()
