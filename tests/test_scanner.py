import tempfile
from pathlib import Path
import unittest

from pqc_evidencekit.scanner import KitError, assess, parse_probe, parse_target, probe_specs, result_exit_code, reserve_output


HYBRID = """CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Signature type: rsa_pss_rsae_sha256
Verification: OK
Negotiated TLS1.3 group: X25519MLKEM768
DONE
"""
TRADITIONAL = HYBRID.replace("Negotiated TLS1.3 group: X25519MLKEM768", "Peer Temp Key: X25519, 253 bits")


class ScannerTests(unittest.TestCase):
    def probe(self, text=HYBRID, **overrides):
        parsed = parse_probe("", text, returncode=0, insecure=overrides.pop("insecure", False), **overrides)
        return dict(parsed, id="hybrid-1", label="test", offered_groups="X25519MLKEM768")

    def test_hybrid_requires_real_completion_sentinel(self):
        good = self.probe()
        self.assertEqual(good["status"], "confirmed")
        self.assertTrue(good["certificate_verified"])
        self.assertEqual(good["key_establishment_family"], "pq_hybrid")
        for false_text in (HYBRID.replace("CONNECTION ESTABLISHED", "CONNECTED"), "", "Protocol version: TLSv1.3\nCiphersuite: A\n"):
            self.assertFalse(self.probe(false_text)["handshake_completed"])
            self.assertNotEqual(self.probe(false_text)["status"], "confirmed")

    def test_ciphersuite_is_not_a_key_exchange_group(self):
        result = self.probe(HYBRID.replace("Negotiated TLS1.3 group: X25519MLKEM768\n", ""))
        self.assertIsNone(result["negotiated_group"])
        self.assertEqual(result["status"], "indeterminate")

    def test_classical_output_format(self):
        self.assertEqual(self.probe(TRADITIONAL)["negotiated_group"], "X25519")
        self.assertEqual(self.probe(TRADITIONAL)["key_establishment_family"], "traditional")

    def test_trust_error_cannot_be_promoted(self):
        result = self.probe(HYBRID + "verify error:num=62:hostname mismatch\n")
        self.assertFalse(result["certificate_verified"])
        self.assertEqual(result["error_category"], "trust_failure")
        self.assertNotEqual(result["status"], "confirmed")

    def test_insecure_is_never_verified(self):
        result = self.probe(insecure=True)
        self.assertTrue(result["handshake_completed"])
        self.assertFalse(result["certificate_verified"])
        assessment = assess([result], insecure=True)
        self.assertEqual(assessment["identity"]["status"], "unverified")
        self.assertEqual(result_exit_code({"assessment": assessment}), 2)

    def test_timeout_is_unknown_not_negative_peer_capability(self):
        result = self.probe("", timed_out=True)
        self.assertEqual(result["error_category"], "timeout")
        self.assertEqual(assess([result], insecure=False)["key_establishment"]["status"], "indeterminate")

    def test_explicit_alert_with_classical_control_is_scoped_not_observed(self):
        failure = self.probe("error:tlsv1 alert handshake failure\n")
        classical = dict(self.probe(TRADITIONAL), id="traditional")
        summary = assess([failure, classical], insecure=False)
        self.assertEqual(failure["status"], "not_negotiated")
        self.assertEqual(summary["key_establishment"]["status"], "not_observed")
        self.assertEqual(summary["fallback"]["status"], "classical_permitted")

    def test_partial_client_group_availability_is_not_peer_rejection(self):
        failure = self.probe("Local group cannot be set: unavailable\n")
        classical = dict(self.probe(TRADITIONAL), id="traditional")
        self.assertEqual(failure["error_category"], "local_unsupported")
        self.assertEqual(assess([failure, classical], insecure=False)["key_establishment"]["status"], "indeterminate")

    def test_hybrid_key_exchange_keeps_rsa_authentication_separate(self):
        assessment = assess([self.probe()], insecure=False)
        self.assertEqual(assessment["key_establishment"]["status"], "confirmed")
        self.assertEqual(assessment["authentication"]["status"], "traditional_or_mixed_observed")

    def test_draft_kyber_is_not_final_mlkem(self):
        result = self.probe(HYBRID.replace("X25519MLKEM768", "X25519Kyber768Draft00"))
        self.assertEqual(result["key_establishment_family"], "unknown")
        self.assertEqual(assess([result], insecure=False)["key_establishment"]["status"], "indeterminate")

    def test_custom_names_are_not_postquantum_identities(self):
        result = self.probe(HYBRID.replace("X25519MLKEM768", "MLKEMUnregisteredName"))
        self.assertEqual(result["key_establishment_family"], "unknown")
        signature = self.probe(HYBRID.replace("rsa_pss_rsae_sha256", "RSA-MLDSA-custom"))
        self.assertNotEqual(assess([signature], insecure=False)["authentication"]["status"], "pq_signature_observed")

    def test_target_identity_and_ipv6(self):
        self.assertEqual(parse_target("https://example.com:8443/")["port"], 8443)
        ipv6 = parse_target("[::1]:9443")
        self.assertEqual(ipv6["verification_kind"], "ip")
        self.assertIsNone(ipv6["server_name"])
        override = parse_target("192.0.2.1:443", "gateway.example.com")
        self.assertEqual(override["identity_name"], "gateway.example.com")
        self.assertEqual(override["server_name"], "gateway.example.com")

    def test_invalid_target_never_becomes_shell_or_options(self):
        for value in ("-help", "x\n-help", "https://user:pass@example.com", "x:0", "x:65536", "http://example.com", "https://example.com/path", "::1", "x;touch-file", "example.com?a=b", ""):
            with self.subTest(value=value), self.assertRaises(KitError):
                parse_target(value)

    def test_both_mixed_keyshares_are_explicit(self):
        specs = probe_specs(["X25519MLKEM768"])
        self.assertEqual(specs[-2]["offered_groups"], "*X25519MLKEM768:*X25519")
        self.assertEqual(specs[-1]["offered_groups"], "*X25519:*X25519MLKEM768")

    def test_raw_results_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "run"
            reserve_output(path)
            (path / "logs" / "sample.txt").write_text("original")
            with self.assertRaises(KitError):
                reserve_output(path)
            self.assertEqual((path / "logs" / "sample.txt").read_text(), "original")


if __name__ == "__main__":
    unittest.main()
