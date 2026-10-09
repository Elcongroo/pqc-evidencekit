"""Tests for report safety and conservative evidence presentation."""

import re
import unittest
from html.parser import HTMLParser

from pqc_evidencekit.report import render_html


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.request_attributes = []
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        for key, value in attrs:
            if key == "href":
                self.links.append(value)
            if key in ("src", "srcset", "action", "poster"):
                self.request_attributes.append(value)


class ReportTests(unittest.TestCase):
    def fixture(self):
        return {
            "schema_version": "1.0",
            "tool_version": "0.1.0",
            "created_at": "2026-10-09T10:00:00+08:00",
            "target": {"host": "localhost", "port": 4433, "server_name": "localhost"},
            "environment": {"openssl_version": "OpenSSL 3.5.0"},
            "assessment": {
                "key_establishment": {"status": "confirmed", "summary": "观察到混合交换组。"},
                "authentication": {"status": "traditional_or_mixed_observed", "summary": "签名仍为传统算法。"},
                "identity": {"status": "verified", "summary": "对端身份验证通过。"},
                "fallback": {"status": "classical_permitted", "summary": "允许传统交换，不等于降级漏洞。"},
            },
            "probes": [{
                "id": "probe-01", "label": "混合交换", "offered_groups": ["X25519MLKEM768"],
                "status": "confirmed", "handshake_completed": True,
                "identity_mode": "verify_trust_and_name",
                "negotiated_group": "X25519MLKEM768", "peer_signature_type": "RSA-PSS",
                "certificate_verified": True, "duration_ms": 35.15,
                "tls_version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
            }],
            "limitations": ["仅覆盖本次 TLS 握手。"],
            "recommendations": ["使用同一配置复测。"],
        }

    def test_expected_sections_and_raw_records(self):
        document = render_html(self.fixture())
        for label in ("密钥建立", "身份认证算法", "对端身份验证", "传统算法回退", "判断边界", "检测边界"):
            self.assertIn(label, document)
        self.assertIn("Authentication", document)
        self.assertIn("握手签名；证书链算法尚未分析", document)
        self.assertIn("观察到传统或混合签名", document)
        self.assertIn("已验证身份", document)
        self.assertIn("允许传统交换", document)
        self.assertIn("X25519MLKEM768", document)
        self.assertIn("不能据此断言整个系统具备完整抗量子安全性", document)
        self.assertIn("logs/probe-01.stdout.txt", document)
        self.assertIn("logs/probe-01.stderr.txt", document)
        self.assertIn("<details", document)
        self.assertIn("35.1 ms", document)
        self.assertIn('scope="col"', document)
        self.assertIn('lang="zh-CN"', document)

    def test_escape_all_supplied_text_and_attribute_contexts(self):
        result = self.fixture()
        attack = '<script>alert("x")</script><img src=x onerror="alert(1)"> & <a href="https://evil">'
        result["target"] = {"host": attack, "port": attack, "server_name": attack}
        result["created_at"] = attack
        result["tool_version"] = attack
        result["schema_version"] = attack
        result["environment"]["openssl_version"] = attack
        for dimension in result["assessment"].values():
            dimension.update(status=attack, summary=attack)
        probe = result["probes"][0]
        for field in ("label", "offered_groups", "status", "negotiated_group", "peer_signature_type", "tls_version", "cipher", "identity_mode", "error_category", "error_detail"):
            probe[field] = attack
        result["limitations"] = [attack]
        result["recommendations"] = [attack]
        document = render_html(result)
        self.assertNotIn(attack, document)
        self.assertIn("&lt;script&gt;", document)
        self.assertIn("&quot;", document)
        parser = LinkParser()
        parser.feed(document)
        self.assertNotIn("script", parser.tags)
        self.assertNotIn("img", parser.tags)
        self.assertFalse(parser.request_attributes)
        self.assertTrue(all(link.startswith(("#", "logs/", "result.json")) for link in parser.links))

    def test_unsafe_probe_identifiers_cannot_create_links(self):
        for unsafe in ("../other", 'x" onclick="alert(1)', "https://evil/a", "/tmp/secret", "", ".", "..", "x\n", "汉字", "a" * 81, None, 3):
            with self.subTest(probe_id=unsafe):
                result = self.fixture()
                result["probes"][0]["id"] = unsafe
                document = render_html(result)
                parser = LinkParser()
                parser.feed(document)
                self.assertFalse(any(link.startswith("logs/") for link in parser.links))
                self.assertIn("未生成有效记录链接", document)

    def test_empty_results_remain_inconclusive(self):
        document = render_html({})
        self.assertIn("尚无探测记录", document)
        self.assertIn("没有握手记录可供判断", document)
        self.assertEqual(document.count("暂无足够结果"), 4)
        self.assertEqual(document.count("待判定"), 4)
        self.assertNotIn("status-positive", document.split("</style>", 1)[1])

    def test_null_and_malformed_optional_fields_do_not_imply_success(self):
        result = {
            "target": None, "environment": [], "assessment": {"identity": "passed"},
            "probes": [None, {"id": "safe_02", "status": "inconclusive", "duration_ms": float("nan"), "certificate_verified": "yes"}],
            "limitations": "not a list", "recommendations": None,
        }
        document = render_html(result)
        self.assertIn("尚无法判定", document)
        self.assertIn("未判定 · Unknown", document)
        self.assertNotIn("nan ms", document)
        self.assertIn("logs/safe_02.stdout.txt", document)

    def test_only_local_links_and_no_remote_assets(self):
        document = render_html(self.fixture())
        parser = LinkParser()
        parser.feed(document)
        self.assertEqual(parser.links, ["#assessment", "result.json", "logs/probe-01.stdout.txt", "logs/probe-01.stderr.txt"])
        self.assertFalse(parser.request_attributes)
        self.assertNotIn("script", parser.tags)
        self.assertNotIn("iframe", parser.tags)
        self.assertNotIn("link", parser.tags)
        self.assertIsNone(re.search(r"url\s*\(", document, re.IGNORECASE))
        self.assertIn("default-src 'none'", document)

    def test_ipv6_target_formatting(self):
        result = self.fixture()
        result["target"]["host"] = "::1"
        document = render_html(result)
        self.assertIn("[::1]:4433", document)

    def test_insecure_observation_cannot_display_identity_as_verified(self):
        result = self.fixture()
        result["assessment"]["identity"] = {"status": "unverified", "summary": "未验证观测。"}
        result["probes"][0].update(identity_mode="unverified_observation", certificate_verified=True)
        document = render_html(result)
        self.assertIn("身份未验证", document)
        self.assertIn("未验证观测（--insecure）", document)
        self.assertIn("<td>未强制验证 · Not enforced</td>", document)
        self.assertNotIn("已验证身份", document)

    def test_scanner_status_labels_are_readable(self):
        result = self.fixture()
        result["probes"][0]["status"] = "not_negotiated"
        result["assessment"]["authentication"]["status"] = "pq_signature_observed"
        document = render_html(result)
        self.assertIn("本次未协商成功", document)
        self.assertIn("观察到后量子握手签名", document)


if __name__ == "__main__":
    unittest.main()
