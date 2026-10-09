import json
import os
from pathlib import Path
import tempfile
import unittest

from pqc_evidencekit.demo import run_demo
from pqc_evidencekit.scanner import file_sha256


@unittest.skipUnless(os.environ.get("PQC_EVIDENCEKIT_INTEGRATION") == "1", "real localhost integration explicitly disabled")
class RealHandshakeTests(unittest.TestCase):
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
