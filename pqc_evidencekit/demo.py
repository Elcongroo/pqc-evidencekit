"""Disposable localhost services and decisive negative tests; never reuse secrets."""

from __future__ import annotations

from contextlib import contextmanager
import html
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time

from .scanner import KitError, file_sha256, inspect_openssl, parse_target, run_probe, scan


@contextmanager
def tls_server(executable: str, certificate: Path, key: Path, groups: str):
    """Bind only loopback; wait for readiness, reap all children even on failure."""
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    command = [executable, "s_server", "-accept", f"127.0.0.1:{port}", "-cert", str(certificate),
               "-key", str(key), "-tls1_3", "-groups", groups, "-www", "-quiet"]
    with tempfile.TemporaryFile() as server_log:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=server_log, stderr=server_log)
        try:
            ready = False
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    server_log.seek(0)
                    raise KitError("演示服务启动失败：" + server_log.read().decode("utf-8", "replace")[:2000])
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        ready = True
                        break
                except OSError:
                    time.sleep(0.03)
            if not ready:
                raise KitError("演示服务未能及时启动。")
            yield port
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)


def run_demo(output: Path, *, executable: str = "openssl") -> Path:
    environment = inspect_openssl(executable)
    if "x25519mlkem768" not in {g.lower() for g in environment["supported_tls13_groups"]}:
        raise KitError("本地演示需要X25519MLKEM768；请选择包含该组的OpenSSL。")
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise KitError("演示目录已有内容；请选择新目录以保留每次原始结果。")
    output.mkdir(parents=True, exist_ok=True)
    assertions = []
    def check(name, condition):
        assertions.append({"name": name, "passed": bool(condition)})
    with tempfile.TemporaryDirectory(prefix="pqc-evidencekit-demo-") as temporary:
        private = Path(temporary)
        certificate, key = private / "server.pem", private / "server-key.pem"
        creation = subprocess.run([environment["openssl_path"], "req", "-x509", "-newkey", "rsa:2048", "-noenc",
                                   "-keyout", str(key), "-out", str(certificate), "-days", "1", "-subj", "/CN=localhost",
                                   "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"], capture_output=True, timeout=20)
        if creation.returncode:
            raise KitError("无法生成一次性演示证书。")
        for name, group in (("hybrid", "X25519MLKEM768"), ("traditional", "X25519")):
            print("本地对照：" + name, flush=True)
            with tls_server(environment["openssl_path"], certificate, key, group) as port:
                target = parse_target(f"127.0.0.1:{port}", "localhost")
                result = scan(target, output / name, executable=environment["openssl_path"], groups=["X25519MLKEM768"],
                              cafile=str(certificate), timeout=4)
                result_status = result["assessment"]["key_establishment"]["status"]
                check(name + " key-establishment verdict", result_status == ("confirmed" if name == "hybrid" else "not_observed"))
                check(name + " verified identity", result["assessment"]["identity"]["status"] == "verified")
                by_id = {p["id"]: p for p in result["probes"]}
                check(name + " forced group observation", by_id["hybrid-1"]["status"] == ("confirmed" if name == "hybrid" else "not_negotiated"))
                check(name + " traditional observation", by_id["traditional"]["status"] == ("not_negotiated" if name == "hybrid" else "confirmed"))
                # Prove hybrid KEX did not magically replace the RSA authentication.
                check(name + " RSA authentication remains separate", "rsa" in (by_id["default"]["peer_signature_type"] or "").lower())
                if name == "hybrid":
                    negative_logs = output / "negative" / "logs"
                    negative_logs.mkdir(parents=True)
                    failures = []
                    for probe_id, bad_target, ca, insecure in (
                        ("untrusted-certificate", target, None, False),
                        ("wrong-peername", parse_target(f"127.0.0.1:{port}", "wrong.invalid"), str(certificate), False),
                        ("unverified-observation", target, None, True),
                    ):
                        probe = run_probe(bad_target, {"id": probe_id, "label": probe_id, "offered_groups": "X25519MLKEM768"},
                                          environment, negative_logs, timeout=4, cafile=ca, insecure=insecure)
                        failures.append(probe)
                        if insecure:
                            check(probe_id + " never attributes a verified identity", probe["status"] == "confirmed" and not probe["certificate_verified"])
                        else:
                            check(probe_id + " rejected as trust failure", probe["error_category"] == "trust_failure" and not probe["certificate_verified"] and probe["status"] != "confirmed")
                    (output / "negative" / "result.json").write_text(json.dumps(failures, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    # At this point the services and temporary certificate/key are already gone.
    regression = {"scope": "fresh real localhost TLS handshakes; ephemeral RSA server identity", "checks": assertions,
                  "passed": sum(item["passed"] for item in assertions), "total": len(assertions)}
    (output / "demo-result.json").write_text(json.dumps(regression, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    rows = "".join(f"<tr><td>{html.escape(item['name'])}</td><td>{'通过' if item['passed'] else '失败'}</td></tr>" for item in assertions)
    (output / "index.html").write_text('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        '<title>PQC EvidenceKit · 本地演示</title><style>body{font:16px/1.7 system-ui,sans-serif;max-width:960px;margin:4rem auto;padding:0 1.5rem;color:#132c3b;background:#f6f8fb}a{color:#087c74}table{border-collapse:collapse;width:100%;background:white}td{padding:10px;border-bottom:1px solid #dde6e9}</style>'
        f'<h1>PQC EvidenceKit 本地演示</h1><p>{regression["passed"]}/{regression["total"]}项真实握手检查通过。临时服务已停止，私钥已随临时目录清理。</p>'
        '<p><a href="hybrid/summary.html">查看混合交换端点</a> · <a href="traditional/summary.html">查看传统端点</a> · <a href="negative/result.json">三个负向/边界结果</a></p>'
        '<p>两个端点都采用RSA身份认证，只有前者采用后量子混合密钥交换；此对照用于验证结论边界。</p>'
        '<table>' + rows + '</table><p>原始日志、JSON和SHA-256保存在本目录。该演示证明工具的检测路径，不证明使用者已掌握协议，也不代表外部设备能力。</p></html>', encoding="utf-8")
    (output / "manifest.sha256").write_text("".join(f"{file_sha256(p)}  {p.relative_to(output).as_posix()}\n"
                                                 for p in sorted(output.rglob("*")) if p.is_file() and p != output / "manifest.sha256"), encoding="utf-8")
    print(f"真实检查：{regression['passed']}/{regression['total']}\n演示入口：{(output / 'index.html').resolve()}", flush=True)
    if regression["passed"] != regression["total"]:
        raise KitError("本地回归未全部通过，请查看demo-result.json。")
    return output / "index.html"
