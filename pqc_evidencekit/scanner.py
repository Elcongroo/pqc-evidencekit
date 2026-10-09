"""Fresh TLS 1.3 handshakes using the installed OpenSSL CLI, without a shell."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

from . import __version__

HYBRID_GROUPS = ("X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024")
GROUP_NAMES = {name.lower(): name for name in HYBRID_GROUPS}
GROUP_NAMES.update({"x25519": "X25519", "x448": "X448"})
LIMITATIONS = [
    "结果仅适用于记录的TLS终止点、端口、SNI、客户端配置与检测时间；代理/CDN后端未检测。",
    "混合密钥交换与抗量子身份认证分别判断；成功协商混合组不意味着整个连接或设备完全抗量子。",
    "握手签名是CertificateVerify使用的方案；证书签发者签名及完整证书链的抗量子能力尚未分析。",
    "失败可能来自网络、证书、客户端认证、服务端策略或本机实现，不能直接推出对端不支持PQC。",
    "黑盒握手无法独立审查对端KDF输入、随机数、密钥销毁、硬件保护或实现漏洞。",
    "耗时是OpenSSL子进程的墙钟时间，包含启动、连接、握手与结束，不是纯握手或ML-KEM运算耗时。",
    "本版只测TLS 1.3新鲜握手，不测会话恢复、0-RTT、STARTTLS、QUIC或IKE/IPsec。",
    "传统交换允许与主动降级漏洞是不同结论；本版未执行主动中间人攻击。",
    "日志是原始OpenSSL端点观察；本版未生成网络PCAP或服务端函数追踪。",
]


class KitError(Exception):
    """An actionable local configuration error, rather than a peer verdict."""


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def normalize_host(value: str) -> str:
    if not value or any(c.isspace() for c in value) or any(c in value for c in "/\\@?#%"):
        raise KitError("目标主机格式无效；请输入域名或IP地址。")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        try:
            name = value.rstrip(".").encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise KitError("域名无法转换为IDNA。") from exc
        if len(name) > 253 or not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                                     for label in name.split(".")):
            raise KitError("目标域名格式无效。")
        return name.lower()


def parse_target(value: str, servername: str | None = None) -> dict:
    """Accept an origin or host[:port]; preserve hostname verification with SNI."""
    if not value or any(c.isspace() or ord(c) < 32 for c in value):
        raise KitError("目标不能包含空白或控制字符。")
    try:
        parsed = urlsplit(value if "://" in value else "//" + value)
        if parsed.scheme and parsed.scheme != "https":
            raise KitError("仅接受https://或主机:端口，STARTTLS尚未实现。")
        if parsed.username is not None or parsed.password is not None or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise KitError("请输入TLS入口，不要包含账号、路径、查询参数或片段。")
        host = normalize_host(parsed.hostname or "")
        port = 443 if parsed.port is None else parsed.port
        if not 1 <= port <= 65535:
            raise KitError("端口必须在1至65535之间。")
    except ValueError as exc:
        raise KitError("目标格式无效；IPv6请使用[地址]:端口。") from exc
    if servername is not None:
        identity_name = normalize_host(servername)
    else:
        identity_name = host
    try:
        ipaddress.ip_address(identity_name)
        server_name, verification_kind = None, "ip"
    except ValueError:
        server_name, verification_kind = identity_name, "hostname"
    return {"host": host, "port": port, "server_name": server_name,
            "identity_name": identity_name, "verification_kind": verification_kind}


def inspect_openssl(executable: str = "openssl") -> dict:
    resolved = shutil.which(executable)
    if not resolved:
        raise KitError("未找到OpenSSL；请安装OpenSSL 3.5+或用--openssl指定路径。")
    resolved = str(Path(resolved).resolve())
    env = dict(os.environ, LC_ALL="C", LANG="C")
    try:
        version = subprocess.run([resolved, "version", "-a"], capture_output=True, text=True, timeout=5, env=env)
        match = re.search(r"OpenSSL (\d+)\.(\d+)\.(\d+)", version.stdout)
        if version.returncode or not match or tuple(map(int, match.groups())) < (3, 5, 0):
            raise KitError("本版要求OpenSSL 3.5+；本机版本不可用于可靠的混合组检测。")
        groups = subprocess.run([resolved, "list", "-tls-groups", "-tls1_3"], capture_output=True, text=True, timeout=5, env=env)
        if groups.returncode:
            raise KitError("OpenSSL无法枚举TLS组；检查配置和Provider是否正常。")
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise KitError("OpenSSL本机检查失败：" + type(exc).__name__) from exc
    supported = [item for item in re.split(r"[:\s]+", groups.stdout.strip()) if item]
    return {"openssl_path": resolved, "openssl_binary_sha256": file_sha256(Path(resolved)),
            "openssl_version": version.stdout.splitlines()[0], "openssl_version_details": version.stdout,
            "supported_tls13_groups": supported,
            "identity_scope": "CLI executable hash and version output; loaded providers/libraries are not traced"}


def canonical_group(value: str | None) -> str | None:
    if value is None:
        return None
    return GROUP_NAMES.get(value.lower(), value)


def key_family(group: str | None) -> str:
    if group in HYBRID_GROUPS:
        return "pq_hybrid"
    if group and re.fullmatch(r"X25519|X448|secp\d+r1|prime256v1|ffdhe\d+|brainpool\w+", group, re.I):
        return "traditional"
    return "unknown"


def classify_error(text: str, timed_out: bool = False) -> str:
    lower = text.lower()
    if timed_out:
        return "timeout"
    if any(s in lower for s in ("certificate verify failed", "verification error", "verify error", "hostname mismatch", "ip address mismatch")):
        return "trust_failure"
    if any(s in lower for s in ("cannot be set", "group cannot", "unknown group", "no suitable groups", "unable to load", "unknown option")):
        return "local_unsupported"
    if any(s in lower for s in ("connection refused", "connect:errno", "bio_connect", "name or service not known", "network is unreachable", "permission denied")):
        return "network"
    if "alert" in lower:
        return "tls_alert"
    return "parse_unknown"


def parse_probe(stdout: str, stderr: str, *, returncode: int | None, insecure: bool, timed_out: bool = False) -> dict:
    """CONNECTION ESTABLISHED is emitted after SSL_is_init_finished, unlike rc."""
    combined = stdout + "\n" + stderr
    def field(pattern: str) -> str | None:
        match = re.search(pattern, combined, re.MULTILINE | re.IGNORECASE)
        return match.group(1).strip() if match else None
    protocol = field(r"^Protocol version:\s*(\S+)")
    group = field(r"^Negotiated TLS1\.3 group:\s*(\S+)") or field(r"^Peer Temp Key:\s*([^,\n]+)")
    completed = bool(re.search(r"^CONNECTION ESTABLISHED\s*$", combined, re.MULTILINE)) and protocol == "TLSv1.3"
    # A trust error must never be promoted even if some earlier text looks successful.
    trust_error = classify_error(combined) == "trust_failure"
    verified = completed and not insecure and bool(re.search(r"^Verification:\s*OK\s*$", combined, re.MULTILINE)) and not trust_error
    status = "confirmed" if completed and group and (verified or insecure) else "indeterminate"
    category = None if status == "confirmed" else classify_error(combined, timed_out)
    # A TLS alert is an observed failed attempt, not proof that PQC is absent.
    if not completed and category == "tls_alert":
        status = "not_negotiated"
    errors = [line.strip() for line in combined.splitlines()
              if any(term in line.lower() for term in ("error", "alert", "errno", "refused", "unsupported"))]
    return {"status": status, "handshake_completed": completed, "certificate_verified": verified,
            "identity_mode": "unverified_observation" if insecure else "verify_trust_and_name",
            "tls_version": protocol, "cipher": field(r"^Ciphersuite:\s*(\S+)"),
            "negotiated_group": canonical_group(group), "key_establishment_family": key_family(canonical_group(group)),
            "peer_signature_type": field(r"^(?:Peer )?Signature type:\s*(.+)$"),
            "peer_certificate": field(r"^Peer certificate:\s*(.+)$"),
            "error_category": category, "error_detail": "\n".join(errors[-5:])[:2000] or ("等待超时" if timed_out else None),
            "process_returncode": returncode, "process_timed_out": timed_out}


def probe_specs(groups: list[str]) -> list[dict]:
    specs = [{"id": "default", "label": "客户端默认策略", "offered_groups": None},
             {"id": "traditional", "label": "仅传统X25519", "offered_groups": "X25519"}]
    for index, group in enumerate(groups, 1):
        specs.append({"id": f"hybrid-{index}", "label": "仅混合组 " + group, "offered_groups": group})
    if groups:
        specs.extend([
            {"id": "mixed-hybrid-first", "label": "混合优先，提供双方keyshare", "offered_groups": f"*{groups[0]}:*X25519"},
            {"id": "mixed-traditional-first", "label": "传统优先，提供双方keyshare", "offered_groups": f"*X25519:*{groups[0]}"},
        ])
    return specs


def run_probe(target: dict, spec: dict, environment: dict, logs: Path, *, timeout: float, cafile: str | None, insecure: bool) -> dict:
    host = target["host"]
    address = f"[{host}]:{target['port']}" if ":" in host else f"{host}:{target['port']}"
    command = [environment["openssl_path"], "s_client", "-connect", address, "-tls1_3", "-brief", "-no_ticket"]
    if target["server_name"]:
        command += ["-servername", target["server_name"]]
    else:
        command += ["-noservername"]
    if not insecure:
        command += ["-verify_return_error", "-verify_hostname" if target["verification_kind"] == "hostname" else "-verify_ip", target["identity_name"]]
    if cafile:
        command += ["-CAfile", cafile]
    if spec["offered_groups"]:
        command += ["-groups", spec["offered_groups"]]
    supported = {g.lower() for g in environment["supported_tls13_groups"]}
    required = [g.lstrip("*") for g in (spec["offered_groups"] or "").split(":") if g]
    started = time.perf_counter()
    timed_out, returncode = False, None
    if any(g.lower() not in supported for g in required):
        stdout, stderr = "", "Local group cannot be set: group is not available in this OpenSSL configuration.\n"
    else:
        try:
            execution = subprocess.run(command, input="", capture_output=True, text=True, encoding="utf-8", errors="replace",
                                       timeout=timeout, env=dict(os.environ, LC_ALL="C", LANG="C"))
            stdout, stderr, returncode = execution.stdout, execution.stderr, execution.returncode
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            def decode(value):
                return value.decode("utf-8", "replace") if isinstance(value, bytes) else (value or "")
            stdout, stderr = decode(exc.stdout), decode(exc.stderr)
        except OSError as exc:
            stdout, stderr = "", "Local execution error: " + str(exc)
    parsed = parse_probe(stdout, stderr, returncode=returncode, insecure=insecure, timed_out=timed_out)
    if stderr.startswith("Local execution error"):
        parsed.update(status="indeterminate", error_category="local_execution", error_detail=stderr)
    for suffix, value in (("stdout.txt", stdout), ("stderr.txt", stderr)):
        (logs / f"{spec['id']}.{suffix}").write_text(value, encoding="utf-8")
    (logs / f"{spec['id']}.command.json").write_text(json.dumps(command, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return dict(spec, **parsed, duration_ms=round((time.perf_counter() - started) * 1000, 2), duration_scope="subprocess_wall_time")


def assess(probes: list[dict], *, insecure: bool) -> dict:
    successful = [p for p in probes if p["status"] == "confirmed" and p["handshake_completed"]]
    hybrid = [p for p in successful if p["key_establishment_family"] == "pq_hybrid"]
    classical = [p for p in successful if p["key_establishment_family"] == "traditional"]
    forced = [p for p in probes if p["id"].startswith("hybrid-")]
    if hybrid:
        key = {"status": "confirmed", "summary": "实际完成后量子/混合密钥交换：" + ", ".join(sorted({p['negotiated_group'] for p in hybrid})),
               "verified_peer": not insecure}
    elif classical and forced and all(p["status"] == "not_negotiated" for p in forced):
        key = {"status": "not_observed", "summary": "传统握手成功，所测混合组握手均被拒绝；仅说明本入口本次未接受这些组合。", "verified_peer": not insecure}
    else:
        key = {"status": "indeterminate", "summary": "未取得足以确认对端混合交换能力的完整结果；请查看各次检测原因。", "verified_peer": False}
    signatures = sorted({p["peer_signature_type"] for p in successful if p["peer_signature_type"]})
    if signatures:
        # Names outside this exact allowlist remain conventional or unknown;
        # a provider-defined name containing 'mldsa' is not an algorithm identity.
        pq_signature = all(s.lower() in {"mldsa44", "mldsa65", "mldsa87"} for s in signatures)
        auth = {"status": "pq_signature_observed" if pq_signature else "traditional_or_mixed_observed",
                "summary": "已观察握手签名：" + ", ".join(signatures) + "。证书链抗量子能力未分析。"}
    else:
        auth = {"status": "indeterminate", "summary": "未取得握手签名方案；不能确认抗量子身份认证。"}
    if insecure:
        identity = {"status": "unverified", "summary": "用户启用--insecure：信任与名称未强制验证，结果不能归属于已验证身份。"}
    elif successful:
        identity = {"status": "verified", "summary": "成功样本通过证书信任与主机名/IP验证；仍需核对不同检测的异常。"}
    else:
        identity = {"status": "indeterminate", "summary": "没有通过身份验证的成功握手。"}
    fallback = {"status": "classical_permitted" if classical else "not_observed",
                "summary": "已实际完成传统交换，入口允许所测传统组；这不等于降级漏洞。" if classical else "未观察到传统组成功；失败原因及其他传统组尚需另查。"}
    return {"key_establishment": key, "authentication": auth, "identity": identity, "fallback": fallback}


def reserve_output(path: Path) -> None:
    if path.exists() and (not path.is_dir() or any(path.iterdir())):
        raise KitError("输出目录已有内容；请选择新的目录，避免覆盖原始结果。")
    path.mkdir(parents=True, exist_ok=True)
    (path / "logs").mkdir()


def save_result(result: dict, path: Path) -> None:
    from .report import render_html
    (path / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (path / "summary.html").write_text(render_html(result), encoding="utf-8")
    (path / "manifest.sha256").write_text("".join(f"{file_sha256(p)}  {p.relative_to(path).as_posix()}\n"
                                               for p in sorted(path.rglob("*")) if p.is_file() and p.name != "manifest.sha256"), encoding="utf-8")


def scan(target: dict, output: Path, *, executable: str = "openssl", groups: list[str] | None = None,
         timeout: float = 8, cafile: str | None = None, insecure: bool = False, progress=None) -> dict:
    if not 0.1 <= timeout <= 120:
        raise KitError("每次检测超时必须在0.1至120秒之间。")
    selected = list(HYBRID_GROUPS if groups is None else groups)
    if not selected or len(set(selected)) != len(selected) or any(g not in HYBRID_GROUPS for g in selected):
        raise KitError("请选择不重复的RFC 10024混合组：" + ", ".join(HYBRID_GROUPS))
    if cafile and not Path(cafile).is_file():
        raise KitError("--cafile指定的证书文件不存在。")
    environment = inspect_openssl(executable)
    reserve_output(output)
    results = []
    specs = probe_specs(selected)
    for index, spec in enumerate(specs, 1):
        if progress:
            progress(index, len(specs), spec["label"])
        results.append(run_probe(target, spec, environment, output / "logs", timeout=timeout, cafile=cafile, insecure=insecure))
    assessment = assess(results, insecure=insecure)
    result = {"schema_version": "1.0", "tool_version": __version__, "created_at": datetime.now(timezone.utc).isoformat(),
              "target": target, "environment": environment, "assessment": assessment, "probes": results,
              "limitations": LIMITATIONS, "recommendations": [
                  "先查看混合组强制测试，再对照默认及传统组结果；默认选传统不等于没有混合能力。",
                  "若迁移策略要求混合交换，应在实际客户端和服务端禁用传统兼容选项，并另做策略回归。",
                  "保留原始日志与manifest；需要设备内部KDF或硬件结论时，增加可插桩的受控实验。"],
              "tested_groups": selected, "transport": "tcp", "protocol": "TLS1.3",
              "certificate_chain_pq_assessment": "not_tested", "implementation_review": "not_observable"}
    save_result(result, output)
    return result


def result_exit_code(result: dict) -> int:
    identity = result["assessment"]["identity"]["status"]
    status = result["assessment"]["key_establishment"]["status"]
    if identity != "verified":
        return 2
    return 0 if status == "confirmed" else (1 if status == "not_observed" else 2)
