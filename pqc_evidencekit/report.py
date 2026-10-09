"""Render an offline, escaped HTML view of a peer capability assessment.

The renderer deliberately does not infer security conclusions. Each assessment
dimension is supplied by the scanner and displayed separately. The complete
machine-readable record and unmodified process output remain adjacent files.
"""

from __future__ import annotations

import html
import json
import math
import re
from collections.abc import Mapping
from urllib.parse import quote


_SAFE_PROBE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")
_DIMENSIONS = (
    ("key_establishment", "密钥建立", "Key establishment", "本次握手协商了什么交换组"),
    ("authentication", "身份认证算法", "Authentication", "握手签名；证书链算法尚未分析"),
    ("identity", "对端身份验证", "Identity verification", "证书链及主机名是否通过验证"),
    ("fallback", "传统算法回退", "Fallback", "本次探测是否观察到传统组协商"),
)
_STATUS_LABELS = {
    "confirmed": ("已确认本次协商", "positive"),
    "not_negotiated": ("本次未协商成功", "neutral"),
    "pq_signature_observed": ("观察到后量子握手签名", "positive"),
    "traditional_or_mixed_observed": ("未确认全为抗量子签名", "caution"),
    "verified": ("已验证身份", "positive"),
    "unverified": ("身份未验证", "caution"),
    "classical_permitted": ("允许传统交换", "caution"),
    "supported": ("支持", "positive"),
    "observed": ("已观察到", "positive"),
    "passed": ("通过", "positive"),
    "success": ("成功", "positive"),
    "completed": ("已完成", "positive"),
    "failed": ("失败", "negative"),
    "unsupported": ("未观察到支持", "neutral"),
    "not_supported": ("未观察到支持", "neutral"),
    "unavailable": ("不可用", "neutral"),
    "indeterminate": ("尚无法判定", "neutral"),
    "inconclusive": ("尚无法判定", "neutral"),
    "unknown": ("未知", "neutral"),
    "not_tested": ("未测试", "neutral"),
    "not_observed": ("未观察到", "neutral"),
    "partial": ("部分结果", "caution"),
    "fallback_observed": ("已观察到回退", "caution"),
    "traditional_only": ("仅观察到传统算法", "caution"),
    "warning": ("需关注", "caution"),
    "skipped": ("已跳过", "neutral"),
    "pending": ("待判定", "neutral"),
}


def _text(value: object, default: str = "未记录") -> str:
    if value is None or value == "":
        return default
    if isinstance(value, (list, tuple)):
        return ", ".join(_text(item, "") for item in value) or default
    if isinstance(value, Mapping):
        return json.dumps(dict(value), ensure_ascii=False, default=str)
    return str(value)


def _escape(value: object, default: str = "未记录") -> str:
    return html.escape(_text(value, default), quote=True)


def _mapping(value: object) -> Mapping:
    return value if isinstance(value, Mapping) else {}


def _sequence(value: object) -> list:
    return list(value) if isinstance(value, (list, tuple)) else []


def _status(value: object) -> str:
    raw = _text(value, "pending")
    label, tone = _STATUS_LABELS.get(raw.lower(), (raw, "neutral"))
    return (
        f'<span class="status status-{tone}"><span class="status-dot" aria-hidden="true"></span>'
        f'{_escape(label)}<span class="status-code">{_escape(raw)}</span></span>'
    )


def _boolean(value: object) -> str:
    if value is True:
        return "是 · Yes"
    if value is False:
        return "否 · No"
    return "未判定 · Unknown"


def _duration(value: object) -> str:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if math.isfinite(value) and value >= 0:
            return f"{value:,.1f} ms"
    return "未记录"


def _identity_mode(value: object) -> str:
    return {
        "unverified_observation": "未验证观测（--insecure）",
        "verify_trust_and_name": "强制验证信任与主机名/IP",
    }.get(_text(value, ""), _text(value))


def _raw_links(probe_id: object) -> str:
    if not isinstance(probe_id, str) or not _SAFE_PROBE_ID.fullmatch(probe_id):
        return '<p class="muted">未生成有效记录链接 · No valid record link</p>'
    basename = quote(probe_id, safe="")
    return (
        '<div class="raw-links" aria-label="原始进程输出 Raw process output">'
        f'<a href="logs/{basename}.stdout.txt">标准输出 <span lang="en">stdout</span></a>'
        f'<a href="logs/{basename}.stderr.txt">错误输出 <span lang="en">stderr</span></a>'
        "</div>"
    )


def _probe_row(value: object, index: int) -> str:
    probe = _mapping(value)
    label = _escape(probe.get("label"), f"探测 {index}")
    fields = (
        ("记录 ID", probe.get("id")),
        ("身份模式", _identity_mode(probe.get("identity_mode"))),
        ("握手完成", _boolean(probe.get("handshake_completed"))),
        ("TLS 版本", probe.get("tls_version")),
        ("密码套件", probe.get("cipher")),
        ("对端签名类型", probe.get("peer_signature_type")),
        ("错误类别", probe.get("error_category")),
        ("错误详情", probe.get("error_detail")),
    )
    detail_fields = "".join(f"<dt>{_escape(name)}</dt><dd>{_escape(item)}</dd>" for name, item in fields)
    identity_result = (
        "未强制验证 · Not enforced" if probe.get("identity_mode") == "unverified_observation"
        else _boolean(probe.get("certificate_verified"))
    )
    return (
        '<tr><th scope="row"><span class="probe-label">' + label + "</span>"
        '<details class="probe-details"><summary>查看记录 <span lang="en">Details</span></summary>'
        f'<dl>{detail_fields}</dl>{_raw_links(probe.get("id"))}</details></th>'
        f'<td class="mono">{_escape(probe.get("offered_groups"))}</td>'
        f'<td>{_status(probe.get("status"))}</td>'
        f'<td class="mono">{_escape(probe.get("negotiated_group"), "未观察到")}</td>'
        f'<td>{_escape(identity_result)}</td>'
        f'<td class="number">{_escape(_duration(probe.get("duration_ms")))}</td></tr>'
    )


def _items(values: object, empty: str) -> str:
    items = _sequence(values)
    if not items:
        return f'<p class="muted">{_escape(empty)}</p>'
    return '<ul class="note-list">' + "".join(f"<li>{_escape(item)}</li>" for item in items) + "</ul>"


_CSS = """
:root { color-scheme: light; --ink: #17273b; --muted: #5e6d80; --line: #dce4ec;
  --paper: #fff; --canvas: #f2f5f8; --accent: #126879; --positive: #226944;
  --negative: #a43136; --caution: #8a5b10; }
* { box-sizing: border-box; }
body { margin: 0; background: var(--canvas); color: var(--ink);
  font-family: system-ui, -apple-system, "Segoe UI", "Noto Sans CJK SC", sans-serif;
  line-height: 1.6; font-size: 15px; }
a { color: #075d76; text-decoration-thickness: 1px; text-underline-offset: 3px; }
a:hover { color: #032f45; }
a:focus-visible, summary:focus-visible { outline: 3px solid #428daa; outline-offset: 4px; }
.skip-link { position: absolute; top: -60px; left: 16px; background: white; padding: 10px 18px; z-index: 5; }
.skip-link:focus { top: 12px; }
.shell { max-width: 1160px; margin: 0 auto; padding: 38px 28px 48px; }
.masthead { display: flex; gap: 24px; justify-content: space-between; align-items: flex-start; }
.wordmark { font-size: 13px; font-weight: 750; letter-spacing: .08em; text-transform: uppercase; color: var(--accent); }
.wordmark::before { content: ""; display: inline-block; width: 10px; height: 10px; margin-right: 9px; background: var(--accent); border-radius: 3px; }
h1 { margin: 12px 0 5px; font-size: clamp(25px, 4vw, 36px); line-height: 1.3; letter-spacing: -.025em; }
.subtitle { margin: 0; color: var(--muted); max-width: 700px; }
.export-link { flex-shrink: 0; padding: 9px 15px; border: 1px solid #bfcdd8; border-radius: 8px;
  background: var(--paper); text-decoration: none; font-size: 13px; font-weight: 650; margin-top: 4px; }
.identity { margin: 26px 0 18px; padding: 18px 22px; background: var(--paper); border: 1px solid var(--line); border-radius: 12px; }
.identity dl { display: grid; grid-template-columns: 1.5fr 1fr 1fr; gap: 16px 24px; margin: 0; }
.identity dt { font-size: 12px; color: var(--muted); margin-bottom: 4px; }
.identity dd { margin: 0; font-weight: 600; overflow-wrap: anywhere; }
.identity .secondary { font-size: 13px; color: var(--muted); font-weight: 400; }
.boundary { display: flex; gap: 12px; padding: 15px 18px; border: 1px solid #c4dbe2; border-left: 4px solid var(--accent);
  border-radius: 8px; background: #eaf3f6; font-size: 14px; }
.boundary strong { flex-shrink: 0; color: #124f60; }
.boundary p { margin: 0; }
.section-title { display: flex; align-items: baseline; justify-content: space-between; gap: 15px; margin: 29px 0 13px; }
h2 { font-size: 18px; margin: 0; }
.en { color: var(--muted); font-size: 12px; font-weight: 450; margin-left: 6px; }
.section-meta { color: var(--muted); font-size: 12px; }
.cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; }
.card { background: var(--paper); border: 1px solid var(--line); border-radius: 10px; padding: 19px 18px; min-width: 0; }
.card h3 { margin: 0; font-size: 16px; }
.card .en { display: block; margin: 1px 0 0; }
.card-prompt { color: var(--muted); font-size: 12px; margin: 8px 0 14px; min-height: 38px; }
.card-summary { font-size: 14px; margin: 13px 0 0; overflow-wrap: anywhere; }
.status { display: inline-flex; align-items: center; flex-wrap: wrap; gap: 6px; padding: 4px 8px; border-radius: 5px;
  background: #edf0f4; color: #526174; font-size: 12px; line-height: 1.45; font-weight: 650; }
.status-positive { color: var(--positive); background: #e8f3eb; }
.status-negative { color: var(--negative); background: #f9e9e9; }
.status-caution { color: var(--caution); background: #fcf2de; }
.status-dot { width: 6px; height: 6px; border-radius: 100%; background: currentColor; }
.status-code { font-size: 10px; font-weight: 400; opacity: .9; overflow-wrap: anywhere; }
.table-wrap { border: 1px solid var(--line); border-radius: 10px; overflow-x: auto; background: var(--paper); }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
caption { text-align: left; color: var(--muted); padding: 14px 18px; font-size: 12px; border-bottom: 1px solid var(--line); }
thead { background: #f6f8fa; }
th, td { text-align: left; padding: 14px 16px; vertical-align: top; border-bottom: 1px solid var(--line); }
thead th { font-weight: 650; white-space: nowrap; }
thead .en { display: block; margin: 1px 0 0; font-size: 10px; }
tbody th { min-width: 230px; width: 28%; font-weight: 500; }
tbody tr:last-child th, tbody tr:last-child td { border-bottom: 0; }
.probe-label { font-weight: 650; }
.mono { font-family: ui-monospace, "SFMono-Regular", Consolas, monospace; overflow-wrap: anywhere; min-width: 130px; }
.number { font-variant-numeric: tabular-nums; white-space: nowrap; }
.probe-details { margin-top: 7px; font-size: 12px; }
.probe-details summary { cursor: pointer; color: var(--accent); width: fit-content; }
.probe-details summary span { color: var(--muted); font-size: 10px; }
.probe-details dl { display: grid; grid-template-columns: auto 1fr; gap: 5px 12px; margin: 12px 0; }
.probe-details dt { color: var(--muted); }
.probe-details dd { margin: 0; overflow-wrap: anywhere; }
.raw-links { display: flex; flex-wrap: wrap; gap: 8px 14px; margin-top: 10px; }
.raw-links span { font-family: ui-monospace, monospace; font-size: 10px; }
.empty { padding: 34px 20px; text-align: center; }
.empty strong { display: block; margin-bottom: 7px; }
.empty p { margin: 0; color: var(--muted); }
.notes { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; margin-top: 24px; }
.note-panel { padding: 20px 22px; background: var(--paper); border: 1px solid var(--line); border-radius: 10px; }
.note-list { padding-left: 20px; margin: 12px 0 0; font-size: 14px; }
.note-list li { margin: 7px 0; overflow-wrap: anywhere; }
.muted { color: var(--muted); font-size: 13px; }
.provenance { margin-top: 26px; padding-top: 18px; border-top: 1px solid #ccd7e1; }
.provenance h2 { font-size: 14px; }
.provenance dl { display: grid; grid-template-columns: auto 1fr; gap: 4px 16px; margin: 9px 0; font-size: 12px; }
.provenance dt { color: var(--muted); }
.provenance dd { margin: 0; overflow-wrap: anywhere; }
footer { margin-top: 18px; color: var(--muted); font-size: 11px; }
@media (max-width: 960px) { .cards { grid-template-columns: repeat(2, 1fr); } }
@media (max-width: 620px) { .shell { padding: 22px 16px 32px; } .masthead { display: block; }
  .export-link { display: inline-block; margin-top: 15px; } .identity { padding: 15px 16px; }
  .identity dl { grid-template-columns: 1fr; gap: 12px; } .cards, .notes { grid-template-columns: 1fr; }
  .card-prompt { min-height: 0; } .boundary { display: block; } .boundary strong { display: block; margin-bottom: 5px; }
  .section-title { align-items: flex-start; } .section-meta { text-align: right; } }
@media print { body { background: white; font-size: 10pt; } .shell { max-width: none; padding: 0; }
  .skip-link, .export-link { display: none; } .cards { grid-template-columns: repeat(2, 1fr); }
  .card, .note-panel, .identity, .boundary { break-inside: avoid; } .table-wrap { overflow: visible; }
  th, td { padding: 7px; } .probe-details { display: block; } a { color: inherit; } }
"""


def render_html(result: dict) -> str:
    """Return a self-contained Chinese-first report, without touching files.

    All supplied text is HTML-escaped. Only fixed relative paths and validated
    probe IDs become links; no supplied target or URL is used as an href.
    Missing fields remain explicitly unobserved rather than implying success.
    """
    result = _mapping(result)
    target = _mapping(result.get("target"))
    environment = _mapping(result.get("environment"))
    assessment = _mapping(result.get("assessment"))
    probes = _sequence(result.get("probes"))
    host = _text(target.get("host"), "未指定对端")
    port = _text(target.get("port"), "未指定端口")
    endpoint = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    cards = []
    for key, name, english, prompt in _DIMENSIONS:
        dimension = _mapping(assessment.get(key))
        cards.append(
            f'<article class="card"><h3>{name}<span class="en" lang="en">{english}</span></h3>'
            f'<p class="card-prompt">{prompt}</p>{_status(dimension.get("status"))}'
            f'<p class="card-summary">{_escape(dimension.get("summary"), "暂无足够结果，请查看探测记录与检测边界。")}</p></article>'
        )
    if probes:
        probe_content = (
            '<table><caption>每条记录对应一次主动握手尝试。展开记录可查看错误详情及原始输出；耗时包含连接和进程开销。</caption>'
            '<thead><tr><th scope="col">探测<span class="en" lang="en">Probe</span></th>'
            '<th scope="col">请求交换组<span class="en" lang="en">Offered groups</span></th>'
            '<th scope="col">结果<span class="en" lang="en">Outcome</span></th>'
            '<th scope="col">协商交换组<span class="en" lang="en">Negotiated group</span></th>'
            '<th scope="col">身份验证<span class="en" lang="en">Certificate verified</span></th>'
            '<th scope="col">探测耗时<span class="en" lang="en">Elapsed</span></th></tr></thead>'
            '<tbody>' + "".join(_probe_row(probe, i + 1) for i, probe in enumerate(probes)) + '</tbody></table>'
        )
    else:
        probe_content = (
            '<div class="empty"><strong>尚无探测记录</strong>'
            '<p>没有握手记录可供判断；这不表示对端支持或不支持后量子密钥交换。</p></div>'
        )
    return f'''<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>对端后量子能力观测 · {_escape(endpoint)} · PQC EvidenceKit</title>
<style>{_CSS}</style>
</head>
<body>
<a class="skip-link" href="#assessment">跳转至结果 · Skip to results</a>
<main class="shell">
  <header class="masthead">
    <div><div class="wordmark">PQC EvidenceKit</div><h1>对端后量子能力观测</h1>
    <p class="subtitle">基于实际握手的能力检测与可追溯记录 <span lang="en">· Peer capability assessment</span></p></div>
    <a class="export-link" href="result.json">查看完整 JSON <span lang="en">↗</span></a>
  </header>
  <section class="identity" aria-label="检测对象与时间 Target and time">
    <dl><div><dt>检测对端 <span lang="en">Target</span></dt><dd>{_escape(endpoint)}</dd></div>
    <div><dt>TLS 服务名 <span lang="en">Server name / SNI</span></dt><dd>{_escape(target.get("server_name"))}</dd></div>
    <div><dt>生成时间 <span lang="en">Created at</span></dt><dd class="secondary">{_escape(result.get("created_at"))}</dd></div></dl>
  </section>
  <aside class="boundary" aria-label="结论边界 Assessment boundary"><strong>判断边界</strong>
    <p>交换组支持、身份认证算法、证书验证和回退行为分别判断。协商到混合交换组只能说明本次连接的可观测行为，不能据此断言整个系统具备完整抗量子安全性。失败结果也可能来自网络、证书或本地工具能力。</p>
  </aside>
  <section id="assessment" aria-labelledby="assessment-title">
    <div class="section-title"><h2 id="assessment-title">四个判断维度 <span class="en" lang="en">Assessment dimensions</span></h2><span class="section-meta">结论仅适用于本次检测</span></div>
    <div class="cards">{''.join(cards)}</div>
  </section>
  <section aria-labelledby="probes-title">
    <div class="section-title"><h2 id="probes-title">逐次探测记录 <span class="en" lang="en">Probe records</span></h2><span class="section-meta">{len(probes)} 条记录</span></div>
    <div class="table-wrap">{probe_content}</div>
  </section>
  <div class="notes">
    <section class="note-panel" aria-labelledby="limits-title"><h2 id="limits-title">检测边界 <span class="en" lang="en">Limitations</span></h2>
    {_items(result.get('limitations'), '未提供额外边界说明，请结合上方判断边界解读。')}</section>
    <section class="note-panel" aria-labelledby="next-title"><h2 id="next-title">建议验证动作 <span class="en" lang="en">Next checks</span></h2>
    {_items(result.get('recommendations'), '尚无额外建议；请先检查完整记录和原始输出。')}</section>
  </div>
  <section class="provenance" aria-labelledby="provenance-title"><h2 id="provenance-title">运行来源 <span class="en" lang="en">Provenance</span></h2>
    <dl><dt>探测工具版本</dt><dd>PQC EvidenceKit {_escape(result.get('tool_version'))}</dd>
    <dt>本地 OpenSSL</dt><dd>{_escape(environment.get('openssl_version'))}</dd>
    <dt>结果格式版本</dt><dd>{_escape(result.get('schema_version'))}</dd></dl>
  </section>
  <footer>报告可离线查看，无远程字体、脚本或统计请求。请与 result.json 和 logs 目录一起保存与分享。</footer>
</main>
</body>
</html>'''
