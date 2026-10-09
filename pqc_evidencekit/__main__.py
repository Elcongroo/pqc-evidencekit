"""Human-friendly CLI. Exit codes are capability observations, not safety scores."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import webbrowser

from . import __version__
from .scanner import HYBRID_GROUPS, KitError, inspect_openssl, parse_target, result_exit_code, scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pqc-evidencekit", description="检测TLS对端实际混合交换能力，生成可追溯报告。")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    doctor = commands.add_parser("doctor", help="检查本机OpenSSL与混合组能力")
    doctor.add_argument("--openssl", default="openssl")
    doctor.add_argument("--json", action="store_true")
    check = commands.add_parser("scan", help="检测一个TLS入口（域名、IP或https://入口）")
    check.add_argument("target")
    check.add_argument("--out", type=Path, default=Path("report/scan"), help="新的报告目录，默认report/scan")
    check.add_argument("--servername", help="SNI及预期证书身份，用于指定IP的虚拟主机")
    check.add_argument("--cafile", help="额外信任的PEM CA文件，用于私有服务")
    check.add_argument("--insecure", action="store_true", help="不强制验证身份；仅作未验证入口观察，退出码为2")
    check.add_argument("--timeout", type=float, default=8)
    check.add_argument("--groups", default=",".join(HYBRID_GROUPS), help="逗号分隔的RFC 10024混合组")
    check.add_argument("--openssl", default="openssl")
    check.add_argument("--open", action="store_true", help="完成后用默认浏览器打开本地报告")
    demo = commands.add_parser("demo", help="本机运行混合/传统对照及三个负向用例，不需要管理员权限")
    demo.add_argument("--out", type=Path, default=Path("report/demo"))
    demo.add_argument("--openssl", default="openssl")
    demo.add_argument("--open", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "doctor":
            info = inspect_openssl(args.openssl)
            if args.json:
                print(json.dumps(info, ensure_ascii=False, indent=2))
            else:
                print("PQC EvidenceKit · 本机检查\n" + info["openssl_version"])
                supported = {g.lower() for g in info["supported_tls13_groups"]}
                for group in HYBRID_GROUPS:
                    print(f"  {'可用' if group.lower() in supported else '不可用'}  {group}")
                print("下一步：python3 -m pqc_evidencekit demo")
            return 0 if any(g.lower() in {s.lower() for s in info["supported_tls13_groups"]} for g in HYBRID_GROUPS) else 2
        if args.command == "demo":
            from .demo import run_demo
            result_path = run_demo(args.out, executable=args.openssl)
            if args.open:
                webbrowser.open(result_path.resolve().as_uri())
            return 0
        target = parse_target(args.target, args.servername)
        result = scan(target, args.out, executable=args.openssl, timeout=args.timeout, cafile=args.cafile,
                      insecure=args.insecure, groups=[g.strip() for g in args.groups.split(",")],
                      progress=lambda i, total, label: print(f"[{i}/{total}] {label}", flush=True))
        for item in result["assessment"].values():
            print(item["summary"])
        print("报告：" + str((args.out / "summary.html").resolve()))
        if args.open:
            webbrowser.open((args.out / "summary.html").resolve().as_uri())
        return result_exit_code(result)
    except (KitError, PermissionError) as exc:
        print("无法完成检测：" + str(exc), file=sys.stderr)
        if isinstance(exc, PermissionError):
            print("当前执行环境可能禁止网络连接；请在允许本机网络的终端运行。", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("检测已中断；保留已收集的日志，不作为完整结论。", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
