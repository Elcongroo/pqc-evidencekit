# PQC EvidenceKit

[English](README.en.md) · [手工实验](docs/manual-lab.zh.md) · [结果怎样解释](docs/evidence-model.zh.md) · [结构与扩展](docs/architecture.zh.md)

**检测一个 TLS 1.3 端点能否实际完成后量子混合密钥交换，并保存可复查的原始输出。**

你给出 `主机:端口`，工具用多组真实握手观察实际协商组，生成离线 HTML 和 JSON 报告。报告分别展示密钥交换、身份验证与握手签名，避免把“使用 ML-KEM”解读成“整个系统已经抗量子”。

当前版本是 TLS 1.3 MVP。Python 部分只用标准库；需要本机 OpenSSL 3.5 或更新版本及相应混合组。IKEv2/IPsec、自动 PCAP、密码函数追踪、网络性能与 MTU 测试尚未实现。

## 先跑本地演示

在仓库根目录执行。首次学习建议先看[手工实验](docs/manual-lab.zh.md)，逐步观察同一条握手路径；下面是日常复现入口。

```sh
python3 -m pqc_evidencekit doctor
python3 -m pqc_evidencekit demo --out report/demo
```

打开生成目录中的 HTML 报告。演示会创建新的临时证书，启动仅允许混合交换与仅允许传统交换的两个本地端点，检查结果差异并停止服务。演示不依赖外部网站，不需要管理员权限。

程序保留原始结果，拒绝覆盖已有内容的输出目录。重复运行时换成 `report/demo-run-02` 等新目录。

如果检查提示 OpenSSL 版本或混合组不足，指定已有的新版程序：

```sh
python3 -m pqc_evidencekit doctor --openssl /path/to/openssl
python3 -m pqc_evidencekit demo --openssl /path/to/openssl --out report/demo
```

`/path/to/openssl` 是需要替换的程序路径。Python 3.10+ 可以直接从本仓库运行，无须安装 Python 依赖。也可选用 `python3 -m pip install .` 安装到自己的环境。

## 检测自己的服务

把 `example.com` 替换为你准备测试的 TLS 服务域名：

```sh
python3 -m pqc_evidencekit scan example.com:443 --out report/site --open
```

默认验证证书信任链与服务身份，每次探测都启动一个新的 TLS 1.3 握手。`--open` 尝试打开本地报告；没有桌面的环境直接打开报告文件即可。

当连接地址与证书域名不同：

```sh
python3 -m pqc_evidencekit scan 192.0.2.10:443 \
  --servername gateway.example.com --cafile ./ca.pem --out report/gateway
```

这里的 IP 和域名是文档示例。`--servername` 指定 SNI 和预期身份，`--cafile` 指定可信 CA。IPv6 地址写成 `[::1]:8443`。

| 选项 | 用途 |
| --- | --- |
| `--openssl PATH` | 选择 OpenSSL 程序，适合系统默认版本较旧的机器 |
| `--servername NAME` | 指定 TLS SNI 与身份验证使用的名称 |
| `--cafile FILE` | 使用自己的 CA 信任文件 |
| `--timeout 8` | 单次探测超时秒数；超时结果为无法判定 |
| `--groups A,B,C` | 指定待测混合组，逗号分隔 |
| `--insecure` | 诊断时跳过身份验证；报告明确标注，结果不能算已验证身份 |
| `--open` | 生成后尝试打开 HTML 报告 |

默认测试 `X25519MLKEM768`、`SecP256r1MLKEM768`、`SecP384r1MLKEM1024`。程序先检查本机是否能提出相应组；客户端缺能力时，不据此否定服务器。

## 它回答哪些问题

| 探测 | 想观察的行为 |
| --- | --- |
| 本机 OpenSSL 默认配置 | 默认握手实际选中了什么 |
| 只提出传统 `X25519` | 传统对照连接能否建立 |
| 每个混合组单独提出 | 此端点在当前条件下能否完成该混合交换 |
| 混合组与 `X25519` 一起提出，交换排列顺序 | 同时提供两种 key share 时，实际使用哪一组 |

**成功完成经身份验证的混合握手，是该 TLS 终止端点在此次条件下具有对应协议能力的正向证据。** 握手失败、超时、访问策略拒绝或要求客户端证书，不能一概转换成“不支持 PQC”。

只允许混合组时失败、传统对照成功，可以报告“本次强制混合探测未成功”，但仍需检查服务策略、SNI、后端差异和网络条件。混合与传统同时允许时选中传统组，也可能是正常配置偏好；单次观测不能证明存在降级攻击。

若域名经过 CDN、反向代理或负载均衡，检测对象是可见的 TLS 终止点。它不会自动证明源站、代理到源站链路或整个网关数据面具有相同能力。详见[结果解释与证据边界](docs/evidence-model.zh.md)。

## 报告与退出状态

报告包含机器可读结果、可在浏览器打开的摘要、每次调用的原始日志与 SHA-256 清单：

```text
report/site/
├── summary.html
├── result.json
├── manifest.sha256
└── logs/
    ├── default.stdout.txt
    ├── default.stderr.txt
    └── ...
```

日志与报告保存在你指定的输出目录，默认 `report/` 被 Git 忽略；自选其他目录时需自行检查 Git 状态。不要把内部目标或实验密钥提交到公开仓库。

| 退出码 | 含义 |
| --- | --- |
| `0` | 观察到混合交换且服务身份验证通过；演示命令则表示预期对照通过 |
| `1` | 完成相关探测后未观察到混合交换，或混合提案被拒绝；不等于目标绝无 PQC 能力 |
| `2` | 无法判定，包括工具缺失、客户端能力不足、目标格式、身份验证或连接问题 |

`--insecure` 的观测可以辅助定位，但不满足“服务身份已验证”的成功条件。详细理由、每个探测状态及原始输出应一起读，不能只依据退出码作产品安全结论。

程序记录的过程耗时包括进程启动和连接等待，不能当作经过控制的纯握手性能基准。当前版本不输出虚构的 PCAP、调用追踪、证书链抗量子合规结论或数据面验证结论。

## 开发与验证

```sh
python3 -m unittest discover -s tests -v
PQC_EVIDENCEKIT_INTEGRATION=1 python3 -m unittest discover -s tests -v
```

第二条需要具有混合组能力的 OpenSSL，并运行真实本地演示。CI 默认运行 Python 3.10 与 3.13 的测试；手工启动工作流并启用集成选项时，会构建固定版本的上游 OpenSSL，再执行真实集成测试。环境缺失应明确失败或标为未运行，不能作为集成验证通过。

## 标准与实现参考

- [RFC 8446：TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html)：协商、CertificateVerify、Finished 与密钥派生的关系。
- [RFC 10024：TLS 1.3 的三种 PQ/T 混合组](https://www.rfc-editor.org/rfc/rfc10024.html)：本工具默认检测的具体组。
- [RFC 9954：TLS 1.3 混合交换的一般构造](https://www.rfc-editor.org/rfc/rfc9954.html)：理解组合机制与安全边界。
- [OpenSSL 3.5 s_client](https://docs.openssl.org/3.5/man1/openssl-s_client/)、[s_server](https://docs.openssl.org/3.5/man1/openssl-s_server/)：实际执行的客户端与演示服务端。
- [FIPS 203：ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)：算法标准；识别组名称不是实现认证。

代码采用 [MIT 许可证](LICENSE)。欢迎提交带工具版本、可复现条件、预期与实际结果的问题。公开材料中请使用本地演示或脱敏目标，保留原始结果与结论的区别。
