# PQC EvidenceKit

[中文](README.md) · [Manual localhost lab](docs/manual-lab.zh.md) · [Evidence boundaries](docs/evidence-model.zh.md)

**Observe whether a TLS 1.3 endpoint can complete post-quantum/traditional hybrid key establishment, with reproducible raw output.**

Give the CLI a `host:port`. It performs fresh handshakes with different group offers and writes offline HTML, JSON, raw OpenSSL output, and SHA-256 hashes. Key establishment, identity verification, and handshake signatures are reported separately.

This is a TLS 1.3 MVP using Python's standard library. It requires Python 3.10+ and OpenSSL 3.5+ with the requested hybrid groups available. IKEv2/IPsec, automatic packet capture, cryptographic function tracing, MTU testing, and controlled performance benchmarking are not implemented.

## Quick start

Run from the repository root:

```sh
python3 -m pqc_evidencekit doctor
python3 -m pqc_evidencekit demo --out report/demo
```

Open the generated HTML report. The demo creates a fresh temporary localhost certificate, starts hybrid-only and classical-only endpoints, checks the expected contrast, and stops them. No remote endpoint or administrator privileges are required. The [manual lab](docs/manual-lab.zh.md) explains the underlying commands before automation.

Existing nonempty output directories are never overwritten. Use a new directory such as `report/demo-run-02` when repeating a run.

Select a newer OpenSSL executable if your system version is too old:

```sh
python3 -m pqc_evidencekit doctor --openssl /path/to/openssl
python3 -m pqc_evidencekit demo --openssl /path/to/openssl --out report/demo
```

Replace `/path/to/openssl` with the actual executable. No Python runtime dependencies are needed. Installing with `python3 -m pip install .` is optional.

## Probe an endpoint

Replace the example domain with your TLS endpoint:

```sh
python3 -m pqc_evidencekit scan example.com:443 --out report/site --open
```

The default verifies the certificate trust chain and service identity. Each probe creates a fresh TLS 1.3 connection. To connect by address while verifying a DNS identity:

```sh
python3 -m pqc_evidencekit scan 192.0.2.10:443 \
  --servername gateway.example.com --cafile ./ca.pem --out report/gateway
```

These addresses are documentation examples. Bracket IPv6 addresses, e.g. `[::1]:8443`.

| Option | Purpose |
| --- | --- |
| `--openssl PATH` | Select the OpenSSL executable |
| `--servername NAME` | Set SNI and the expected service identity |
| `--cafile FILE` | Supply a custom trusted CA file |
| `--timeout 8` | Bound each probe; timeouts are inconclusive |
| `--groups A,B,C` | Select hybrid groups using comma-separated names |
| `--insecure` | Diagnostic observation without identity verification; explicitly labeled |
| `--open` | Try to open the generated HTML report |

The default groups are `X25519MLKEM768`, `SecP256r1MLKEM768`, and `SecP384r1MLKEM1024`. The local tool's capabilities are checked before drawing conclusions about a peer.

## What a result means

The probe set includes native OpenSSL defaults, classical-only `X25519`, each hybrid group alone, and mixed hybrid/classical offers in both orders, supplying both key shares. An authenticated completed hybrid handshake is positive evidence for that TLS terminator under those conditions.

A timeout, certificate failure, access policy, missing client certificate, or failed handshake does **not** establish that the peer lacks all PQC support. A mixed offer selecting a classical group can reflect a configured preference; it does not establish an active downgrade attack. CDN and reverse-proxy results describe the visible TLS termination point, not automatically the origin or an entire gateway.

A PQ hybrid key exchange does not imply PQ authentication. The TLS CertificateVerify signature and certificate issuer signatures have different roles. This release reports observable handshake signature information; it does not certify a complete PQ certificate chain or audit remote key derivation and randomness.

| Exit code | Meaning |
| --- | --- |
| `0` | A hybrid exchange was observed with verified identity; for the demo, the expected contrast passed |
| `1` | Relevant probes completed without observing a hybrid exchange, or a hybrid offer was rejected |
| `2` | Inconclusive: tooling, local capability, target format, identity, or connection issues |

Read the per-probe reasons and raw output with the exit code. `--insecure` observations do not meet the verified-identity success condition. Reported wall-clock durations include process and connection overhead; they are not isolated handshake benchmarks.

## Tests

```sh
python3 -m unittest discover -s tests -v
PQC_EVIDENCEKIT_INTEGRATION=1 python3 -m unittest discover -s tests -v
```

The second command requires a hybrid-capable OpenSSL and runs real local integration. CI tests Python 3.10 and 3.13 by default. The optional manual integration job builds a fixed upstream OpenSSL release, checks the required groups, and enables real integration tests. A missing environment must not masquerade as a passed integration test.

The default `report/` directory, certificates, and private keys are ignored by Git. If you choose a different output directory, check Git status yourself. The demo does not publish its temporary keys. Review files before sharing endpoint reports.

## Primary references

- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html)
- [RFC 10024 — concrete TLS 1.3 PQ/T hybrid groups](https://www.rfc-editor.org/rfc/rfc10024.html)
- [RFC 9954 — general hybrid construction](https://www.rfc-editor.org/rfc/rfc9954.html)
- [OpenSSL 3.5 s_client](https://docs.openssl.org/3.5/man1/openssl-s_client/) and [s_server](https://docs.openssl.org/3.5/man1/openssl-s_server/)
- [NIST FIPS 203 — ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)

Licensed under [MIT](LICENSE). Reproducible issue reports should distinguish raw observations, expected behavior, and the conclusion being proposed.
