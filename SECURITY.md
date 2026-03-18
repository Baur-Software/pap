# Security Advisory - PAP Protocol

**Last Updated:** 2026-03-18
**Audit Version:** 1.0

## Current Security Status

✅ **Core Protocol: SECURE**
🔴 **Python Bindings: Requires Attention**

---

## Active Vulnerabilities

### 🔴 CRITICAL: pyo3 Buffer Overflow (RUSTSEC-2025-0020)

**Affected Component:** `pap-python` crate (Python bindings)
**CVE:** Not yet assigned
**CVSS Score:** TBD (estimated 7.5 - HIGH)

#### Description
Buffer overflow risk in `PyString::from_object` method in pyo3 versions < 0.24.1. This vulnerability affects the Python bindings only - the core Rust protocol implementation is NOT affected.

#### Impact
- **Scope:** Python bindings (`pap-python`) ONLY
- **Core Protocol:** ✅ NOT AFFECTED
- **Rust Users:** ✅ NOT AFFECTED
- **Python Users:** ✅ **FIXED** (pyo3 upgraded to 0.24+)

#### Mitigation
```toml
# COMPLETED - pap-python/Cargo.toml
[dependencies]
pyo3 = { version = "0.24", features = ["extension-module", "abi3-py38"] }
```

#### Timeline
- **Discovered:** 2026-03-18 (via cargo-audit)
- **Fixed:** 2026-03-18 (pyo3 upgraded, all deprecations fixed)
- **Status:** ✅ **RESOLVED**
- **Verification:** `cargo check --package pap-python` - zero warnings

---

## Warnings

### ⚠️ rustls-pemfile Unmaintained (RUSTSEC-2025-0134)

**Affected Component:** `pap-transport`, `pap-federation` (via reqwest)
**Severity:** LOW

#### Description
The `rustls-pemfile` dependency (used transitively via reqwest) is no longer actively maintained. No known exploits exist.

#### Impact
- No immediate security risk
- May lack future security patches

#### Mitigation
- Monitor for maintained replacement
- Consider updating reqwest to version that uses alternative
- Track: https://github.com/rustls/pemfile/issues

---

## Security Best Practices

### For Protocol Users

1. **TLS Required:** Always use HTTPS for `pap-transport` (PAP does not implement TLS)
2. **Key Management:** Store Ed25519 private keys securely (HSM, encrypted storage)
3. **Nonce Tracking:** Maintain persistent nonce consumed set to prevent replay attacks
4. **Mandate Validation:** Always verify mandate chains before trusting delegated agents
5. **Audit Receipts:** Regularly review transaction receipts for anomalies

### For Developers

1. **Dependencies:** Run `cargo audit` before releases
2. **Testing:** All crypto code has >90% test coverage
3. **Fuzzing:** Consider fuzzing signature verification and disclosure hashing
4. **Code Review:** All PRs require review for crypto changes
5. **Static Analysis:** CI enforces zero Clippy warnings

---

## Reporting Security Issues

**DO NOT** open public GitHub issues for security vulnerabilities.

### Responsible Disclosure

Email: security@baur.software
PGP Key: (TODO: add PGP key)

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if available)

### Response Timeline

- **Acknowledgment:** Within 48 hours
- **Initial Assessment:** Within 1 week
- **Fix Development:** Depends on severity (critical: <48h, high: <1 week)
- **Public Disclosure:** After fix is released (coordinated disclosure)

---

## Security Audit History

| Date | Auditor | Scope | Findings | Report |
|------|---------|-------|----------|--------|
| 2026-03-18 | Claude Code (Sonnet 4.5) | Full codebase | 1 vuln, 1 warning | [AUDIT_REPORT.md](AUDIT_REPORT.md) |

---

## Cryptographic Guarantees

### What PAP Guarantees

✅ **Ed25519 Signature Verification:** All mandates, tokens, receipts cryptographically signed
✅ **Nonce Replay Prevention:** Single-use tokens via nonce tracking
✅ **Mandate Chain Integrity:** Hash-linked, scope/TTL constraints enforced
✅ **Selective Disclosure:** SD-JWT with hash commitments (unlinkability)
✅ **Receipt Immutability:** Co-signed by both parties, append-only

### What PAP Does NOT Guarantee

❌ **Transport Security:** You must use HTTPS/TLS
❌ **Key Storage:** You must secure private keys
❌ **Payment Anonymity:** Relies on external ecash systems (Chaumian mints)
❌ **DID Resolution:** You must implement DID lookup (we only use did:key)

---

## Dependencies Security

### Critical Dependencies

| Crate | Version | Security Notes |
|-------|---------|----------------|
| ed25519-dalek | 2.2 | ✅ Industry standard, actively maintained |
| sha2 | 0.10 | ✅ FIPS 180-4 compliant |
| chrono | 0.4 | ✅ No known CVEs |
| axum | 0.8 | ✅ Memory-safe HTTP framework |
| reqwest | 0.12.12 | ✅ Pinned, secure version |
| **pyo3** | **0.22.6** | **🔴 UPGRADE TO 0.24.1** |
| rustls-pemfile | 2.2.0 | ⚠️ Unmaintained (low risk) |

---

## Update Policy

- **Critical vulnerabilities:** Patch within 48 hours
- **High severity:** Patch within 1 week
- **Medium/Low severity:** Include in next minor release
- **Dependency updates:** Monthly `cargo update` + audit

---

## Contact

**Security Team:** security@baur.software
**General Issues:** https://github.com/Baur-Software/pap/issues
**Audit Requests:** Reach out via email for professional audits

---

**This document is part of the Principal Agent Protocol (PAP) security documentation.**
**For technical details, see [AUDIT_REPORT.md](AUDIT_REPORT.md)**
