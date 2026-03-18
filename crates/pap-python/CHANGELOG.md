# Changelog - PAP Python SDK

All notable changes to the Python SDK will be documented in this file.

## [Unreleased]

### Added
- Comprehensive README with API reference and examples
- Python SDK status documentation
- Type hints in docstrings

### Changed
- **SECURITY:** Upgraded pyo3 from 0.22.6 to 0.24+ (fixes RUSTSEC-2025-0020)
- Migrated all deprecated PyO3 0.24 APIs (`get_type_bound` → `get_type`)
- Improved error messages in exception hierarchy

### Fixed
- All compiler warnings eliminated (5 → 0)
- PyO3 buffer overflow vulnerability patched

## [0.1.0] - Not Yet Released

### Added
- Initial Python bindings for PAP protocol
- Complete key management (PrincipalKeypair, SessionKeypair)
- Mandate issuance and delegation
- Scope and disclosure constraints
- Selective disclosure JWT (SD-JWT)
- Marketplace registry with query API
- HTTP transport client (blocking API)
- Transaction receipts with co-signing
- Comprehensive test suite (511 lines, 50+ tests)
- Maturin build system with abi3 support

### Security
- Ed25519 signatures for all operations
- Memory-safe (PyO3 guarantees)
- No secret key export (security by design)

---

**Note:** This project follows [Semantic Versioning](https://semver.org/).
