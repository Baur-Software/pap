# Project: Principal Agent Protocol (PAP)

PAP is **not a SaaS app or demo**—it's a protocol specification with a reference implementation in Rust. We're building a secure, privacy-preserving agent negotiation protocol that places the human principal at the root of trust.

## Key Architecture

- **Multi-crate Rust monorepo** under `crates/` (pap-core, pap-did, pap-credential, pap-transport, pap-federation, pap-marketplace, pap-proto, pap-webauthn)
- **Papillon** (under `apps/papillon/`) is a desktop reference implementation, not marketing material
- **Examples** in `examples/` demonstrate the full protocol surface (search, travel-booking, delegation-chain, payment, networked, federated, webauthn)
- **Python bindings** via PyO3 (`crates/pap-python/`) for broader language support

## Development Standards

- **SOLID principles** apply throughout—composition over inheritance, dependency inversion, single responsibility
- **Comprehensive tests** required for all features, especially cryptographic operations and protocol invariants
- **No mocking or shortcuts** in the core library—implementations must be real and spec-compliant
- **Specification-first**: Reference the RFC-style specification (docs/specification.md) as source of truth
- Decode `did:key` identities, W3C VCs, SD-JWTs, and JSON-LD according to the spec, not convenience

## Core Concepts (Never Remove)

- **Mandate-based delegation** with cryptographic scope/TTL bounds
- **Ephemeral session DIDs** unlinked to principal identity
- **Protocol-enforced context minimization** via SD-JWT selective disclosure
- **Co-signed transaction receipts** containing property references only—never values
- **Progressive decay states** (Active → Degraded → ReadOnly → Suspended)
- No novel cryptography, no central registry, no token economy

## Design System

See DESIGN.md for the complete design system (colors, typography, spacing, schema.org component mapping).

Key rules:
- Purple `#6c5ce7` is the brand color — never remove or replace it
- Wing spectrum colors have semantic meaning (teal=resolved, gold=in-progress, coral=error)
- All JSON-LD content is rendered as text only — never innerHTML
- Fonts: Satoshi (display), DM Sans (body), JetBrains Mono (code/DIDs)

## gstack

For all web browsing tasks, use the `/browse` skill from gstack. NEVER use `mcp__claude-in-chrome__*` tools.
