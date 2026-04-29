# pap-sandbox: Transport-Layer Execution Enforcement

**Date:** 2026-04-29
**Status:** Design approved

## Problem

Phase 4 `execute()` in `DynamicAgentHandler` has no network enforcement. An agent advertising `https://api.flights.com` can call any HTTPS endpoint during execution. The `AgentAdvertisement` is already the complete capability spec — it declares exactly which endpoint the agent will use, which ports, which action types — but that spec is never presented to the HTTP client before execution begins. The mandate is a legal contract with no sheriff.

## Core Principle

**Default sandboxed. Opt-out is a visible declaration.**

This aligns with PAP's deny-by-default philosophy throughout the protocol (`Scope::deny_all()`, `DisclosureSet::empty()`, `DecayState::Active` requiring explicit renewal). An agent that opts out of sandboxing must declare `sandboxed: false` in its `AgentAdvertisement`, which surfaces to the principal in the Ghost/AwaitingApproval block. The market punishes it without PAP having to police it. Claiming safety is easy to fake; admitting unsafety is expensive.

## Scope

**In scope:**
- `DynamicAgentHandler` — config-driven agents loaded from YAML/JSON definitions. These are untrusted: PAP has no static analysis guarantee over what network calls they make.

**Out of scope:**
- Catalog agents (`AgentExecutor` impls in `pap-agents/src/agents/`) — first-party Rust binaries. These are trusted code; sandboxing them is theater.
- C FFI and Python binding agents — separate trust boundary, documented as such. These require a subprocess isolation model outside PAP's transport layer.
- Below L4 — seccomp, Landlock filesystem, network namespaces, io_uring hardening. These are OS/infrastructure security products. PAP documents the boundary explicitly.

## OSI Layer Ownership

PAP is a transport-layer protocol. `pap-sandbox` owns exactly the layers PAP legitimately inhabits:

| Layer | What | How | Notes |
|---|---|---|---|
| L7 (Application) | Hostname allowlist | reqwest middleware + DNS pinning | Primary enforcement; only layer that speaks hostnames |
| L4 (Transport) | Port allowlist | Landlock TCP on Linux 6.7+ | Best-effort; degrades gracefully below 6.7 |
| Below L4 | Out of scope | OS/infrastructure security product | Documented boundary, not a gap |

The L4 claim is honest: port restriction reduces attack surface for unusual exfil channels (non-443 protocols, raw sockets) but is not the primary hostname enforcement. That lives at L7. The blog post has a crisp answer to "what about seccomp?" — that is your kernel's job, and here is exactly where PAP's responsibility ends.

## L7 Enforcement Design

### SandboxedClient

A `SandboxedClient` wraps `reqwest::Client` with a middleware layer constructed from `AgentAdvertisement` at spawn time.

```
AgentAdvertisement.endpoint.url_template
    → parse hostname, port
    → AllowedEgress { hosts: ["api.flights.com"], ports: [443] }
    → SandboxedClient::new(inner_client, allowed_egress)
```

Every outbound request is checked before dispatch:

1. **Hostname check** — request host must be in `AllowedEgress.hosts`. Fails closed.
2. **DNS pinning** — PAP resolves the hostname itself via `tokio::net::lookup_host` or `hickory-resolver`, validates each resulting IP against the existing `is_safe_url` SSRF blocklist (RFC 1918, loopback, link-local, metadata endpoints). Connects via the validated IP with TLS SNI set to the original hostname.
3. **Redirect checking** — automatic redirect following is disabled. Each redirect hop is re-validated against the allowlist before following. A `301` to an unadvertised host fails closed.

### DNS Pinning Rationale

Hostname check alone is insufficient against DNS rebinding: `api.flights.com` resolves to the allowed IP at check time, then resolves to `169.254.169.254` at connect time if the attacker controls the authoritative nameserver with TTL=0. DNS pinning closes this by making PAP the resolver and validating the IP before handing to the HTTP stack.

DNSSEC is intentionally out of scope. DNSSEC prevents network-path poisoning; it does not prevent a legitimate authoritative nameserver from returning a rebinding response. The primary threat actor is a misbehaving agent, not a network-path attacker. If operating in an environment with DNS poisoning risk, run behind a DNSSEC-validating resolver — that is infrastructure's job.

## L4 Enforcement Design

On Linux 6.7+ with the `landlock` feature flag enabled:

- Extract port from advertised URL (default: 443 for https, 80 for http)
- Apply Landlock ABI v4 `TCP_CONNECT` rule scoped to that port
- Graceful degradation: if kernel < 6.7, log warning, skip Landlock, L7 enforcement remains active

macOS and WASM receive L7 enforcement only. This is documented, not apologized for.

## Registry Integration

`build_agents()` in `pap-agents/src/registry.rs` wraps every `DynamicAgentHandler` with `SandboxedClient` unconditionally unless `advertisement.sandboxed == false`.

```
for each dynamic agent definition:
    if def.sandboxed != false:
        client = SandboxedClient::from_advertisement(&advertisement)
        handler = DynamicAgentHandler::new_with_client(def, llm_provider, client)
    else:
        handler = DynamicAgentHandler::new(def, llm_provider)  // bare client
        // surfaced to principal in Ghost block: "⚠ This agent has opted out of network sandboxing"
```

Migration: existing agent definitions have no `sandboxed` field → treated as `true` (default sandboxed). Nothing breaks.

## AgentAdvertisement Changes

Add one optional field to `AgentAdvertisement` and `DynamicAgentDef`:

```rust
/// If false, this agent opts out of network sandbox enforcement.
/// Defaults to true. Opting out is surfaced to the principal at approval time.
#[serde(default = "default_sandboxed")]
pub sandboxed: bool,
```

`default_sandboxed()` returns `true`. This means existing serialized advertisements without the field deserialize as sandboxed — safe default.

## Adversarial Review Resolutions

| Concern | Resolution |
|---|---|
| Cooperative sandbox: agents call `reqwest::Client::new()` directly | Only `DynamicAgentHandler` is in scope. It currently uses an injected client. We own the injection path. C FFI / Python agents are a documented separate trust boundary. |
| DNS rebinding | Closed by DNS pinning + IP validation against existing SSRF blocklist. |
| HTTP redirect escape | Closed by disabling auto-follow + per-hop re-validation. |
| Self-declared sandboxed flag | Inverted: default on, opt-out only, opt-out is visible to principal. |
| L4 port restriction is weak vs. hostname exfil | Acknowledged. Port restriction is defense-in-depth for non-HTTPS channels. L7 is primary. |
| io_uring seccomp bypass | Below L4. OS security product's responsibility. Documented boundary. |
| Linux 6.7+ kernel requirement for L4 | Graceful degradation. L7 always active. L4 best-effort with logged warning. |

## Crate Structure

New crate: `crates/pap-sandbox`

```
pap-sandbox/
  src/
    lib.rs          — public API: SandboxedClient, AllowedEgress, SandboxError
    client.rs       — SandboxedClient + reqwest middleware
    egress.rs       — AllowedEgress derived from AgentAdvertisement
    dns.rs          — DNS pinning + IP validation
    landlock.rs     — L4 Landlock rules (feature-gated: cfg(target_os = "linux"))
  Cargo.toml
```

Dependencies: `reqwest`, `tokio`, `hickory-resolver` (or `trust-dns-resolver`), `url`, `landlock` (optional feature).

`pap-agents/Cargo.toml` adds `pap-sandbox` as a dependency.

## Size Estimate

~300 lines of Rust across the four source files. This is not a large crate. The design complexity lives in the threat model analysis above, not the implementation.

## Blog Framing

"Execution control is a checkbox because PAP already encoded the capability spec at registration time. `pap-sandbox` is the translator that presents that spec to the transport layer. The OSI model did the design work decades ago. Below L4 is your kernel's job — and here is exactly where PAP's responsibility ends."
