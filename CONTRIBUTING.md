# Contributing to PAP

PAP is published at draft stage specifically to invite feedback, objections, and alternative proposals.

## What We Want

- **Protocol-level feedback**: Does the trust model hold? Are there attack vectors we've missed? Can the capture test be tightened?
- **Competing implementations**: A Python or TypeScript implementation would prove the protocol is language-independent. If the spec is only readable in Rust, the spec is incomplete.
- **Integration patterns**: How to add PAP compliance to an existing LangChain agent, CrewAI workflow, or MCP tool provider.
- **Formal specification review**: The protocol currently lives in code. An RFC-style document needs adversarial review.
- **Real-world testing**: Run the examples against actual services. Where does the protocol break? What's missing?

## How to Contribute

### Issues

File an issue for:
- Protocol design questions or concerns
- Implementation bugs
- Missing test coverage
- Documentation gaps
- Feature requests (evaluated against the capture test)

### Pull Requests

1. Fork the repo
2. Create a feature branch from `main`
3. Write tests for new functionality
4. Ensure `cargo test --workspace` passes
5. Ensure `cargo clippy --workspace` has no warnings
6. Ensure `cargo fmt --all` is clean
7. Open a PR with a clear description of what changed and why

### The Capture Test

Every contribution is evaluated against a single question: **does this reduce or expand the attack surface for incumbent platform capture?**

Proposals that introduce new trusted third parties, centralize discovery, soften disclosure enforcement, or create compatibility with metering models should be evaluated as potential capture vectors first and protocol improvements second.

This is not a purity test. It is a design constraint. The protocol's value is that it structurally prevents the patterns that captured every previous generation of open standards.

## Code Style

- Rust stable toolchain
- `cargo fmt` for formatting
- `cargo clippy` with `-D warnings`
- Tests co-located with implementation (in `mod tests` blocks)
- All public types documented with `///` doc comments
- Examples should be self-contained and demonstrate a specific protocol feature

## Architecture Decisions

Major architectural changes should be discussed in an issue before implementation. This includes:
- New crates
- Changes to the mandate/session/receipt types
- New protocol phases or extensions
- Transport layer changes
- Federation protocol changes

## License

By contributing, you agree that your contributions will be licensed under the project's MIT OR Apache-2.0 dual license.
