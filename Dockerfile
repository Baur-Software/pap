# Multi-stage build: compile PAP agents and utilities in a builder stage,
# then copy binaries into a slim runtime image.

# Stage 1: Builder
FROM rust:1.75 as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    libsodium-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace
COPY . .

# Build PAP agent runner (placeholder binary that would execute agents)
# In production, this would be a full agent executor with sandbox integration
RUN cargo build --release --bin pap-agent 2>/dev/null || true

# Stage 2: Runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    libsodium23 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy agent runner binary from builder (if it exists)
COPY --from=builder /build/target/release/pap-agent /usr/local/bin/pap-agent 2>/dev/null || true

# Fallback: minimal script that logs context receipt and exits with error.
# The real pap-agent binary handles full IPC; this placeholder signals
# that the build didn't produce one so the parent gets a clear failure.
RUN if [ ! -f /usr/local/bin/pap-agent ]; then \
  cat > /usr/local/bin/pap-agent << 'EOF'
#!/bin/bash
# Placeholder — real binary not built. Exit non-zero so parent
# surfaces the failure via ExecutionState::Failed rather than
# silently succeeding with empty output.
echo "pap-agent placeholder: binary not available" >&2
exit 1
EOF
  chmod +x /usr/local/bin/pap-agent; \
fi

# Default entrypoint: run agent executor
ENTRYPOINT ["/usr/local/bin/pap-agent"]
CMD []
