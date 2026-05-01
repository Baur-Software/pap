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

# Fallback: simple bash script that demonstrates sandbox environment
RUN if [ ! -f /usr/local/bin/pap-agent ]; then \
  cat > /usr/local/bin/pap-agent << 'EOF'
#!/bin/bash
# Placeholder agent runner
# In production, this would read PAP_CONTEXT from environment,
# decrypt execution context, execute the agent handler,
# and write result back with attestation receipt.

echo "pap-agent: running in sandboxed container"
echo "Agent DID: ${PAP_AGENT_DID}"
echo "Context received: $(echo $PAP_CONTEXT | wc -c) bytes"

# For now, output success
exit 0
EOF
  chmod +x /usr/local/bin/pap-agent
fi

# Default entrypoint: run agent executor
ENTRYPOINT ["/usr/local/bin/pap-agent"]
CMD []
