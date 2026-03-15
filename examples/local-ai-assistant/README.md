# Local AI Assistant — PAP Example

A personal AI assistant running entirely on your hardware, using PAP to safely interact with external services.

## What This Demonstrates

1. **Local-first AI**: Ollama runs your LLM locally. Your prompts never leave your machine.
2. **Zero-disclosure search**: SearXNG provides private web search. No query logging. No tracking.
3. **Selective disclosure**: Weather lookup discloses only a city name — no identity, no device info.
4. **Marketplace discovery**: The orchestrator finds providers at runtime. No pre-configured API keys.
5. **Ephemeral sessions**: Each service interaction uses throwaway session DIDs. No correlation possible.
6. **Auditable receipts**: Every interaction produces a signed receipt showing what *types* of data were shared.

## Architecture

```
[You] -> [Ollama LLM] -> [PAP Orchestrator] -> [Marketplace] -> [Provider Agents]
                                                      |
                                  +------------------+------------------+
                                  |                  |                  |
                            [SearXNG Agent]   [Weather Agent]   [Wikipedia Agent]
                            (zero disclosure) (city name only)  (zero disclosure)
```

The orchestrator is the **only** component that knows who you are. Every downstream agent sees an ephemeral session DID and only the data fields permitted by the mandate.

## Quick Start

```bash
# 1. Start all services (model is pulled automatically — no manual step needed)
docker compose up -d

# 2. Ask a question (triggers PAP handshake with external services)
curl http://localhost:9010/ask \
  -H "Content-Type: application/json" \
  -d '{"query": "What is the weather in Seattle and what is the population?"}'

# 3. View the disclosure audit log
curl http://localhost:9090/receipts | jq .
# Or open http://localhost:9090 in a browser
```

**First startup takes a few minutes** — Docker builds the Rust services and pulls the LLM model. Subsequent starts are fast (model is cached in the `ollama_data` volume).

## Configuration

Copy `.env.example` to `.env` to customize:

```bash
cp .env.example .env
```

| Variable | Default | Description |
|----------|---------|-------------|
| `LLM_MODEL` | `mistral` | Ollama model to pull and use. See `.env.example` for options. |
| `OPENWEATHER_API_KEY` | `demo` | OpenWeatherMap free-tier key ([get one here](https://openweathermap.org/appid)) |
| `SEARXNG_SECRET` | `pap-demo-secret` | SearXNG instance secret |

**Changing the model**: Update `LLM_MODEL` in `.env` and re-run `docker compose up -d`. The `ollama-pull` service will fetch the new model automatically.

## GPU Acceleration (NVIDIA)

For faster inference, overlay the GPU compose file:

```bash
# Install NVIDIA Container Toolkit first (one-time setup):
# https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/install-guide.html

docker compose -f docker-compose.yml -f docker-compose.gpu.yml up -d

# Verify GPU is visible to Ollama:
docker exec ollama nvidia-smi
```

## Using Host Ollama (already installed locally)

If Ollama is already running on your machine, you can skip the container entirely and save ~4 GB of RAM. Override the LLM URL when starting:

```bash
# macOS / Linux — host is reachable as host-gateway
LLM_URL=http://host.docker.internal:11434/api/generate \
  docker compose up -d --scale ollama=0 --scale ollama-pull=0

# The orchestrator will use your local Ollama instead of the container.
# Make sure your model is already pulled: ollama pull mistral
```

> **Note on Windows/WSL2**: `host.docker.internal` resolves automatically. On Linux, you may need to add `--add-host=host-gateway:host-gateway` to the orchestrator service, or use your machine's LAN IP.

## What You'll See

The orchestrator decomposes your question into sub-tasks, discovers providers via the marketplace, and executes each with a separate PAP session:

```
[mandate] Scope: [SearchAction, CheckAction], TTL: 8h
[marketplace] Found 3 providers for SearchAction (0 require personal disclosure)
[marketplace] Found 1 provider for CheckAction (requires: Place.name)
[session] Weather Agent: disclosed [Place.name: "Seattle"] via SD-JWT
[session] Private Search Agent: disclosed [] (nothing)
[session] Encyclopedia Agent: disclosed [] (nothing)
[receipt] Weather: {disclosed: ["schema:Place.name"], values: [REDACTED]}
[receipt] Search: {disclosed: [], values: []}
[receipt] Encyclopedia: {disclosed: [], values: []}
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| Ollama | 11434 | Local LLM inference |
| SearXNG | 8888 | Private metasearch engine |
| Marketplace | 9000 | PAP agent marketplace registry |
| Search Provider | 9001 | PAP-wrapped SearXNG |
| Weather Provider | 9002 | PAP-wrapped OpenWeatherMap |
| Wikipedia Provider | 9003 | PAP-wrapped Wikipedia API |
| Orchestrator | 9010 | PAP orchestrator + LLM integration |
| Receipt Viewer | 9090 | Disclosure audit log viewer (browser UI) |

## Startup Sequence

```
ollama          (starts, begins serving)
  └─► ollama-pull  (waits for healthy, pulls LLM model, exits 0)
        └─► orchestrator  (starts only after model is confirmed ready)
              └─► receipt-viewer
marketplace ──► search-provider, weather-provider, wikipedia-provider
searxng     ──► search-provider
```

No manual model-pull step. No race conditions on cold start.

## The Point

You asked about the weather. A normal assistant would send your IP address, device fingerprint, and account identity to a weather API. This assistant sent an ephemeral DID and the word "Seattle."

That's the difference between a tool that works for a platform and a tool that works for you.
