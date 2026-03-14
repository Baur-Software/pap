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
# Start all services
docker compose up -d

# Pull an LLM model
docker exec ollama ollama pull mistral

# Ask a question (triggers PAP handshake with external services)
curl http://localhost:9010/ask \
  -H "Content-Type: application/json" \
  -d '{"query": "What is the weather in Seattle and what is the population?"}'

# View the disclosure audit log
curl http://localhost:9090/receipts | jq .
```

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

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENWEATHER_API_KEY` | `demo` | OpenWeatherMap API key (free tier: openweathermap.org/appid) |
| `SEARXNG_SECRET` | `pap-demo-secret` | SearXNG instance secret |

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
| Receipt Viewer | 9090 | Disclosure audit log viewer |

## The Point

You asked about the weather. A normal assistant would send your IP address, device fingerprint, and account identity to a weather API. This assistant sent an ephemeral DID and the word "Seattle."

That's the difference between a tool that works for a platform and a tool that works for you.
