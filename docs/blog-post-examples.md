# Show Me the Agents: PAP in Practice

The [first post](https://baursoftware.com/your-agent-works-for-a-platform-it-should-work-for-you/) introduced the Principal Agent Protocol and walked through the proof-of-concept examples. The protocol primitives work. The question that matters now: what would you actually build with this?

This post answers that question with five concrete scenarios. Each one exercises a different combination of protocol features. Each one is designed to make a specific problem viscerally obvious — and then show what the same interaction looks like when the human principal controls the trust chain.

## The Landscape: Protocols Without Privacy

Before the scenarios, a quick orientation on why PAP exists.

Six months into the agent protocol race, here is where we stand:

**Google A2A** defines agent cards and task lifecycle. Privacy is an "opacity principle" — aspirational, not enforced. No context minimization. No session ephemerality. Auth formalization is still on the roadmap.

**Anthropic MCP** connects models to tools and data sources. It does this well. But it is not an agent-to-agent protocol. There is no concept of agents negotiating with other agents, no selective disclosure, and no mechanism for the principal to constrain what the model shares with tools at the protocol level. MCP's security principles are stated, not enforced — the spec itself says this.

**Microsoft Semantic Kernel / AutoGen** assumes all agents in the system trust each other. Identity is Azure AD. The trust boundary is the Microsoft ecosystem.

**ACP** handles REST-based agent interoperability. Thin trust layer. No cryptographic identity. Now merging governance with A2A.

**Every framework** — CrewAI, LangGraph, OpenAI Agents SDK — treats privacy as an implementation detail. LangGraph's default pattern is a shared scratchpad where every agent sees everything. None enforce context minimization. None define session ephemerality. None have economic primitives.

The common thread: **no existing protocol enforces context minimization at the protocol level.** Disclosure is always voluntary. Session residue is always undefined. Privacy is always somebody else's problem.

PAP makes it the protocol's problem.

## Scenario 1: Your AI Assistant Uses Tools Without Leaking Your Identity

The simplest scenario. The one every developer building on top of a local LLM will hit immediately.

**The setup**: You run Mistral (or Llama, or Phi) via Ollama on your laptop. You ask: "What's the weather in Seattle and what's the latest news about renewable energy?"

**What happens today**: Your assistant calls OpenWeatherMap and Brave Search with your API keys. Those services log your IP, your auth identity, and every query. Your weather lookups are correlated with your search history. Over time, the services build a profile of your interests and location patterns.

**What happens with PAP**: Your orchestrator agent issues a mandate scoped to `[SearchAction, CheckAction]` with an 8-hour TTL. It queries the local marketplace for providers. SearXNG (self-hosted, zero-disclosure) handles search. OpenWeatherMap handles weather — but receives only an ephemeral session DID and the word "Seattle" via SD-JWT selective disclosure. Your name, IP, and device ID are cryptographically withheld. The session closes. The DID is discarded. Tomorrow's weather query is unlinkable to today's.

```
[mandate] Scope: [SearchAction, CheckAction], TTL: 8h, Disclosure: minimal
[marketplace] Found 3 providers for SearchAction (0 require personal disclosure)
[marketplace] Found 1 provider for CheckAction (requires: Place.name only)
[session] Weather: disclosed [Place.name] via SD-JWT. Values: never in receipt.
[session] Search: disclosed [] (nothing).
[receipt] Signed by both parties. Auditable. Contains zero personal data.
```

**The docker-compose version** is in the repo: `examples/local-ai-assistant/`. Ollama, SearXNG, a PAP marketplace, three provider agents (search, weather, encyclopedia), an orchestrator, and a receipt viewer. `docker compose up -d` and you're running it.

**What this proves**: tool use does not require identity disclosure. The protocol enforces this. The application developer does not have to remember to strip headers or rotate API keys. The mandate says what can be disclosed. The SD-JWT makes it structurally impossible to disclose more.

## Scenario 2: Shopping Without Becoming a Target

You searched for a stroller once. Now every website thinks you are pregnant. For six months.

This is not an exaggeration. It is how behavioral advertising works. A single search query triggers profile updates across dozens of data brokers. Your "pregnancy score" affects insurance quotes, ad targeting, and financial product recommendations. You cannot undo it.

**With PAP**: Your personal agent searches for strollers via SearXNG (zero disclosure). It contacts retailer agents via the marketplace. The mandate permits disclosure of: shipping region (zip prefix only) and budget range. Retailer agents compete on price and features without knowing who you are.

The marketplace does the filtering before the negotiation starts. An agent that requires your full name, email, and phone number to show you stroller prices? It never appears in the results. The mandate cannot satisfy its disclosure requirements, so the marketplace excludes it.

Three retailers respond. You pick one. Your agent handles payment through a privacy-preserving channel (Chaumian ecash proof — the vendor receives proof of value transfer but nothing that identifies the payer). The stroller arrives. The internet has no memory of your search.

**What the demo shows**: A split screen. Left side: the normal flow — your query propagating through data brokers, profile updates, ad targeting. Right side: the PAP flow — three vendor agents competing, disclosure requirements color-coded (green = minimal, red = excessive), ephemeral sessions, and a final receipt showing exactly what was shared. The contrast is the entire argument.

## Scenario 3: Your Child Online Without Surveillance Capitalism

Your 11-year-old wants to look up volcanoes for a school project. You want them to be safe. YouTube wants to build a psychological profile that will follow them for the rest of their lives.

By age 13, a child has a shadow profile across dozens of platforms that predicts their vulnerabilities, insecurities, and spending triggers. COPPA technically requires consent. The "consent" is a checkbox you clicked once.

**With PAP**: You are the trust root. Your child's agent carries a mandate delegated from your keypair. The mandate specifies:

- Scope: `education.content` (not social, not shopping, not entertainment)
- Disclosure: `age_range: 10-12` via SD-JWT. Nothing else. No name, no school, no persistent ID.
- TTL: 2 hours per session. Auto-expire. No continuity tokens issued.
- Policy: approve educational content automatically, flag entertainment, block in-app purchases.

Each content request uses a new session DID. The platform cannot correlate Monday's volcano search with Tuesday's dinosaur search. There is no longitudinal behavioral profile because there is no continuity for the protocol to leak.

**The protocol feature that matters**: marketplace disclosure filtering. Content providers that require student identity, behavioral data, or engagement metrics are excluded before any connection is made. Your child never even sees the privacy-hostile option.

## Scenario 4: Medical Questions Without a Permanent Record

You have a weird mole. You want to know if it is something to worry about. You Google it.

You have now altered your insurance risk profile. Health-adjacent data brokers flag you as "cancer concern." If you apply for life insurance, the underwriter's data vendor may surface your search history as a risk signal. You never had cancer. You had a normal mole. But the data says you were worried, and that data never expires.

**With PAP**: Your local LLM does initial triage — no network call. If it needs external data, it queries a medical knowledge service via PAP. The SD-JWT discloses: `adult, dermatological inquiry`. Nothing else. The session DID is ephemeral. The service cannot link this query to any identity. The receipt records `[subject: dermatology]` — never the question you asked or the answer you received.

You book a dermatologist appointment. Only at that point does your agent ask: "The booking service needs your name and insurance ID. Approve?" You approve. The booking agent receives exactly two fields. The medical knowledge service never learns your name. Your insurance company sees a routine dermatology visit, not a cancer scare.

**The protocol feature that matters**: information flow isolation between scopes. Data obtained under the `health.research` scope cannot cross into the `health.booking` scope. This is enforced by the mandate chain, not by application logic.

## Scenario 5: B2B Data Exchange with Revocable, Scoped Access

During M&A due diligence, Company A's legal agent needs to share financial documents with Company B's analysis agent. Requirements that OAuth cannot satisfy:

1. Access must be revocable at any moment by Company A's principal.
2. Company B's agent should see specific fields (revenue, headcount) but not others (customer names, contracts).
3. Every access must produce a non-repudiable receipt.
4. The relationship should survive across weeks without re-authentication.

**With PAP**: Company A issues a continuity token to Company B's agent. The token carries a 30-day TTL set by Company A (not Company B's preference). The mandate permits `ReadOnly` access to financial summaries. SD-JWT selective disclosure ensures Company B sees `revenue: $15M, headcount: 120` but never customer names or contract details — the SD-JWT payload structurally cannot reveal fields excluded by the mandate.

Every access generates a signed receipt: `[accessed: financials.revenue, financials.headcount at 14:32 UTC]`. No values in the receipt — just property references. During a regulatory audit, Company A can prove exactly what categories of data were shared and when, without exposing the actual numbers.

Company A revokes access mid-diligence? Delete the continuity token. Company B's next request fails with a signed revocation proof. There is no stale token floating in a cache somewhere. Revocation is instant because the token is the relationship.

**The protocol feature that matters**: continuity tokens with principal-controlled TTL. The vendor (Company B) retains nothing. The relationship exists only because the principal (Company A) holds the token and chooses to present it.

## What These Scenarios Have in Common

Every scenario follows the same pattern:

```
[Principal] -> [Mandate with scoped permissions]
    -> [Orchestrator discovers providers via marketplace]
        -> [SD-JWT selective disclosure per interaction]
            -> [Ephemeral session DIDs, no correlation]
                -> [Signed receipts, no stored values]
                    -> [Session closes, keys discarded]
```

And every scenario makes the same argument: the privacy gap in agent-to-agent communication is not a feature request. It is an architectural flaw in every protocol currently deployed. Policy-based privacy fails at agent scale because agents follow instructions, and the instructions come from whoever designed the agent — not necessarily from the principal the agent claims to serve.

PAP makes the principal's intent cryptographically bound to every interaction. Not by policy. Not by configuration. By the mandate chain that every downstream agent must verify before it can act.

## Try It

The repo has seven working examples. Four exercise the core protocol (search, travel-booking, delegation-chain, payment). Three exercise the transport and federation layers (networked-search, federated-discovery, webauthn-ceremony). The local AI assistant docker-compose brings them together with real services.

```bash
git clone https://github.com/Baur-Software/pap.git
cd pap
cargo test                           # all tests
cargo run --bin search               # zero disclosure
cargo run --bin travel-booking       # selective disclosure
cargo run --bin delegation-chain     # hierarchical trust
cargo run --bin payment              # protocol extensions
cargo run --bin networked-search     # HTTP transport
cargo run --bin federated-discovery  # marketplace federation
```

The protocol is in the types. The constraints are in the compiler. The trust model is in the signatures.

If you build agents, the question is not whether they can talk to each other. The question is who they answer to.

---

*Todd Baur is the founder of [Baur Software](https://baursoftware.com). PAP is open source under MIT/Apache-2.0. The repo is at [github.com/Baur-Software/pap](https://github.com/Baur-Software/pap). Comments, objections, and alternative proposals are the point of publishing at draft stage.*
