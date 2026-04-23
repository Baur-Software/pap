# LinkedIn Post Options for PAP Launch

## Option A: The Provocation (Best for Engagement)

---

You searched for a stroller once. Now every website thinks you're pregnant. For six months.

That's not a bug. That's how the current internet works. One query. Forty-seven data brokers. A "pregnancy score" attached to your identity that affects insurance quotes and ad targeting. You can't undo it.

Now imagine every AI agent in your life — your assistant, your shopping agent, your health advisor — leaking context the same way. Except faster, more detailed, and fully automated.

Every agent protocol currently being built makes this worse, not better. A2A, MCP, ACP — none enforce context minimization at the protocol level. Privacy is voluntary. Session data is undefined. Disclosure is the developer's problem.

We built something different.

The Principal Agent Protocol (PAP) puts the human at the root of trust. Not the platform. Not the cloud provider. You.

- Your agent carries a cryptographic mandate from you. It can only do what you explicitly permit.
- SD-JWT selective disclosure: share your city for a weather lookup. Withhold your name, email, and device ID. Structurally.
- Ephemeral session DIDs: services can't correlate today's query with tomorrow's.
- Receipts record what *types* of data were shared. Never the values.

The repo is open source, written in Rust, with seven working examples you can run right now.

New blog post walks through five real-world scenarios — from shopping without being profiled, to medical queries without creating a permanent record, to B2B data rooms with instant revocation.

Blog: https://baursoftware.com/show-me-the-agents-pap-in-practice/
Repo: https://github.com/Baur-Software/pap

If you build agents, the question isn't whether they can talk to each other. The question is who they answer to.

#AI #Privacy #AgentProtocol #OpenSource #Rust #ZeroTrust

---

## Option B: The Technical Hook (Best for Developer Audience)

---

I've been reviewing the agent protocol landscape: A2A, MCP, ACP, AGNTCY, CrewAI, LangGraph, OpenAI Agents SDK.

Not one of them enforces context minimization at the protocol level. Not one defines session ephemerality as a guarantee. Not one has economic primitives for agent-to-agent transactions.

Privacy in every existing protocol is a stated principle, not an enforced constraint. MCP's own spec says it "cannot enforce these security principles at the protocol level." A2A's Secure Passport extension is voluntary. LangGraph's default is a shared scratchpad where every agent sees everything.

So we built PAP — the Principal Agent Protocol.

The design premise: the human principal is the root of trust. Every downstream agent carries a cryptographically verifiable mandate. Delegation cannot exceed parent scope. Sessions use ephemeral DIDs. Receipts contain property references, never values. The cloud is a stateless utility, not a relationship that accumulates your context.

Built on standards that already exist: WebAuthn, W3C DIDs, W3C VCs, SD-JWT, Schema.org, Oblivious HTTP. No new cryptography. No token economy. No central registry.

The Rust implementation ships with seven examples: zero-disclosure search, selective disclosure with SD-JWT, 4-level delegation chains, privacy-preserving payment, HTTP transport, federated marketplace discovery, and WebAuthn integration.

New post walks through five scenarios with docker-compose examples: local AI assistant with Ollama + SearXNG, private shopping agent, children's privacy, medical queries, and B2B data rooms.

https://baursoftware.com/show-me-the-agents-pap-in-practice/
https://github.com/Baur-Software/pap

MIT/Apache-2.0. Clone it. Run the tests. Tell me what breaks.

#AgentProtocol #Privacy #Rust #WebAuthn #DID #OpenSource

---

## Option C: The Story (Best for Broad Reach)

---

I Googled a mole once. Just checking if it was normal.

Within hours, I started seeing ads for cancer screening. Life insurance companies. Health supplements. The search was logged, sold to data brokers, and attached to my identity. My "health concern score" went up. I never had cancer. I had a normal mole.

Now imagine an AI agent doing this on your behalf — automatically, continuously, across every service it touches. That's where we're headed with current agent protocols. They're designed for platforms, not for people.

We spent the last few months building a different kind of protocol. One where:

Your AI asks a medical knowledge service about a mole. The service sees: "adult, dermatological inquiry." That's it. No name. No IP. No persistent ID. The session ends and the keys are thrown away.

You ask about the weather. The service sees an ephemeral ID and the word "Seattle." Not your name. Not your location history.

Your child researches volcanoes for school. YouTube sees: "minor, age 10-12, educational content." Not a name. Not a behavioral profile. Each session is unlinkable.

This is what the Principal Agent Protocol does. The human is the root of trust. Every agent carries a cryptographic mandate that limits what it can see and share. The protocol enforces it — not the developer, not the platform.

Open source. Rust. Seven working examples. New blog post with real-world scenarios:

https://baursoftware.com/show-me-the-agents-pap-in-practice/

Your agent should work for you, not for a platform.

#AI #Privacy #OpenSource #AgentProtocol

---

## Posting Strategy

**Recommended**: Post Option C (The Story) first — it has the broadest emotional resonance and is most likely to get reshares from non-technical audiences. Follow up 2-3 days later with Option B (Technical Hook) for the developer audience. Option A works as a comment-section conversation starter if the original post gets traction.

**Timing**: Tuesday or Wednesday, 8-10 AM Eastern. LinkedIn's algorithm favors posts that get engagement in the first 60 minutes.

**Engagement strategy**: Reply to every comment in the first 2 hours. Ask questions back. "What's your experience with agent privacy? Have you seen any protocol that actually enforces this?"
