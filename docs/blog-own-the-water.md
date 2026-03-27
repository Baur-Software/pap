# Own the Water, Not the Pipe

What happens when a platform discovers PAP and realizes the moat isn't where they thought it was?

## The Thought Experiment

Imagine GitHub discovers the Principal Agent Protocol. Not as a curiosity — as infrastructure. They look at Chrysalis, PAP's federated agent registry, and they see distribution. They pitch hosting a Chrysalis node for their users. Agents that search repos, surface CI failures, triage issues, query package dependencies — all running through PAP's six-phase handshake with cryptographic mandates and ephemeral sessions.

The first question is obvious: how does a user search their *private* repos through an anonymous protocol?

PAP uses ephemeral session DIDs. The whole point is that the agent on the other side of a transaction cannot identify the principal. So how does GitHub authorize access when it can't know who's asking?

This is where most people assume the protocol breaks. It's actually where it gets interesting.

## The Operator Holds the Credential

Today, every application that wants to access your GitHub repos goes through OAuth. Register an app. Redirect the user to GitHub. Exchange a code for a token. Store the token server-side. Refresh it. Handle revocation webhooks. Build a UI around the data. Every application repeats this ceremony independently. The token lives with the app. The session lives with GitHub. The user is the commodity that flows between them.

PAP inverts this.

A Chrysalis operator — a company, a university, a community host — runs a node with agents registered in the federation. The operator holds a GitHub App installation token, the same way a company today holds API credentials for the services its infrastructure depends on. When a user asks "search repos for authentication handlers," the query arrives via an ephemeral session DID, scoped by a cryptographic mandate with a TTL. The agent uses the operator's credential to call the GitHub API, returns Schema.org JSON-LD results, and co-signs a receipt that contains property references only — never repo names, never code, never content.

The user never touches a bearer token. The session DID is unlinkable to any previous session. The operator can't accumulate a user profile because the protocol won't let them — ephemeral sessions, scoped mandates, property-reference-only receipts. The operator holds the credential to GitHub. That's it. That's all they hold.

This is the same credential position as GitHub today. The difference is what else the operator holds — which in PAP's case is nothing.

## The Friction Collapse

But here's what makes this more than a privacy story.

Today's integration tax for accessing GitHub data through a third-party tool:

1. Register an OAuth application with GitHub
2. Implement the redirect flow
3. Exchange authorization codes for tokens
4. Store tokens securely server-side
5. Implement token refresh logic
6. Handle scope changes and revocations
7. Build your own UI around the API responses
8. Repeat for every single application that wants repo access

With a PAP operator:

1. Operator configures their GitHub App token once
2. Users query through any PAP browser
3. The agent handles the rest

The OAuth dance disappears. Per-user token storage disappears. The per-app registration disappears. The operator's credential serves every user on the node, and no user's identity is exposed to GitHub or to the operator. Any PAP browser can connect to the node. Users switch operators the way they switch DNS providers — invisibly, losslessly, because the relationship is with the protocol, not with the operator.

And this cascades into everything.

**Cross-platform code search.** "Find where we handle authentication" works across a GitHub operator, a GitLab operator, and a Bitbucket operator. One query, three agents, the PAP browser orchestrates. Nobody builds that integration today because the auth plumbing per provider is brutal. With operator-held credentials, the auth plumbing is the operator's problem, not the user's.

**CI visibility.** "Show me failing builds" becomes a mandate to a GitHub Actions agent on an operator's Chrysalis node. The operator's credential has `actions:read` scope. No dashboard tab-switching, no API client, no token juggling.

**Issue triage across organizations.** "What's assigned to me across all my orgs" is currently impossible without building a custom aggregator that holds tokens for every org. With PAP, it's one query that fans out to however many org-scoped operators exist in the federation. Each operator holds their own org's credentials. The user holds nothing.

**Dependency auditing.** "Which repos use this vulnerable package" is a mandate to an operator whose credential has `repo:read` scope. Today this requires Dependabot configuration per-repo, or a third-party SCA tool with its own OAuth integration, or a custom script that manages tokens for every org.

All of that friction dissolves. Not because the APIs changed, but because the *authorization model* changed. The credential is operator-held. The session is user-controlled. The protocol enforces the boundary between them.

## Why Incumbents Won't Do This

This is where the thought experiment breaks down — and where the real opportunity appears.

GitHub *could* run a Chrysalis node. The code is open source. The protocol is MIT-licensed. Nothing stops them. But running a Chrysalis node means accepting PAP's constraints: ephemeral sessions they can't track, scoped mandates they can't expand, receipts they can't mine. It means becoming a credential holder and agent host — and giving up session ownership, behavioral data, UI lock-in, and the entire capture stack that funds the business.

GitHub's moat isn't the credential. It's the pipe. OAuth, the web UI, Copilot's full-context access, API rate limits as a monetization lever, the billing relationship, the behavioral graph. The credential is one small piece of a total capture architecture. You can't use GitHub's credential without accepting all of it.

Asking GitHub to adopt PAP is asking them to voluntarily dismantle that architecture. History says incumbents don't do this. The innovator's dilemma isn't a pitch deck problem — it's a structural one. The existing revenue model makes the new model irrational, even when the new model is better for everyone including the incumbent in the long run.

## The New Incumbent

Which means the opportunity isn't getting GitHub to adopt PAP. It's that GitHub's entrenchment in capture creates the opening for someone who doesn't carry that baggage.

What does code hosting look like if it's PAP-native from day one?

No OAuth. No API keys. No rate limit tiers. Repos are agents. Search is a mandate. Access control is a credential the operator holds, not a permission in someone else's database. The operator runs a Chrysalis node with agents that serve code search, CI status, issue triage, dependency graphs — all through the standard six-phase handshake. Users connect from any PAP browser. They switch between operators the way they switch between search engines — by pointing somewhere else.

The new incumbent doesn't need to be a better GitHub. It needs to be a GitHub that *can't capture* — and make that the feature. The protocol enforces it structurally. Ephemeral sessions can't be accumulated. Receipts can't be mined. Mandates can't exceed their parent scope. These aren't policy promises — they're cryptographic invariants.

A platform built on PAP doesn't need a privacy policy because the protocol *is* the privacy policy. And unlike a privacy policy, it can't be amended by lawyers at 2am before a board meeting.

## The Operator Ecosystem

The real network effect isn't one platform adopting PAP. It's many operators running Chrysalis nodes, each holding credentials for the services their community needs.

A university runs a node with GitHub Education credentials and IEEE Xplore access. A company runs a node with their GitHub Enterprise token and internal APIs. A community runs a node with public API keys pooled from donations. Each operator federates with the others. A user on the university node can discover agents on the company node through federation, if the company publishes them.

The operators compete on quality of service, breadth of agents, and trust — not on data accumulation. Because they *can't* accumulate data. The protocol won't let them.

This is the ecosystem that makes the friction collapse real. Not one platform owning the water. Many operators, each holding a small amount of water, federated into a supply that no single platform controls.

## What This Looks Like in Code

The PAP codebase already has the plumbing for this. The `AgentExecutor` trait supports a `requires_disclosure` field on every agent's metadata. Thirteen agents are live — from zero-disclosure public API agents (DuckDuckGo, Wikipedia, arXiv) to disclosure-required agents (IP Geolocation, Web Page Reader) to the bridge pattern previewed by the GitHub Repos agent.

The public GitHub agent works today with zero authentication: 60 requests per hour, public repos only. The doc comment on line 8 of the implementation already describes the next step: *"Previews the bridge pattern: an operator holding a PAT gets 5000 req/hr, demonstrating how operator credentials enhance service without exposing user identity."*

That operator credential is a deployment configuration, not a protocol change. The agent code stays the same. The operator adds a `GITHUB_TOKEN` environment variable. The `AgentExecutor::execute()` method reads it and adds an `Authorization: Bearer` header. The user's query arrives via ephemeral session, gets answered with the operator's credential, and the session closes. No protocol changes. No new disclosure types. No credential relay.

The protocol already handles everything. The question is who runs the node.

## The Bet

The friction collapse is real. Operator-held credentials eliminate the integration tax that makes every cross-platform workflow painful. Federated agents eliminate the UI lock-in that makes every platform a silo. Protocol-enforced context minimization eliminates the surveillance that makes every interaction a data extraction event.

But none of this happens unless someone builds the first Chrysalis node that matters — one with enough useful agents, enough operator credibility, and enough federation reach that a user chooses it over going directly to github.com.

That's the bet. Not that GitHub will adopt PAP. That someone will build the thing that makes GitHub's capture model feel like what it is: a tax on every developer interaction, collected in behavioral data, enforced by lock-in.

Every previous generation of open standards eventually got captured by platforms that controlled the implementation. PAP's design makes that structurally difficult — ephemeral sessions can't be accumulated, receipts can't be mined, and mandates can't exceed their parent scope. But structural difficulty is not impossibility.

The protocol is open source. The reference implementation runs today. The agents are live. The question isn't whether this architecture works — it's whether someone is ready to be the operator that proves the model.

History says someone will. The incumbents always look entrenched — until they don't.

---

*The [Principal Agent Protocol](https://github.com/Baur-Software/pap) is open source under MIT. Papillion is the desktop reference browser. Chrysalis is the federated agent registry. You can clone the repo and run all of it right now.*
