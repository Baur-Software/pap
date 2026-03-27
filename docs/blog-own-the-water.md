# Own the Water, Not the Pipe

What happens when a platform discovers PAP and realizes the moat isn't where they thought it was?

## The Thought Experiment

Imagine GitHub discovers the Principal Agent Protocol. Not as a curiosity — as infrastructure. They look at Chrysalis, PAP's federated agent registry, and they see distribution. They pitch hosting a Chrysalis node for their users. Agents that search repos, surface CI failures, triage issues, query package dependencies — all running through PAP's six-phase handshake with cryptographic mandates and ephemeral sessions.

The first question is obvious: how does a user search their *private* repos through an anonymous protocol?

PAP uses ephemeral session DIDs. The whole point is that the agent on the other side of a transaction cannot identify the principal. So how does GitHub authorize access when it can't know who's asking?

This is where most people assume the protocol breaks. It's actually where it gets interesting.

## Credentials Travel With the User

Today, if an application wants to access your GitHub repos, it goes through OAuth. Register an app. Redirect the user. Exchange a code for a token. Store the token server-side. Refresh it. Handle revocation webhooks. Build a UI around the data. Every application repeats this ceremony independently. The token lives with the app, not with you.

In PAP, the credential lives in the user's wallet.

GitHub issues an SD-JWT — a selectively disclosable credential — bound to the user's GitHub identity. The user stores it in their PAP browser. When they want to search private repos, they attach the credential to their mandate, disclosing *only* the claims the agent needs: a username and an access scope. Their email, their real name, their principal DID — all redacted. The session DID that carries this mandate is ephemeral. When the session closes, it's gone.

The agent validates the credential, makes the authenticated API call, returns Schema.org JSON-LD results, and co-signs a receipt that contains property references only — never repo names, never code, never content.

GitHub sees that a valid GitHub user queried repos. They *cannot* correlate that query to a specific PAP principal, because the session DID is unlinkable by design.

## The Friction Collapse

But here's what makes this more than a privacy story.

Today's integration tax for accessing GitHub data:

1. Register an OAuth application
2. Implement the redirect flow
3. Exchange authorization codes for tokens
4. Store tokens securely server-side
5. Implement token refresh logic
6. Handle scope changes and revocations
7. Build your own UI around the API responses
8. Repeat for every single application that wants repo access

With PAP:

1. User has a GitHub credential in their wallet
2. They ask their PAP browser a question
3. The agent handles the rest

That's it. The OAuth dance disappears. The token storage liability disappears. The per-app registration disappears. The credential *travels with the user*, not with the app. Any PAP browser can use it. The user discloses it to whichever agent needs it.

And this cascades into everything.

**Cross-platform code search.** "Find where we handle authentication" works across GitHub, GitLab, and Bitbucket if each issues credentials. One query, three agents, the PAP browser orchestrates. Nobody builds that integration today because the auth plumbing per provider is brutal.

**CI visibility.** "Show me failing builds" becomes a mandate to a GitHub Actions agent. The disclosure is a username and `actions:read` scope. No dashboard tab-switching, no API client, no token juggling.

**Issue triage across organizations.** "What's assigned to me across all my orgs" is currently impossible without building a custom aggregator. With PAP, it's one natural-language query that fans out to however many org-scoped agents exist in the federation.

**Dependency auditing.** "Which of my repos use this vulnerable package" is a mandate to an agent that needs `repo:read` scope and returns structured vulnerability data. Today this requires Dependabot configuration per-repo, or a third-party SCA tool with its own OAuth integration, or a custom script that manages tokens for every org.

All of that friction dissolves. Not because the APIs changed, but because the *authorization model* changed. The credential is portable. The agent is stateless. The protocol handles the handshake.

## The Moat Moves

This is where platform operators need to pay attention, because the strategic implications are counterintuitive.

GitHub's current moat is the interface. You go to github.com, you log in, you use their UI. Every API integration reinforces this because every integration requires OAuth registration with GitHub as the identity provider and the session host.

With PAP, GitHub stops being the session host. The user's PAP browser is the session host. GitHub becomes a credential issuer and an agent provider. The UI monopoly dissolves.

At first glance, that looks like GitHub loses. They don't control the interface anymore.

But look at what they gain: **distribution**.

Every PAP browser becomes a GitHub client. Every Chrysalis node that federates GitHub's agents extends their reach. Developers who use Papillion, or whatever PAP browser they prefer, can search GitHub repos without ever opening github.com — but they need a GitHub-issued credential to do it.

GitHub doesn't need to build or maintain the interface. They don't need to support third-party OAuth integrations. They issue credentials, host agents, and collect the federation benefits.

The moat moves from "you must use github.com" to "you need a GitHub credential to access code." That's the difference between owning the pipe and owning the water.

Owning the pipe means you control distribution but you have to maintain the pipe. You build the UI, handle the sessions, manage the tokens, support the OAuth flows, run the webhooks. Every interaction transits your infrastructure.

Owning the water means you control *what flows through any pipe*. You issue the credential once. It works everywhere. Every PAP browser, every Chrysalis node, every federated agent — they all need your water. You maintain none of their pipes.

Which is the stronger position?

## What This Looks Like in Practice

The PAP codebase already has the plumbing for this. The `AgentExecutor` trait supports a `requires_disclosure` field on every agent's metadata. The IP Geolocation agent already requires `schema:IPAddress` disclosure — the pattern is proven in code, not just in theory.

A GitHub-hosted agent would declare `requires_disclosure: ["schema:DigitalCredential"]`. The user's PAP browser would see that requirement, check the wallet for a matching credential, prompt for consent, and attach the selective disclosure to the mandate. The agent would validate the SD-JWT, extract the authorized token, make the API call, and return results.

No new protocol features. No special cases. The same six-phase handshake that handles a zero-disclosure DuckDuckGo search handles an authenticated private-repo query. The only difference is what the user chooses to disclose.

## The Remaining Hard Problem

This isn't a pure privacy win. Correlation attacks are real.

GitHub could attempt timing correlation: this token was used at 3:47pm, and session DID `did:key:z6Mk...` connected at 3:47pm. They could attempt query fingerprinting: only user X has access to repos A, B, and C, and this session queried exactly those repos.

PAP mitigates this through protocol-level design — batched execution breaks timing correlation, context minimization ensures receipts never contain actual values, and progressive decay limits how long correlation windows exist. But mitigation isn't elimination. A sufficiently motivated host with access to both the credential and the connection metadata can narrow the anonymity set.

The honest answer is that PAP gives you *unlinkability by default* against casual correlation, and *plausible deniability* against active correlation. It does not give you absolute anonymity against a host that controls both the credential infrastructure and the agent infrastructure. If GitHub issues the credential and hosts the agent, they have both sides. The protocol makes correlation *harder* and *visible in the audit trail*, but not impossible.

That's a meaningful improvement over today, where correlation isn't just possible — it's the business model.

## The Bet

The friction collapse is real. Portable credentials eliminate the integration tax that makes every cross-platform workflow painful. Federated agents eliminate the UI lock-in that makes every platform a silo. Protocol-enforced context minimization eliminates the surveillance that makes every interaction a data extraction event.

But none of this happens unless platforms see credential issuance as more valuable than session ownership. That's the bet. It's a bet that distribution beats lock-in. That the water is worth more than the pipe.

Every previous generation of open standards eventually got captured by platforms that controlled the implementation. PAP's design makes that structurally difficult — ephemeral sessions can't be accumulated, receipts can't be mined, and mandates can't exceed their parent scope. But structural difficulty is not impossibility.

The protocol is open source. The reference implementation runs today. The agents are live. The question isn't whether this architecture works — it's whether platforms are ready to trade control of the interface for control of the credential.

History suggests they will. It just takes one to go first.

---

*The [Principal Agent Protocol](https://github.com/Baur-Software/pap) is open source under MIT. Papillion is the desktop reference browser. Chrysalis is the federated agent registry. You can clone the repo and run all of it right now.*
