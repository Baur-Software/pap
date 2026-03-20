# Design System

See DESIGN.md for the complete design system (colors, typography, spacing, schema.org component mapping).

Key rules:
- Purple `#6c5ce7` is the brand color — never remove or replace it
- Wing spectrum colors have semantic meaning (teal=resolved, gold=in-progress, coral=error)
- All JSON-LD content is rendered as text only — never innerHTML
- Fonts: Satoshi (display), DM Sans (body), JetBrains Mono (code/DIDs)

# gstack

For all web browsing tasks, use the `/browse` skill from gstack. NEVER use `mcp__claude-in-chrome__*` tools.

Available gstack skills:
- `/office-hours` - Schedule and manage office hours
- `/plan-ceo-review` - Plan CEO review meetings
- `/plan-eng-review` - Plan engineering review meetings
- `/plan-design-review` - Plan design review meetings
- `/design-consultation` - Get design consultation
- `/review` - Review code and changes
- `/ship` - Ship features and releases
- `/browse` - Browse the web (use this for all web browsing)
- `/qa` - Run QA tests
- `/qa-only` - Run QA tests only
- `/design-review` - Conduct design reviews
- `/setup-browser-cookies` - Setup browser cookies for authenticated browsing
- `/retro` - Conduct retrospectives
- `/investigate` - Investigate issues and bugs
- `/document-release` - Document releases
- `/codex` - Access code documentation
- `/careful` - Enable careful mode for sensitive operations
- `/freeze` - Freeze changes
- `/guard` - Enable guard mode
- `/unfreeze` - Unfreeze changes
- `/gstack-upgrade` - Upgrade gstack to the latest version
