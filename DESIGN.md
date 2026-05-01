# Papillon Design System

The butterfly logo is the foundation. Its bilateral symmetry represents the **operator** (left wing) and **orchestrator** (right wing). The body is the **zero-trust boundary** — nothing crosses without proof.

This is a consumer desktop application. Not a SaaS dashboard.

## Logo

`apps/papillon/icons/icon.png` — multicolored butterfly with a spectrum from teal-green through gold to coral-pink, with purple anchoring the base.

## Typography

| Role    | Family         | Fallback                     | Usage                         |
|---------|----------------|------------------------------|-------------------------------|
| Display | Satoshi        | -apple-system, sans-serif    | Headings, canvas names        |
| Body    | DM Sans        | -apple-system, sans-serif    | UI text, labels, descriptions |
| Mono    | JetBrains Mono | SF Mono, monospace           | DIDs, keys, JSON-LD, code     |

### Type Scale

| Name  | Size | Weight | Letter-spacing | Font    |
|-------|------|--------|----------------|---------|
| H1    | 32px | 700    | -0.02em        | Display |
| H2    | 22px | 700    | -0.01em        | Display |
| Body  | 15px | 400    | 0              | Body    |
| UI    | 13px | 400    | 0              | Body    |
| Label | 11px | 500    | 0.08em upper   | Mono    |
| Mono  | 13px | 400    | 0              | Mono    |
| Small | 12px | 400    | 0              | Mono    |

## Color Palette — Wing Spectrum

Colors are extracted from the butterfly logo and mapped to semantic meanings.

### Brand

| Token           | Value                       | Usage                     |
|-----------------|-----------------------------|---------------------------|
| `--purple`      | `#6c5ce7`                   | Brand, identity, actions  |
| `--purple-hover`| `#7f6ff0`                   | Interactive hover state   |
| `--purple-muted`| `rgba(108, 92, 231, 0.12)`  | Subtle backgrounds        |
| `--purple-glow` | `rgba(108, 92, 231, 0.25)`  | Focus rings, emphasis     |

### Wing Spectrum — Semantic

| Token     | Value     | Meaning                         |
|-----------|-----------|----------------------------------|
| `--teal`  | `#2ec4a0` | Resolved, trust confirmed        |
| `--gold`  | `#f0a030` | In-progress, agent working       |
| `--coral` | `#e8706a` | Error, attention, trust broken   |
| `--blue`  | `#5098e0` | Information, neutral status      |
| `--rose`  | `#e060a0` | Delight — use sparingly          |

### Surfaces — Dark Mode

| Token            | Value     |
|------------------|-----------|
| `--bg-0`         | `#0c0b14` |
| `--bg-1`         | `#151420` |
| `--bg-2`         | `#1f1e2e` |
| `--bg-3`         | `#2a2940` |
| `--text-1`       | `#eeeef2` |
| `--text-2`       | `#9494a8` |
| `--text-3`       | `#6a6a80` |
| `--border`       | `#2c2b40` |
| `--border-subtle`| `#222136` |

### Surfaces — Light Mode

| Token            | Value     |
|------------------|-----------|
| `--bg-0`         | `#faf9fc` |
| `--bg-1`         | `#f0eff5` |
| `--bg-2`         | `#e6e5ee` |
| `--bg-3`         | `#d8d7e2` |
| `--text-1`       | `#1a1928` |
| `--text-2`       | `#5c5b70` |
| `--text-3`       | `#8888a0` |
| `--border`       | `#d0cfdc` |
| `--border-subtle`| `#e2e1ec` |

## Spacing & Radius

| Token      | Value |
|------------|-------|
| `--sp-2xs` | 2px   |
| `--sp-xs`  | 4px   |
| `--sp-sm`  | 8px   |
| `--sp-md`  | 16px  |
| `--sp-lg`  | 24px  |
| `--sp-xl`  | 32px  |
| `--sp-2xl` | 48px  |
| `--sp-3xl` | 64px  |
| `--r-sm`   | 4px   |
| `--r-md`   | 8px   |
| `--r-lg`   | 12px  |

## Schema.org to Component Mapping

Agents return JSON-LD with `@type` fields. The frontend renders type-specific card components. All values are rendered as **text only** — never innerHTML — per security spec.

Source: `frontend/src/components/block_renderer/` (module directory: `mod.rs`, `blessed.rs`, `generic.rs`, `field_classify.rs`, `receipt.rs`)

### FlightReservation

Route display card with departure/arrival airports, date, price, carrier.

| JSON-LD Field      | Rendered As              |
|--------------------|--------------------------|
| `departureAirport` | Left side of route arrow |
| `arrivalAirport`   | Right side of route arrow|
| `departureDate`    | Date line                |
| `totalPrice`       | Price (teal/success)     |
| `airline`          | Carrier label            |

CSS: `.typed-flight`, `.typed-flight-route`, `.typed-flight-date`, `.typed-flight-price`, `.typed-flight-carrier`

### LodgingReservation

Hotel card with name, check-in/check-out dates, total price.

| JSON-LD Field  | Rendered As         |
|----------------|---------------------|
| `name`         | Hotel name (bold)   |
| `checkinDate`  | Left side of arrow  |
| `checkoutDate` | Right side of arrow |
| `totalPrice`   | Price (teal/success)|

CSS: `.typed-hotel`, `.typed-hotel-name`, `.typed-hotel-dates`, `.typed-hotel-price`

### SearchResultsPage / SearchAction

List of search results returned from DuckDuckGo or Wikipedia agents.

| JSON-LD Field     | Rendered As              |
|-------------------|--------------------------|
| `results[].title` | Result title (purple)    |
| `results[].url`   | URL in mono              |
| `results[].snippet` | Description text       |

CSS: `.typed-search-results`, `.typed-search-item`, `.typed-search-title`, `.typed-search-url`, `.typed-search-snippet`

### Answer (on-device LLM)

Text response from the on-device Mistral model. Rendered as a clean paragraph via dedicated blessed renderer.

CSS: `.typed-answer`, `.typed-answer-text`

### Generic Renderer

Any `@type` without a blessed renderer is handled by the schema-driven generic renderer. It classifies each field by shape (date, price, URL, DID, nested typed object, list) and renders with appropriate visual treatment. Recurses into nested objects with a depth limit of 4. CSS classes are sanitized and list items capped at 50.

CSS: `.typed-generic`, `.typed-label`, `.typed-field`, `.typed-key`, `.typed-val`, `.typed-field-date`, `.typed-field-price`, `.typed-field-url`, `.typed-field-did`, `.typed-nested`, `.typed-list`, `.typed-truncated`

## Block States

Every canvas block follows a lifecycle:

| State       | Visual                             | CSS Class              |
|-------------|-------------------------------------|------------------------|
| Resolving   | Phase dots + skeleton shimmer       | `.canvas-block.resolving` |
| Resolved    | Typed content card                  | `.canvas-block`           |
| Failed      | Phase dots (red) + error + retry    | `.canvas-block.failed`    |

Phase dots show handshake progress (1-6 phases). See `PhaseDots` component.

## Canvas Layout

- **Empty canvas**: Inspiration lines (fading) + inline prompt
- **With blocks**: Block list + inline prompt at bottom
- **Orchestrator unconfigured**: Setup prompt directing to Settings

The inline prompt is embedded in the canvas, not overlayed. The `Cmd+K` overlay palette is separate and used for power-user access only.

## Principles

1. **Purple is the brand.** Always.
2. **Wing spectrum for semantics.** Teal = trust. Gold = working. Coral = broken.
3. **Text only rendering.** No innerHTML. No user-controlled HTML.
4. **On-device first.** Default architecture runs inference locally. Agents execute in sandboxed isolation.
5. **Zero-trust is visible.** Disclosure status, execution constraints, and block states make the handshake observable. Every receipt shows what was allowed to happen.
