/**
 * Mock for window.__TAURI__.core.invoke() used by the Leptos/WASM frontend.
 *
 * Playwright injects this before the page loads so the WASM app gets
 * realistic responses without the Tauri desktop shell.
 */

import { Page } from "@playwright/test";

// ── Fixture data ──────────────────────────────────────────────

const IDENTITY: Record<string, unknown> = {
  did: "did:key:z6MkTest1234567890abcdef",
  public_key_b64: "dGVzdC1wdWJsaWMta2V5LWJhc2U2NA==",
  created_at: "2026-03-18T00:00:00Z",
};

const SCENARIOS: Record<string, unknown>[] = [
  {
    id: "weather",
    title: "Check the Weather",
    description: "Zero-disclosure weather lookup",
    icon: "\u{26C5}",
    agent_name: "WeatherBot",
    action_type: "weather.lookup",
    requires_disclosure: [],
    returns: ["forecast"],
  },
  {
    id: "booking",
    title: "Book a Flight",
    description: "Travel booking with identity disclosure",
    icon: "\u{2708}\u{FE0F}",
    agent_name: "TravelAgent",
    action_type: "travel.book",
    requires_disclosure: ["name", "email", "passport_number"],
    returns: ["confirmation", "itinerary"],
  },
  {
    id: "payment",
    title: "Send Payment",
    description: "Payment with minimal disclosure",
    icon: "\u{1F4B3}",
    agent_name: "PayBot",
    action_type: "payment.send",
    requires_disclosure: ["account_id"],
    returns: ["receipt"],
  },
];

const ORCHESTRATOR_STATUS = "Disconnected";

const ORCHESTRATOR_CONFIG: Record<string, unknown> = {
  llm_provider: "None",
  mandate_ttl_hours: 8,
  auto_approve_zero_disclosure: true,
};

const SETUP_STATE = {
  has_identity: true,
  setup_complete: true,
  llm_configured: true,
};

const BUILTIN_MODELS = [
  {
    id: "mistral-7b-instruct",
    display_name: "Mistral 7B Instruct",
    size_hint: "4.1 GB",
    quant: "Q4_K_M",
  },
];

const BACKUP_STATUS = { backed_up: false };

// ── Mock handler ──────────────────────────────────────────────

// completedRuns accumulates across invoke calls within one page lifecycle
const MOCK_SCRIPT = `
window.__TAURI__ = {
  core: {
    _completedRuns: [],
    _backedUp: false,
    _successors: [],
    invoke: async function(cmd, args) {
      console.log('[tauri-mock] invoke:', cmd, args);
      const IDENTITY = ${JSON.stringify(IDENTITY)};
      const SCENARIOS = ${JSON.stringify(SCENARIOS)};
      const CONFIG = ${JSON.stringify(ORCHESTRATOR_CONFIG)};

      switch (cmd) {
        case 'create_identity':
        case 'get_identity':
          return IDENTITY;

        case 'list_scenarios':
          return SCENARIOS;

        case 'get_orchestrator_status':
          return ${JSON.stringify(ORCHESTRATOR_STATUS)};

        case 'get_orchestrator_config':
          return CONFIG;

        case 'get_setup_state':
          return ${JSON.stringify(SETUP_STATE)};

        case 'list_builtin_models':
          return ${JSON.stringify(BUILTIN_MODELS)};

        case 'configure_orchestrator':
          return args?.config ?? CONFIG;

        case 'run_scenario': {
          const sid = args?.scenarioId ?? 'weather';
          const scenario = SCENARIOS.find(s => s.id === sid) || SCENARIOS[0];
          const now = new Date().toISOString();
          const result = {
            scenario_id: sid,
            agent_name: scenario.agent_name,
            steps: [
              { step_number: 1, step_name: 'Discover Agent', status: 'completed', detail: 'Found ' + scenario.agent_name + ' in registry', timestamp: now },
              { step_number: 2, step_name: 'Issue Mandate', status: 'completed', detail: 'Root mandate signed', timestamp: now },
              { step_number: 3, step_name: 'Open Session', status: 'completed', detail: 'session-abc123', timestamp: now },
              { step_number: 4, step_name: 'Exchange Data', status: 'completed', detail: 'Action: ' + scenario.action_type, timestamp: now },
              { step_number: 5, step_name: 'Co-sign Receipt', status: 'completed', detail: 'Both parties signed', timestamp: now },
              { step_number: 6, step_name: 'Close Session', status: 'completed', detail: 'Session closed cleanly', timestamp: now },
            ],
            receipt: {
              session_id: 'session-abc123',
              action: scenario.action_type,
              initiator_did: IDENTITY.did,
              receiver_did: 'did:key:z6MkAgent999',
              property_refs: scenario.requires_disclosure,
              co_signed: true,
              timestamp: now,
            },
            receipt_url: 'pap://receipts/session-abc123',
            completed_at: now,
            success: true,
            error: null,
          };
          window.__TAURI__.core._completedRuns.push(result);
          return result;
        }

        case 'list_completed_runs':
          return window.__TAURI__.core._completedRuns;

        case 'get_key_backup_status':
          return { backed_up: window.__TAURI__.core._backedUp };

        case 'export_key':
          window.__TAURI__.core._backedUp = true;
          return {
            seed_b64: 'dGVzdC1zZWVkLWtleS1iYXNlNjQ',
            did: IDENTITY.did,
            exported_at: new Date().toISOString(),
          };

        case 'import_key':
          return IDENTITY;

        case 'list_successors':
          return window.__TAURI__.core._successors;

        case 'add_successor': {
          const entry = {
            successor_did: args?.successorDid ?? '',
            relationship: args?.relationship ?? 'executor',
            notes: args?.notes ?? '',
            created_at: new Date().toISOString(),
          };
          window.__TAURI__.core._successors.push(entry);
          return window.__TAURI__.core._successors;
        }

        case 'remove_successor': {
          window.__TAURI__.core._successors = window.__TAURI__.core._successors
            .filter(s => s.successor_did !== args?.successorDid);
          return window.__TAURI__.core._successors;
        }

        case 'navigate_registry':
          return {
            url: args?.url ?? 'pap://local',
            agent_count: 3,
            peer_count: 0,
          };

        case 'list_agents':
          return [
            { name: 'DuckDuckGo Search', did: 'did:key:z6MkDDG', action_types: ['search.web'], requires_disclosure: [], description: 'Web search via DuckDuckGo Instant Answer API' },
            { name: 'Wikipedia', did: 'did:key:z6MkWiki', action_types: ['knowledge.lookup'], requires_disclosure: [], description: 'Knowledge lookup via Wikipedia REST API' },
            { name: 'Mistral AI', did: 'did:key:z6MkMistral', action_types: ['ai.inference'], requires_disclosure: [], description: 'On-device inference via Candle' },
          ];

        case 'search_agents':
          return [];

        case 'sync_agents':
          return null;

        case 'discover_peers':
          return [];

        case 'add_bookmark':
        case 'list_bookmarks':
          return [];

        case 'canvas_prompt':
          return {
            canvas_id: 'canvas-1',
            blocks: [
              {
                id: 'block-1',
                block_type: 'text',
                title: 'Response',
                content: 'Here is your answer.',
                status: 'ready',
                linked_block_ids: [],
              },
            ],
          };

        case 'canvas_reshape':
        case 'canvas_retry':
          return {
            id: args?.blockId ?? 'block-1',
            block_type: 'text',
            title: 'Reshaped',
            content: 'Updated content.',
            status: 'ready',
            linked_block_ids: [],
          };

        case 'load_builtin_model':
          return null;

        case 'check_llm_connection':
          return 'Hello! I am a mock LLM response.';

        default:
          console.warn('[tauri-mock] unhandled command:', cmd);
          return null;
      }
    }
  }
};
`;

/**
 * Install the Tauri mock on a page before WASM loads.
 * Call this in beforeEach or as a fixture.
 */
export async function installTauriMock(page: Page): Promise<void> {
  await page.addInitScript(MOCK_SCRIPT);
}
