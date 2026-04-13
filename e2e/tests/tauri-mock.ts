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

const ORCHESTRATOR_STATUS = "Ready";

const ORCHESTRATOR_CONFIG: Record<string, unknown> = {
  llm_provider: "None",
  mandate_ttl_hours: 8,
  auto_approve_zero_disclosure: true,
};

const SETUP_STATE = {
  identity_created: true,
  llm_configured: true,
  setup_complete: true,
};

const BUILTIN_MODELS = [
  {
    id: "tinyllama-1.1b",
    display_name: "TinyLlama 1.1B Chat (Q4)",
    repo: "TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF",
    filename: "tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf",
    size_hint: "~0.6 GB",
    download_url: "https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf",
    tokenizer_url: "https://huggingface.co/TinyLlama/TinyLlama-1.1B-Chat-v1.0/resolve/main/tokenizer.json",
    web_compatible: false,
  },
];

const MODEL_AVAILABILITY = [
  { model_id: "tinyllama-1.1b", model_present: true, tokenizer_present: true, ready: true },
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
    _mandates: {},
    _orchestratorConfig: ${JSON.stringify(ORCHESTRATOR_CONFIG)},
    _localAgents: [
      {
        name: 'Web Page Reader',
        provider_name: 'Papillon',
        provider_did: 'did:key:z6MkPap001',
        capabilities: ['schema:ReadAction'],
        object_types: ['WebPage'],
        requires_disclosure: [],
        returns: ['WebPage'],
        endpoint: null,
        content_hash: 'web-reader-hash',
        agent_did: 'did:key:z6MkPapAgent001',
        source: 'compiled',
        published_to: [],
      },
      {
        name: 'On-Device AI',
        provider_name: 'Papillon',
        provider_did: 'did:key:z6MkPap002',
        capabilities: ['schema:AskAction'],
        object_types: ['Answer'],
        requires_disclosure: [],
        returns: ['Answer'],
        endpoint: null,
        content_hash: 'on-device-ai-hash',
        agent_did: 'did:key:z6MkPapAgent002',
        source: 'compiled',
        published_to: [],
      },
      {
        name: 'DuckDuckGo Search',
        provider_name: 'DuckDuckGo',
        provider_did: 'did:key:z6MkDDG111',
        capabilities: ['schema:SearchAction'],
        object_types: ['SearchAction'],
        requires_disclosure: [],
        returns: ['results'],
        endpoint: null,
        content_hash: 'ddg-local-hash',
        agent_did: 'did:key:z6MkDDGAgent111',
        source: 'catalog',
        published_to: [],
      },
      {
        name: 'Wikipedia Lookup',
        provider_name: 'Wikimedia',
        provider_did: 'did:key:z6MkWiki222',
        capabilities: ['schema:SearchAction'],
        object_types: ['SearchAction'],
        requires_disclosure: [],
        returns: ['article'],
        endpoint: null,
        content_hash: 'wiki-local-hash',
        agent_did: 'did:key:z6MkWikiAgent222',
        source: 'catalog',
        published_to: [],
      },
      {
        name: 'My Custom Agent',
        provider_name: 'Local Operator',
        provider_did: 'did:key:z6MkCustom333',
        capabilities: ['schema:Action'],
        object_types: ['Action'],
        requires_disclosure: [],
        returns: ['response'],
        endpoint: null,
        content_hash: 'custom-local-hash',
        agent_did: 'did:key:z6MkCustomAgent333',
        source: 'user_created',
        published_to: ['https://chrysalis.example.com'],
      },
    ],
    _templates: [
      {
        id: 'tmpl-flight',
        template_name: 'Default Flight Template',
        schema_type: 'FlightReservation',
        principal_did: null,
        template_config: {
          version: 1,
          layout: { type: 'grid', columns: 2 },
          fields: [
            { path: 'reservationNumber', label: 'Confirmation', display: 'text' },
            { path: 'underName.name', label: 'Passenger', display: 'text' },
          ],
        },
        version: 1,
        enabled: true,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z',
        created_by: null,
      },
      {
        id: 'tmpl-hotel',
        template_name: 'Default Hotel Template',
        schema_type: 'LodgingReservation',
        principal_did: null,
        template_config: {
          version: 1,
          layout: { type: 'grid', columns: 1 },
          fields: [
            { path: 'name', label: 'Hotel', display: 'title' },
            { path: 'address', label: 'Location', display: 'text' },
          ],
        },
        version: 1,
        enabled: true,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z',
        created_by: null,
      },
    ],
    invoke: async function(cmd, rawArgs) {
      // serde_wasm_bindgen serializes serde_json::Value objects as JS Maps.
      // Convert Maps to plain objects so property access (args.key) works.
      function mapToObj(val) {
        if (val instanceof Map) {
          const obj = {};
          for (const [k, v] of val) obj[k] = mapToObj(v);
          return obj;
        }
        if (Array.isArray(val)) return val.map(mapToObj);
        if (val && typeof val === 'object' && !(val instanceof Date)) {
          const obj = {};
          for (const k of Object.keys(val)) obj[k] = mapToObj(val[k]);
          return obj;
        }
        return val;
      }
      const args = mapToObj(rawArgs);
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
          return window.__TAURI__.core._orchestratorConfig;

        case 'get_setup_state':
          return ${JSON.stringify(SETUP_STATE)};

        case 'list_builtin_models':
          return ${JSON.stringify(BUILTIN_MODELS)};

        case 'check_model_availability':
          return ${JSON.stringify(MODEL_AVAILABILITY)};

        case 'download_builtin_model':
          return ${JSON.stringify(MODEL_AVAILABILITY[0])};

        case 'configure_orchestrator':
          if (args?.config) {
            window.__TAURI__.core._orchestratorConfig = args.config;
          }
          return window.__TAURI__.core._orchestratorConfig;

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
          // Registry browser — returns remote/federated agents
          // live: true is required so build_catalog() indexes them for pap:// suggestions
          return [
            { name: 'DuckDuckGo Search', provider_name: 'DuckDuckGo', provider_did: 'did:key:z6MkDDG', capabilities: ['schema:SearchAction'], object_types: ['SearchAction'], requires_disclosure: [], returns: ['results'], endpoint: null, content_hash: 'ddg-hash', agent_did: 'did:key:z6MkDDGFed', source: 'catalog', published_to: [], live: true },
            { name: 'Wikipedia', provider_name: 'Wikimedia', provider_did: 'did:key:z6MkWiki', capabilities: ['schema:SearchAction'], object_types: ['SearchAction'], requires_disclosure: [], returns: ['article'], endpoint: null, content_hash: 'wiki-hash', agent_did: 'did:key:z6MkWikiFed', source: 'catalog', published_to: [], live: true },
            { name: 'Mistral AI', provider_name: 'Mistral', provider_did: 'did:key:z6MkMistral', capabilities: ['schema:CreateAction'], object_types: ['InferenceAction'], requires_disclosure: [], returns: ['response'], endpoint: null, content_hash: 'mistral-hash', agent_did: 'did:key:z6MkMistralFed', source: 'catalog', published_to: [], live: true },
          ];

        case 'list_local_agents':
          // Local agent fleet — returns managed agents with full AgentInfo
          return window.__TAURI__.core._localAgents;

        case 'save_agent': {
          // Persist a new DynamicAgentDef, return AgentInfo with agent_did
          const def = args?.def ?? {};
          const agentDid = 'did:key:z6MkGen' + Math.random().toString(36).substr(2, 9);
          const newAgent = {
            name: def.name ?? 'Unnamed Agent',
            provider_name: def.provider ?? 'Local Operator',
            provider_did: agentDid,
            capabilities: def.action ? [def.action] : ['schema:Action'],
            object_types: def.object_types ?? [],
            requires_disclosure: def.requires_disclosure ?? [],
            returns: def.returns ?? [],
            endpoint: null,
            content_hash: 'saved-' + Math.random().toString(36).substr(2, 9),
            agent_did: agentDid,
            source: 'user_created',
            published_to: [],
          };
          window.__TAURI__.core._localAgents.push(newAgent);
          return newAgent;
        }

        case 'update_agent': {
          const def = args?.def ?? {};
          const did = def.agent_did;
          const idx = window.__TAURI__.core._localAgents.findIndex(a => a.agent_did === did);
          if (idx !== -1) {
            window.__TAURI__.core._localAgents[idx] = {
              ...window.__TAURI__.core._localAgents[idx],
              name: def.name ?? window.__TAURI__.core._localAgents[idx].name,
              capabilities: def.action ? [def.action] : window.__TAURI__.core._localAgents[idx].capabilities,
              published_to: def.published_to ?? window.__TAURI__.core._localAgents[idx].published_to,
            };
            return window.__TAURI__.core._localAgents[idx];
          }
          return null;
        }

        case 'delete_agent': {
          const did = args?.agent_did;
          window.__TAURI__.core._localAgents = window.__TAURI__.core._localAgents.filter(a => a.agent_did !== did);
          return null;
        }

        case 'generate_agent': {
          // Returns a preview DynamicAgentDef (not yet saved — no agent_did)
          const prompt = args?.prompt ?? 'search the web';
          return {
            name: 'Generated: ' + prompt.slice(0, 30),
            provider: 'Generated',
            action: 'schema:SearchAction',
            object_types: ['SearchAction'],
            requires_disclosure: [],
            returns: ['results'],
            endpoint: {
              url_template: 'https://api.example.com/search?q={query}',
              method: 'GET',
              headers: {},
              response_jsonpath: '$.results',
            },
            agent_did: null,
            operator_key_seed: null,
            source: 'generated',
            published_to: [],
            schema_version: 1,
            catalog_path: null,
            updated_at: new Date().toISOString(),
          };
        }

        case 'publish_agent': {
          const did = args?.agent_did;
          const url = args?.registry_url ?? '';
          const agent = window.__TAURI__.core._localAgents.find(a => a.agent_did === did);
          if (agent && url && !agent.published_to.includes(url)) {
            agent.published_to.push(url);
          }
          return null;
        }

        case 'unpublish_agent': {
          const did = args?.agent_did;
          const url = args?.registry_url ?? '';
          const agent = window.__TAURI__.core._localAgents.find(a => a.agent_did === did);
          if (agent) {
            agent.published_to = agent.published_to.filter(u => u !== url);
          }
          return null;
        }

        case 'sync_agents':
          return null;

        case 'discover_peers':
          return [];

        case 'add_bookmark':
        case 'list_bookmarks':
          return [];

        case 'canvas_prompt': {
          // Emit a block_resolved event after a short delay so the Leptos
          // reactive UI transitions from Resolving → Resolved with typed content.
          const blockId = (args && (args.block_id || args.blockId)) || 'block-mock';
          const promptText = ((args && args.text) || '').toLowerCase();
          // Map prompt keywords to schema types and typed content payloads.
          function typedBlock(schemaType, contentObj) {
            return {
              id: blockId,
              prompt_id: (args && (args.prompt_id || args.promptId)) || 'p-mock',
              state: 'Resolved',
              schema_type: schemaType,
              // Include receipt sentinel so render_typed_content unwraps 'result'
              content: { result: contentObj, receipt: { status: 'ok', session: 'mock-session-001' } },
              linked_block_ids: [],
              created_at: new Date().toISOString(),
              updated_at: new Date().toISOString(),
            };
          }
          var block = null;
          if (promptText.includes('__movie') || promptText.includes('mock:movie')) {
            block = typedBlock('Movie', { name: 'Inception', datePublished: '2010', director: { name: 'Christopher Nolan' }, genre: 'Sci-Fi', aggregateRating: { ratingValue: '8.8' }, description: 'A mind-bending thriller.' });
          } else if (promptText.includes('__tvseries') || promptText.includes('mock:tvseries')) {
            block = typedBlock('TVSeries', { name: 'Breaking Bad', startDate: '2008', broadcastChannel: 'AMC', numberOfSeasons: '5', description: 'A chemistry teacher turns drug lord.' });
          } else if (promptText.includes('__videogame') || promptText.includes('mock:videogame')) {
            block = typedBlock('VideoGame', { name: 'The Legend of Zelda', genre: 'Adventure', gamePlatform: 'Nintendo Switch', author: { name: 'Nintendo' }, description: 'An epic adventure game.' });
          } else if (promptText.includes('__musicrecording') || promptText.includes('mock:musicrecording')) {
            block = typedBlock('MusicRecording', { name: 'Bohemian Rhapsody', byArtist: { name: 'Queen' }, inAlbum: { name: 'A Night at the Opera' }, duration: 'PT5M55S' });
          } else if (promptText.includes('__musicgroup') || promptText.includes('mock:musicgroup')) {
            block = typedBlock('MusicGroup', { name: 'The Beatles', genre: 'Rock', foundingDate: '1960', description: 'Legendary British rock band.' });
          } else if (promptText.includes('__book') || promptText.includes('mock:book')) {
            block = typedBlock('Book', { name: 'The Rust Programming Language', author: { name: 'Steve Klabnik' }, publisher: { name: 'No Starch Press' }, datePublished: '2019', isbn: '978-1593278281', description: 'The official Rust book.' });
          } else if (promptText.includes('__newsarticle') || promptText.includes('mock:newsarticle')) {
            block = typedBlock('NewsArticle', { headline: 'Rust Tops Developer Survey for 9th Year', publisher: { name: 'Stack Overflow' }, datePublished: '2024-06-01', description: 'Rust remains the most loved language.', url: 'https://survey.stackoverflow.co/2024' });
          } else if (promptText.includes('__scholarlyarticle') || promptText.includes('mock:scholarlyarticle')) {
            block = typedBlock('ScholarlyArticle', { name: 'Attention Is All You Need', author: [{ name: 'Vaswani et al.' }], isPartOf: 'NeurIPS 2017', datePublished: '2017', identifier: '10.5555/3295222.3295349', abstract: 'We propose the Transformer architecture.' });
          } else if (promptText.includes('__person') || promptText.includes('mock:person')) {
            block = typedBlock('Person', { name: 'Grace Hopper', jobTitle: 'Rear Admiral', affiliation: { name: 'US Navy' }, description: 'Pioneer of computer programming.', url: 'https://en.wikipedia.org/wiki/Grace_Hopper' });
          } else if (promptText.includes('__organization') || promptText.includes('mock:organization')) {
            block = typedBlock('Organization', { name: 'Mozilla Foundation', '@type': 'Organization', address: { addressLocality: 'San Francisco', addressCountry: 'US' }, description: 'Champions of the open web.', url: 'https://mozilla.org' });
          } else if (promptText.includes('__weather') || promptText.includes('mock:weather')) {
            block = typedBlock('WeatherForecast', { name: 'San Francisco', temperature: '65°F', description: 'Foggy with partial clearing', humidity: '78%', windSpeed: '15 mph' });
          } else if (promptText.includes('__geocoords') || promptText.includes('mock:geocoords')) {
            block = typedBlock('GeoCoordinates', { name: 'Eiffel Tower', latitude: 48.8584, longitude: 2.2945, elevation: '330m', address: 'Champ de Mars, Paris, France' });
          } else if (promptText.includes('__product') || promptText.includes('mock:product')) {
            block = typedBlock('Product', { name: 'Framework Laptop 16', brand: { name: 'Framework' }, offers: { price: '1049.00' }, aggregateRating: { ratingValue: '4.7' }, description: 'A modular, repairable laptop.' });
          } else if (promptText.includes('__event') || promptText.includes('mock:event')) {
            block = typedBlock('Event', { name: 'RustConf 2024', startDate: '2024-09-10', endDate: '2024-09-11', location: { name: 'Montreal, Canada' }, organizer: { name: 'Rust Foundation' }, description: 'Annual Rust programming conference.' });
          } else if (promptText.includes('__sportsteam') || promptText.includes('mock:sportsteam')) {
            block = typedBlock('SportsTeam', { name: 'World Cup Final 2026', homeTeam: { name: 'Spain' }, awayTeam: { name: 'Brazil' }, startDate: '2026-07-19', location: { name: 'MetLife Stadium, NJ' } });
          } else if (promptText.includes('__course') || promptText.includes('mock:course')) {
            block = typedBlock('Course', { name: 'CS50: Introduction to Computer Science', provider: { name: 'Harvard / edX' }, description: 'A broad introduction to computer science.', url: 'https://cs50.harvard.edu' });
          } else if (promptText.includes('__nutrition') || promptText.includes('mock:nutrition')) {
            block = typedBlock('NutritionInformation', { name: 'Avocado', servingSize: '100g', calories: '160', proteinContent: '2g', carbohydrateContent: '9g', fatContent: '15g' });
          } else if (promptText.includes('__jobposting') || promptText.includes('mock:jobposting')) {
            block = typedBlock('JobPosting', { title: 'Senior Rust Engineer', hiringOrganization: { name: 'Fastly' }, jobLocation: { address: { addressLocality: 'Remote' } }, datePosted: '2024-05-01', baseSalary: { value: { minValue: 180000, maxValue: 250000 } }, description: 'Build high-performance networking software.' });
          } else if (promptText.includes('__visualartwork') || promptText.includes('mock:visualartwork')) {
            block = typedBlock('VisualArtwork', { name: 'Starry Night', creator: { name: 'Vincent van Gogh' }, artMedium: 'Oil on canvas', dateCreated: '1889', locationCreated: { name: 'MoMA, New York' }, description: 'A swirling night sky over a village.' });
          } else if (promptText.includes('__definedterm') || promptText.includes('mock:definedterm')) {
            block = typedBlock('DefinedTerm', { name: 'monad', inDefinedTermSet: 'noun', description: 'A design pattern in functional programming representing computations as chains.' });
          } else if (promptText.includes('__quotation') || promptText.includes('mock:quotation')) {
            block = typedBlock('Quotation', { text: 'Programs must be written for people to read, and only incidentally for machines to execute.', spokenByCharacter: { name: 'Harold Abelson' }, citation: { name: 'SICP' } });
          } else if (promptText.includes('__flightreservation') || promptText.includes('mock:flightreservation')) {
            block = typedBlock('FlightReservation', { reservationNumber: 'PX-4892', underName: { name: 'Ada Lovelace' }, departureAirport: 'SFO', arrivalAirport: 'JFK', departureDate: '2026-06-01', departureTime: '09:15', arrivalTime: '17:45', airline: 'United', totalPrice: 382.00 });
          } else if (promptText.includes('__hotel') || promptText.includes('mock:hotel')) {
            block = typedBlock('LodgingReservation', { reservationNumber: 'H-78321', underName: { name: 'Grace Hopper' }, name: 'The Grand Pacific', checkinDate: '2026-07-10', checkoutDate: '2026-07-13', totalPrice: 540.00 });
          } else {
            // Generic answer block for non-typed prompts
            block = {
              id: blockId,
              prompt_id: (args && (args.prompt_id || args.promptId)) || 'p-mock',
              state: 'Resolved',
              schema_type: null,
              content: { result: 'Here is your answer.' },
              linked_block_ids: [],
              created_at: new Date().toISOString(),
              updated_at: new Date().toISOString(),
            };
          }
          var resolvedBlock = block;
          setTimeout(function() {
            window.__TAURI__.event.emit('block_resolved', { block: resolvedBlock });
          }, 200);
          return null;
        }

        case 'canvas_reshape':
        case 'canvas_retry': {
          const retryBlockId = (args && (args.block_id || args.blockId)) || 'block-1';
          setTimeout(function() {
            window.__TAURI__.event.emit('block_resolved', {
              block: {
                id: retryBlockId,
                prompt_id: 'p-retry',
                state: 'Resolved',
                schema_type: null,
                content: { result: 'Updated content.' },
                linked_block_ids: [],
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString(),
              }
            });
          }, 200);
          return null;
        }

        case 'load_builtin_model':
          return null;

        case 'check_llm_connection':
          return 'Hello! I am a mock LLM response.';

        // ─── Template CRUD Commands ───
        case 'get_global_templates': {
          // Return all global templates (including disabled) so the settings
          // page can display and re-enable them. The enabled flag is metadata
          // rendered in the UI, not a query filter for the settings list.
          // Use == null (loose) to match both null and undefined — serde_wasm_bindgen
          // double-serialization converts Option::None → Value::Null → undefined.
          return window.__TAURI__.core._templates.filter(
            (t) => t.principal_did == null
          );
        }

        case 'get_profile_templates': {
          const principal_did = args?.principal_did || args?.principalDid;
          return window.__TAURI__.core._templates.filter(
            (t) => t.principal_did === principal_did && t.enabled
          );
        }

        case 'create_template': {
          const template = args?.template || {};
          const id = 'tmpl-' + Math.random().toString(36).substr(2, 9);
          const now = new Date().toISOString();
          const newTemplate = {
            id,
            template_name: template.template_name,
            schema_type: template.schema_type,
            principal_did: template.principal_did ?? null,
            template_config: template.template_config || {},
            version: 1,
            enabled: true,
            created_at: now,
            updated_at: now,
            created_by: template.created_by ?? null,
          };
          window.__TAURI__.core._templates.push(newTemplate);
          return null; // Success (returns () in actual Rust)
        }

        case 'update_template': {
          const template = args?.template || {};
          const idx = window.__TAURI__.core._templates.findIndex(
            (t) => t.template_name === template.template_name
          );
          if (idx !== -1) {
            window.__TAURI__.core._templates[idx] = {
              ...window.__TAURI__.core._templates[idx],
              ...template,
              // Normalize undefined → null for nullable fields (serde_wasm_bindgen
              // double-serialization turns Option::None into JS undefined).
              principal_did: template.principal_did ?? window.__TAURI__.core._templates[idx].principal_did ?? null,
              created_by: template.created_by ?? window.__TAURI__.core._templates[idx].created_by ?? null,
              updated_at: new Date().toISOString(),
            };
          }
          return null;
        }

        case 'delete_template': {
          const template_name = args?.template_name || args?.templateName;
          window.__TAURI__.core._templates = window.__TAURI__.core._templates.filter(
            (t) => t.template_name !== template_name
          );
          return null;
        }

        case 'set_template_enabled': {
          const template_name = args?.template_name || args?.templateName;
          const enabled = args?.enabled;
          const template = window.__TAURI__.core._templates.find(
            (t) => t.template_name === template_name
          );
          if (template) {
            template.enabled = enabled;
          }
          return null;
        }

        case 'auto_generate_template': {
          const schemaType = args?.schema_type || args?.schemaType || 'GeneratedType';
          const existing = window.__TAURI__.core._templates.find(
            (t) => t.schema_type === schemaType && t.enabled
          );
          if (existing) return null; // already has template — skip generation
          const generated = {
            id: 'tmpl-gen-' + Math.random().toString(36).substr(2, 9),
            template_name: 'Auto: ' + schemaType,
            schema_type: schemaType,
            principal_did: null,
            template_config: {
              version: 1,
              layout: { type: 'flex', direction: 'column', spacing: 'md' },
              fields: [{ path: 'name', label: null, display: 'title', condition: null, style: null }],
            },
            version: 1,
            enabled: true,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
            created_by: 'orchestrator',
          };
          window.__TAURI__.core._templates.push(generated);
          return generated;
        }

        case 'export_templates': {
          return JSON.stringify(window.__TAURI__.core._templates);
        }

        case 'import_templates': {
          const jsonStr = args?.json_str || args?.jsonStr || '[]';
          try {
            const imported = JSON.parse(jsonStr);
            const existingNames = new Set(window.__TAURI__.core._templates.map(t => t.template_name));
            for (const t of imported) {
              if (!existingNames.has(t.template_name)) {
                window.__TAURI__.core._templates.push(t);
                existingNames.add(t.template_name);
              }
            }
          } catch (_) {}
          return null;
        }

        // ── Tier 2 Test: Error scenarios ────────────────────────
        case 'run_scenario_with_error': {
          // Test validation error when mandate scope exceeds agent capabilities
          const sid = args?.scenarioId ?? 'weather';
          const scenario = SCENARIOS.find(s => s.id === sid) || SCENARIOS[0];
          if (args?.triggerError === 'scope_exceeded') {
            return {
              success: false,
              error: 'Mandate scope exceeds agent capabilities',
              error_code: 'SCOPE_EXCEEDED',
              scenario_id: sid,
            };
          }
          if (args?.triggerError === 'ttl_expired') {
            return {
              success: false,
              error: 'Mandate TTL exceeded during negotiation',
              error_code: 'TTL_EXPIRED',
              scenario_id: sid,
            };
          }
          // Fallback to normal scenario
          return { success: true, scenario_id: sid };
        }

        // ── Tier 2 Test: Registry search and filtering ────────────────
        case 'search_agents': {
          const query = args?.query ?? '';
          const actionType = args?.actionType ?? '';
          const allAgents = [
            { name: 'DuckDuckGo Search', did: 'did:key:z6MkDDG', action_types: ['search.web'], requires_disclosure: [], description: 'Web search' },
            { name: 'Wikipedia', did: 'did:key:z6MkWiki', action_types: ['knowledge.lookup'], requires_disclosure: [], description: 'Knowledge lookup' },
            { name: 'Mistral AI', did: 'did:key:z6MkMistral', action_types: ['ai.inference'], requires_disclosure: [], description: 'AI inference' },
          ];
          // Filter by action_type if provided
          if (actionType) {
            return allAgents.filter(a => a.action_types.includes(actionType));
          }
          // Filter by query if provided
          if (query) {
            return allAgents.filter(a =>
              a.name.toLowerCase().includes(query.toLowerCase()) ||
              a.description.toLowerCase().includes(query.toLowerCase())
            );
          }
          return allAgents;
        }

        // ── Tier 2 Test: Orchestrator state transitions ─────────────────
        case 'get_orchestrator_status_transition': {
          // Validate state transitions (not all transitions are valid)
          const requestedState = args?.state || 'Ready';
          const validStates = ['Disconnected', 'Ready', 'Failed'];

          if (!validStates.includes(requestedState)) {
            return {
              success: false,
              error: 'Invalid state: ' + requestedState,
              error_code: 'INVALID_STATE',
            };
          }

          // Return confirmed state
          return requestedState;
        }

        case 'list_profiles':
          return [
            {
              id: 'profile-default',
              label: 'Default',
              active: true,
              created_at: '2026-01-01T00:00:00Z',
            },
          ];

        case 'get_health_status':
          return {
            status: 'ok',
            timestamp: new Date().toISOString(),
            uptime_seconds: 120,
            version: '0.1.0-mock',
          };

        // ── Tier 3 Canary: Mandate issuance ─────────────────────────────
        case 'issue_mandate': {
          const agentDid = args?.agentDid || args?.agent_did || 'did:key:z6MkAgent999';
          const scope = args?.scope || ['schema:SearchAction'];
          const ttlHours = args?.ttlHours || args?.ttl_hours || 8;
          const now = new Date();
          const ttl = new Date(now.getTime() + ttlHours * 3600 * 1000);
          const mandateHash = 'mandate-' + Math.random().toString(36).substr(2, 12);
          const mandate = {
            mandate_hash: mandateHash,
            principal_did: IDENTITY.did,
            agent_did: agentDid,
            issuer_did: IDENTITY.did,
            parent_mandate_hash: null,
            scope: scope,
            ttl: ttl.toISOString(),
            decay_state: 'Active',
            issued_at: now.toISOString(),
            algorithm: 'Ed25519',
            signature: 'mock-sig-' + mandateHash,
            success: true,
          };
          window.__TAURI__.core._mandates[mandateHash] = mandate;
          return mandate;
        }

        // ── Tier 3 Canary: Mandate delegation with scope containment ────
        case 'delegate_mandate': {
          const parentHash = args?.parentMandateHash || args?.parent_mandate_hash;
          const subAgentDid = args?.subAgentDid || args?.sub_agent_did || 'did:key:z6MkSubAgent888';
          const requestedScope = args?.scope || [];
          const ttlHours = args?.ttlHours || args?.ttl_hours || 1;

          const parent = window.__TAURI__.core._mandates[parentHash];
          if (!parent) {
            return { success: false, error: 'Parent mandate not found', error_code: 'MANDATE_NOT_FOUND' };
          }

          // Scope containment: every requested action must be in parent scope.
          const parentScope = parent.scope || [];
          const violations = requestedScope.filter((s) => !parentScope.includes(s));
          if (violations.length > 0) {
            return {
              success: false,
              error: 'Child mandate scope exceeds parent: ' + violations.join(', '),
              error_code: 'SCOPE_EXCEEDED',
            };
          }

          // TTL containment: child TTL must not exceed parent TTL.
          const parentTtl = new Date(parent.ttl);
          const childTtl = new Date(Date.now() + ttlHours * 3600 * 1000);
          if (childTtl > parentTtl) {
            return { success: false, error: 'Child TTL exceeds parent TTL', error_code: 'TTL_EXCEEDED' };
          }

          const childHash = 'mandate-child-' + Math.random().toString(36).substr(2, 12);
          const now = new Date();
          const child = {
            mandate_hash: childHash,
            principal_did: parent.principal_did,
            agent_did: subAgentDid,
            issuer_did: parent.agent_did,
            parent_mandate_hash: parentHash,
            scope: requestedScope,
            ttl: childTtl.toISOString(),
            decay_state: 'Active',
            issued_at: now.toISOString(),
            algorithm: 'Ed25519',
            signature: 'mock-sig-' + childHash,
            success: true,
          };
          window.__TAURI__.core._mandates[childHash] = child;
          return child;
        }

        // canvas_plan_prompt is the Tauri IPC entry point for the planning
        // phase — same mock behaviour as canvas_prompt (emit block_resolved
        // after a short delay so the Leptos UI can transition states).
        case 'canvas_plan_prompt': {
          const blockId = (args && (args.block_id || args.blockId)) || 'block-mock';
          const promptText = ((args && args.text) || '').toLowerCase();
          function typedBlock2(schemaType, contentObj) {
            return {
              id: blockId,
              prompt_id: (args && (args.prompt_id || args.promptId)) || 'p-mock',
              state: 'Resolved',
              schema_type: schemaType,
              // Include receipt sentinel so render_typed_content unwraps 'result'
              content: { result: contentObj, receipt: { status: 'ok', session: 'mock-session-001' } },
              linked_block_ids: [],
              created_at: new Date().toISOString(),
              updated_at: new Date().toISOString(),
            };
          }
          var planBlock = null;
          if (promptText.includes('mock:movie') || promptText.includes('__movie')) {
            planBlock = typedBlock2('Movie', { name: 'Inception', datePublished: '2010', director: { name: 'Christopher Nolan' }, genre: 'Sci-Fi', aggregateRating: { ratingValue: '8.8' }, description: 'A mind-bending thriller.' });
          } else if (promptText.includes('mock:tvseries') || promptText.includes('__tvseries')) {
            planBlock = typedBlock2('TVSeries', { name: 'Breaking Bad', startDate: '2008', broadcastChannel: 'AMC', numberOfSeasons: '5', description: 'A chemistry teacher turns drug lord.' });
          } else if (promptText.includes('mock:videogame') || promptText.includes('__videogame')) {
            planBlock = typedBlock2('VideoGame', { name: 'The Legend of Zelda', genre: 'Adventure', gamePlatform: 'Nintendo Switch', author: { name: 'Nintendo' }, description: 'An epic adventure game.' });
          } else if (promptText.includes('mock:musicrecording') || promptText.includes('__musicrecording')) {
            planBlock = typedBlock2('MusicRecording', { name: 'Bohemian Rhapsody', byArtist: { name: 'Queen' }, inAlbum: { name: 'A Night at the Opera' }, duration: 'PT5M55S' });
          } else if (promptText.includes('mock:musicgroup') || promptText.includes('__musicgroup')) {
            planBlock = typedBlock2('MusicGroup', { name: 'The Beatles', genre: 'Rock', foundingDate: '1960', description: 'Legendary British rock band.' });
          } else if (promptText.includes('mock:book') || promptText.includes('__book')) {
            planBlock = typedBlock2('Book', { name: 'The Rust Programming Language', author: { name: 'Steve Klabnik' }, publisher: { name: 'No Starch Press' }, datePublished: '2019', isbn: '978-1593278281', description: 'The official Rust book.' });
          } else if (promptText.includes('mock:newsarticle') || promptText.includes('__newsarticle')) {
            planBlock = typedBlock2('NewsArticle', { headline: 'Rust Tops Developer Survey for 9th Year', publisher: { name: 'Stack Overflow' }, datePublished: '2024-06-01', description: 'Rust remains the most loved language.', url: 'https://survey.stackoverflow.co/2024' });
          } else if (promptText.includes('mock:scholarlyarticle') || promptText.includes('__scholarlyarticle')) {
            planBlock = typedBlock2('ScholarlyArticle', { name: 'Attention Is All You Need', author: [{ name: 'Vaswani et al.' }], isPartOf: 'NeurIPS 2017', datePublished: '2017', identifier: '10.5555/3295222.3295349', abstract: 'We propose the Transformer architecture.' });
          } else if (promptText.includes('mock:person') || promptText.includes('__person')) {
            planBlock = typedBlock2('Person', { name: 'Grace Hopper', jobTitle: 'Rear Admiral', affiliation: { name: 'US Navy' }, description: 'Pioneer of computer programming.', url: 'https://en.wikipedia.org/wiki/Grace_Hopper' });
          } else if (promptText.includes('mock:organization') || promptText.includes('__organization')) {
            planBlock = typedBlock2('Organization', { name: 'Mozilla Foundation', '@type': 'Organization', address: { addressLocality: 'San Francisco', addressCountry: 'US' }, description: 'Champions of the open web.', url: 'https://mozilla.org' });
          } else if (promptText.includes('mock:weather') || promptText.includes('__weather')) {
            planBlock = typedBlock2('WeatherForecast', { name: 'San Francisco', temperature: '65°F', description: 'Foggy with partial clearing', humidity: '78%', windSpeed: '15 mph' });
          } else if (promptText.includes('mock:geocoords') || promptText.includes('__geocoords')) {
            planBlock = typedBlock2('GeoCoordinates', { name: 'Eiffel Tower', latitude: 48.8584, longitude: 2.2945, elevation: '330m', address: 'Champ de Mars, Paris, France' });
          } else if (promptText.includes('mock:product') || promptText.includes('__product')) {
            planBlock = typedBlock2('Product', { name: 'Framework Laptop 16', brand: { name: 'Framework' }, offers: { price: '1049.00' }, aggregateRating: { ratingValue: '4.7' }, description: 'A modular, repairable laptop.' });
          } else if (promptText.includes('mock:event') || promptText.includes('__event')) {
            planBlock = typedBlock2('Event', { name: 'RustConf 2024', startDate: '2024-09-10', endDate: '2024-09-11', location: { name: 'Montreal, Canada' }, organizer: { name: 'Rust Foundation' }, description: 'Annual Rust programming conference.' });
          } else if (promptText.includes('mock:sportsteam') || promptText.includes('__sportsteam')) {
            planBlock = typedBlock2('SportsTeam', { name: 'World Cup Final 2026', homeTeam: { name: 'Spain' }, awayTeam: { name: 'Brazil' }, startDate: '2026-07-19', location: { name: 'MetLife Stadium, NJ' } });
          } else if (promptText.includes('mock:course') || promptText.includes('__course')) {
            planBlock = typedBlock2('Course', { name: 'CS50: Introduction to Computer Science', provider: { name: 'Harvard / edX' }, description: 'A broad introduction to computer science.', url: 'https://cs50.harvard.edu' });
          } else if (promptText.includes('mock:nutrition') || promptText.includes('__nutrition')) {
            planBlock = typedBlock2('NutritionInformation', { name: 'Avocado', servingSize: '100g', calories: '160', proteinContent: '2g', carbohydrateContent: '9g', fatContent: '15g' });
          } else if (promptText.includes('mock:jobposting') || promptText.includes('__jobposting')) {
            planBlock = typedBlock2('JobPosting', { title: 'Senior Rust Engineer', hiringOrganization: { name: 'Fastly' }, jobLocation: { address: { addressLocality: 'Remote' } }, datePosted: '2024-05-01', baseSalary: { value: { minValue: 180000, maxValue: 250000 } }, description: 'Build high-performance networking software.' });
          } else if (promptText.includes('mock:visualartwork') || promptText.includes('__visualartwork')) {
            planBlock = typedBlock2('VisualArtwork', { name: 'Starry Night', creator: { name: 'Vincent van Gogh' }, artMedium: 'Oil on canvas', dateCreated: '1889', locationCreated: { name: 'MoMA, New York' }, description: 'A swirling night sky over a village.' });
          } else if (promptText.includes('mock:definedterm') || promptText.includes('__definedterm')) {
            planBlock = typedBlock2('DefinedTerm', { name: 'monad', inDefinedTermSet: 'noun', description: 'A design pattern in functional programming representing computations as chains.' });
          } else if (promptText.includes('mock:quotation') || promptText.includes('__quotation')) {
            planBlock = typedBlock2('Quotation', { text: 'Programs must be written for people to read, and only incidentally for machines to execute.', spokenByCharacter: { name: 'Harold Abelson' }, citation: { name: 'SICP' } });
          } else if (promptText.includes('mock:flightreservation') || promptText.includes('__flightreservation')) {
            planBlock = typedBlock2('FlightReservation', { reservationNumber: 'PX-4892', underName: { name: 'Ada Lovelace' }, departureAirport: 'SFO', arrivalAirport: 'JFK', departureDate: '2026-06-01', departureTime: '09:15', arrivalTime: '17:45', airline: 'United', totalPrice: 382.00 });
          } else if (promptText.includes('mock:hotel') || promptText.includes('__hotel')) {
            planBlock = typedBlock2('LodgingReservation', { reservationNumber: 'H-78321', underName: { name: 'Grace Hopper' }, name: 'The Grand Pacific', checkinDate: '2026-07-10', checkoutDate: '2026-07-13', totalPrice: 540.00 });
          } else {
            planBlock = {
              id: blockId,
              prompt_id: (args && (args.prompt_id || args.promptId)) || 'p-mock',
              state: 'Resolved',
              schema_type: null,
              content: { result: 'Here is your answer.' },
              linked_block_ids: [],
              created_at: new Date().toISOString(),
              updated_at: new Date().toISOString(),
            };
          }
          var resolvedPlanBlock = planBlock;
          setTimeout(function() {
            window.__TAURI__.event.emit('block_resolved', { block: resolvedPlanBlock });
          }, 200);
          return null;
        }

        case 'get_recovery_status':
          return { has_recovery: false, guardian_count: 0, threshold: 0 };

        default:
          console.warn('[tauri-mock] unhandled command:', cmd);
          return null;
      }
    }
  },
  event: {
    _handlers: {},
    listen: async function(event, handler) {
      if (!window.__TAURI__.event._handlers[event]) {
        window.__TAURI__.event._handlers[event] = [];
      }
      window.__TAURI__.event._handlers[event].push(handler);
      console.log('[tauri-mock] event.listen:', event);
      return function() {
        const arr = window.__TAURI__.event._handlers[event];
        if (arr) {
          const idx = arr.indexOf(handler);
          if (idx !== -1) arr.splice(idx, 1);
        }
      };
    },
    emit: function(event, payload) {
      var handlers = window.__TAURI__.event._handlers[event] || [];
      handlers.forEach(function(h) { h({ event: event, id: 1, payload: payload }); });
    },
  },
};
`;

/**
 * Install the Tauri mock on a page before WASM loads.
 * Call this in beforeEach or as a fixture.
 */
export async function installTauriMock(page: Page): Promise<void> {
  await page.addInitScript(MOCK_SCRIPT);
}
