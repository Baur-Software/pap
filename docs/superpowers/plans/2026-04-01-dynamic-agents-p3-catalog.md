# Dynamic Agents — Part 3: Catalog

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create ~25 TOML catalog entries (replacing the 13 deleted compiled agents plus more), and write the catalog loader module.

**Architecture:** Catalog TOML files live in crates/pap-agents/catalog/{domain}/. Each file deserializes into DynamicAgentDef (minus runtime fields). The loader reads them at startup and produces Vec<DynamicAgentDef> ready for DB insertion.

**Tech Stack:** Rust, toml 0.8, std::fs, serde

---

## Task 6: Catalog TOML files

- [ ] Create `crates/pap-agents/catalog/search/duckduckgo.toml`
- [ ] Create `crates/pap-agents/catalog/search/brave.toml`
- [ ] Create `crates/pap-agents/catalog/knowledge/wikipedia.toml`
- [ ] Create `crates/pap-agents/catalog/knowledge/dictionary.toml`
- [ ] Create `crates/pap-agents/catalog/knowledge/rest_countries.toml`
- [ ] Create `crates/pap-agents/catalog/science/arxiv.toml`
- [ ] Create `crates/pap-agents/catalog/science/open_meteo.toml`
- [ ] Create `crates/pap-agents/catalog/science/nasa_apod.toml`
- [ ] Create `crates/pap-agents/catalog/finance/frankfurter.toml`
- [ ] Create `crates/pap-agents/catalog/finance/coingecko.toml`
- [ ] Create `crates/pap-agents/catalog/geo/nominatim.toml`
- [ ] Create `crates/pap-agents/catalog/geo/ip_geolocation.toml`
- [ ] Create `crates/pap-agents/catalog/culture/open_library.toml`
- [ ] Create `crates/pap-agents/catalog/culture/hacker_news.toml`
- [ ] Create `crates/pap-agents/catalog/culture/github_repos.toml`
- [ ] Create `crates/pap-agents/catalog/culture/itunes.toml`
- [ ] Create `crates/pap-agents/catalog/food/open_food_facts.toml`
- [ ] Create `crates/pap-agents/catalog/food/the_meal_db.toml`
- [ ] Create `crates/pap-agents/catalog/health/open_fda_drugs.toml`
- [ ] Create `crates/pap-agents/catalog/sports/sports_db.toml`
- [ ] Create `crates/pap-agents/catalog/government/congress_api.toml`
- [ ] Create `crates/pap-agents/catalog/government/world_bank.toml`
- [ ] Commit: `feat(pap-agents): add 22 catalog TOML entries`

### File contents

Every file must have:
- `schema_version = 1`
- `name`, `provider`, `description`
- `action` using the appropriate schema.org action type
- `object_types`, `returns` as arrays
- `requires_disclosure = []` (unless the agent genuinely needs user data)
- `source = "Catalog"`
- `llm_instructions` — meaningful domain-specific fallback prompt
- `subagents = []`
- `[endpoint]` section with real URL, method, response_jsonpath, response_schema_type
- URL must be `https://` only and a real, working zero-auth public API

---

#### `crates/pap-agents/catalog/search/duckduckgo.toml`

```toml
schema_version = 1
name = "DuckDuckGo Search"
provider = "DuckDuckGo"
description = "Web search via DuckDuckGo. Returns organic search results without tracking."
action = "schema:SearchAction"
object_types = ["schema:WebPage"]
requires_disclosure = []
returns = ["schema:SearchResultsPage"]
source = "Catalog"
llm_instructions = """
You are a web search assistant. The user has searched for a topic.
Provide factual, relevant information about their query based on your knowledge.
Focus on accurate, up-to-date information. Keep your response concise and informative.
"""
subagents = []

[endpoint]
url_template = "https://api.duckduckgo.com/?q={query}&format=json&no_html=1&skip_disambig=1"
method = "Get"
response_jsonpath = "$.AbstractText"
response_schema_type = "schema:SearchResultsPage"
```

---

#### `crates/pap-agents/catalog/search/brave.toml`

```toml
schema_version = 1
name = "Brave Search"
provider = "Brave Software"
description = "Privacy-preserving web search via Brave's independent search index."
action = "schema:SearchAction"
object_types = ["schema:WebPage"]
requires_disclosure = []
returns = ["schema:SearchResultsPage"]
source = "Catalog"
llm_instructions = """
You are a web search assistant helping with independent, privacy-preserving search.
The user has searched for a topic. Provide accurate, factual information based on
your knowledge. Avoid speculation. Keep your response focused and informative.
"""
subagents = []

[endpoint]
url_template = "https://search.brave.com/api/suggest?q={query}&rich=1"
method = "Get"
response_jsonpath = "$[1][0]"
response_schema_type = "schema:SearchResultsPage"
```

---

#### `crates/pap-agents/catalog/knowledge/wikipedia.toml`

```toml
schema_version = 1
name = "Wikipedia Knowledge"
provider = "Wikimedia Foundation"
description = "Search Wikipedia articles via the Wikimedia REST API v1. Returns article excerpts and URLs."
action = "schema:SearchAction"
object_types = ["schema:Article"]
requires_disclosure = []
returns = ["schema:Article"]
source = "Catalog"
llm_instructions = """
You are a knowledge assistant drawing on encyclopedic information.
The user has asked about a topic. Provide a concise, factual summary of the subject.
Prioritize well-established facts. Note if the topic is disputed or evolving.
Keep your response to 2-4 paragraphs.
"""
subagents = []

[endpoint]
url_template = "https://en.wikipedia.org/w/rest.php/v1/search/page?q={query}&limit=5"
method = "Get"
response_jsonpath = "$.pages[0].excerpt"
response_schema_type = "schema:Article"
```

---

#### `crates/pap-agents/catalog/knowledge/dictionary.toml`

```toml
schema_version = 1
name = "Free Dictionary"
provider = "dictionaryapi.dev"
description = "Look up word definitions, phonetics, and etymology via the Free Dictionary API."
action = "schema:SearchAction"
object_types = ["schema:DefinedTerm"]
requires_disclosure = []
returns = ["schema:DefinedTerm"]
source = "Catalog"
llm_instructions = """
You are a dictionary assistant. The user has asked for the definition of a word.
Provide the primary definition, part of speech, phonetic pronunciation if known,
and a usage example. If the word has multiple meanings, list the most common ones.
"""
subagents = []

[endpoint]
url_template = "https://api.dictionaryapi.dev/api/v2/entries/en/{query}"
method = "Get"
response_jsonpath = "$[0].meanings[0].definitions[0].definition"
response_schema_type = "schema:DefinedTerm"
```

---

#### `crates/pap-agents/catalog/knowledge/rest_countries.toml`

```toml
schema_version = 1
name = "REST Countries"
provider = "REST Countries"
description = "Look up country information including capital, population, currency, and languages."
action = "schema:SearchAction"
object_types = ["schema:Country"]
requires_disclosure = []
returns = ["schema:Country"]
source = "Catalog"
llm_instructions = """
You are a geography and geopolitics assistant. The user has asked about a country.
Provide factual information including official name, capital city, population,
official languages, currency, region, and any notable geographic or political facts.
Be concise and accurate.
"""
subagents = []

[endpoint]
url_template = "https://restcountries.com/v3.1/name/{query}?fields=name,capital,population,currencies,languages,region,subregion,flags"
method = "Get"
response_jsonpath = "$[0].name.common"
response_schema_type = "schema:Country"
```

---

#### `crates/pap-agents/catalog/science/arxiv.toml`

```toml
schema_version = 1
name = "arXiv Search"
provider = "Cornell University"
description = "Search academic preprints on arXiv across physics, mathematics, computer science, and more."
action = "schema:SearchAction"
object_types = ["schema:ScholarlyArticle"]
requires_disclosure = []
returns = ["schema:ScholarlyArticle"]
source = "Catalog"
llm_instructions = """
You are an academic research assistant specializing in scientific literature.
The user has searched for a research topic. Summarize what is currently known
about this area of research, key findings, and important contributors.
Use precise scientific language appropriate to the field.
"""
subagents = []

[endpoint]
url_template = "https://export.arxiv.org/api/query?search_query=all:{query}&start=0&max_results=5"
method = "Get"
response_jsonpath = "$.feed.entry[0].summary"
response_schema_type = "schema:ScholarlyArticle"
```

---

#### `crates/pap-agents/catalog/science/open_meteo.toml`

```toml
schema_version = 1
name = "Open-Meteo Weather"
provider = "Open-Meteo"
description = "Retrieve current weather and forecasts using latitude/longitude coordinates. No API key required."
action = "schema:SearchAction"
object_types = ["schema:Place"]
requires_disclosure = []
returns = ["schema:WeatherForecast"]
source = "Catalog"
llm_instructions = """
You are a weather information assistant. The user has asked about weather conditions.
Provide a helpful summary of typical weather patterns for the location and time of year,
including temperature ranges, precipitation likelihood, and any seasonal considerations.
Note that you cannot provide real-time forecasts without current data.
"""
subagents = []

[endpoint]
url_template = "https://api.open-meteo.com/v1/forecast?latitude=52.52&longitude=13.41&current_weather=true&q={query}"
method = "Get"
response_jsonpath = "$.current_weather.temperature"
response_schema_type = "schema:WeatherForecast"
```

---

#### `crates/pap-agents/catalog/science/nasa_apod.toml`

```toml
schema_version = 1
name = "NASA Astronomy Picture of the Day"
provider = "NASA"
description = "Fetch NASA's Astronomy Picture of the Day with title, explanation, and image URL."
action = "schema:ViewAction"
object_types = ["schema:ImageObject"]
requires_disclosure = []
returns = ["schema:ImageObject"]
source = "Catalog"
llm_instructions = """
You are an astronomy education assistant. The user has asked about a space or astronomy topic.
Provide a clear, engaging explanation suitable for a general audience.
Include relevant scientific context, scale, and significance.
Reference well-known missions, discoveries, or celestial objects where applicable.
"""
subagents = []

[endpoint]
url_template = "https://api.nasa.gov/planetary/apod?api_key=DEMO_KEY&concept_tags=True&q={query}"
method = "Get"
response_jsonpath = "$.explanation"
response_schema_type = "schema:ImageObject"
```

---

#### `crates/pap-agents/catalog/finance/frankfurter.toml`

```toml
schema_version = 1
name = "Frankfurter Exchange Rates"
provider = "Frankfurter"
description = "Look up current and historical foreign exchange rates from the European Central Bank."
action = "schema:SearchAction"
object_types = ["schema:MonetaryAmount"]
requires_disclosure = []
returns = ["schema:ExchangeRateSpecification"]
source = "Catalog"
llm_instructions = """
You are a foreign exchange information assistant. The user has asked about currency exchange rates.
Provide context about the currency pair, typical rate ranges, and factors that influence
exchange rates between these currencies. Note that exact current rates require live data.
"""
subagents = []

[endpoint]
url_template = "https://api.frankfurter.app/latest?from={query}"
method = "Get"
response_jsonpath = "$.rates"
response_schema_type = "schema:ExchangeRateSpecification"
```

---

#### `crates/pap-agents/catalog/finance/coingecko.toml`

```toml
schema_version = 1
name = "CoinGecko Crypto Prices"
provider = "CoinGecko"
description = "Look up cryptocurrency prices, market cap, and 24h change via CoinGecko's public API."
action = "schema:SearchAction"
object_types = ["schema:MonetaryAmount"]
requires_disclosure = []
returns = ["schema:MonetaryAmount"]
source = "Catalog"
llm_instructions = """
You are a cryptocurrency information assistant. The user has asked about a digital asset.
Provide factual information about the asset including its purpose, technology, and market context.
Do not give financial advice or price predictions. Focus on factual, educational content.
"""
subagents = []

[endpoint]
url_template = "https://api.coingecko.com/api/v3/search?query={query}"
method = "Get"
response_jsonpath = "$.coins[0].name"
response_schema_type = "schema:MonetaryAmount"
```

---

#### `crates/pap-agents/catalog/geo/nominatim.toml`

```toml
schema_version = 1
name = "Nominatim Geocoding"
provider = "OpenStreetMap"
description = "Forward geocoding: convert place names and addresses to coordinates via Nominatim."
action = "schema:SearchAction"
object_types = ["schema:Place"]
requires_disclosure = []
returns = ["schema:GeoCoordinates"]
source = "Catalog"
llm_instructions = """
You are a geography and location assistant. The user has asked about a place or address.
Provide factual information about the location including its country, region, notable
landmarks, and geographic context. If it is a well-known location, describe what it is
known for.
"""
subagents = []

[endpoint]
url_template = "https://nominatim.openstreetmap.org/search?q={query}&format=json&limit=1"
method = "Get"
response_jsonpath = "$[0].display_name"
response_schema_type = "schema:GeoCoordinates"
```

---

#### `crates/pap-agents/catalog/geo/ip_geolocation.toml`

```toml
schema_version = 1
name = "IP Geolocation"
provider = "ip-api.com"
description = "Look up approximate geographic location for a public IP address."
action = "schema:SearchAction"
object_types = ["schema:Place"]
requires_disclosure = []
returns = ["schema:GeoCoordinates"]
source = "Catalog"
llm_instructions = """
You are a network and geolocation assistant. The user has provided an IP address or
asked about network location. Explain how IP geolocation works, its limitations,
and typical accuracy expectations. Do not speculate about specific individuals.
"""
subagents = []

[endpoint]
url_template = "https://ip-api.com/json/{query}?fields=status,country,regionName,city,lat,lon,timezone,isp"
method = "Get"
response_jsonpath = "$.city"
response_schema_type = "schema:GeoCoordinates"
```

---

#### `crates/pap-agents/catalog/culture/open_library.toml`

```toml
schema_version = 1
name = "Open Library Books"
provider = "Internet Archive"
description = "Search for books and authors via Open Library's public API."
action = "schema:SearchAction"
object_types = ["schema:Book"]
requires_disclosure = []
returns = ["schema:Book"]
source = "Catalog"
llm_instructions = """
You are a literary research assistant. The user has searched for a book or author.
Provide factual information about the work including author, publication year,
themes, and significance. If it is a well-known work, briefly describe its plot
and cultural impact. Keep your response to 2-3 paragraphs.
"""
subagents = []

[endpoint]
url_template = "https://openlibrary.org/search.json?q={query}&limit=5&fields=title,author_name,first_publish_year,subject"
method = "Get"
response_jsonpath = "$.docs[0].title"
response_schema_type = "schema:Book"
```

---

#### `crates/pap-agents/catalog/culture/hacker_news.toml`

```toml
schema_version = 1
name = "Hacker News Search"
provider = "Algolia / Y Combinator"
description = "Search Hacker News stories and comments via the Algolia HN Search API."
action = "schema:SearchAction"
object_types = ["schema:DiscussionForumPosting"]
requires_disclosure = []
returns = ["schema:DiscussionForumPosting"]
source = "Catalog"
llm_instructions = """
You are a technology news and community discussion assistant. The user has asked
about a topic relevant to the Hacker News community — typically technology, startups,
science, or programming. Summarize what is known about the topic, recent developments,
and community sentiment if applicable. Keep your response concise and technically accurate.
"""
subagents = []

[endpoint]
url_template = "https://hn.algolia.com/api/v1/search?query={query}&tags=story&hitsPerPage=5"
method = "Get"
response_jsonpath = "$.hits[0].title"
response_schema_type = "schema:DiscussionForumPosting"
```

---

#### `crates/pap-agents/catalog/culture/github_repos.toml`

```toml
schema_version = 1
name = "GitHub Repository Search"
provider = "GitHub"
description = "Search public GitHub repositories by keyword via the GitHub REST API."
action = "schema:SearchAction"
object_types = ["schema:SoftwareSourceCode"]
requires_disclosure = []
returns = ["schema:SoftwareSourceCode"]
source = "Catalog"
llm_instructions = """
You are a software development assistant. The user has searched for open source
repositories or code related to a topic. Describe what types of projects exist
in this space, the most popular languages and frameworks used, and what to look
for when evaluating repositories on this topic.
"""
subagents = []

[endpoint]
url_template = "https://api.github.com/search/repositories?q={query}&sort=stars&order=desc&per_page=5"
method = "Get"
response_jsonpath = "$.items[0].full_name"
response_schema_type = "schema:SoftwareSourceCode"
```

---

#### `crates/pap-agents/catalog/culture/itunes.toml`

```toml
schema_version = 1
name = "iTunes Search"
provider = "Apple"
description = "Search the iTunes catalog for music, podcasts, apps, and other media."
action = "schema:SearchAction"
object_types = ["schema:MusicRecording"]
requires_disclosure = []
returns = ["schema:MusicRecording"]
source = "Catalog"
llm_instructions = """
You are a music and media discovery assistant. The user has searched for an artist,
album, song, or podcast. Provide factual information about the requested media including
genre, release date, key tracks or episodes, and cultural significance where applicable.
Keep your response informative and to the point.
"""
subagents = []

[endpoint]
url_template = "https://itunes.apple.com/search?term={query}&limit=5&media=music"
method = "Get"
response_jsonpath = "$.results[0].trackName"
response_schema_type = "schema:MusicRecording"
```

---

#### `crates/pap-agents/catalog/food/open_food_facts.toml`

```toml
schema_version = 1
name = "Open Food Facts"
provider = "Open Food Facts"
description = "Look up nutritional data for food products by name or barcode."
action = "schema:SearchAction"
object_types = ["schema:FoodEstablishment"]
requires_disclosure = []
returns = ["schema:NutritionInformation"]
source = "Catalog"
llm_instructions = """
You are a nutrition lookup assistant. The user has asked about a food product.
Return the nutritional information as accurately as possible including calories,
macronutrients (protein, carbohydrates, fat), and key micronutrients if notable.
Limit your response to factual nutritional data only.
"""
subagents = []

[endpoint]
url_template = "https://world.openfoodfacts.org/cgi/search.pl?search_terms={query}&search_simple=1&action=process&json=1"
method = "Get"
response_jsonpath = "$.products[0].product_name"
response_schema_type = "schema:NutritionInformation"
```

---

#### `crates/pap-agents/catalog/food/the_meal_db.toml`

```toml
schema_version = 1
name = "TheMealDB Recipe Search"
provider = "TheMealDB"
description = "Search for recipes and meal ideas by name or ingredient via TheMealDB."
action = "schema:SearchAction"
object_types = ["schema:Recipe"]
requires_disclosure = []
returns = ["schema:Recipe"]
source = "Catalog"
llm_instructions = """
You are a culinary assistant. The user has asked about a recipe or dish.
Provide a concise description of the dish including its origin, key ingredients,
cooking method, and serving suggestions. If it is a classic dish, mention common
regional variations. Keep your response practical and appetizing.
"""
subagents = []

[endpoint]
url_template = "https://www.themealdb.com/api/json/v1/1/search.php?s={query}"
method = "Get"
response_jsonpath = "$.meals[0].strMeal"
response_schema_type = "schema:Recipe"
```

---

#### `crates/pap-agents/catalog/health/open_fda_drugs.toml`

```toml
schema_version = 1
name = "openFDA Drug Search"
provider = "U.S. Food and Drug Administration"
description = "Search FDA drug labeling information including indications, warnings, and dosage."
action = "schema:SearchAction"
object_types = ["schema:Drug"]
requires_disclosure = []
returns = ["schema:Drug"]
source = "Catalog"
llm_instructions = """
You are a pharmaceutical information assistant providing general reference information only.
The user has asked about a medication. Provide factual information about the drug class,
general indications, and important safety considerations from public FDA labeling.
Always note that this information is for reference only and does not constitute medical advice.
Direct users to consult a healthcare professional for personal medical decisions.
"""
subagents = []

[endpoint]
url_template = "https://api.fda.gov/drug/label.json?search=openfda.brand_name:{query}&limit=1"
method = "Get"
response_jsonpath = "$.results[0].indications_and_usage[0]"
response_schema_type = "schema:Drug"
```

---

#### `crates/pap-agents/catalog/sports/sports_db.toml`

```toml
schema_version = 1
name = "TheSportsDB Team Search"
provider = "TheSportsDB"
description = "Search for sports teams, leagues, and events via TheSportsDB public API."
action = "schema:SearchAction"
object_types = ["schema:SportsTeam"]
requires_disclosure = []
returns = ["schema:SportsTeam"]
source = "Catalog"
llm_instructions = """
You are a sports information assistant. The user has asked about a sports team, league,
or event. Provide factual information including the sport, league, home city, founding
year, notable achievements, and current standing if known. Keep your response factual
and concise.
"""
subagents = []

[endpoint]
url_template = "https://www.thesportsdb.com/api/v1/json/3/searchteams.php?t={query}"
method = "Get"
response_jsonpath = "$.teams[0].strTeam"
response_schema_type = "schema:SportsTeam"
```

---

#### `crates/pap-agents/catalog/government/congress_api.toml`

```toml
schema_version = 1
name = "Congress.gov Bill Search"
provider = "Library of Congress"
description = "Search U.S. Congressional bills and legislation via the Congress.gov API."
action = "schema:SearchAction"
object_types = ["schema:GovernmentPermit"]
requires_disclosure = []
returns = ["schema:GovernmentPermit"]
source = "Catalog"
llm_instructions = """
You are a U.S. legislative research assistant. The user has asked about a bill,
law, or Congressional topic. Provide factual information about the legislation
including its purpose, sponsors, current status, and potential impact.
Reference official bill numbers and titles where applicable.
Keep your response factual and nonpartisan.
"""
subagents = []

[endpoint]
url_template = "https://api.congress.gov/v3/bill?query={query}&format=json&limit=5&api_key=DEMO_KEY"
method = "Get"
response_jsonpath = "$.bills[0].title"
response_schema_type = "schema:GovernmentPermit"
```

---

#### `crates/pap-agents/catalog/government/world_bank.toml`

```toml
schema_version = 1
name = "World Bank Indicators"
provider = "World Bank"
description = "Query World Bank development indicators including GDP, population, and poverty data."
action = "schema:SearchAction"
object_types = ["schema:Dataset"]
requires_disclosure = []
returns = ["schema:Dataset"]
source = "Catalog"
llm_instructions = """
You are a development economics and international statistics assistant.
The user has asked about a country's economic or social development indicators.
Provide factual information from publicly available World Bank data including GDP,
population, poverty rates, education, and health indicators where relevant.
Cite approximate figures and note the data vintage when possible.
"""
subagents = []

[endpoint]
url_template = "https://api.worldbank.org/v2/country/{query}/indicator/NY.GDP.MKTP.CD?format=json&mrv=1"
method = "Get"
response_jsonpath = "$[1][0].value"
response_schema_type = "schema:Dataset"
```

---

## Task 7: Catalog loader module

- [ ] Create `crates/pap-agents/src/catalog.rs`
- [ ] Modify `crates/pap-agents/src/lib.rs` — add `pub mod catalog; pub use catalog::load_catalog;`
- [ ] Run `cargo test -p pap-agents -- catalog::` — expected: all pass
- [ ] Commit: `feat(pap-agents): add catalog loader`

### `crates/pap-agents/src/catalog.rs`

```rust
//! Catalog loader — reads all *.toml files from the catalog directory
//! and converts them to DynamicAgentDef values ready for DB insertion.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::dynamic::{DynamicAgentDef, DynamicAgentSource, HttpEndpointConfig};
use crate::url_safety::is_safe_url;

/// Subset of DynamicAgentDef that can be deserialized from a catalog TOML file.
/// Runtime fields (operator_key_seed, agent_did, published_to, created_at,
/// updated_at) are absent — they are generated at first-startup load.
#[derive(Debug, Deserialize)]
struct CatalogEntry {
    schema_version: u32,
    name: String,
    provider: String,
    description: String,
    action: String,
    #[serde(default)]
    object_types: Vec<String>,
    #[serde(default)]
    requires_disclosure: Vec<String>,
    #[serde(default)]
    returns: Vec<String>,
    endpoint: Option<HttpEndpointConfig>,
    #[serde(default)]
    llm_instructions: String,
    #[serde(default)]
    subagents: Vec<String>,
}

/// Read all `*.toml` files under `catalog_dir` (recursively), parse each as a
/// `CatalogEntry`, validate endpoint URL safety, and return the full list of
/// `DynamicAgentDef` values with `source = Catalog`.
///
/// Files that fail to parse or whose endpoint URL fails safety validation are
/// logged via `eprintln!` and skipped — they do not cause a panic or abort the
/// load of other entries.
///
/// `catalog_path` on each returned def is the path relative to `catalog_dir`,
/// using forward-slash separators regardless of platform
/// (e.g. `"search/duckduckgo.toml"`).
pub fn load_catalog(catalog_dir: &Path) -> Vec<DynamicAgentDef> {
    let mut defs = Vec::new();
    collect_toml_files(catalog_dir, catalog_dir, &mut defs);
    defs
}

fn collect_toml_files(root: &Path, dir: &Path, out: &mut Vec<DynamicAgentDef>) {
    let read_dir = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            eprintln!("[catalog] cannot read directory {}: {}", dir.display(), e);
            return;
        }
    };

    for entry in read_dir.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_toml_files(root, &path, out);
        } else if path.extension().and_then(|s| s.to_str()) == Some("toml") {
            if let Some(def) = load_one(root, &path) {
                out.push(def);
            }
        }
    }
}

fn load_one(root: &Path, path: &PathBuf) -> Option<DynamicAgentDef> {
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[catalog] cannot read {}: {}", path.display(), e);
            return None;
        }
    };

    let entry: CatalogEntry = match toml::from_str(&raw) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("[catalog] parse error in {}: {}", path.display(), e);
            return None;
        }
    };

    if let Some(ref ep) = entry.endpoint {
        if !is_safe_url(&ep.url_template) {
            eprintln!(
                "[catalog] unsafe URL in {}: {}",
                path.display(),
                ep.url_template
            );
            return None;
        }
    }

    // Compute relative path with forward slashes for catalog_path stability.
    let rel = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");

    Some(DynamicAgentDef {
        schema_version: entry.schema_version,
        name: entry.name,
        provider: entry.provider,
        description: entry.description,
        action: entry.action,
        object_types: entry.object_types,
        requires_disclosure: entry.requires_disclosure,
        returns: entry.returns,
        endpoint: entry.endpoint,
        llm_instructions: entry.llm_instructions,
        subagents: entry.subagents,
        source: DynamicAgentSource::Catalog,
        catalog_path: Some(rel),
        operator_key_seed: None,
        agent_did: None,
        published_to: vec![],
        created_at: String::new(),
        updated_at: String::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn catalog_dir() -> PathBuf {
        // The catalog lives at crates/pap-agents/catalog/ relative to CARGO_MANIFEST_DIR.
        let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        PathBuf::from(manifest).join("catalog")
    }

    #[test]
    fn load_catalog_finds_all_entries() {
        let defs = load_catalog(&catalog_dir());
        assert!(
            defs.len() >= 22,
            "expected at least 22 catalog entries, found {}",
            defs.len()
        );
    }

    #[test]
    fn catalog_path_is_relative_to_catalog_dir() {
        let defs = load_catalog(&catalog_dir());
        let ddg = defs
            .iter()
            .find(|d| d.name == "DuckDuckGo Search")
            .expect("DuckDuckGo entry missing from catalog");
        let cp = ddg.catalog_path.as_deref().expect("catalog_path is None");
        assert_eq!(cp, "search/duckduckgo.toml");
        assert!(!cp.starts_with('/'), "catalog_path must be relative, got: {cp}");
    }

    #[test]
    fn catalog_entries_have_valid_urls() {
        let defs = load_catalog(&catalog_dir());
        for def in &defs {
            if let Some(ref ep) = def.endpoint {
                assert!(
                    is_safe_url(&ep.url_template),
                    "unsafe URL in catalog entry '{}': {}",
                    def.name,
                    ep.url_template
                );
            }
        }
    }

    #[test]
    fn catalog_entries_have_schema_org_actions() {
        let defs = load_catalog(&catalog_dir());
        for def in &defs {
            assert!(
                def.action.starts_with("schema:"),
                "action '{}' in entry '{}' does not start with 'schema:'",
                def.action,
                def.name
            );
        }
    }

    #[test]
    fn malformed_toml_is_skipped() {
        let tmp = TempDir::new().unwrap();
        let bad = tmp.path().join("bad.toml");
        let mut f = std::fs::File::create(&bad).unwrap();
        writeln!(f, "this is not valid toml = [[[").unwrap();

        let defs = load_catalog(tmp.path());
        assert!(
            defs.is_empty(),
            "expected empty result for malformed TOML, got {} entries",
            defs.len()
        );
    }
}
```

### Modification to `crates/pap-agents/src/lib.rs`

Add after the existing module declarations:

```rust
pub mod catalog;
pub use catalog::load_catalog;
```

The final `lib.rs` module block will look like:

```rust
pub mod agents;
pub mod catalog;
pub mod executor;
pub mod registry;
pub mod session_store;
mod simple;

pub use catalog::load_catalog;
pub use executor::{AgentExecutor, AgentMeta};
pub use registry::{build_agents, AgentSet};
pub use simple::SimpleAgent;
```

### Run tests

```bash
cargo test -p pap-agents -- catalog::
```

Expected output: all 5 catalog tests pass.

---

## Notes

- `is_safe_url` is assumed to exist in `crates/pap-agents/src/url_safety.rs` as defined in Part 2 of this plan series. The catalog loader imports it from `crate::url_safety`.
- `DynamicAgentDef`, `DynamicAgentSource`, and `HttpEndpointConfig` are assumed to be defined in `crates/pap-agents/src/dynamic.rs` as specified in Part 1.
- The `toml` crate (version `0.8`) and `tempfile` (for tests) must be present in `crates/pap-agents/Cargo.toml`. Add them if missing:
  ```toml
  [dependencies]
  toml = "0.8"

  [dev-dependencies]
  tempfile = "3"
  ```
- `congress_api.toml` uses `DEMO_KEY` for the Congress.gov API. The production loader should substitute a configured API key from the operator's environment or profile settings, but the catalog TOML itself uses the placeholder. URL safety validation passes because the scheme is `https://` and the host is not RFC 1918 or localhost.
- `nasa_apod.toml` similarly uses NASA's `DEMO_KEY` which is a publicly documented rate-limited demo key, not a secret.
- All 22 entries use zero-auth or publicly documented demo-key APIs. None of them expose user data (all have `requires_disclosure = []`).
