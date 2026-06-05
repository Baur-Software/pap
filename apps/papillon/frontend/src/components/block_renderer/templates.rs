use super::renderer::BlockRenderer;
use super::BlockContext;
use crate::state::canvas::CanvasState;
use leptos::prelude::*;
use serde_json::Value;

/// Extract a string field from JSON-LD content, defaulting to "-".
fn text_field(content: &Value, key: &str) -> String {
    content
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("-")
        .to_string()
}

/// FlightReservation template — route card with departure/arrival, date, price, carrier.
pub struct FlightTemplate;

impl BlockRenderer for FlightTemplate {
    fn render(&self, content: &Value) -> AnyView {
        let departure = text_field(content, "departureAirport");
        let arrival = text_field(content, "arrivalAirport");
        let date = text_field(content, "departureDate");
        let price = text_field(content, "totalPrice");
        let carrier = text_field(content, "airline");

        view! {
            <div class="typed-flight">
                <div class="typed-flight-route">{format!("{} \u{2192} {}", departure, arrival)}</div>
                <div class="typed-flight-date">{date}</div>
                <div class="typed-flight-price">{format!("${}", price)}</div>
                <div class="typed-flight-carrier">{carrier}</div>
            </div>
        }
        .into_any()
    }

    fn schema_types(&self) -> Vec<&'static str> {
        vec!["FlightReservation"]
    }
}

/// LodgingReservation template — hotel card with name, dates, price.
pub struct HotelTemplate;

impl BlockRenderer for HotelTemplate {
    fn render(&self, content: &Value) -> AnyView {
        let name = text_field(content, "name");
        let checkin = text_field(content, "checkinDate");
        let checkout = text_field(content, "checkoutDate");
        let price = text_field(content, "totalPrice");

        view! {
            <div class="typed-hotel">
                <div class="typed-hotel-name">{name}</div>
                <div class="typed-hotel-dates">{format!("{} \u{2192} {}", checkin, checkout)}</div>
                <div class="typed-hotel-price">{format!("${}", price)}</div>
            </div>
        }
        .into_any()
    }

    fn schema_types(&self) -> Vec<&'static str> {
        vec!["LodgingReservation"]
    }
}

/// SearchResultsPage template — turns Schema.org search JSON-LD into a browsable
/// result list. Agents send data only; Papillon chooses this UI from `@type`.
pub struct SearchResultsTemplate;

#[derive(Clone, Debug)]
struct SearchResultAction {
    label: String,
    target: String,
}

#[derive(Clone, Debug)]
struct SearchResultItem {
    name: String,
    url: String,
    description: String,
    source: String,
    actions: Vec<SearchResultAction>,
}

impl BlockRenderer for SearchResultsTemplate {
    fn render(&self, content: &Value) -> AnyView {
        let results = extract_search_results(content);
        let result_count = results.len();
        let canvas_state = use_context::<CanvasState>();
        let source_block_id = use_context::<BlockContext>().map(|c| c.id.get_value());
        let result_views = results
            .into_iter()
            .map(|item| {
                let pap_url = to_pap_url(&item.url);
                let source_for_click = source_block_id.clone();
                let canvas_for_click = canvas_state;
                let title = if item.name.is_empty() {
                    item.url.clone()
                } else {
                    item.name
                };

                let title_view = if let Some(pap_url) = pap_url {
                    let pap_for_click = pap_url.clone();
                    view! {
                        <a
                            class="typed-search-title"
                            href=pap_url
                            on:click=move |e: leptos::ev::MouseEvent| {
                                e.prevent_default();
                                if let Some(cs) = canvas_for_click {
                                    cs.submit_agent_link(pap_for_click.clone(), source_for_click.clone());
                                }
                            }
                        >
                            {title}
                        </a>
                    }
                    .into_any()
                } else {
                    view! { <div class="typed-search-title">{title}</div> }.into_any()
                };

                let source_view = if item.source.is_empty() {
                    view! { <></> }.into_any()
                } else {
                    view! { <div class="typed-search-url">{item.source}</div> }.into_any()
                };

                let description_view = if item.description.is_empty() {
                    view! { <></> }.into_any()
                } else {
                    view! { <p class="typed-search-snippet">{item.description}</p> }.into_any()
                };

                let action_views = item
                    .actions
                    .into_iter()
                    .filter_map(|action| {
                        let target_title = action.target;
                        let target_for_click = to_pap_url(&target_title)?;
                        let source_for_action = source_block_id.clone();
                        let canvas_for_action = canvas_state;

                        Some(view! {
                            <button
                                class="typed-search-action"
                                title=target_title
                                on:click=move |e: leptos::ev::MouseEvent| {
                                    e.stop_propagation();
                                    if let Some(cs) = canvas_for_action {
                                        cs.submit_agent_link(target_for_click.clone(), source_for_action.clone());
                                    }
                                }
                            >
                                {action.label}
                            </button>
                        })
                    })
                    .collect::<Vec<_>>();

                let actions_view = if action_views.is_empty() {
                    view! { <></> }.into_any()
                } else {
                    view! {
                        <div class="typed-search-actions">
                            {action_views}
                        </div>
                    }
                    .into_any()
                };

                view! {
                    <article class="typed-search-item">
                        <div class="typed-search-main">
                            {title_view}
                            {source_view}
                            {description_view}
                        </div>
                        {actions_view}
                    </article>
                }
            })
            .collect::<Vec<_>>();

        let result_body = if result_count == 0 {
            view! { <div class="typed-search-empty">"No structured results returned."</div> }
                .into_any()
        } else {
            view! { <>{result_views}</> }.into_any()
        };

        view! {
            <div class="typed-search-results">
                <div class="typed-search-header">
                    <span class="typed-search-kicker">"Schema.org SearchResultsPage"</span>
                    <span class="typed-search-count">
                        {if result_count == 1 {
                            "1 result".to_string()
                        } else {
                            format!("{result_count} results")
                        }}
                    </span>
                </div>
                {result_body}
            </div>
        }
        .into_any()
    }

    fn schema_types(&self) -> Vec<&'static str> {
        vec!["SearchResultsPage"]
    }
}

fn extract_search_results(content: &Value) -> Vec<SearchResultItem> {
    let mut raw_items: Vec<Value> = Vec::new();

    if has_type(content, "SearchResult") && !has_result_collection(content) {
        raw_items.push(content.clone());
    }

    if let Some(items) = content
        .get("mainEntity")
        .and_then(|v| v.get("itemListElement"))
        .and_then(|v| v.as_array())
    {
        raw_items.extend(items.iter().cloned());
    }

    if let Some(items) = content.get("itemListElement").and_then(|v| v.as_array()) {
        raw_items.extend(items.iter().cloned());
    }

    if raw_items.is_empty() {
        if let Some(items) = content.get("result").and_then(|v| v.as_array()) {
            raw_items.extend(items.iter().cloned());
        } else if let Some(items) = content
            .get("result")
            .and_then(|v| v.get("itemListElement"))
            .and_then(|v| v.as_array())
        {
            raw_items.extend(items.iter().cloned());
        }
    }

    raw_items
        .iter()
        .filter_map(search_item_from_value)
        .take(20)
        .collect()
}

fn has_result_collection(content: &Value) -> bool {
    content
        .get("mainEntity")
        .and_then(|v| v.get("itemListElement"))
        .and_then(|v| v.as_array())
        .is_some()
        || content
            .get("itemListElement")
            .and_then(|v| v.as_array())
            .is_some()
        || content.get("result").and_then(|v| v.as_array()).is_some()
        || content
            .get("result")
            .and_then(|v| v.get("itemListElement"))
            .and_then(|v| v.as_array())
            .is_some()
}

fn search_item_from_value(value: &Value) -> Option<SearchResultItem> {
    let item = value.get("item").unwrap_or(value);
    let payload = if has_type(item, "ListItem") {
        item.get("item").unwrap_or(item)
    } else {
        item
    };

    let name = textish(payload, "name")
        .or_else(|| textish(payload, "headline"))
        .or_else(|| textish(value, "name"))
        .unwrap_or_else(|| "Untitled result".to_string());
    let url = textish(payload, "url")
        .or_else(|| textish(payload, "sameAs"))
        .or_else(|| textish(value, "url"))
        .unwrap_or_default();
    let description = textish(payload, "description")
        .or_else(|| textish(payload, "text"))
        .or_else(|| textish(value, "description"))
        .unwrap_or_default();
    let source = if url.is_empty() {
        textish(payload, "provider")
            .or_else(|| textish(payload, "publisher"))
            .or_else(|| textish(payload, "source"))
            .unwrap_or_default()
    } else {
        url.clone()
    };
    let actions = extract_actions(payload);

    if name.is_empty() && url.is_empty() && description.is_empty() {
        None
    } else {
        Some(SearchResultItem {
            name,
            url,
            description,
            source,
            actions,
        })
    }
}

fn extract_actions(value: &Value) -> Vec<SearchResultAction> {
    let Some(actions) = value.get("potentialAction") else {
        return vec![];
    };

    match actions {
        Value::Array(items) => items.iter().filter_map(action_from_value).collect(),
        other => action_from_value(other).into_iter().collect(),
    }
}

fn action_from_value(value: &Value) -> Option<SearchResultAction> {
    let label = textish(value, "name")
        .or_else(|| textish(value, "@type").map(|t| t.trim_start_matches("schema:").to_string()))
        .unwrap_or_else(|| "Open".to_string());
    let target = textish(value, "target")
        .or_else(|| value.get("target").and_then(|v| textish(v, "urlTemplate")))
        .or_else(|| value.get("target").and_then(|v| textish(v, "url")))
        .or_else(|| textish(value, "url"))
        .unwrap_or_default();

    if target.is_empty() || to_pap_url(&target).is_none() {
        None
    } else {
        Some(SearchResultAction { label, target })
    }
}

fn has_type(value: &Value, expected: &str) -> bool {
    match value.get("@type") {
        Some(Value::String(t)) => t == expected || t.trim_start_matches("schema:") == expected,
        Some(Value::Array(types)) => types.iter().any(|t| {
            t.as_str()
                .map(|s| s == expected || s.trim_start_matches("schema:") == expected)
                .unwrap_or(false)
        }),
        _ => false,
    }
}

fn textish(value: &Value, key: &str) -> Option<String> {
    let value = value.get(key)?;
    match value {
        Value::String(s) if !s.trim().is_empty() => Some(s.trim().to_string()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Object(_) => textish(value, "name").or_else(|| textish(value, "url")),
        Value::Array(items) => items.iter().find_map(|item| match item {
            Value::String(s) if !s.trim().is_empty() => Some(s.trim().to_string()),
            Value::Object(_) => textish(item, "name").or_else(|| textish(item, "url")),
            _ => None,
        }),
        _ => None,
    }
}

fn to_pap_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.contains('{')
        || trimmed.contains('}')
        || trimmed.chars().any(char::is_whitespace)
    {
        return None;
    }

    if let Some(rest) = trimmed.strip_prefix("https://") {
        if rest.is_empty() {
            None
        } else {
            Some(format!("pap://{rest}"))
        }
    } else if let Some(rest) = trimmed.strip_prefix("http://") {
        if rest.is_empty() {
            None
        } else {
            Some(format!("pap://{rest}"))
        }
    } else if trimmed.starts_with("pap://") && trimmed.len() > "pap://".len() {
        Some(trimmed.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod search_results_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extracts_search_results_from_item_list_shapes() {
        let content = json!({
            "@type": "SearchResultsPage",
            "mainEntity": {
                "@type": "ItemList",
                "itemListElement": [
                    {
                        "@type": "ListItem",
                        "item": {
                            "@type": "SearchResult",
                            "name": "Papillon overview",
                            "url": "https://example.com/papillon",
                            "description": "A schema-driven browser result.",
                            "potentialAction": {
                                "@type": "ReadAction",
                                "target": "https://example.com/papillon/open"
                            }
                        }
                    },
                    {
                        "@type": "SearchResult",
                        "headline": "Agent registry",
                        "sameAs": "https://registry.example/agents"
                    }
                ]
            }
        });

        let results = extract_search_results(&content);

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].name, "Papillon overview");
        assert_eq!(results[0].url, "https://example.com/papillon");
        assert_eq!(results[0].description, "A schema-driven browser result.");
        assert_eq!(results[0].actions.len(), 1);
        assert_eq!(results[1].name, "Agent registry");
        assert_eq!(results[1].url, "https://registry.example/agents");
    }

    #[test]
    fn does_not_duplicate_top_level_search_result_with_collection() {
        let content = json!({
            "@type": "SearchResult",
            "name": "Wrapper result",
            "itemListElement": [
                {
                    "@type": "SearchResult",
                    "name": "Only child",
                    "url": "https://example.com/child"
                }
            ]
        });

        let results = extract_search_results(&content);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "Only child");
    }

    #[test]
    fn search_item_from_value_reads_list_item_payload() {
        let value = json!({
            "@type": "ListItem",
            "name": "Position label",
            "item": {
                "@type": "SearchResult",
                "name": "Payload title",
                "url": "https://example.com/payload",
                "description": "Payload description"
            }
        });

        let item = search_item_from_value(&value).expect("item should parse");

        assert_eq!(item.name, "Payload title");
        assert_eq!(item.url, "https://example.com/payload");
        assert_eq!(item.description, "Payload description");
    }

    #[test]
    fn has_type_matches_schema_prefix_and_array_values() {
        assert!(has_type(
            &json!({"@type": "schema:SearchResultsPage"}),
            "SearchResultsPage"
        ));
        assert!(has_type(
            &json!({"@type": ["schema:Thing", "SearchResult"]}),
            "SearchResult"
        ));
        assert!(!has_type(&json!({"@type": "Article"}), "SearchResult"));
    }

    #[test]
    fn textish_reads_scalar_object_and_array_values() {
        assert_eq!(
            textish(&json!({"provider": {"name": "DuckDuckGo"}}), "provider").as_deref(),
            Some("DuckDuckGo")
        );
        assert_eq!(textish(&json!({"rank": 3}), "rank").as_deref(), Some("3"));
        assert_eq!(
            textish(
                &json!({"sameAs": ["", {"url": "https://example.com/alt"}]}),
                "sameAs"
            )
            .as_deref(),
            Some("https://example.com/alt")
        );
    }

    #[test]
    fn to_pap_url_rewrites_only_resolved_http_urls() {
        assert_eq!(
            to_pap_url("https://example.com/path?q=1").as_deref(),
            Some("pap://example.com/path?q=1")
        );
        assert_eq!(
            to_pap_url("http://example.com").as_deref(),
            Some("pap://example.com")
        );
        assert_eq!(
            to_pap_url("pap://registry.example/agent").as_deref(),
            Some("pap://registry.example/agent")
        );
        assert_eq!(to_pap_url("{+url}"), None);
        assert_eq!(to_pap_url("https://example.com/{id}"), None);
        assert_eq!(to_pap_url("javascript:alert(1)"), None);
    }

    #[test]
    fn action_from_value_skips_uri_templates() {
        let action = json!({
            "@type": "SearchAction",
            "target": {
                "@type": "EntryPoint",
                "urlTemplate": "https://example.com/search?q={query}"
            }
        });

        assert!(action_from_value(&action).is_none());
    }

    #[test]
    fn search_results_template_only_registers_page_type() {
        assert_eq!(
            SearchResultsTemplate.schema_types(),
            vec!["SearchResultsPage"]
        );
    }
}

/// Answer template — on-device AI response rendered as a paragraph.
pub struct AnswerTemplate;

impl BlockRenderer for AnswerTemplate {
    fn render(&self, content: &Value) -> AnyView {
        let text = content
            .get("text")
            .and_then(|v| v.as_str())
            .unwrap_or("-")
            .to_string();

        view! {
            <div class="typed-answer">
                <p class="typed-answer-text">{text}</p>
            </div>
        }
        .into_any()
    }

    fn schema_types(&self) -> Vec<&'static str> {
        vec!["Answer"]
    }
}

// ── Entertainment ────────────────────────────────────────────────────────────

/// Movie template — title, year, director, genre, rating.
pub struct MovieTemplate;

impl BlockRenderer for MovieTemplate {
    fn render(&self, content: &Value) -> AnyView {
        let title = text_field(content, "name");
        let year = text_field(content, "datePublished");
        let director = content
            .get("director")
            .and_then(|d| d.get("name").or(d.as_str().map(|_| d)))
            .and_then(|v| v.as_str())
            .unwrap_or("-")
            .to_string();
        let genre = content
            .get("genre")
            .and_then(|v| v.as_str())
            .unwrap_or("-")
            .to_string();
        let rating = text_field(content, "contentRating");
        let description = text_field(content, "description");

        view! {
            <div class="typed-movie">
                <div class="typed-movie-title">{title}</div>
                <div class="typed-movie-meta">
                    <span class="typed-movie-year">{year}</span>
                    <span class="typed-movie-genre">{genre}</span>
                    <span class="typed-movie-rating">{rating}</span>
                </div>
                <div class="typed-movie-director">{"Dir: "}{director}</div>
                <div class="typed-movie-description">{description}</div>
            </div>
        }
        .into_any()
    }

    fn schema_types(&self) -> Vec<&'static str> {
        vec!["Movie"]
    }
}

/// TVSeries template — title, network, seasons, synopsis.
pub struct TvSeriesTemplate;

impl BlockRenderer for TvSeriesTemplate {
    fn render(&self, content: &Value) -> AnyView {
        let title = text_field(content, "name");
        let network = text_field(content, "broadcastChannel");
        let start_date = text_field(content, "startDate");
        let num_seasons = text_field(content, "numberOfSeasons");
        let description = text_field(content, "description");

        view! {
            <div class="typed-tv-series">
                <div class="typed-tv-title">{title}</div>
                <div class="typed-tv-meta">
                    <span class="typed-tv-network">{network}</span>
                    <span class="typed-tv-start">{start_date}</span>
                    <span class="typed-tv-seasons">{format!("{} seasons", num_seasons)}</span>
                </div>
                <div class="typed-tv-description">{description}</div>
            </div>
        }
        .into_any()
    }

    fn schema_types(&self) -> Vec<&'static str> {
        vec!["TVSeries"]
    }
}

/// VideoGame template — title, platform, genre, developer, rating.
pub struct VideoGameTemplate;

impl BlockRenderer for VideoGameTemplate {
    fn render(&self, content: &Value) -> AnyView {
        let title = text_field(content, "name");
        let platform = content
            .get("gamePlatform")
            .and_then(|v| v.as_str())
            .unwrap_or("-")
            .to_string();
        let genre = text_field(content, "genre");
        let developer = text_field(content, "author");
        let description = text_field(content, "description");

        view! {
            <div class="typed-video-game">
                <div class="typed-game-title">{title}</div>
                <div class="typed-game-meta">
                    <span class="typed-game-platform">{platform}</span>
                    <span class="typed-game-genre">{genre}</span>
                    <span class="typed-game-developer">{developer}</span>
                </div>
                <div class="typed-game-description">{description}</div>
            </div>
        }
        .into_any()
    }

    fn schema_types(&self) -> Vec<&'static str> {
        vec!["VideoGame", "Game"]
    }
}

/// MusicRecording template — track, artist, album, duration.
pub struct MusicRecordingTemplate;

impl BlockRenderer for MusicRecordingTemplate {
    fn render(&self, content: &Value) -> AnyView {
        let title = text_field(content, "name");
        let artist = content
            .get("byArtist")
            .and_then(|a| a.get("name").or(a.as_str().map(|_| a)))
            .and_then(|v| v.as_str())
            .unwrap_or("-")
            .to_string();
        let album = content
            .get("inAlbum")
            .and_then(|a| a.get("name").or(a.as_str().map(|_| a)))
            .and_then(|v| v.as_str())
            .unwrap_or("-")
            .to_string();
        let duration = text_field(content, "duration");

        view! {
            <div class="typed-music-recording">
                <div class="typed-music-title">{title}</div>
                <div class="typed-music-meta">
                    <span class="typed-music-artist">{artist}</span>
                    <span class="typed-music-album">{album}</span>
                    <span class="typed-music-duration">{duration}</span>
                </div>
            </div>
        }
        .into_any()
    }

    fn schema_types(&self) -> Vec<&'static str> {
        vec!["MusicRecording", "AudioObject"]
    }
}

/// MusicGroup/MusicAlbum template — artist/album card.
pub struct MusicGroupTemplate;

impl BlockRenderer for MusicGroupTemplate {
    fn render(&self, content: &Value) -> AnyView {
        let name = text_field(content, "name");
        let genre = text_field(content, "genre");
        let founding_date = text_field(content, "foundingDate");
        let description = text_field(content, "description");

        view! {
            <div class="typed-music-group">
                <div class="typed-music-group-name">{name}</div>
                <div class="typed-music-group-meta">
                    <span class="typed-music-group-genre">{genre}</span>
                    <span class="typed-music-group-founded">{founding_date}</span>
                </div>
                <div class="typed-music-group-description">{description}</div>
            </div>
        }
        .into_any()
    }

    fn schema_types(&self) -> Vec<&'static str> {
        vec!["MusicGroup", "MusicAlbum"]
    }
}

/// Book template — title, author, publisher, ISBN, year.
pub struct BookTemplate;

impl BlockRenderer for BookTemplate {
    fn render(&self, content: &Value) -> AnyView {
        let title = text_field(content, "name");
        let author = content
            .get("author")
            .and_then(|a| a.get("name").or(a.as_str().map(|_| a)))
            .and_then(|v| v.as_str())
            .unwrap_or("-")
            .to_string();
        let publisher = content
            .get("publisher")
            .and_then(|p| p.get("name").or(p.as_str().map(|_| p)))
            .and_then(|v| v.as_str())
            .unwrap_or("-")
            .to_string();
        let year = text_field(content, "datePublished");
        let isbn = text_field(content, "isbn");
        let description = text_field(content, "description");

        view! {
            <div class="typed-book">
                <div class="typed-book-title">{title}</div>
                <div class="typed-book-author">{author}</div>
                <div class="typed-book-meta">
                    <span class="typed-book-publisher">{publisher}</span>
                    <span class="typed-book-year">{year}</span>
                    <span class="typed-book-isbn">{isbn}</span>
                </div>
                <div class="typed-book-description">{description}</div>
            </div>
        }
        .into_any()
    }

    fn schema_types(&self) -> Vec<&'static str> {
        vec!["Book"]
    }
}

// ── News & Media ──────────────────────────────────────────────────────────────

/// NewsArticle template — headline, source, date, snippet.
pub struct NewsArticleTemplate;

impl BlockRenderer for NewsArticleTemplate {
    fn render(&self, content: &Value) -> AnyView {
        let headline = text_field(content, "headline");
        let source = content
            .get("publisher")
            .and_then(|p| p.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("-")
            .to_string();
        let date = text_field(content, "datePublished");
        let description = text_field(content, "description");
        let url = text_field(content, "url");

        view! {
            <div class="typed-news-article">
                <div class="typed-news-headline">{headline}</div>
                <div class="typed-news-meta">
                    <span class="typed-news-source">{source}</span>
                    <span class="typed-news-date">{date}</span>
                </div>
                <div class="typed-news-description">{description}</div>
                <div class="typed-news-url">{url}</div>
            </div>
        }
        .into_any()
    }

    fn schema_types(&self) -> Vec<&'static str> {
        vec!["NewsArticle", "Article"]
    }
}

/// ScholarlyArticle template — title, authors, journal, year, DOI, abstract.
pub struct ScholarlyArticleTemplate;

impl BlockRenderer for ScholarlyArticleTemplate {
    fn render(&self, content: &Value) -> AnyView {
        let title = text_field(content, "name");
        let authors = content
            .get("author")
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .take(3)
                    .filter_map(|a| a.get("name").and_then(|n| n.as_str()))
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_else(|| text_field(content, "author"));
        let journal = text_field(content, "isPartOf");
        let year = text_field(content, "datePublished");
        let doi = text_field(content, "identifier");
        let abstract_text = text_field(content, "abstract");

        view! {
            <div class="typed-scholarly-article">
                <div class="typed-paper-title">{title}</div>
                <div class="typed-paper-authors">{authors}</div>
                <div class="typed-paper-meta">
                    <span class="typed-paper-journal">{journal}</span>
                    <span class="typed-paper-year">{year}</span>
                    <span class="typed-paper-doi">{doi}</span>
                </div>
                <div class="typed-paper-abstract">{abstract_text}</div>
            </div>
        }
        .into_any()
    }

    fn schema_types(&self) -> Vec<&'static str> {
        vec!["ScholarlyArticle"]
    }
}

// ── People & Organizations ────────────────────────────────────────────────────

/// Person template — name, title, affiliation, bio.
pub struct PersonTemplate;

impl BlockRenderer for PersonTemplate {
    fn render(&self, content: &Value) -> AnyView {
        let name = text_field(content, "name");
        let job_title = text_field(content, "jobTitle");
        let affiliation = content
            .get("affiliation")
            .and_then(|a| a.get("name").or(a.as_str().map(|_| a)))
            .and_then(|v| v.as_str())
            .unwrap_or("-")
            .to_string();
        let description = text_field(content, "description");
        let url = text_field(content, "url");

        view! {
            <div class="typed-person">
                <div class="typed-person-name">{name}</div>
                <div class="typed-person-meta">
                    <span class="typed-person-title">{job_title}</span>
                    <span class="typed-person-affiliation">{affiliation}</span>
                </div>
                <div class="typed-person-bio">{description}</div>
                <div class="typed-person-url">{url}</div>
            </div>
        }
        .into_any()
    }

    fn schema_types(&self) -> Vec<&'static str> {
        vec!["Person"]
    }
}

/// Organization template — name, type, description, website.
pub struct OrganizationTemplate;

impl BlockRenderer for OrganizationTemplate {
    fn render(&self, content: &Value) -> AnyView {
        let name = text_field(content, "name");
        let org_type = text_field(content, "@type");
        let description = text_field(content, "description");
        let url = text_field(content, "url");
        let location = content
            .get("location")
            .and_then(|l| l.get("name").or(l.as_str().map(|_| l)))
            .and_then(|v| v.as_str())
            .unwrap_or("-")
            .to_string();

        view! {
            <div class="typed-organization">
                <div class="typed-org-name">{name}</div>
                <div class="typed-org-meta">
                    <span class="typed-org-type">{org_type}</span>
                    <span class="typed-org-location">{location}</span>
                </div>
                <div class="typed-org-description">{description}</div>
                <div class="typed-org-url">{url}</div>
            </div>
        }
        .into_any()
    }

    fn schema_types(&self) -> Vec<&'static str> {
        vec![
            "Organization",
            "LocalBusiness",
            "FoodEstablishment",
            "LodgingBusiness",
        ]
    }
}

// ── Places & Weather ──────────────────────────────────────────────────────────

/// WeatherForecast template — temperature, conditions, location.
pub struct WeatherForecastTemplate;

impl BlockRenderer for WeatherForecastTemplate {
    fn render(&self, content: &Value) -> AnyView {
        let location = text_field(content, "name");
        let temperature = text_field(content, "temperature");
        let description = text_field(content, "description");
        let humidity = text_field(content, "humidity");
        let wind = text_field(content, "windSpeed");

        view! {
            <div class="typed-weather">
                <div class="typed-weather-location">{location}</div>
                <div class="typed-weather-temp">{temperature}</div>
                <div class="typed-weather-conditions">{description}</div>
                <div class="typed-weather-details">
                    <span class="typed-weather-humidity">{format!("Humidity: {}", humidity)}</span>
                    <span class="typed-weather-wind">{format!("Wind: {}", wind)}</span>
                </div>
            </div>
        }
        .into_any()
    }

    fn schema_types(&self) -> Vec<&'static str> {
        vec!["WeatherForecast"]
    }
}

/// GeoCoordinates template — lat, lon, elevation, address.
pub struct GeoCoordinatesTemplate;

impl BlockRenderer for GeoCoordinatesTemplate {
    fn render(&self, content: &Value) -> AnyView {
        let name = text_field(content, "name");
        let lat = text_field(content, "latitude");
        let lon = text_field(content, "longitude");
        let elevation = text_field(content, "elevation");
        let address = text_field(content, "address");

        view! {
            <div class="typed-geocoords">
                <div class="typed-geo-name">{name}</div>
                <div class="typed-geo-coords">
                    <span class="typed-geo-lat">{format!("Lat: {}", lat)}</span>
                    <span class="typed-geo-lon">{format!("Lon: {}", lon)}</span>
                    <span class="typed-geo-elevation">{format!("Elev: {}", elevation)}</span>
                </div>
                <div class="typed-geo-address">{address}</div>
            </div>
        }
        .into_any()
    }

    fn schema_types(&self) -> Vec<&'static str> {
        vec!["GeoCoordinates", "Place"]
    }
}

// ── Commerce & Products ───────────────────────────────────────────────────────

/// Product template — name, brand, price, description, rating.
pub struct ProductTemplate;

impl BlockRenderer for ProductTemplate {
    fn render(&self, content: &Value) -> AnyView {
        let name = text_field(content, "name");
        let brand = content
            .get("brand")
            .and_then(|b| b.get("name").or(b.as_str().map(|_| b)))
            .and_then(|v| v.as_str())
            .unwrap_or("-")
            .to_string();
        let price = content
            .get("offers")
            .and_then(|o| o.get("price"))
            .and_then(|v| v.as_str())
            .unwrap_or("-")
            .to_string();
        let description = text_field(content, "description");
        let rating = content
            .get("aggregateRating")
            .and_then(|r| r.get("ratingValue"))
            .and_then(|v| v.as_str().or_else(|| None))
            .map(|v| v.to_string())
            .unwrap_or("-".to_string());

        view! {
            <div class="typed-product">
                <div class="typed-product-name">{name}</div>
                <div class="typed-product-meta">
                    <span class="typed-product-brand">{brand}</span>
                    <span class="typed-product-price">{format!("${}", price)}</span>
                    <span class="typed-product-rating">{format!("★ {}", rating)}</span>
                </div>
                <div class="typed-product-description">{description}</div>
            </div>
        }
        .into_any()
    }

    fn schema_types(&self) -> Vec<&'static str> {
        vec!["Product"]
    }
}

// ── Events & Activities ───────────────────────────────────────────────────────

/// Event template — name, date, location, description.
pub struct EventTemplate;

impl BlockRenderer for EventTemplate {
    fn render(&self, content: &Value) -> AnyView {
        let name = text_field(content, "name");
        let start_date = text_field(content, "startDate");
        let end_date = text_field(content, "endDate");
        let location = content
            .get("location")
            .and_then(|l| l.get("name").or(l.as_str().map(|_| l)))
            .and_then(|v| v.as_str())
            .unwrap_or("-")
            .to_string();
        let description = text_field(content, "description");
        let organizer = text_field(content, "organizer");

        view! {
            <div class="typed-event">
                <div class="typed-event-name">{name}</div>
                <div class="typed-event-dates">
                    <span class="typed-event-start">{start_date}</span>
                    <span class="typed-event-end">{end_date}</span>
                </div>
                <div class="typed-event-location">{location}</div>
                <div class="typed-event-organizer">{organizer}</div>
                <div class="typed-event-description">{description}</div>
            </div>
        }
        .into_any()
    }

    fn schema_types(&self) -> Vec<&'static str> {
        vec!["Event", "SportsEvent", "MusicEvent"]
    }
}

/// SportsEvent template — home vs away, score, date, venue.
pub struct SportsEventTemplate;

impl BlockRenderer for SportsEventTemplate {
    fn render(&self, content: &Value) -> AnyView {
        let name = text_field(content, "name");
        let home = content
            .get("homeTeam")
            .and_then(|t| t.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("-")
            .to_string();
        let away = content
            .get("awayTeam")
            .and_then(|t| t.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("-")
            .to_string();
        let start_date = text_field(content, "startDate");
        let location = content
            .get("location")
            .and_then(|l| l.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("-")
            .to_string();

        view! {
            <div class="typed-sports-event">
                <div class="typed-sports-name">{name}</div>
                <div class="typed-sports-matchup">
                    <span class="typed-sports-home">{home}</span>
                    <span class="typed-sports-vs">"vs"</span>
                    <span class="typed-sports-away">{away}</span>
                </div>
                <div class="typed-sports-meta">
                    <span class="typed-sports-date">{start_date}</span>
                    <span class="typed-sports-venue">{location}</span>
                </div>
            </div>
        }
        .into_any()
    }

    fn schema_types(&self) -> Vec<&'static str> {
        vec!["SportsTeam"]
    }
}

// ── Education ─────────────────────────────────────────────────────────────────

/// Course template — name, provider, description, url.
pub struct CourseTemplate;

impl BlockRenderer for CourseTemplate {
    fn render(&self, content: &Value) -> AnyView {
        let name = text_field(content, "name");
        let provider = content
            .get("provider")
            .and_then(|p| p.get("name").or(p.as_str().map(|_| p)))
            .and_then(|v| v.as_str())
            .unwrap_or("-")
            .to_string();
        let description = text_field(content, "description");
        let url = text_field(content, "url");

        view! {
            <div class="typed-course">
                <div class="typed-course-name">{name}</div>
                <div class="typed-course-provider">{provider}</div>
                <div class="typed-course-description">{description}</div>
                <div class="typed-course-url">{url}</div>
            </div>
        }
        .into_any()
    }

    fn schema_types(&self) -> Vec<&'static str> {
        vec!["Course", "LearningResource"]
    }
}

// ── Health & Nutrition ────────────────────────────────────────────────────────

/// NutritionInformation template — calories, macros, serving size.
pub struct NutritionTemplate;

impl BlockRenderer for NutritionTemplate {
    fn render(&self, content: &Value) -> AnyView {
        let name = text_field(content, "name");
        let calories = text_field(content, "calories");
        let protein = text_field(content, "proteinContent");
        let carbs = text_field(content, "carbohydrateContent");
        let fat = text_field(content, "fatContent");
        let serving = text_field(content, "servingSize");

        view! {
            <div class="typed-nutrition">
                <div class="typed-nutrition-name">{name}</div>
                <div class="typed-nutrition-serving">{format!("Serving: {}", serving)}</div>
                <div class="typed-nutrition-macros">
                    <span class="typed-nutrition-calories">{format!("{} kcal", calories)}</span>
                    <span class="typed-nutrition-protein">{format!("Protein: {}", protein)}</span>
                    <span class="typed-nutrition-carbs">{format!("Carbs: {}", carbs)}</span>
                    <span class="typed-nutrition-fat">{format!("Fat: {}", fat)}</span>
                </div>
            </div>
        }
        .into_any()
    }

    fn schema_types(&self) -> Vec<&'static str> {
        vec!["NutritionInformation"]
    }
}

// ── Jobs ──────────────────────────────────────────────────────────────────────

/// JobPosting template — title, company, location, salary, description.
pub struct JobPostingTemplate;

impl BlockRenderer for JobPostingTemplate {
    fn render(&self, content: &Value) -> AnyView {
        let title = text_field(content, "title");
        let company = content
            .get("hiringOrganization")
            .and_then(|o| o.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("-")
            .to_string();
        let location = text_field(content, "jobLocation");
        let date_posted = text_field(content, "datePosted");
        let salary = text_field(content, "baseSalary");
        let description = text_field(content, "description");

        view! {
            <div class="typed-job-posting">
                <div class="typed-job-title">{title}</div>
                <div class="typed-job-company">{company}</div>
                <div class="typed-job-meta">
                    <span class="typed-job-location">{location}</span>
                    <span class="typed-job-date">{date_posted}</span>
                    <span class="typed-job-salary">{salary}</span>
                </div>
                <div class="typed-job-description">{description}</div>
            </div>
        }
        .into_any()
    }

    fn schema_types(&self) -> Vec<&'static str> {
        vec!["JobPosting"]
    }
}

// ── Arts ──────────────────────────────────────────────────────────────────────

/// VisualArtwork template — title, artist, medium, date, museum.
pub struct VisualArtworkTemplate;

impl BlockRenderer for VisualArtworkTemplate {
    fn render(&self, content: &Value) -> AnyView {
        let title = text_field(content, "name");
        let artist = content
            .get("creator")
            .and_then(|a| a.get("name").or(a.as_str().map(|_| a)))
            .and_then(|v| v.as_str())
            .unwrap_or("-")
            .to_string();
        let medium = text_field(content, "artMedium");
        let date = text_field(content, "dateCreated");
        let location = content
            .get("locationCreated")
            .and_then(|l| l.get("name").or(l.as_str().map(|_| l)))
            .and_then(|v| v.as_str())
            .unwrap_or("-")
            .to_string();
        let description = text_field(content, "description");

        view! {
            <div class="typed-visual-artwork">
                <div class="typed-artwork-title">{title}</div>
                <div class="typed-artwork-artist">{artist}</div>
                <div class="typed-artwork-meta">
                    <span class="typed-artwork-medium">{medium}</span>
                    <span class="typed-artwork-date">{date}</span>
                    <span class="typed-artwork-location">{location}</span>
                </div>
                <div class="typed-artwork-description">{description}</div>
            </div>
        }
        .into_any()
    }

    fn schema_types(&self) -> Vec<&'static str> {
        vec!["VisualArtwork"]
    }
}

// ── Vocabulary ────────────────────────────────────────────────────────────────

/// DefinedTerm template — word, definition, part of speech, examples.
pub struct DefinedTermTemplate;

impl BlockRenderer for DefinedTermTemplate {
    fn render(&self, content: &Value) -> AnyView {
        let term = text_field(content, "name");
        let definition = text_field(content, "description");
        let part_of_speech = text_field(content, "inDefinedTermSet");

        view! {
            <div class="typed-defined-term">
                <div class="typed-term-word">{term}</div>
                <div class="typed-term-pos">{part_of_speech}</div>
                <div class="typed-term-definition">{definition}</div>
            </div>
        }
        .into_any()
    }

    fn schema_types(&self) -> Vec<&'static str> {
        vec!["DefinedTerm"]
    }
}

/// Quotation template — quote, author, source.
pub struct QuotationTemplate;

impl BlockRenderer for QuotationTemplate {
    fn render(&self, content: &Value) -> AnyView {
        let quote = text_field(content, "text");
        let author = content
            .get("spokenByCharacter")
            .or_else(|| content.get("creator"))
            .and_then(|a| a.get("name").or(a.as_str().map(|_| a)))
            .and_then(|v| v.as_str())
            .unwrap_or("-")
            .to_string();
        let source = text_field(content, "citation");

        view! {
            <div class="typed-quotation">
                <blockquote class="typed-quote-text">{format!("\u{201C}{}\u{201D}", quote)}</blockquote>
                <div class="typed-quote-attribution">
                    <span class="typed-quote-author">{format!("\u{2014} {}", author)}</span>
                    <span class="typed-quote-source">{source}</span>
                </div>
            </div>
        }
        .into_any()
    }

    fn schema_types(&self) -> Vec<&'static str> {
        vec!["Quotation"]
    }
}

// ── Web ───────────────────────────────────────────────────────────────────────

/// WebPage template — browser-tab-style block for web browsing on the canvas.
///
/// Rendered when the Web Page Reader agent returns `schema:WebPage` JSON-LD,
/// which happens whenever the user browses via `pap://domain.com`. The block
/// shows a URL bar, page title, description, publisher, and body text extract.
///
/// The URL bar renders the page URL as a `pap://` link so that clicking it
/// opens a new browse block via `submit_agent_link()` (LinkOrigin::Agent).
pub struct WebPageTemplate;

impl BlockRenderer for WebPageTemplate {
    fn render(&self, content: &Value) -> AnyView {
        let title = text_field(content, "name");
        let url = text_field(content, "url");
        let description = text_field(content, "description");
        let body_text = text_field(content, "text");

        // Publisher: either a bare string or an object with "name".
        let publisher = content
            .get("publisher")
            .and_then(|p| p.get("name").or(Some(p)))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // Author: either a bare string or an object with "name".
        let author = content
            .get("author")
            .and_then(|a| a.get("name").or(Some(a)))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // Published date — trim to date part if it includes a time component.
        let date_raw = text_field(content, "datePublished");
        let date = if date_raw == "-" {
            String::new()
        } else {
            date_raw.split('T').next().unwrap_or(&date_raw).to_string()
        };

        // Rewrite the URL to a pap:// link so it routes through submit_agent_link().
        let pap_url = if url.starts_with("https://") {
            format!("pap://{}", &url["https://".len()..])
        } else if url.starts_with("http://") {
            format!("pap://{}", &url["http://".len()..])
        } else {
            url.clone()
        };

        view! {
            <div class="typed-webpage">
                // ── URL bar ───────────────────────────────────────────────────
                <div class="typed-webpage-bar">
                    <span class="typed-webpage-favicon" aria-hidden="true">"🌐"</span>
                    <a class="typed-webpage-url" href=pap_url>{url.clone()}</a>
                </div>
                // ── Page body ─────────────────────────────────────────────────
                <div class="typed-webpage-body">
                    <h2 class="typed-webpage-title">{title}</h2>

                    // Byline: publisher · author · date
                    {
                        let byline_parts: Vec<String> = [
                            if publisher.is_empty() { None } else { Some(publisher) },
                            if author.is_empty() { None } else { Some(author) },
                            if date.is_empty() { None } else { Some(date) },
                        ]
                        .into_iter()
                        .flatten()
                        .collect();

                        if byline_parts.is_empty() {
                            view! { <></> }.into_any()
                        } else {
                            let byline = byline_parts.join(" \u{00b7} ");
                            view! { <p class="typed-webpage-byline">{byline}</p> }.into_any()
                        }
                    }

                    {if description != "-" && !description.is_empty() {
                        view! { <p class="typed-webpage-description">{description}</p> }.into_any()
                    } else {
                        view! { <></> }.into_any()
                    }}

                    {if body_text != "-" && !body_text.is_empty() {
                        view! { <div class="typed-webpage-text">{body_text}</div> }.into_any()
                    } else {
                        view! { <></> }.into_any()
                    }}
                </div>
            </div>
        }
        .into_any()
    }

    fn schema_types(&self) -> Vec<&'static str> {
        vec!["WebPage"]
    }
}
