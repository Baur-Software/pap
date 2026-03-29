use super::renderer::BlockRenderer;
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

/// SearchResultsPage / SearchAction template — list of search results.
///
/// All agents return schema.org JSON-LD with `mainEntity.itemListElement`.
/// Individual items vary by type (NewsArticle uses `headline`, SearchResult
/// uses `name`, Article uses `name`, etc.) so we try multiple field names.
pub struct SearchTemplate;

impl SearchTemplate {
    /// Extract the best display title from a schema.org item.
    fn item_title(item: &Value) -> String {
        item.get("headline")
            .or_else(|| item.get("name"))
            .or_else(|| item.get("title"))
            .and_then(|v| v.as_str())
            .unwrap_or("-")
            .to_string()
    }

    /// Extract description/snippet text from a schema.org item.
    fn item_description(item: &Value) -> String {
        item.get("description")
            .or_else(|| item.get("snippet"))
            .or_else(|| item.get("abstract"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    }

    /// Extract items from the JSON-LD content.
    /// Schema.org path: `mainEntity.itemListElement`
    fn extract_items(content: &Value) -> Vec<Value> {
        // Schema.org: mainEntity.itemListElement
        content
            .get("mainEntity")
            .and_then(|me| me.get("itemListElement"))
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
    }
}

impl BlockRenderer for SearchTemplate {
    fn render(&self, content: &Value) -> AnyView {
        let items = Self::extract_items(content);

        let rendered = items
            .into_iter()
            .map(|item| {
                let title = Self::item_title(&item);
                let url = item
                    .get("url")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let description = Self::item_description(&item);
                view! {
                    <div class="typed-search-item">
                        <span class="typed-search-title">{title}</span>
                        <span class="typed-search-url">{url}</span>
                        <span class="typed-search-snippet">{description}</span>
                    </div>
                }
            })
            .collect::<Vec<_>>();

        view! {
            <div class="typed-search-results">
                {rendered}
            </div>
        }
        .into_any()
    }

    fn schema_types(&self) -> Vec<&'static str> {
        vec!["SearchResultsPage", "SearchAction"]
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
