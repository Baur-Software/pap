use leptos::prelude::*;
use serde_json::Value;

/// Extract a string field from JSON-LD content, defaulting to "-".
pub fn text_field(content: &Value, key: &str) -> String {
    content
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("-")
        .to_string()
}

/// FlightReservation — route card with departure/arrival, date, price, carrier.
pub fn render_flight(content: &Value) -> AnyView {
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

/// LodgingReservation — hotel card with name, dates, price.
pub fn render_hotel(content: &Value) -> AnyView {
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

/// SearchResultsPage / SearchAction — list of search results.
pub fn render_search_results(content: &Value) -> AnyView {
    let items = content
        .get("results")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let rendered = items
        .into_iter()
        .map(|item| {
            let title = item
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or("-")
                .to_string();
            let url = item
                .get("url")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let snippet = item
                .get("snippet")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            view! {
                <div class="typed-search-item">
                    <span class="typed-search-title">{title}</span>
                    <span class="typed-search-url">{url}</span>
                    <span class="typed-search-snippet">{snippet}</span>
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

/// Answer — on-device AI response rendered as a paragraph.
pub fn render_answer(content: &Value) -> AnyView {
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
