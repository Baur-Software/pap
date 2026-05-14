use leptos::prelude::*;
use papillon_shared::IntentPlan;

#[component]
pub fn GhostBlockRenderer(plan: IntentPlan) -> impl IntoView {
    let primary_return_type = plan
        .returns
        .first()
        .cloned()
        .unwrap_or_else(|| "schema:Thing".to_string());

    let schema_icon = get_schema_icon(&primary_return_type);
    let agent_count = plan.candidates.len();

    view! {
        <div class="ghost-block">
            <div class="ghost-header">
                <span class="ghost-schema-icon">{schema_icon}</span>
                <span class="ghost-schema-type">{primary_return_type.clone()}</span>
                <span class="ghost-agent-count">
                    "From " {agent_count} " "
                    {if agent_count == 1 { "agent" } else { "agents" }}
                </span>
            </div>
            <div class="ghost-skeleton">
                <SkeletonPreview schema_type=primary_return_type />
            </div>
        </div>
    }
}

#[component]
fn SkeletonPreview(schema_type: String) -> impl IntoView {
    view! {
        <div class="skeleton-container">
            {match schema_type.as_str() {
                "schema:FlightReservation" => view! {
                    <div class="skeleton-flight">
                        <SkeletonField label="Flight" value="████ ████" />
                        <SkeletonField label="Price" value="$███" />
                        <SkeletonField label="Duration" value="█h ██m" />
                        <SkeletonField label="Route" value="███ → ███" />
                    </div>
                }.into_any(),
                "schema:WeatherForecast" => view! {
                    <div class="skeleton-weather">
                        <SkeletonField label="Location" value="████████" />
                        <SkeletonField label="Temp" value="██°" />
                        <SkeletonField label="Conditions" value="██████" />
                    </div>
                }.into_any(),
                "schema:NewsArticle" => view! {
                    <div class="skeleton-article">
                        <SkeletonField label="Headline" value="████████████████" />
                        <SkeletonField label="Author" value="████████" />
                        <SkeletonField label="Published" value="████" />
                    </div>
                }.into_any(),
                _ => view! {
                    <div class="skeleton-generic">
                        <SkeletonField label="Data" value="████████████" />
                        <SkeletonField label="Info" value="██████" />
                        <SkeletonField label="Detail" value="████████" />
                    </div>
                }.into_any(),
            }}
        </div>
    }
}

#[component]
fn SkeletonField(label: &'static str, value: &'static str) -> impl IntoView {
    view! {
        <div class="skeleton-field">
            <span class="skeleton-label">{label}":"</span>
            <span class="skeleton-value">{value}</span>
        </div>
    }
}

fn get_schema_icon(schema_type: &str) -> &'static str {
    match schema_type {
        "schema:FlightReservation" => "✈️",
        "schema:WeatherForecast" => "🌤️",
        "schema:NewsArticle" => "📰",
        "schema:Product" => "🛍️",
        "schema:Event" => "📅",
        "schema:Recipe" => "🍳",
        _ => "📄",
    }
}
