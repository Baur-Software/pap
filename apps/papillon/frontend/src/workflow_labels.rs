pub fn render_label_for_schema(schema: &str) -> String {
    let tail = schema.rsplit(':').next().unwrap_or(schema);
    match tail {
        "FlightReservation" => "Airline ticket".into(),
        "LodgingReservation" => "Hotel stay".into(),
        "TransitReservation" | "TransitTicket" => "Transit pass".into(),
        "TrainReservation" => "Train ticket".into(),
        "BusReservation" => "Bus ticket".into(),
        "Trip" => "Trip view".into(),
        "WeatherForecast" => "Weather card".into(),
        "Person" => "Person card".into(),
        "Organization" => "Organization card".into(),
        "Product" => "Product card".into(),
        "Event" => "Event card".into(),
        "NewsArticle" | "ScholarlyArticle" => "Article view".into(),
        "Book" => "Book card".into(),
        "Question" => "Answer card".into(),
        "Dataset" => "Dataset preview".into(),
        "Recipe" => "Recipe card".into(),
        "HowTo" => "How-to guide".into(),
        "LocalBusiness" => "Place card".into(),
        "VisualArtwork" => "Artwork card".into(),
        "Course" => "Course card".into(),
        "Quotation" => "Quote card".into(),
        _ if tail.ends_with("Reservation") => {
            format!("{} confirmation", humanize_schema_term(tail))
        }
        _ if tail.ends_with("Ticket") => {
            format!(
                "{} ticket",
                humanize_schema_term(tail.trim_end_matches("Ticket"))
            )
        }
        _ => format!("{} view", humanize_schema_term(tail)),
    }
}

pub fn user_visible_schema_type_label(schema: &str) -> String {
    if should_prefer_artifact_label(schema) {
        render_label_for_schema(schema)
    } else {
        humanize_schema_term(schema)
    }
}

pub fn humanize_schema_term(value: &str) -> String {
    let tail = value
        .rsplit(['.', ':', '/'])
        .next()
        .unwrap_or(value)
        .replace(['_', '-'], " ");
    let chars = tail.chars().collect::<Vec<_>>();
    let mut spaced = String::new();
    for (index, ch) in chars.iter().enumerate() {
        if index > 0
            && ch.is_uppercase()
            && (chars[index - 1].is_lowercase()
                || chars
                    .get(index + 1)
                    .map(|next| next.is_lowercase())
                    .unwrap_or(false))
        {
            spaced.push(' ');
        }
        spaced.push(*ch);
    }
    let lower = spaced
        .split_whitespace()
        .map(|word| word.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(" ");
    capitalize_first(&lower)
}

pub fn workflow_port_label(path: &str) -> String {
    if !path.contains('.') && path.contains(':') {
        return user_visible_schema_type_label(path);
    }

    let tail = path
        .rsplit(['.', ':', '/'])
        .next()
        .unwrap_or(path)
        .replace(['_', '-'], " ");
    let chars = tail.chars().collect::<Vec<_>>();
    let mut spaced = String::new();
    for (index, ch) in chars.iter().enumerate() {
        if index > 0
            && ch.is_uppercase()
            && (chars[index - 1].is_lowercase()
                || chars
                    .get(index + 1)
                    .map(|next| next.is_lowercase())
                    .unwrap_or(false))
        {
            spaced.push(' ');
        }
        spaced.push(*ch);
    }
    let lower = spaced
        .split_whitespace()
        .map(|word| word.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(" ");
    capitalize_first(&lower)
}

pub fn humanize_reason(reason: &str) -> String {
    let reason = reason.replace('_', " ").replace('-', " ");
    capitalize_first(reason.trim())
}

fn should_prefer_artifact_label(schema: &str) -> bool {
    let tail = schema.rsplit(':').next().unwrap_or(schema);
    matches!(
        tail,
        "FlightReservation"
            | "LodgingReservation"
            | "TransitReservation"
            | "TransitTicket"
            | "TrainReservation"
            | "BusReservation"
            | "Trip"
            | "WeatherForecast"
            | "Person"
            | "Organization"
            | "Product"
            | "Event"
            | "NewsArticle"
            | "ScholarlyArticle"
            | "Book"
            | "Question"
            | "Dataset"
            | "Recipe"
            | "HowTo"
            | "LocalBusiness"
            | "VisualArtwork"
            | "Course"
            | "Quotation"
    ) || tail.ends_with("Reservation")
        || tail.ends_with("Ticket")
}

fn capitalize_first(text: &str) -> String {
    let mut chars = text.chars();
    let Some(first) = chars.next() else {
        return String::new();
    };
    format!("{}{}", first.to_uppercase(), chars.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn humanize_schema_term_reads_like_people_talk() {
        assert_eq!(humanize_schema_term("schema:FlightReservation"), "Flight reservation");
        assert_eq!(
            humanize_schema_term("schema:FlightReservation.departureDate"),
            "Departure date"
        );
    }

    #[test]
    fn render_label_prefers_human_artifact_names() {
        assert_eq!(render_label_for_schema("schema:FlightReservation"), "Airline ticket");
        assert_eq!(render_label_for_schema("schema:TransitTicket"), "Transit pass");
    }

    #[test]
    fn workflow_port_label_uses_render_labels_for_schema_types() {
        assert_eq!(workflow_port_label("schema:FlightReservation"), "Airline ticket");
        assert_eq!(workflow_port_label("schema:Date"), "Date");
        assert_eq!(
            workflow_port_label("schema:FlightReservation.departureDate"),
            "Departure date"
        );
    }
}
