use super::field_classify::FieldKind;

/// Vocabulary-driven property classification.
///
/// Schema.org defines the expected type for each property on each type.
/// Instead of guessing from key name heuristics (`contains("date")`,
/// `contains("price")`), we consult the vocabulary directly.
///
/// This makes field classification deterministic — `departureDate` is a
/// `DateTime` because `schema:FlightReservation.departureDate` has range
/// `Date | DateTime`, not because the key happens to contain "date".
///
/// The catalog covers all properties used across the shipped templates and
/// their immediate parent types. Unknown properties fall back to the
/// heuristic classifier in `field_classify.rs`.
pub fn classify_by_property(property_name: &str) -> Option<FieldKind> {
    match property_name {
        // ── DateTime ─────────────────────────────────────────────────────────
        // schema:Date | schema:DateTime range
        "startDate"
        | "endDate"
        | "datePublished"
        | "dateCreated"
        | "dateModified"
        | "datePosted"
        | "dateRead"
        | "dateReceived"
        | "dateSent"
        | "departureDate"
        | "arrivalDate"
        | "checkinDate"
        | "checkoutDate"
        | "validFrom"
        | "validThrough"
        | "birthDate"
        | "deathDate"
        | "foundingDate"
        | "dissolutionDate"
        | "scheduledTime"
        | "expectedArrivalTime"
        | "expectedDepartureTime"
        | "doorTime"
        | "expires"
        | "releaseDate"
        | "uploadDate"
        | "copyrightYear"
        | "publishedOn"
        | "temporalCoverage" => Some(FieldKind::DateTime),

        // ── Price ─────────────────────────────────────────────────────────────
        // schema:MonetaryAmount | schema:Number | schema:Text range on price props
        "price"
        | "totalPrice"
        | "originalPrice"
        | "minPrice"
        | "maxPrice"
        | "lowPrice"
        | "highPrice"
        | "amount"
        | "basePrice"
        | "pricePerNight"
        | "baseSalary"
        | "estimatedSalary"
        | "salary"
        | "value" // schema:MonetaryAmount.value
        | "cost" => Some(FieldKind::Price),

        // ── URL ───────────────────────────────────────────────────────────────
        // schema:URL range
        "url"
        | "sameAs"
        | "mainEntityOfPage"
        | "discussionUrl"
        | "thumbnailUrl"
        | "embedUrl"
        | "downloadUrl"
        | "installUrl"
        | "targetUrl"
        | "contentUrl"
        | "image"
        | "logo"
        | "photo"
        | "maps"
        | "hasMap"
        | "replyToUrl"
        | "ticketToken"
        | "checkoutPageURLTemplate" => Some(FieldKind::ExternalUrl),

        // All other known properties — explicitly scalar so the heuristic
        // doesn't mistakenly promote them (e.g., a field named "timestamp"
        // in a non-temporal context).
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flight_properties_classify_correctly() {
        assert_eq!(
            classify_by_property("departureDate"),
            Some(FieldKind::DateTime)
        );
        assert_eq!(
            classify_by_property("arrivalDate"),
            Some(FieldKind::DateTime)
        );
        assert_eq!(
            classify_by_property("totalPrice"),
            Some(FieldKind::Price)
        );
    }

    #[test]
    fn lodging_properties_classify_correctly() {
        assert_eq!(
            classify_by_property("checkinDate"),
            Some(FieldKind::DateTime)
        );
        assert_eq!(
            classify_by_property("checkoutDate"),
            Some(FieldKind::DateTime)
        );
        assert_eq!(
            classify_by_property("pricePerNight"),
            Some(FieldKind::Price)
        );
    }

    #[test]
    fn url_properties_classify_correctly() {
        assert_eq!(classify_by_property("url"), Some(FieldKind::ExternalUrl));
        assert_eq!(classify_by_property("sameAs"), Some(FieldKind::ExternalUrl));
        assert_eq!(
            classify_by_property("thumbnailUrl"),
            Some(FieldKind::ExternalUrl)
        );
    }

    #[test]
    fn unknown_property_returns_none() {
        assert_eq!(classify_by_property("name"), None);
        assert_eq!(classify_by_property("description"), None);
        assert_eq!(classify_by_property("headline"), None);
    }

    #[test]
    fn salary_properties_classify_as_price() {
        assert_eq!(classify_by_property("baseSalary"), Some(FieldKind::Price));
        assert_eq!(
            classify_by_property("estimatedSalary"),
            Some(FieldKind::Price)
        );
    }

    #[test]
    fn event_date_properties_classify_correctly() {
        assert_eq!(classify_by_property("startDate"), Some(FieldKind::DateTime));
        assert_eq!(classify_by_property("endDate"), Some(FieldKind::DateTime));
        assert_eq!(classify_by_property("doorTime"), Some(FieldKind::DateTime));
    }
}
