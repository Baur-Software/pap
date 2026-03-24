// Schema.org vocabulary sets for agent capabilities, object types, properties, and return types.
// Curated for PAP (Principal Agent Protocol) agent use cases.

/// Schema.org action types representing agent capabilities
pub const SCHEMA_ORG_ACTIONS: &[&str] = &[
    "schema:SearchAction",
    "schema:BookAction",
    "schema:ReserveAction",
    "schema:PayAction",
    "schema:OrderAction",
    "schema:ViewAction",
    "schema:BuyAction",
    "schema:RentAction",
    "schema:ScheduleAction",
    "schema:ReplyAction",
    "schema:SendAction",
    "schema:DownloadAction",
    "schema:ListenAction",
    "schema:WatchAction",
    "schema:ReadAction",
    "schema:TradeAction",
    "schema:UpdateAction",
    "schema:DeleteAction",
    "schema:CreateAction",
];

/// Schema.org object types that agents work with
pub const SCHEMA_ORG_OBJECT_TYPES: &[&str] = &[
    "schema:Person",
    "schema:PostalAddress",
    "schema:PaymentMethod",
    "schema:CreditCard",
    "schema:BankAccount",
    "schema:Hotel",
    "schema:Flight",
    "schema:Restaurant",
    "schema:Event",
    "schema:Movie",
    "schema:Book",
    "schema:Product",
    "schema:Place",
    "schema:LocalBusiness",
    "schema:Organization",
    "schema:ProgramMembership",
    "schema:TrainingEvent",
];

/// Schema.org property types that may require disclosure
pub const SCHEMA_ORG_PROPERTIES: &[&str] = &[
    "schema:Person.name",
    "schema:Person.email",
    "schema:Person.telephone",
    "schema:Person.birthDate",
    "schema:Person.address",
    "schema:PostalAddress.streetAddress",
    "schema:PostalAddress.city",
    "schema:PostalAddress.state",
    "schema:PostalAddress.postalCode",
    "schema:PostalAddress.country",
    "schema:PaymentMethod.cardNumber",
    "schema:PaymentMethod.expirationDate",
    "schema:PaymentMethod.cvv",
    "schema:CreditCard.cardBrand",
    "schema:CreditCard.cardExpiration",
    "schema:Organization.name",
    "schema:Organization.url",
    "schema:LocalBusiness.priceRange",
];

/// Schema.org return types for agent responses
pub const SCHEMA_ORG_RETURNS: &[&str] = &[
    "schema:SearchResult",
    "schema:SearchResultsPage",
    "schema:Thing",
    "schema:Reservation",
    "schema:Order",
    "schema:BookingConfirmation",
    "schema:PaymentStatusType",
    "schema:Hotel",
    "schema:Flight",
    "schema:Restaurant",
    "schema:Event",
    "schema:Person",
    "schema:Place",
    "schema:LocalBusiness",
    "schema:BusReservation",
    "schema:EventReservation",
    "schema:FlightReservation",
    "schema:TrainReservation",
];

/// Filter vocabulary items by search term (case-insensitive prefix match)
pub fn filter_actions(term: &str) -> Vec<String> {
    if term.is_empty() {
        return SCHEMA_ORG_ACTIONS.iter().map(|s| s.to_string()).collect();
    }
    let lower = term.to_lowercase();
    SCHEMA_ORG_ACTIONS
        .iter()
        .filter(|item| item.to_lowercase().contains(&lower))
        .map(|s| s.to_string())
        .collect()
}

/// Filter object types by search term
pub fn filter_object_types(term: &str) -> Vec<String> {
    if term.is_empty() {
        return SCHEMA_ORG_OBJECT_TYPES
            .iter()
            .map(|s| s.to_string())
            .collect();
    }
    let lower = term.to_lowercase();
    SCHEMA_ORG_OBJECT_TYPES
        .iter()
        .filter(|item| item.to_lowercase().contains(&lower))
        .map(|s| s.to_string())
        .collect()
}

/// Filter properties by search term
pub fn filter_properties(term: &str) -> Vec<String> {
    if term.is_empty() {
        return SCHEMA_ORG_PROPERTIES
            .iter()
            .map(|s| s.to_string())
            .collect();
    }
    let lower = term.to_lowercase();
    SCHEMA_ORG_PROPERTIES
        .iter()
        .filter(|item| item.to_lowercase().contains(&lower))
        .map(|s| s.to_string())
        .collect()
}

/// Filter return types by search term
pub fn filter_returns(term: &str) -> Vec<String> {
    if term.is_empty() {
        return SCHEMA_ORG_RETURNS.iter().map(|s| s.to_string()).collect();
    }
    let lower = term.to_lowercase();
    SCHEMA_ORG_RETURNS
        .iter()
        .filter(|item| item.to_lowercase().contains(&lower))
        .map(|s| s.to_string())
        .collect()
}
