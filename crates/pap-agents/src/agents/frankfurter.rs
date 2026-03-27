use std::collections::HashMap;

use pap_transport::TransportError;
use serde::Deserialize;
use serde_json::json;

use crate::executor::{AgentExecutor, AgentMeta};

/// Frankfurter currency exchange — zero disclosure, ECB reference rates.
pub struct FrankfurterExecutor;

impl AgentExecutor for FrankfurterExecutor {
    fn meta(&self) -> AgentMeta {
        AgentMeta {
            name: "Frankfurter Exchange",
            provider: "Frankfurter",
            action: "schema:TradeAction",
            object_types: &["schema:MonetaryAmount"],
            requires_disclosure: &[],
            returns: &["schema:MonetaryAmount"],
        }
    }

    fn execute(&self, query: &str) -> Result<serde_json::Value, TransportError> {
        let (from, to, amount) = parse_currency_query(query)?;

        let client = reqwest::blocking::Client::builder()
            .user_agent("Papillon/0.1 (PAP Browser)")
            .build()
            .map_err(|e: reqwest::Error| TransportError::ServerError(e.to_string()))?;

        let resp: FrankfurterResponse = client
            .get("https://api.frankfurter.app/latest")
            .query(&[
                ("from", from.as_str()),
                ("to", to.as_str()),
                ("amount", &amount.to_string()),
            ])
            .send()
            .map_err(|e: reqwest::Error| {
                TransportError::ServerError(format!("Frankfurter request: {e}"))
            })?
            .json()
            .map_err(|e: reqwest::Error| {
                TransportError::ServerError(format!("Frankfurter parse: {e}"))
            })?;

        let converted = resp.rates.get(&to).copied().unwrap_or(0.0);
        let rate = if amount > 0.0 {
            converted / amount
        } else {
            0.0
        };

        Ok(json!({
            "@context": "https://schema.org",
            "@type": "ExchangeRateSpecification",
            "currency": from,
            "currentExchangeRate": {
                "@type": "UnitPriceSpecification",
                "price": rate,
                "priceCurrency": to
            },
            "amount": {
                "@type": "MonetaryAmount",
                "value": amount,
                "currency": from
            },
            "result": {
                "@type": "MonetaryAmount",
                "value": converted,
                "currency": to
            },
            "validFrom": resp.date
        }))
    }
}

#[derive(Deserialize)]
struct FrankfurterResponse {
    #[allow(dead_code)]
    amount: f64,
    #[allow(dead_code)]
    base: String,
    date: String,
    rates: HashMap<String, f64>,
}

/// Parse "USD EUR", "100 USD EUR", or "USD to EUR" into (from, to, amount).
fn parse_currency_query(query: &str) -> Result<(String, String, f64), TransportError> {
    let upper = query.to_uppercase();
    let tokens: Vec<&str> = upper
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|s| !s.is_empty() && *s != "TO" && *s != "IN" && *s != "->")
        .collect();

    match tokens.len() {
        2 => Ok((tokens[0].to_string(), tokens[1].to_string(), 1.0)),
        3 => {
            if let Ok(amount) = tokens[0].parse::<f64>() {
                Ok((tokens[1].to_string(), tokens[2].to_string(), amount))
            } else if let Ok(amount) = tokens[2].parse::<f64>() {
                Ok((tokens[0].to_string(), tokens[1].to_string(), amount))
            } else {
                Err(TransportError::ServerError(
                    "Expected format: 'USD EUR' or '100 USD EUR'".into(),
                ))
            }
        }
        _ => Err(TransportError::ServerError(
            "Expected format: 'USD EUR' or '100 USD EUR'".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real payload from https://api.frankfurter.app/latest?from=USD&to=EUR&amount=100
    const REAL_PAYLOAD: &str = r#"{
        "amount": 100.0,
        "base": "USD",
        "date": "2026-03-26",
        "rates": { "EUR": 86.66 }
    }"#;

    #[test]
    fn deserialize_real_payload() {
        let resp: FrankfurterResponse = serde_json::from_str(REAL_PAYLOAD).unwrap();
        assert!((resp.amount - 100.0).abs() < 0.01);
        assert_eq!(resp.base, "USD");
        assert_eq!(resp.date, "2026-03-26");
        assert!((resp.rates["EUR"] - 86.66).abs() < 0.01);
    }

    #[test]
    fn parse_currency_two_tokens() {
        let (from, to, amount) = parse_currency_query("USD EUR").unwrap();
        assert_eq!(from, "USD");
        assert_eq!(to, "EUR");
        assert!((amount - 1.0).abs() < 0.01);
    }

    #[test]
    fn parse_currency_amount_first() {
        let (from, to, amount) = parse_currency_query("100 USD EUR").unwrap();
        assert_eq!(from, "USD");
        assert_eq!(to, "EUR");
        assert!((amount - 100.0).abs() < 0.01);
    }

    #[test]
    fn parse_currency_with_to() {
        let (from, to, amount) = parse_currency_query("USD to EUR").unwrap();
        assert_eq!(from, "USD");
        assert_eq!(to, "EUR");
        assert!((amount - 1.0).abs() < 0.01);
    }

    #[test]
    fn parse_currency_invalid() {
        assert!(parse_currency_query("USD").is_err());
        assert!(parse_currency_query("").is_err());
    }
}
