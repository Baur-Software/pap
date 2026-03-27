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
            .user_agent("Papillion/0.1 (PAP Browser)")
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
