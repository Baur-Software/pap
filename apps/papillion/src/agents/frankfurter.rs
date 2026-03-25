use std::collections::HashMap;

use pap_core::receipt::TransactionReceipt;
use pap_core::session::CapabilityToken;
use pap_did::SessionKeypair;
use pap_transport::{AgentHandler, TransportError};
use serde::Deserialize;
use serde_json::json;

use super::session_store::SessionStore;

/// Frankfurter currency exchange agent.
///
/// Calls the Frankfurter API (European Central Bank reference rates) —
/// zero disclosure, public API. Uses TradeAction, demonstrating the
/// financial protocol surface. Query format: "USD EUR" or "100 USD EUR".
/// Sessions are TTL-bounded and reaped automatically.
pub struct FrankfurterAgent {
    sessions: SessionStore<Option<String>>, // query
}

impl Default for FrankfurterAgent {
    fn default() -> Self {
        Self {
            sessions: SessionStore::new(),
        }
    }
}

impl FrankfurterAgent {
    pub fn new() -> Self {
        Self::default()
    }
}

impl AgentHandler for FrankfurterAgent {
    fn handle_token(&self, token: CapabilityToken) -> Result<(String, String), TransportError> {
        if token.action != "schema:TradeAction" {
            return Err(TransportError::ServerError(format!(
                "Unsupported action: {}",
                token.action
            )));
        }

        let session_id = uuid::Uuid::new_v4().to_string();
        let did = self.sessions.insert(session_id.clone(), None);
        Ok((session_id, did))
    }

    fn handle_did_exchange(
        &self,
        session_id: &str,
        _initiator_session_did: &str,
    ) -> Result<(), TransportError> {
        if !self.sessions.exists(session_id) {
            return Err(TransportError::ServerError("Unknown session".into()));
        }
        Ok(())
    }

    fn handle_disclosure(
        &self,
        session_id: &str,
        disclosures: Vec<serde_json::Value>,
    ) -> Result<(), TransportError> {
        let query = disclosures
            .iter()
            .find_map(|d| d.get("query").and_then(|v| v.as_str()))
            .map(String::from);

        if let Some(q) = query {
            self.sessions.with_mut(session_id, |data| {
                *data = Some(q);
            })?;
        }
        Ok(())
    }

    fn execute(&self, session_id: &str) -> Result<serde_json::Value, TransportError> {
        let query = self
            .sessions
            .with(session_id, |data| data.clone())?
            .ok_or_else(|| {
                TransportError::ServerError("No query provided in disclosures".into())
            })?;

        let (from, to, amount) = parse_currency_query(&query)?;

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

    fn co_sign_receipt(
        &self,
        mut receipt: TransactionReceipt,
    ) -> Result<TransactionReceipt, TransportError> {
        let key = self.sessions.signing_key(&receipt.session_id);
        match key {
            Some(k) => receipt.co_sign(&k),
            None => {
                let k = SessionKeypair::generate();
                receipt.co_sign(k.signing_key());
            }
        }
        Ok(receipt)
    }

    fn handle_close(&self, session_id: &str) -> Result<(), TransportError> {
        self.sessions.remove(session_id);
        Ok(())
    }
}

// ── Frankfurter API types ─────────────────────────────────────

#[derive(Deserialize)]
struct FrankfurterResponse {
    #[allow(dead_code)]
    amount: f64,
    #[allow(dead_code)]
    base: String,
    date: String,
    rates: HashMap<String, f64>,
}

// ── Helpers ───────────────────────────────────────────────────

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
