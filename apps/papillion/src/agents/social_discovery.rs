use pap_core::receipt::TransactionReceipt;
use pap_core::session::CapabilityToken;
use pap_did::SessionKeypair;
use pap_federation::FederatedRegistry;
use pap_transport::{AgentHandler, TransportError};
use serde_json::json;
use std::sync::{Arc, Mutex};

use super::session_store::SessionStore;

/// Session data for an in-progress discovery query.
#[derive(Clone)]
struct DiscoveryQuery {
    /// Trait keywords to match against advertisement metadata
    keywords: Vec<String>,
}

/// Social Discovery agent — finds people through their Trait Beacon agents.
///
/// Queries the federated registry for agents advertising `schema:Person`
/// object types (Trait Beacons). Filters by keyword match against the
/// advertisement's name and provider. Returns the real advertisement
/// data as Schema.org Service entries — each one is a live agent
/// endpoint the orchestrator can initiate a handshake with.
///
/// The pipeline orchestrator chains this agent's output into actual
/// PAP handshakes with each discovered beacon to get their full
/// Person JSON-LD. This agent does the discovery; the pipeline does
/// the handshakes.
///
/// Capability: schema:DiscoverAction
/// Object types: schema:Person
/// Requires disclosure: [] (zero disclosure from searcher)
/// Returns: schema:ItemList of schema:Service (agent advertisements)
pub struct SocialDiscoveryAgent {
    sessions: SessionStore<Option<DiscoveryQuery>>,
    registry: Arc<Mutex<FederatedRegistry>>,
}

impl SocialDiscoveryAgent {
    pub fn new(registry: Arc<Mutex<FederatedRegistry>>) -> Self {
        Self {
            sessions: SessionStore::new(),
            registry,
        }
    }
}

impl AgentHandler for SocialDiscoveryAgent {
    fn handle_token(&self, token: CapabilityToken) -> Result<(String, String), TransportError> {
        if token.action != "schema:DiscoverAction" {
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
        let mut keywords = Vec::new();
        let mut has_criteria = false;

        for disclosure in &disclosures {
            if let Some(query) = disclosure.get("query").and_then(|v| v.as_str()) {
                has_criteria = true;
                for word in query.split_whitespace() {
                    keywords.push(word.to_lowercase());
                }
            }
            if let Some(trait_arr) = disclosure.get("traits").and_then(|v| v.as_array()) {
                has_criteria = true;
                for t in trait_arr {
                    if let Some(s) = t.as_str() {
                        keywords.push(s.to_lowercase());
                    }
                }
            }
        }

        if has_criteria {
            self.sessions.with_mut(session_id, |data| {
                *data = Some(DiscoveryQuery { keywords });
            })?;
        }

        Ok(())
    }

    fn execute(&self, session_id: &str) -> Result<serde_json::Value, TransportError> {
        let query = self
            .sessions
            .with(session_id, |data| data.clone())?
            .ok_or_else(|| {
                TransportError::ServerError("No discovery criteria provided in disclosures".into())
            })?;

        let registry = self
            .registry
            .lock()
            .map_err(|e| TransportError::ServerError(format!("Registry lock failed: {e}")))?;

        // Query for InformAction agents — these are Trait Beacons
        let beacons = registry.query_local("schema:InformAction");

        // Filter to Person-typed beacons, then keyword-match against
        // the advertisement's real metadata
        let matches: Vec<serde_json::Value> = beacons
            .into_iter()
            .filter(|ad| ad.object_types.iter().any(|t| t == "schema:Person"))
            .filter(|ad| {
                if query.keywords.is_empty() {
                    return true;
                }
                let searchable = format!(
                    "{} {}",
                    ad.name.to_lowercase(),
                    ad.provider.name.to_lowercase(),
                );
                query.keywords.iter().any(|kw| searchable.contains(kw))
            })
            .map(|ad| {
                // Return the real advertisement as JSON-LD — this is what
                // the registry actually contains, not fabricated data
                json!({
                    "@context": ad.context,
                    "@type": ad.schema_type,
                    "name": ad.name,
                    "provider": {
                        "@type": ad.provider.schema_type,
                        "name": ad.provider.name,
                        "identifier": ad.provider.did,
                    },
                    "potentialAction": ad.capability,
                    "object": ad.object_types,
                    "requiresDisclosure": ad.requires_disclosure,
                    "result": ad.returns,
                    "identifier": ad.signed_by,
                })
            })
            .collect();

        Ok(json!({
            "@context": "https://schema.org",
            "@type": "ItemList",
            "additionalType": "DiscoverAction",
            "numberOfItems": matches.len(),
            "itemListElement": matches,
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use pap_marketplace::AgentAdvertisement;

    fn mint_token(action: &str) -> CapabilityToken {
        CapabilityToken::mint(
            "did:key:z6Mktarget".into(),
            action.into(),
            "did:key:z6Mkissuer".into(),
            Utc::now() + chrono::Duration::minutes(5),
        )
    }

    fn registry_with_beacons() -> Arc<Mutex<FederatedRegistry>> {
        let mut registry = FederatedRegistry::new();

        // A real Trait Beacon advertisement — this is what a Papillion
        // node publishes when the user configures their Advertise page
        let kp = pap_did::PrincipalKeypair::generate();
        let did = kp.did();
        let mut ad = AgentAdvertisement::new(
            "Alice's Beacon",
            "Alice",
            &did,
            vec!["schema:InformAction".into()],
            vec!["schema:Person".into()],
            vec![],
            vec!["schema:Person".into()],
        );
        ad.sign(kp.signing_key());
        registry.register_local(ad).unwrap();

        // A non-person agent — must be filtered out by object_types
        let kp2 = pap_did::PrincipalKeypair::generate();
        let did2 = kp2.did();
        let mut ad2 = AgentAdvertisement::new(
            "Weather Agent",
            "Open-Meteo",
            &did2,
            vec!["schema:CheckAction".into()],
            vec!["schema:WeatherForecast".into()],
            vec![],
            vec!["schema:WeatherForecast".into()],
        );
        ad2.sign(kp2.signing_key());
        registry.register_local(ad2).unwrap();

        Arc::new(Mutex::new(registry))
    }

    fn run_discovery(
        registry: Arc<Mutex<FederatedRegistry>>,
        disclosure: serde_json::Value,
    ) -> serde_json::Value {
        let agent = SocialDiscoveryAgent::new(registry);
        let (sid, _) = agent
            .handle_token(mint_token("schema:DiscoverAction"))
            .unwrap();
        agent.handle_did_exchange(&sid, "did:key:z6Mktest").unwrap();
        agent.handle_disclosure(&sid, vec![disclosure]).unwrap();
        let result = agent.execute(&sid).unwrap();
        agent.handle_close(&sid).unwrap();
        result
    }

    #[test]
    fn rejects_wrong_action() {
        let registry = Arc::new(Mutex::new(FederatedRegistry::new()));
        let agent = SocialDiscoveryAgent::new(registry);
        assert!(agent
            .handle_token(mint_token("schema:SearchAction"))
            .is_err());
    }

    #[test]
    fn discovers_person_beacons_by_keyword() {
        let result = run_discovery(registry_with_beacons(), json!({ "query": "alice" }));

        assert_eq!(result["@type"], "ItemList");
        assert_eq!(result["numberOfItems"], 1);

        let item = &result["itemListElement"][0];
        assert_eq!(item["@type"], "schema:Service");
        assert_eq!(item["name"], "Alice's Beacon");
        assert_eq!(item["provider"]["name"], "Alice");
        // identifier is the real DID from the advertisement
        assert!(item["identifier"].as_str().unwrap().starts_with("did:key:"));
    }

    #[test]
    fn filters_non_person_agents() {
        let result = run_discovery(registry_with_beacons(), json!({ "query": "weather" }));
        assert_eq!(result["numberOfItems"], 0);
    }

    #[test]
    fn empty_registry_returns_empty_list() {
        let result = run_discovery(
            Arc::new(Mutex::new(FederatedRegistry::new())),
            json!({ "query": "anyone" }),
        );
        assert_eq!(result["numberOfItems"], 0);
        assert!(result["itemListElement"].as_array().unwrap().is_empty());
    }

    #[test]
    fn no_keywords_returns_all_person_beacons() {
        let result = run_discovery(registry_with_beacons(), json!({ "traits": [] }));
        assert_eq!(result["numberOfItems"], 1);
    }

    #[test]
    fn structured_traits_disclosure() {
        let result = run_discovery(registry_with_beacons(), json!({ "traits": ["alice"] }));
        assert_eq!(result["numberOfItems"], 1);
    }

    #[test]
    fn no_criteria_errors() {
        let registry = Arc::new(Mutex::new(FederatedRegistry::new()));
        let agent = SocialDiscoveryAgent::new(registry);
        let (sid, _) = agent
            .handle_token(mint_token("schema:DiscoverAction"))
            .unwrap();
        agent.handle_did_exchange(&sid, "did:key:z6Mktest").unwrap();
        // No disclosure at all
        agent.handle_disclosure(&sid, vec![]).unwrap();
        assert!(agent.execute(&sid).is_err());
    }
}
