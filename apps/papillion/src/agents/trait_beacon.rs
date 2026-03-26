use pap_core::receipt::TransactionReceipt;
use pap_core::session::CapabilityToken;
use pap_did::SessionKeypair;
use pap_transport::{AgentHandler, TransportError};
use serde_json::json;
use std::sync::RwLock;

use super::session_store::SessionStore;

/// Trait Beacon agent — advertises the principal's traits to the federation.
///
/// This is the "business card" agent. The principal builds their profile
/// as a Schema.org Person JSON-LD document through the Advertise settings
/// page. Whatever properties they choose to include — name, jobTitle,
/// knowsAbout, custom fields — become their advertised traits. There is
/// no fixed schema; the document is the user's to define.
///
/// When another node's SocialDiscoveryAgent finds this agent in the
/// federated registry and initiates a handshake, the Trait Beacon
/// responds with the principal's JSON-LD document verbatim.
///
/// Capability: schema:InformAction
/// Object types: schema:Person
/// Requires disclosure: [] (zero disclosure from querier)
/// Returns: schema:Person (user-defined JSON-LD)
pub struct TraitBeaconAgent {
    sessions: SessionStore<()>,
    /// The principal's advertised profile as raw Schema.org JSON-LD.
    /// Set via the Advertise settings page. No fixed schema — the
    /// user defines whatever properties they want to be found by.
    profile: RwLock<serde_json::Value>,
}

impl TraitBeaconAgent {
    pub fn new() -> Self {
        Self {
            sessions: SessionStore::new(),
            profile: RwLock::new(json!({
                "@context": "https://schema.org",
                "@type": "Person",
            })),
        }
    }

    /// Create a beacon with a pre-built JSON-LD profile.
    /// The value must have `@type: Person` — everything else is up to the user.
    pub fn with_profile(profile: serde_json::Value) -> Self {
        Self {
            sessions: SessionStore::new(),
            profile: RwLock::new(profile),
        }
    }

    /// Replace the advertised profile. Called when the user saves
    /// changes in the Advertise settings page.
    pub fn set_profile(&self, profile: serde_json::Value) {
        *self.profile.write().unwrap() = profile;
    }
}

impl Default for TraitBeaconAgent {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentHandler for TraitBeaconAgent {
    fn handle_token(&self, token: CapabilityToken) -> Result<(String, String), TransportError> {
        if token.action != "schema:InformAction" {
            return Err(TransportError::ServerError(format!(
                "Unsupported action: {}",
                token.action
            )));
        }

        let session_id = uuid::Uuid::new_v4().to_string();
        let did = self.sessions.insert(session_id.clone(), ());
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
        _disclosures: Vec<serde_json::Value>,
    ) -> Result<(), TransportError> {
        if !self.sessions.exists(session_id) {
            return Err(TransportError::ServerError("Unknown session".into()));
        }
        Ok(())
    }

    fn execute(&self, session_id: &str) -> Result<serde_json::Value, TransportError> {
        if !self.sessions.exists(session_id) {
            return Err(TransportError::ServerError(
                "Unknown or expired session".into(),
            ));
        }

        Ok(self.profile.read().unwrap().clone())
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

    fn mint_token(action: &str) -> CapabilityToken {
        CapabilityToken::mint(
            "did:key:z6Mktarget".into(),
            action.into(),
            "did:key:z6Mkissuer".into(),
            Utc::now() + chrono::Duration::minutes(5),
        )
    }

    fn alice_profile() -> serde_json::Value {
        json!({
            "@context": "https://schema.org",
            "@type": "Person",
            "name": "Alice",
            "jobTitle": "Protocol Engineer",
            "knowsAbout": ["rust", "privacy", "cryptography"],
            "hasOccupation": {
                "@type": "Occupation",
                "skills": ["distributed-systems", "protocol-design"]
            },
            "workLocation": {
                "@type": "Place",
                "address": {
                    "@type": "PostalAddress",
                    "addressLocality": "Berlin",
                    "addressCountry": "DE"
                }
            },
            "knowsLanguage": ["en", "de"],
            "description": "Building privacy-preserving protocols",
            "pap:seeking": ["rust developers", "privacy researchers"]
        })
    }

    fn run_handshake(agent: &TraitBeaconAgent) -> serde_json::Value {
        let token = mint_token("schema:InformAction");
        let (session_id, _) = agent.handle_token(token).unwrap();
        agent
            .handle_did_exchange(&session_id, "did:key:z6Mktest")
            .unwrap();
        agent.handle_disclosure(&session_id, vec![]).unwrap();
        let result = agent.execute(&session_id).unwrap();
        agent.handle_close(&session_id).unwrap();
        result
    }

    #[test]
    fn test_rejects_wrong_action() {
        let agent = TraitBeaconAgent::new();
        assert!(agent
            .handle_token(mint_token("schema:SearchAction"))
            .is_err());
    }

    #[test]
    fn test_accepts_inform_action() {
        let agent = TraitBeaconAgent::new();
        let result = agent.handle_token(mint_token("schema:InformAction"));
        assert!(result.is_ok());
        let (session_id, did) = result.unwrap();
        assert!(!session_id.is_empty());
        assert!(did.starts_with("did:key:"));
    }

    #[test]
    fn test_returns_full_profile_verbatim() {
        let profile = alice_profile();
        let agent = TraitBeaconAgent::with_profile(profile.clone());
        let result = run_handshake(&agent);
        assert_eq!(result, profile);
    }

    #[test]
    fn test_empty_profile_returns_bare_person() {
        let agent = TraitBeaconAgent::new();
        let result = run_handshake(&agent);

        assert_eq!(result["@type"], "Person");
        assert_eq!(result["@context"], "https://schema.org");
        // No other fields — the user hasn't advertised anything
        assert_eq!(result.as_object().unwrap().len(), 2);
    }

    #[test]
    fn test_set_profile_reflects_immediately() {
        let agent = TraitBeaconAgent::new();

        agent.set_profile(json!({
            "@context": "https://schema.org",
            "@type": "Person",
            "name": "Bob",
            "knowsAbout": ["web3"],
            "customField": "anything the user wants"
        }));

        let result = run_handshake(&agent);
        assert_eq!(result["name"], "Bob");
        assert_eq!(result["knowsAbout"][0], "web3");
        assert_eq!(result["customField"], "anything the user wants");
    }

    #[test]
    fn test_arbitrary_schema_properties() {
        let agent = TraitBeaconAgent::with_profile(json!({
            "@context": "https://schema.org",
            "@type": "Person",
            "name": "Carol",
            "alumniOf": {
                "@type": "CollegeOrUniversity",
                "name": "MIT"
            },
            "award": "Best Protocol 2025",
            "contactPoint": {
                "@type": "ContactPoint",
                "contactType": "business",
                "availableLanguage": "en"
            }
        }));

        let result = run_handshake(&agent);
        assert_eq!(result["alumniOf"]["name"], "MIT");
        assert_eq!(result["award"], "Best Protocol 2025");
        assert_eq!(result["contactPoint"]["contactType"], "business");
    }

    #[test]
    fn test_expired_session_rejected() {
        let agent = TraitBeaconAgent::new();
        assert!(agent.execute("nonexistent-session").is_err());
    }
}
