use pap_transport::TransportError;
use serde::Deserialize;
use serde_json::json;

use crate::executor::{AgentExecutor, AgentMeta};

/// Percent-encode a string for use in URL paths.
fn url_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                String::from(b as char)
            }
            _ => format!("%{:02X}", b),
        })
        .collect()
}

/// Free Dictionary — zero disclosure, public API for word definitions.
pub struct DictionaryExecutor;

impl AgentExecutor for DictionaryExecutor {
    fn meta(&self) -> AgentMeta {
        AgentMeta {
            name: "Free Dictionary",
            provider: "dictionaryapi.dev",
            action: "schema:SearchAction",
            object_types: &["schema:DefinedTerm"],
            requires_disclosure: &[],
            returns: &["schema:DefinedTerm"],
        }
    }

    fn execute(&self, query: &str) -> Result<serde_json::Value, TransportError> {
        let word = query.split_whitespace().next().unwrap_or(query);

        let client = reqwest::blocking::Client::builder()
            .user_agent("Papillion/0.1 (PAP Browser)")
            .build()
            .map_err(|e: reqwest::Error| TransportError::ServerError(e.to_string()))?;

        let entries: Vec<DictEntry> = client
            .get(format!(
                "https://api.dictionaryapi.dev/api/v2/entries/en/{}",
                url_encode(word)
            ))
            .send()
            .map_err(|e: reqwest::Error| {
                TransportError::ServerError(format!("Dictionary request: {e}"))
            })?
            .json()
            .map_err(|e: reqwest::Error| {
                TransportError::ServerError(format!("Dictionary parse: {e}"))
            })?;

        let entry = entries.into_iter().next().ok_or_else(|| {
            TransportError::ServerError(format!("No definition found for '{word}'"))
        })?;

        let phonetic = entry
            .phonetics
            .iter()
            .find_map(|p| p.text.clone())
            .unwrap_or_default();

        let definitions: Vec<serde_json::Value> = entry
            .meanings
            .into_iter()
            .flat_map(|m| {
                let pos = m.part_of_speech.clone();
                m.definitions.into_iter().take(3).map(move |d| {
                    let mut def = json!({
                        "@type": "DefinedTerm",
                        "name": word,
                        "description": d.definition,
                        "inDefinedTermSet": pos
                    });
                    if let Some(ex) = d.example {
                        def["exampleOfWork"] = json!(ex);
                    }
                    def
                })
            })
            .collect();

        Ok(json!({
            "@context": "https://schema.org",
            "@type": "DefinedTerm",
            "name": entry.word,
            "pronunciation": phonetic,
            "description": definitions.first().and_then(|d| d["description"].as_str()).unwrap_or(""),
            "mainEntity": {
                "@type": "ItemList",
                "numberOfItems": definitions.len(),
                "itemListElement": definitions
            }
        }))
    }
}

#[derive(Deserialize)]
struct DictEntry {
    word: String,
    phonetics: Vec<DictPhonetic>,
    meanings: Vec<DictMeaning>,
}

#[derive(Deserialize)]
struct DictPhonetic {
    text: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DictMeaning {
    part_of_speech: String,
    definitions: Vec<DictDefinition>,
}

#[derive(Deserialize)]
struct DictDefinition {
    definition: String,
    example: Option<String>,
}
