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
            .user_agent("Papillon/0.1 (PAP Browser)")
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

#[cfg(test)]
mod tests {
    use super::*;

    // Real payload from https://api.dictionaryapi.dev/api/v2/entries/en/ephemeral
    const REAL_PAYLOAD: &str = r#"[{
        "word": "ephemeral",
        "phonetic": "/əˈfɛ.mə.ɹəl/",
        "phonetics": [{
            "text": "/əˈfɛ.mə.ɹəl/",
            "audio": "https://api.dictionaryapi.dev/media/pronunciations/en/ephemeral-us.mp3",
            "sourceUrl": "https://commons.wikimedia.org/w/index.php?curid=2526689",
            "license": { "name": "BY-SA 3.0", "url": "https://creativecommons.org/licenses/by-sa/3.0" }
        }],
        "meanings": [
            {
                "partOfSpeech": "noun",
                "definitions": [
                    { "definition": "Something which lasts for a short period of time.", "synonyms": ["ephemeron"], "antonyms": [] }
                ],
                "synonyms": ["ephemeron"],
                "antonyms": []
            },
            {
                "partOfSpeech": "adjective",
                "definitions": [
                    { "definition": "Lasting for a short period of time.", "synonyms": ["evanescent", "fleeting"], "antonyms": ["eternal", "permanent"] },
                    { "definition": "Existing for only one day, as with some flowers, insects, and diseases.", "synonyms": [], "antonyms": [] },
                    { "definition": "(of a body of water) Usually dry, but filling with water for brief periods during and after precipitation.", "synonyms": [], "antonyms": [] }
                ],
                "synonyms": ["evanescent", "fleeting"],
                "antonyms": ["eternal", "permanent"]
            }
        ],
        "license": { "name": "CC BY-SA 3.0", "url": "https://creativecommons.org/licenses/by-sa/3.0" },
        "sourceUrls": ["https://en.wiktionary.org/wiki/ephemeral"]
    }]"#;

    #[test]
    fn deserialize_real_payload() {
        let entries: Vec<DictEntry> = serde_json::from_str(REAL_PAYLOAD).unwrap();
        assert_eq!(entries.len(), 1);

        let entry = &entries[0];
        assert_eq!(entry.word, "ephemeral");
        assert_eq!(entry.phonetics.len(), 1);
        assert_eq!(entry.phonetics[0].text.as_deref(), Some("/əˈfɛ.mə.ɹəl/"));
        assert_eq!(entry.meanings.len(), 2);
        assert_eq!(entry.meanings[0].part_of_speech, "noun");
        assert_eq!(entry.meanings[1].part_of_speech, "adjective");
        assert_eq!(entry.meanings[1].definitions.len(), 3);
        assert!(entry.meanings[1].definitions[0]
            .definition
            .contains("Lasting for a short period"));
    }

    #[test]
    fn deserialize_with_example() {
        let json = r#"[{
            "word": "hello",
            "phonetics": [],
            "meanings": [{
                "partOfSpeech": "interjection",
                "definitions": [{
                    "definition": "A greeting.",
                    "example": "Hello, world!"
                }]
            }]
        }]"#;
        let entries: Vec<DictEntry> = serde_json::from_str(json).unwrap();
        assert_eq!(
            entries[0].meanings[0].definitions[0].example.as_deref(),
            Some("Hello, world!")
        );
    }
}
