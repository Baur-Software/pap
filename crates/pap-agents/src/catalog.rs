//! Catalog loader — reads all *.toml files from the catalog directory
//! and converts them to DynamicAgentDef values ready for DB insertion.

use crate::dynamic::{is_safe_url, DynamicAgentDef, DynamicAgentSource, HttpEndpointConfig};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct CatalogEntry {
    schema_version: u32,
    name: String,
    provider: String,
    description: String,
    action: String,
    #[serde(default)]
    object_types: Vec<String>,
    #[serde(default)]
    requires_disclosure: Vec<String>,
    #[serde(default)]
    returns: Vec<String>,
    endpoint: Option<HttpEndpointConfig>,
    #[serde(default)]
    llm_instructions: String,
    #[serde(default)]
    subagents: Vec<String>,
}

pub fn load_catalog(catalog_dir: &Path) -> Vec<DynamicAgentDef> {
    let mut defs = Vec::new();
    collect_toml_files(catalog_dir, catalog_dir, &mut defs);
    defs
}

fn collect_toml_files(root: &Path, dir: &Path, out: &mut Vec<DynamicAgentDef>) {
    let read_dir = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            eprintln!("[catalog] cannot read directory {}: {}", dir.display(), e);
            return;
        }
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_toml_files(root, &path, out);
        } else if path.extension().and_then(|s| s.to_str()) == Some("toml") {
            if let Some(def) = load_one(root, &path) {
                out.push(def);
            }
        }
    }
}

fn load_one(root: &Path, path: &Path) -> Option<DynamicAgentDef> {
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[catalog] cannot read {}: {}", path.display(), e);
            return None;
        }
    };
    let entry: CatalogEntry = match toml::from_str(&raw) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("[catalog] parse error in {}: {}", path.display(), e);
            return None;
        }
    };
    if let Some(ref ep) = entry.endpoint {
        if !is_safe_url(&ep.url_template) {
            eprintln!(
                "[catalog] unsafe URL in {}: {}",
                path.display(),
                ep.url_template
            );
            return None;
        }
    }
    let rel = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    Some(DynamicAgentDef {
        schema_version: entry.schema_version,
        name: entry.name,
        provider: entry.provider,
        description: entry.description,
        action: entry.action,
        object_types: entry.object_types,
        requires_disclosure: entry.requires_disclosure,
        returns: entry.returns,
        endpoint: entry.endpoint,
        llm_instructions: entry.llm_instructions,
        subagents: entry.subagents,
        source: DynamicAgentSource::Catalog,
        catalog_path: Some(rel),
        operator_key_seed: None,
        agent_did: None,
        published_to: vec![],
        created_at: String::new(),
        updated_at: String::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn catalog_dir() -> PathBuf {
        let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        PathBuf::from(manifest).join("catalog")
    }

    #[test]
    fn load_catalog_finds_all_entries() {
        let defs = load_catalog(&catalog_dir());
        assert!(
            defs.len() >= 22,
            "expected at least 22 catalog entries, found {}",
            defs.len()
        );
    }

    #[test]
    fn catalog_path_is_relative_to_catalog_dir() {
        let defs = load_catalog(&catalog_dir());
        let ddg = defs
            .iter()
            .find(|d| d.name == "DuckDuckGo Search")
            .expect("DuckDuckGo entry missing");
        let cp = ddg.catalog_path.as_deref().expect("catalog_path is None");
        assert_eq!(cp, "search/duckduckgo.toml");
        assert!(!cp.starts_with('/'));
    }

    #[test]
    fn catalog_entries_have_valid_urls() {
        let defs = load_catalog(&catalog_dir());
        for def in &defs {
            if let Some(ref ep) = def.endpoint {
                assert!(
                    is_safe_url(&ep.url_template),
                    "unsafe URL in '{}': {}",
                    def.name,
                    ep.url_template
                );
            }
        }
    }

    #[test]
    fn catalog_entries_have_schema_org_actions() {
        let defs = load_catalog(&catalog_dir());
        for def in &defs {
            assert!(
                def.action.starts_with("schema:"),
                "action '{}' in '{}' does not start with 'schema:'",
                def.action,
                def.name
            );
        }
    }

    #[test]
    fn malformed_toml_is_skipped() {
        let tmp = TempDir::new().unwrap();
        let bad = tmp.path().join("bad.toml");
        let mut f = std::fs::File::create(&bad).unwrap();
        writeln!(f, "this is not valid toml = [[[").unwrap();
        let defs = load_catalog(tmp.path());
        assert!(
            defs.is_empty(),
            "expected empty result for malformed TOML, got {} entries",
            defs.len()
        );
    }
}
