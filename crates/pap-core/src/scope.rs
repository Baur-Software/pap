use serde::{Deserialize, Serialize};

/// A scope is a set of permitted actions. Deny by default — an agent can only
/// do what its mandate explicitly permits.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Scope {
    pub actions: Vec<ScopeAction>,
}

/// A single permitted action expressed as a Schema.org action reference
/// with optional conditions. Schema.org describes the "what"; the conditions
/// govern "under what terms".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScopeAction {
    /// Schema.org action type, e.g. "schema:SearchAction", "schema:PayAction"
    pub action: String,

    /// Optional Schema.org object type constraint, e.g. "schema:Flight"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,

    /// Protocol-level conditions (not Schema.org extensions)
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub conditions: serde_json::Map<String, serde_json::Value>,
}

/// The set of context classes an agent holds and the conditions for sharing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DisclosureSet {
    pub entries: Vec<DisclosureEntry>,
}

/// A single disclosure entry — what type of context, which properties are
/// permitted/prohibited, and retention constraints.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DisclosureEntry {
    /// Schema.org type, e.g. "schema:Person"
    #[serde(rename = "type")]
    pub schema_type: String,

    /// Properties the agent is permitted to disclose
    pub permitted_properties: Vec<String>,

    /// Properties the agent must never disclose
    pub prohibited_properties: Vec<String>,

    /// If true, disclosed data is valid only for the session duration
    #[serde(default)]
    pub session_only: bool,

    /// If true, the receiving party must not retain disclosed data
    #[serde(default)]
    pub no_retention: bool,
}

impl Scope {
    /// Create a scope with the given actions.
    pub fn new(actions: Vec<ScopeAction>) -> Self {
        Self { actions }
    }

    /// Empty scope — denies everything.
    pub fn deny_all() -> Self {
        Self { actions: vec![] }
    }

    /// Check whether this scope contains (permits) a given action type.
    pub fn permits(&self, action: &str) -> bool {
        self.actions.iter().any(|a| a.action == action)
    }

    /// Check whether `child` is a subset of `self`. A delegated scope
    /// cannot exceed its parent.
    pub fn contains(&self, child: &Scope) -> bool {
        child.actions.iter().all(|child_action| {
            self.actions.iter().any(|parent_action| {
                parent_action.action == child_action.action
                    && match (&parent_action.object, &child_action.object) {
                        (Some(p), Some(c)) => p == c,
                        (None, _) => true,        // parent unconstrained
                        (Some(_), None) => false, // child broader than parent
                    }
            })
        })
    }
}

impl ScopeAction {
    /// Create a scope action with no conditions.
    pub fn new(action: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            object: None,
            conditions: serde_json::Map::new(),
        }
    }

    /// Create a scope action with an object type constraint.
    pub fn with_object(action: impl Into<String>, object: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            object: Some(object.into()),
            conditions: serde_json::Map::new(),
        }
    }
}

impl DisclosureSet {
    pub fn new(entries: Vec<DisclosureEntry>) -> Self {
        Self { entries }
    }

    /// Empty disclosure set — disclose nothing.
    pub fn empty() -> Self {
        Self { entries: vec![] }
    }

    /// Property references only (for receipts — never values).
    pub fn property_refs(&self) -> Vec<String> {
        self.entries
            .iter()
            .flat_map(|e| {
                e.permitted_properties
                    .iter()
                    .map(|p| format!("{}.{}", e.schema_type, p))
            })
            .collect()
    }
}

impl DisclosureEntry {
    pub fn new(
        schema_type: impl Into<String>,
        permitted: Vec<String>,
        prohibited: Vec<String>,
    ) -> Self {
        Self {
            schema_type: schema_type.into(),
            permitted_properties: permitted,
            prohibited_properties: prohibited,
            session_only: false,
            no_retention: false,
        }
    }

    pub fn session_only(mut self) -> Self {
        self.session_only = true;
        self
    }

    pub fn no_retention(mut self) -> Self {
        self.no_retention = true;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_all_permits_nothing() {
        let scope = Scope::deny_all();
        assert!(!scope.permits("schema:SearchAction"));
        assert!(!scope.permits("schema:PayAction"));
    }

    #[test]
    fn scope_permits_declared_action() {
        let scope = Scope::new(vec![ScopeAction::new("schema:SearchAction")]);
        assert!(scope.permits("schema:SearchAction"));
        assert!(!scope.permits("schema:PayAction"));
    }

    #[test]
    fn child_scope_subset() {
        let parent = Scope::new(vec![
            ScopeAction::new("schema:SearchAction"),
            ScopeAction::new("schema:PayAction"),
        ]);
        let child = Scope::new(vec![ScopeAction::new("schema:SearchAction")]);
        assert!(parent.contains(&child));
        assert!(!child.contains(&parent));
    }

    #[test]
    fn child_cannot_exceed_parent_object() {
        let parent = Scope::new(vec![ScopeAction::with_object(
            "schema:ReserveAction",
            "schema:Flight",
        )]);
        let child = Scope::new(vec![ScopeAction::new("schema:ReserveAction")]);
        assert!(!parent.contains(&child));

        let child_ok = Scope::new(vec![ScopeAction::with_object(
            "schema:ReserveAction",
            "schema:Flight",
        )]);
        assert!(parent.contains(&child_ok));
    }

    #[test]
    fn disclosure_set_property_refs() {
        let ds = DisclosureSet::new(vec![DisclosureEntry::new(
            "schema:Person",
            vec!["schema:name".into()],
            vec!["schema:email".into()],
        )]);
        let refs = ds.property_refs();
        assert_eq!(refs, vec!["schema:Person.schema:name"]);
    }

    #[test]
    fn empty_disclosure_discloses_nothing() {
        let ds = DisclosureSet::empty();
        assert!(ds.property_refs().is_empty());
    }

    #[test]
    fn disclosure_entry_builder() {
        let entry = DisclosureEntry::new("schema:Person", vec!["schema:name".into()], vec![])
            .session_only()
            .no_retention();

        assert!(entry.session_only);
        assert!(entry.no_retention);
    }

    #[test]
    fn scope_serialization_roundtrip() {
        let scope = Scope::new(vec![ScopeAction::new("schema:SearchAction")]);
        let json = serde_json::to_string(&scope).unwrap();
        let scope2: Scope = serde_json::from_str(&json).unwrap();
        assert_eq!(scope, scope2);
    }
}
