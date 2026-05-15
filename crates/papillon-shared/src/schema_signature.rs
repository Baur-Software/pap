use serde::{Deserialize, Serialize};
use crate::AgentInfo;

/// Schema.org I/O signature for an agent or block container.
/// Defines what types go in and what types come out.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SchemaSignature {
    /// Schema.org types this agent/block accepts as input.
    /// Empty vec means no input required (e.g., "list all flights" with no location).
    pub input_types: Vec<String>,
    /// Schema.org types this agent/block returns.
    pub output_types: Vec<String>,
}

impl SchemaSignature {
    /// Construct signature from AgentInfo's object_types (input) and returns (output).
    pub fn from_agent(agent: &AgentInfo) -> Self {
        SchemaSignature {
            input_types: agent.object_types.clone(),
            output_types: agent.returns.clone(),
        }
    }

    /// Check if this signature's outputs can wire to another signature's inputs.
    /// Returns true when: ALL of `other`'s input_types are present in `self`'s output_types.
    /// This is a subset check: other.input_types ⊆ self.output_types.
    pub fn can_wire_to(&self, other: &SchemaSignature) -> bool {
        if other.input_types.is_empty() {
            // Target requires no input — cannot wire to a source block
            return false;
        }
        // Check that every required input type is present in our outputs
        other.input_types.iter().all(|req| self.output_types.contains(req))
    }

    /// Check if an agent's signature matches this container's signature.
    /// Used for multi-agent selection: agents must have same I/O contract.
    pub fn matches(&self, other: &SchemaSignature) -> bool {
        self.input_types == other.input_types && self.output_types == other.output_types
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_can_wire_place_to_weather() {
        let place_sig = SchemaSignature {
            input_types: vec![],
            output_types: vec!["schema:Place".into()],
        };
        let weather_sig = SchemaSignature {
            input_types: vec!["schema:Place".into()],
            output_types: vec!["schema:WeatherForecast".into()],
        };
        assert!(place_sig.can_wire_to(&weather_sig));
    }

    #[test]
    fn test_cannot_wire_weather_to_place() {
        let weather_sig = SchemaSignature {
            input_types: vec!["schema:Place".into()],
            output_types: vec!["schema:WeatherForecast".into()],
        };
        let place_sig = SchemaSignature {
            input_types: vec![],
            output_types: vec!["schema:Place".into()],
        };
        assert!(!weather_sig.can_wire_to(&place_sig));
    }

    #[test]
    fn test_from_agent_info() {
        let agent = AgentInfo {
            name: "Weather Agent".into(),
            provider_name: "Test".into(),
            provider_did: "did:key:z123".into(),
            capabilities: vec![],
            object_types: vec!["schema:Place".into()],
            requires_disclosure: vec![],
            returns: vec!["schema:WeatherForecast".into()],
            endpoint: None,
            content_hash: "".into(),
            agent_did: None,
            source: "test".into(),
            published_to: vec![],
            live: false,
            category: "weather".into(),
            execution_target: Default::default(),
            lifecycle: Default::default(),
        };
        let sig = SchemaSignature::from_agent(&agent);
        assert_eq!(sig.input_types, vec!["schema:Place"]);
        assert_eq!(sig.output_types, vec!["schema:WeatherForecast"]);
    }

    #[test]
    fn test_matches_identical_signatures() {
        let sig1 = SchemaSignature {
            input_types: vec!["schema:Place".into()],
            output_types: vec!["schema:WeatherForecast".into()],
        };
        let sig2 = SchemaSignature {
            input_types: vec!["schema:Place".into()],
            output_types: vec!["schema:WeatherForecast".into()],
        };
        assert!(sig1.matches(&sig2));
    }

    #[test]
    fn test_matches_different_signatures() {
        let sig1 = SchemaSignature {
            input_types: vec!["schema:Place".into()],
            output_types: vec!["schema:WeatherForecast".into()],
        };
        let sig2 = SchemaSignature {
            input_types: vec!["schema:Place".into()],
            output_types: vec!["schema:Event".into()],
        };
        let sig3 = SchemaSignature {
            input_types: vec!["schema:DateTime".into()],
            output_types: vec!["schema:WeatherForecast".into()],
        };
        assert!(!sig1.matches(&sig2));
        assert!(!sig1.matches(&sig3));
    }

    #[test]
    fn test_cannot_wire_partial_overlap() {
        let source = SchemaSignature {
            input_types: vec![],
            output_types: vec!["schema:Place".into()],
        };
        let target = SchemaSignature {
            input_types: vec!["schema:Place".into(), "schema:DateTime".into()],
            output_types: vec!["schema:Event".into()],
        };
        assert!(!source.can_wire_to(&target));
    }
}
