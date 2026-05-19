use crate::SchemaSignature;
use serde::{Deserialize, Serialize};

/// A block container holds N agents with the same schema signature.
/// Positioned on a 2D canvas with input/output ports for visual wiring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockContainer {
    /// Unique block ID.
    pub id: String,
    /// Parent canvas ID.
    pub canvas_id: String,
    /// Shared schema.org I/O signature for all agents in this container.
    pub signature: SchemaSignature,
    /// Names of agents selected for execution (must all match signature).
    pub agent_names: Vec<String>,
    /// 2D position on canvas for visual layout.
    pub position: BlockPosition,
    /// IDs of blocks wired to this block's inputs.
    pub input_connections: Vec<String>,
    /// IDs of blocks this block's outputs wire to.
    pub output_connections: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// 2D position for node-graph layout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockPosition {
    pub x: f64,
    pub y: f64,
}

/// A wired connection between two blocks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockConnection {
    pub id: String,
    pub from_block: String,
    pub to_block: String,
    pub created_at: String,
}

/// Wiring validation error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WiringError {
    /// Target block's input types are not a subset of source block's output types.
    IncompatibleTypes {
        from_outputs: Vec<String>,
        to_inputs: Vec<String>,
    },
    /// Connection would require disclosure of properties not in source block's scope.
    DisclosureViolation {
        required: Vec<String>,
        available: Vec<String>,
    },
    /// Blocks are in different canvases.
    CrossCanvasConnection {
        from_canvas: String,
        to_canvas: String,
    },
    /// Connection would create a cycle.
    CycleDetected,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SchemaSignature;

    #[test]
    fn test_block_container_creation() {
        let sig = SchemaSignature {
            input_types: vec!["schema:Place".into()],
            output_types: vec!["schema:WeatherForecast".into()],
        };
        let container = BlockContainer {
            id: "block-123".into(),
            canvas_id: "canvas-456".into(),
            signature: sig.clone(),
            agent_names: vec!["Weather Agent 1".into(), "Weather Agent 2".into()],
            position: BlockPosition { x: 100.0, y: 200.0 },
            input_connections: vec![],
            output_connections: vec![],
            created_at: "2026-05-14T00:00:00Z".into(),
            updated_at: "2026-05-14T00:00:00Z".into(),
        };
        assert_eq!(container.agent_names.len(), 2);
        assert_eq!(container.signature, sig);
    }

    #[test]
    fn test_block_connection_validation() {
        let conn = BlockConnection {
            id: "conn-1".into(),
            from_block: "block-a".into(),
            to_block: "block-b".into(),
            created_at: "2026-05-14T00:00:00Z".into(),
        };
        assert_eq!(conn.from_block, "block-a");
        assert_eq!(conn.to_block, "block-b");
    }
}
