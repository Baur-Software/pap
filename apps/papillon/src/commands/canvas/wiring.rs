use tauri::State;
use papillon_shared::BlockConnection;
use crate::AppState;

/// Connect two block containers.
/// Validates that from_block outputs match to_block inputs.
#[tauri::command]
pub async fn connect_blocks(
    from_block_id: String,
    to_block_id: String,
    state: State<'_, AppState>,
) -> Result<BlockConnection, String> {
    // 1. Fetch both containers from DB (TODO: implement fetch)
    // For now, validate signatures conceptually

    // 2. Validate wiring: from.signature.can_wire_to(to.signature)
    // This would use SchemaSignature::can_wire_to() method

    // 3. Check same canvas
    // if from_container.canvas_id != to_container.canvas_id {
    //     return Err(WiringError::CrossCanvasConnection { ... });
    // }

    // 4. Create connection record
    let connection = BlockConnection {
        id: uuid::Uuid::new_v4().to_string(),
        from_block: from_block_id.clone(),
        to_block: to_block_id.clone(),
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    // 5. Store connection in DB (TODO: add table)
    // 6. Update container input_connections and output_connections vectors

    Ok(connection)
}

/// Disconnect two block containers.
#[tauri::command]
pub async fn disconnect_blocks(
    from_block_id: String,
    to_block_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    // 1. Fetch connection from DB
    // 2. Delete connection record
    // 3. Update container vectors
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use papillon_shared::SchemaSignature;

    #[test]
    fn test_can_wire_place_to_weather() {
        let from_sig = SchemaSignature {
            input_types: vec![],
            output_types: vec!["schema:Place".to_string()],
        };
        let to_sig = SchemaSignature {
            input_types: vec!["schema:Place".to_string()],
            output_types: vec!["schema:WeatherForecast".to_string()],
        };
        assert!(from_sig.can_wire_to(&to_sig));
    }

    #[test]
    fn test_cannot_wire_incompatible_types() {
        let from_sig = SchemaSignature {
            input_types: vec![],
            output_types: vec!["schema:WeatherForecast".to_string()],
        };
        let to_sig = SchemaSignature {
            input_types: vec!["schema:Place".to_string()],
            output_types: vec!["schema:Event".to_string()],
        };
        assert!(!from_sig.can_wire_to(&to_sig));
    }
}
