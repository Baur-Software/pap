//! Pure canvas helper functions.
//!
//! All functions in this module are dependency-free (no WASM, no I/O) and
//! operate only on the shared types defined in `types.rs`.  They are tested
//! with `cargo test -p papillon-shared` so they run natively without a
//! browser or WASM runtime.

use crate::types::{Canvas, CanvasMessageRecord, CanvasRecord};

/// Return only the messages whose `canvas_id` matches `active_id`.
///
/// Returns an empty `Vec` when `active_id` is `None` or no messages match.
pub fn filter_messages_by_canvas(
    messages: &[CanvasMessageRecord],
    active_id: Option<&str>,
) -> Vec<CanvasMessageRecord> {
    match active_id {
        None => vec![],
        Some(id) => messages
            .iter()
            .filter(|m| m.canvas_id == id)
            .cloned()
            .collect(),
    }
}

/// Merge `incoming` messages into `store`, skipping any whose `id` is
/// already present.  Preserves insertion order for new messages.
pub fn merge_messages_dedup(
    store: &mut Vec<CanvasMessageRecord>,
    incoming: Vec<CanvasMessageRecord>,
) {
    for msg in incoming {
        if !store.iter().any(|m| m.id == msg.id) {
            store.push(msg);
        }
    }
}

/// Merge `records` from the DB into `store`, skipping IDs that are already
/// present.  New entries are initialised with empty `blocks` so they can be
/// lazy-loaded later.
pub fn merge_canvases_from_records(store: &mut Vec<Canvas>, records: &[CanvasRecord]) {
    for rec in records {
        if store.iter().any(|c| c.id == rec.id) {
            continue;
        }
        let now = rec.created_at.clone();
        store.push(Canvas {
            id: rec.id.clone(),
            name: rec.name.clone(),
            blocks: Vec::new(),
            created_at: now.clone(),
            updated_at: now,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CanvasBlock;
    use crate::BlockState;

    // ── helpers ───────────────────────────────────────────────────────────────

    fn make_msg(id: &str, canvas_id: &str, content: &str) -> CanvasMessageRecord {
        CanvasMessageRecord {
            id: id.to_string(),
            canvas_id: canvas_id.to_string(),
            role: "user".to_string(),
            content: content.to_string(),
            block_id: None,
            created_at: "2024-01-01T00:00:00Z".to_string(),
        }
    }

    fn make_canvas_record(id: &str, name: &str) -> CanvasRecord {
        CanvasRecord {
            id: id.to_string(),
            name: name.to_string(),
            created_at: "2024-01-01T00:00:00Z".to_string(),
            updated_at: "2024-01-01T00:00:00Z".to_string(),
        }
    }

    fn make_bare_canvas(id: &str, name: &str) -> Canvas {
        Canvas {
            id: id.to_string(),
            name: name.to_string(),
            blocks: Vec::new(),
            created_at: "2024-01-01T00:00:00Z".to_string(),
            updated_at: "2024-01-01T00:00:00Z".to_string(),
        }
    }

    fn make_block(id: &str) -> CanvasBlock {
        CanvasBlock {
            id: id.to_string(),
            prompt_id: "p".into(),
            prompt_text: Some("test".into()),
            state: BlockState::Resolved,
            schema_type: None,
            content: None,
            linked_block_ids: Vec::new(),
            agent_did: None,
            mandate_expires_at: None,
            preference_guided: false,
            auto_expand: false,
            created_at: String::new(),
            updated_at: String::new(),
        }
    }

    // ── filter_messages_by_canvas ─────────────────────────────────────────────

    #[test]
    fn filter_messages_returns_only_active_canvas_messages() {
        let msgs = vec![
            make_msg("m1", "canvas-A", "hello from A"),
            make_msg("m2", "canvas-B", "hello from B"),
            make_msg("m3", "canvas-A", "second from A"),
        ];
        let result = filter_messages_by_canvas(&msgs, Some("canvas-A"));
        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|m| m.canvas_id == "canvas-A"));
    }

    #[test]
    fn filter_messages_returns_empty_when_no_active_canvas() {
        let msgs = vec![make_msg("m1", "canvas-A", "hello")];
        let result = filter_messages_by_canvas(&msgs, None);
        assert!(result.is_empty());
    }

    #[test]
    fn filter_messages_returns_empty_when_canvas_has_no_messages() {
        let msgs = vec![make_msg("m1", "canvas-A", "hello")];
        let result = filter_messages_by_canvas(&msgs, Some("canvas-B"));
        assert!(result.is_empty());
    }

    #[test]
    fn filter_messages_returns_empty_for_empty_store() {
        let msgs: Vec<CanvasMessageRecord> = vec![];
        let result = filter_messages_by_canvas(&msgs, Some("canvas-A"));
        assert!(result.is_empty());
    }

    #[test]
    fn filter_messages_preserves_order() {
        let msgs = vec![
            make_msg("m1", "canvas-A", "first"),
            make_msg("m2", "canvas-A", "second"),
            make_msg("m3", "canvas-A", "third"),
        ];
        let result = filter_messages_by_canvas(&msgs, Some("canvas-A"));
        assert_eq!(result[0].id, "m1");
        assert_eq!(result[1].id, "m2");
        assert_eq!(result[2].id, "m3");
    }

    #[test]
    fn filter_messages_with_single_canvas_returns_all_its_messages() {
        let msgs: Vec<_> = (0..5)
            .map(|i| make_msg(&format!("m{i}"), "only-canvas", &format!("msg {i}")))
            .collect();
        let result = filter_messages_by_canvas(&msgs, Some("only-canvas"));
        assert_eq!(result.len(), 5);
    }

    #[test]
    fn filter_messages_does_not_clone_messages_from_other_canvases() {
        let msgs = vec![
            make_msg("m1", "A", "in A"),
            make_msg("m2", "B", "in B"),
            make_msg("m3", "C", "in C"),
        ];
        let result = filter_messages_by_canvas(&msgs, Some("B"));
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "m2");
    }

    // ── merge_messages_dedup ──────────────────────────────────────────────────

    #[test]
    fn merge_messages_dedup_adds_new_messages() {
        let mut store = vec![make_msg("existing", "canvas-A", "already here")];
        let incoming = vec![
            make_msg("new-1", "canvas-A", "brand new"),
            make_msg("new-2", "canvas-A", "also new"),
        ];
        merge_messages_dedup(&mut store, incoming);
        assert_eq!(store.len(), 3);
    }

    #[test]
    fn merge_messages_dedup_skips_duplicate_ids() {
        let mut store = vec![make_msg("dup", "canvas-A", "original")];
        let incoming = vec![make_msg("dup", "canvas-A", "duplicate — should be skipped")];
        merge_messages_dedup(&mut store, incoming);
        assert_eq!(store.len(), 1);
        assert_eq!(store[0].content, "original");
    }

    #[test]
    fn merge_messages_dedup_handles_empty_incoming() {
        let mut store = vec![make_msg("m1", "canvas-A", "existing")];
        merge_messages_dedup(&mut store, vec![]);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn merge_messages_dedup_handles_empty_store() {
        let mut store: Vec<CanvasMessageRecord> = vec![];
        let incoming = vec![
            make_msg("m1", "canvas-A", "new"),
            make_msg("m2", "canvas-A", "also new"),
        ];
        merge_messages_dedup(&mut store, incoming);
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn merge_messages_dedup_mixed_new_and_dup() {
        let mut store = vec![make_msg("keep", "canvas-A", "keep me")];
        let incoming = vec![
            make_msg("keep", "canvas-A", "duplicate"),
            make_msg("add", "canvas-B", "add me"),
        ];
        merge_messages_dedup(&mut store, incoming);
        assert_eq!(store.len(), 2);
        assert!(store.iter().any(|m| m.id == "keep"));
        assert!(store.iter().any(|m| m.id == "add"));
    }

    #[test]
    fn merge_messages_dedup_preserves_insertion_order_of_new_messages() {
        let mut store: Vec<CanvasMessageRecord> = vec![];
        let incoming = vec![
            make_msg("first", "c", "a"),
            make_msg("second", "c", "b"),
            make_msg("third", "c", "c"),
        ];
        merge_messages_dedup(&mut store, incoming);
        assert_eq!(store[0].id, "first");
        assert_eq!(store[1].id, "second");
        assert_eq!(store[2].id, "third");
    }

    // ── merge_canvases_from_records ───────────────────────────────────────────

    #[test]
    fn merge_canvases_adds_new_records() {
        let mut store: Vec<Canvas> = vec![];
        let records = vec![
            make_canvas_record("c1", "Canvas One"),
            make_canvas_record("c2", "Canvas Two"),
        ];
        merge_canvases_from_records(&mut store, &records);
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn merge_canvases_skips_existing_ids() {
        let mut store = vec![make_bare_canvas("c1", "Already There")];
        let records = vec![
            make_canvas_record("c1", "Duplicate — skip"),
            make_canvas_record("c2", "New"),
        ];
        merge_canvases_from_records(&mut store, &records);
        assert_eq!(store.len(), 2);
        let c1 = store.iter().find(|c| c.id == "c1").unwrap();
        assert_eq!(c1.name, "Already There"); // original preserved, not overwritten
    }

    #[test]
    fn merge_canvases_from_empty_records_leaves_store_unchanged() {
        let mut store = vec![make_bare_canvas("c1", "Only")];
        merge_canvases_from_records(&mut store, &[]);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn merge_canvases_into_empty_store() {
        let mut store: Vec<Canvas> = vec![];
        let records = vec![make_canvas_record("c1", "New Canvas")];
        merge_canvases_from_records(&mut store, &records);
        assert_eq!(store.len(), 1);
        assert_eq!(store[0].id, "c1");
        assert_eq!(store[0].name, "New Canvas");
        assert!(
            store[0].blocks.is_empty(),
            "new canvas must start with no blocks"
        );
    }

    #[test]
    fn merge_canvases_all_duplicates_changes_nothing() {
        let mut store = vec![make_bare_canvas("c1", "One"), make_bare_canvas("c2", "Two")];
        let records = vec![
            make_canvas_record("c1", "One dup"),
            make_canvas_record("c2", "Two dup"),
        ];
        merge_canvases_from_records(&mut store, &records);
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn merge_canvases_preserves_existing_blocks() {
        let block = make_block("blk");
        let mut store = vec![Canvas {
            id: "c1".into(),
            name: "With Block".into(),
            blocks: vec![block],
            created_at: String::new(),
            updated_at: String::new(),
        }];
        // Trying to re-add c1 via records must not wipe out its blocks.
        let records = vec![make_canvas_record("c1", "c1 from db")];
        merge_canvases_from_records(&mut store, &records);
        assert_eq!(
            store[0].blocks.len(),
            1,
            "existing blocks must be preserved"
        );
    }

    #[test]
    fn merge_canvases_new_entries_start_with_no_blocks() {
        let mut store: Vec<Canvas> = vec![];
        let records = vec![make_canvas_record("fresh", "Fresh Canvas")];
        merge_canvases_from_records(&mut store, &records);
        assert!(
            store[0].blocks.is_empty(),
            "lazily-loaded canvas must have empty blocks initially"
        );
    }

    #[test]
    fn merge_canvases_timestamps_come_from_record() {
        let mut store: Vec<Canvas> = vec![];
        let records = vec![CanvasRecord {
            id: "ts-test".into(),
            name: "Ts".into(),
            created_at: "2025-06-01T12:00:00Z".to_string(),
            updated_at: "2025-06-02T08:00:00Z".to_string(),
        }];
        merge_canvases_from_records(&mut store, &records);
        assert_eq!(store[0].created_at, "2025-06-01T12:00:00Z");
        // updated_at on a freshly-merged canvas is set to created_at (no updater yet)
        assert_eq!(store[0].updated_at, "2025-06-01T12:00:00Z");
    }
}
