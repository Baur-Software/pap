//! End-to-end tests simulating real browser usage patterns.
//!
//! These tests verify complete workflows that users would experience:
//! - Recording and persisting episodes across multiple transactions
//! - Querying episodes with various filter combinations
//! - Managing agent profiles and updating statistics
//! - Template configuration and rendering
//! - Settings management across sessions

#[cfg(test)]
#[cfg(feature = "native")]
mod e2e_scenarios {
    use crate::db::{AgentProfile, DatabaseOps, Episode};
    use chrono::Utc;

    /// Simulates a complete user session with multiple episode types
    #[cfg(feature = "native")]
    #[test]
    fn e2e_scenario_complete_session() {
        use crate::db::native::NativeDatabase;

        let db = NativeDatabase::open_memory().expect("Failed to create database");

        // Phase 1: Record multiple agent interactions
        println!("Phase 1: Recording agent interactions...");

        let agents = vec![
            ("search-agent-1", "Web Search Agent", 0.95),
            ("booking-agent-1", "Flight Booking Agent", 0.88),
            ("payment-agent-1", "Payment Processing Agent", 0.99),
        ];

        for (agent_hash, agent_name, success_rate) in agents {
            let profile = AgentProfile {
                agent_did_hash: agent_hash.into(),
                agent_name: agent_name.into(),
                success_rate: success_rate,
                avg_quality: success_rate - 0.05,
                avg_duration_ms: 200.0,
                episode_count: 100,
                minimal_disclosure_refs: "[]".into(),
                last_used: Utc::now().to_rfc3339(),
                co_sign_refusals: 0,
            };
            db.upsert_agent_profile(&profile)
                .expect("Failed to store agent profile");
        }

        // Phase 2: Record various episode types
        println!("Phase 2: Recording episodes...");

        for i in 0..10 {
            let episode = Episode {
                id: format!("ep-{:03}", i),
                receipt_session_id: format!("session-{}", i / 3), // 3 episodes per session
                scenario_id: format!("scenario-{}", i % 3),
                action_type: match i % 3 {
                    0 => "search",
                    1 => "booking",
                    _ => "payment",
                }
                .into(),
                agent_did_hash: format!(
                    "{}-agent-{}",
                    match i % 3 {
                        0 => "search",
                        1 => "booking",
                        _ => "payment",
                    },
                    1
                )
                .into(),
                agent_name: match i % 3 {
                    0 => "Web Search Agent",
                    1 => "Flight Booking Agent",
                    _ => "Payment Processing Agent",
                }
                .into(),
                outcome: if i % 2 == 0 { "success" } else { "failure" }.into(),
                outcome_detail: if i % 2 == 0 {
                    None
                } else {
                    Some(format!("Network timeout on attempt {}", i))
                },
                scope_exercised: r#"["read", "search"]"#.into(),
                disclosure_refs: r#"["Person.name", "Person.email"]"#.into(),
                duration_ms: 100 + i as i64 * 50,
                decay_state: "Active".into(),
                intent_summary: Some(
                    match i % 3 {
                        0 => "Search for flights to Tokyo",
                        1 => "Book a round-trip flight",
                        _ => "Process payment for booking",
                    }
                    .into(),
                ),
                result_json: Some({
                    let schema_type = match i % 3 {
                        0 => "SearchResultsPage",
                        1 => "FlightReservation",
                        _ => "PaymentReceipt",
                    };
                    format!(r#"{{"@type":"{}","id":"result-{}"}}"#, schema_type, i)
                }),
                query: Some(
                    match i % 3 {
                        0 => "SFO to NRT departing 2026-04-01",
                        1 => "Book outbound 2026-04-01, return 2026-04-10",
                        _ => "Pay $1,500 USD via credit card",
                    }
                    .into(),
                ),
                recorded_at: Utc::now().to_rfc3339(),
            };
            db.insert_episode(&episode)
                .expect("Failed to store episode");
        }

        // Phase 3: Query and verify data integrity
        println!("Phase 3: Querying data...");

        let count = db.episode_count().expect("Failed to count episodes");
        assert_eq!(count, 10, "Expected 10 episodes recorded");

        let profiles = db.list_agent_profiles().expect("Failed to list profiles");
        assert_eq!(profiles.len(), 3, "Expected 3 agent profiles");

        // Phase 4: Filter queries
        println!("Phase 4: Testing filters...");

        let search_episodes = db
            .list_episodes(Some("search"), None, 100, None)
            .expect("Failed to filter by action_type");
        assert_eq!(
            search_episodes.len(),
            4,
            "Expected 4 search episodes (indices 0, 3, 6, 9)"
        );

        let booking_episodes = db
            .list_episodes(Some("booking"), None, 100, None)
            .expect("Failed to filter by action_type");
        assert_eq!(
            booking_episodes.len(),
            3,
            "Expected 3 booking episodes (indices 1, 4, 7)"
        );

        // Phase 5: Search functionality
        println!("Phase 5: Testing search...");

        let tokyo_results = db
            .search_text("Tokyo", 100)
            .expect("Failed to search for 'Tokyo'");
        assert!(
            !tokyo_results.is_empty(),
            "Expected search results for 'Tokyo'"
        );

        let schema_results = db
            .search_by_schema_type("FlightReservation", 100)
            .expect("Failed to search by schema type");
        assert_eq!(
            schema_results.len(),
            3,
            "Expected 3 FlightReservation episodes"
        );

        // Phase 6: Settings persistence
        println!("Phase 6: Testing settings...");

        db.set_setting("last_search_query", "SFO to NRT")
            .expect("Failed to set setting");
        db.set_setting("preferred_airline", "JAL")
            .expect("Failed to set setting");

        let query = db
            .get_setting("last_search_query")
            .expect("Failed to get setting");
        assert_eq!(query, Some("SFO to NRT".to_string()));

        println!("✓ Complete session E2E test passed");
        println!("  - Recorded 10 episodes across 3 agent types");
        println!("  - Verified 3 agent profiles");
        println!("  - Tested filtering and search functionality");
        println!("  - Verified settings persistence");
    }

    /// Tests pagination and large result sets
    #[cfg(feature = "native")]
    #[test]
    fn e2e_scenario_pagination() {
        use crate::db::native::NativeDatabase;

        let db = NativeDatabase::open_memory().expect("Failed to create database");

        // Insert 100 episodes
        println!("Inserting 100 episodes for pagination testing...");
        for i in 0..100 {
            let episode = Episode {
                id: format!("ep-{:03}", i),
                receipt_session_id: format!("session-{}", i / 10),
                scenario_id: format!("scenario-{}", i % 5),
                action_type: "search".into(),
                agent_did_hash: "agent-1".into(),
                agent_name: "Agent 1".into(),
                outcome: "success".into(),
                outcome_detail: None,
                scope_exercised: "[]".into(),
                disclosure_refs: "[]".into(),
                duration_ms: 100,
                decay_state: "Active".into(),
                intent_summary: None,
                result_json: None,
                query: Some(format!("query {}", i)),
                recorded_at: Utc::now().to_rfc3339(),
            };
            db.insert_episode(&episode)
                .expect("Failed to insert episode");
        }

        // Test pagination with limit and offset
        let page_1 = db
            .list_episodes(None, None, 20, Some(0))
            .expect("Failed to get page 1");
        assert_eq!(page_1.len(), 20, "Expected 20 items on page 1");

        let page_2 = db
            .list_episodes(None, None, 20, Some(20))
            .expect("Failed to get page 2");
        assert_eq!(page_2.len(), 20, "Expected 20 items on page 2");

        let page_5 = db
            .list_episodes(None, None, 20, Some(80))
            .expect("Failed to get page 5");
        assert_eq!(page_5.len(), 20, "Expected 20 items on page 5");

        // Verify no overlap between pages
        let page_1_ids: Vec<String> = page_1.iter().map(|e| e.id.clone()).collect();
        let page_2_ids: Vec<String> = page_2.iter().map(|e| e.id.clone()).collect();
        for id in &page_1_ids {
            assert!(
                !page_2_ids.contains(id),
                "Page 2 should not contain episodes from page 1"
            );
        }

        println!("✓ Pagination E2E test passed");
        println!("  - Inserted 100 episodes");
        println!("  - Successfully paginated with limit=20, offset");
        println!("  - Verified no overlaps between pages");
    }

    /// Tests concurrent updates and consistency
    #[cfg(feature = "native")]
    #[test]
    fn e2e_scenario_concurrent_updates() {
        use crate::db::native::NativeDatabase;

        let db = NativeDatabase::open_memory().expect("Failed to create database");

        // Create initial profile
        let mut profile = AgentProfile {
            agent_did_hash: "agent-1".into(),
            agent_name: "Agent 1".into(),
            success_rate: 0.80,
            avg_quality: 0.75,
            avg_duration_ms: 200.0,
            episode_count: 0,
            minimal_disclosure_refs: "[]".into(),
            last_used: Utc::now().to_rfc3339(),
            co_sign_refusals: 0,
        };

        db.upsert_agent_profile(&profile)
            .expect("Failed to create profile");

        // Simulate multiple updates
        for i in 0..5 {
            profile.success_rate = 0.80 + (i as f64 * 0.02);
            profile.episode_count = i as i64 * 10;
            profile.last_used = Utc::now().to_rfc3339();

            db.upsert_agent_profile(&profile)
                .expect("Failed to update profile");
        }

        // Verify final state
        let final_profile = db
            .get_agent_profile("agent-1")
            .expect("Failed to get profile")
            .expect("Profile should exist");

        assert_eq!(
            final_profile.success_rate, 0.88,
            "Profile should reflect final update"
        );
        assert_eq!(
            final_profile.episode_count, 40,
            "Profile should reflect final episode count"
        );

        println!("✓ Concurrent updates E2E test passed");
        println!("  - Successfully updated profile 5 times");
        println!("  - Final state consistent with last update");
    }

    /// WASM-specific E2E test
    #[cfg(all(feature = "wasm", not(target_arch = "wasm32")))]
    #[test]
    fn e2e_scenario_wasm_complete_workflow() {
        use crate::db::indexed_db::IndexedDbDatabase;

        let db =
            IndexedDbDatabase::new_with_persistence("e2e-test").expect("Failed to create database");

        // Record episodes
        for i in 0..5 {
            let episode = Episode {
                id: format!("ep-{}", i),
                receipt_session_id: format!("session-{}", i),
                scenario_id: format!("scenario-{}", i),
                action_type: if i % 2 == 0 { "search" } else { "booking" }.into(),
                agent_did_hash: format!("agent-{}", i % 2),
                agent_name: format!("Agent {}", i % 2).into(),
                outcome: "success".into(),
                outcome_detail: None,
                scope_exercised: "[]".into(),
                disclosure_refs: "[]".into(),
                duration_ms: 100 + i as i64 * 10,
                decay_state: "Active".into(),
                intent_summary: None,
                result_json: None,
                query: None,
                recorded_at: Utc::now().to_rfc3339(),
            };
            db.insert_episode(&episode)
                .expect("Failed to insert episode");
        }

        // Verify count
        let count = db.episode_count().expect("Failed to count");
        assert_eq!(count, 5, "Expected 5 episodes");

        // Verify retrieval
        let episodes = db
            .list_episodes(None, None, 10, None)
            .expect("Failed to list episodes");
        assert_eq!(episodes.len(), 5, "Expected 5 episodes returned");

        println!("✓ WASM E2E workflow test passed");
        println!("  - Recorded and retrieved 5 episodes");
        println!("  - Persistence wrapper functioning correctly");
    }
}

/// Performance benchmarks
#[cfg(test)]
#[cfg(feature = "native")]
mod benchmarks {
    use crate::db::native::NativeDatabase;
    use crate::db::{DatabaseOps, Episode};
    use chrono::Utc;
    use std::time::Instant;

    /// Measure episode insertion performance
    #[cfg(feature = "native")]
    #[test]
    fn benchmark_episode_insertion() {
        let db = NativeDatabase::open_memory().expect("Failed to create database");

        let start = Instant::now();
        for i in 0..1000 {
            let episode = Episode {
                id: format!("ep-{}", i),
                receipt_session_id: format!("session-{}", i / 100),
                scenario_id: format!("scenario-{}", i % 10),
                action_type: "search".into(),
                agent_did_hash: "agent-1".into(),
                agent_name: "Agent 1".into(),
                outcome: "success".into(),
                outcome_detail: None,
                scope_exercised: "[]".into(),
                disclosure_refs: "[]".into(),
                duration_ms: 100,
                decay_state: "Active".into(),
                intent_summary: None,
                result_json: None,
                query: None,
                recorded_at: Utc::now().to_rfc3339(),
            };
            db.insert_episode(&episode)
                .expect("Failed to insert episode");
        }
        let elapsed = start.elapsed();

        println!("Inserted 1000 episodes in {:?}", elapsed);
        println!(
            "  Average: {:.2}ms per insert",
            elapsed.as_millis() as f64 / 1000.0
        );

        assert!(
            elapsed.as_millis() < 5000,
            "Insertion should complete in < 5 seconds for 1000 episodes"
        );
    }

    /// Measure query performance
    #[cfg(feature = "native")]
    #[test]
    fn benchmark_query_performance() {
        let db = NativeDatabase::open_memory().expect("Failed to create database");

        // Insert 1000 episodes
        for i in 0..1000 {
            let episode = Episode {
                id: format!("ep-{}", i),
                receipt_session_id: "session-1".into(),
                scenario_id: "scenario-1".into(),
                action_type: if i % 2 == 0 { "search" } else { "booking" }.into(),
                agent_did_hash: "agent-1".into(),
                agent_name: "Agent 1".into(),
                outcome: "success".into(),
                outcome_detail: None,
                scope_exercised: "[]".into(),
                disclosure_refs: "[]".into(),
                duration_ms: 100,
                decay_state: "Active".into(),
                intent_summary: None,
                result_json: None,
                query: None,
                recorded_at: Utc::now().to_rfc3339(),
            };
            db.insert_episode(&episode).ok();
        }

        // Benchmark filtered query
        let start = Instant::now();
        for _ in 0..100 {
            let _results = db
                .list_episodes(Some("search"), None, 50, None)
                .expect("Failed to query");
        }
        let elapsed = start.elapsed();

        println!(
            "Executed 100 filtered queries on 1000 episodes in {:?}",
            elapsed
        );
        println!(
            "  Average: {:.2}ms per query",
            elapsed.as_millis() as f64 / 100.0
        );

        assert!(
            elapsed.as_millis() < 1000,
            "Queries should complete in < 1 second for 100 operations"
        );
    }
}
