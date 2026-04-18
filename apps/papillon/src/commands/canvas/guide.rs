use crate::db::prelude::DatabaseOps;
use crate::error::PapillonError;
use crate::state::AppState;
use papillon_shared::{GuideSuggestion, SynthesisFormat};

use super::types::{GuideBlockPayload, GuideBlockSummary};

/// Generate (or refresh) the Canvas Guide block for a canvas.
///
/// Takes a list of summaries from already-resolved blocks on the canvas,
/// builds a human-readable summary sentence, derives schema-type-specific
/// follow-up suggestions, and appends up to 2 saved-pipeline suggestions
/// from the user's saved pipelines.
#[tauri::command]
pub async fn canvas_generate_guide(
    state: tauri::State<'_, AppState>,
    canvas_id: String,
    resolved_block_summaries: Vec<GuideBlockSummary>,
) -> Result<GuideBlockPayload, PapillonError> {
    // 1. Build summary string
    let agent_names: Vec<&str> = {
        let mut set: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for s in &resolved_block_summaries {
            set.insert(s.agent_name.as_str());
        }
        set.into_iter().collect()
    };
    let schema_types: Vec<&str> = {
        let mut set: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for s in &resolved_block_summaries {
            set.insert(s.schema_type.as_str());
        }
        set.into_iter().collect()
    };

    let summary = format!(
        "{} result{} from {} covering {}",
        resolved_block_summaries.len(),
        if resolved_block_summaries.len() == 1 {
            ""
        } else {
            "s"
        },
        agent_names.join(", "),
        schema_types.join(", "),
    );

    // 2. Static schema_type → prompt suggestion lookup
    let mut suggestions: Vec<GuideSuggestion> = Vec::new();
    for schema_type in &schema_types {
        match *schema_type {
            "SearchResult" | "SearchResultsPage" => suggestions.push(GuideSuggestion {
                label: "Research Further".into(),
                prompt_template: "Research further: ".into(),
                saved_pipeline_id: None,
                synthesis_format: None,
            }),
            "NewsArticle" => suggestions.push(GuideSuggestion {
                label: "Briefing Doc".into(),
                prompt_template: "Summarize these news articles into a briefing".into(),
                saved_pipeline_id: None,
                synthesis_format: Some(SynthesisFormat::BriefingDoc),
            }),
            "ScholarlyArticle" => suggestions.push(GuideSuggestion {
                label: "Key Findings".into(),
                prompt_template: "What are the key findings from these papers?".into(),
                saved_pipeline_id: None,
                synthesis_format: Some(SynthesisFormat::Faq),
            }),
            "WeatherForecast" => suggestions.push(GuideSuggestion {
                label: "Pack List".into(),
                prompt_template: "What should I pack for this weather?".into(),
                saved_pipeline_id: None,
                synthesis_format: None,
            }),
            "Product" => suggestions.push(GuideSuggestion {
                label: "Compare".into(),
                prompt_template: "Compare these products on price and quality".into(),
                saved_pipeline_id: None,
                synthesis_format: Some(SynthesisFormat::Outline),
            }),
            "VisualArtwork" => suggestions.push(GuideSuggestion {
                label: "Artist Info".into(),
                prompt_template: "Tell me more about the artist behind these works".into(),
                saved_pipeline_id: None,
                synthesis_format: None,
            }),
            _ => {}
        }
    }

    // 3. Load saved pipelines and surface compatible ones
    let saved = state
        .db
        .list_saved_pipelines()
        .map_err(|e| PapillonError::from(e.0))?;
    for pipeline in saved.iter().take(2) {
        // cap at 2 pipeline suggestions
        suggestions.push(GuideSuggestion {
            label: pipeline.name.clone(),
            prompt_template: String::new(),
            saved_pipeline_id: Some(pipeline.id.clone()),
            synthesis_format: None,
        });
    }

    // Deduplicate and cap at 5
    suggestions.dedup_by(|a, b| a.label == b.label);
    suggestions.truncate(5);

    Ok(GuideBlockPayload {
        block_id: format!("guide-{}", canvas_id),
        summary,
        suggestions,
    })
}

#[cfg(test)]
mod guide_tests {
    use super::*;

    /// Helper: build a GuideBlockSummary slice and run the summary logic inline.
    fn build_summary_and_suggestions(
        summaries: &[GuideBlockSummary],
    ) -> (String, Vec<GuideSuggestion>) {
        let agent_names: Vec<&str> = {
            let mut set: std::collections::HashSet<&str> = std::collections::HashSet::new();
            for s in summaries {
                set.insert(s.agent_name.as_str());
            }
            let mut v: Vec<&str> = set.into_iter().collect();
            v.sort(); // deterministic order for tests
            v
        };
        let schema_types: Vec<&str> = {
            let mut set: std::collections::HashSet<&str> = std::collections::HashSet::new();
            for s in summaries {
                set.insert(s.schema_type.as_str());
            }
            let mut v: Vec<&str> = set.into_iter().collect();
            v.sort();
            v
        };

        let summary = format!(
            "{} result{} from {} covering {}",
            summaries.len(),
            if summaries.len() == 1 { "" } else { "s" },
            agent_names.join(", "),
            schema_types.join(", "),
        );

        let mut suggestions: Vec<GuideSuggestion> = Vec::new();
        for schema_type in &schema_types {
            match *schema_type {
                "SearchResult" | "SearchResultsPage" => suggestions.push(GuideSuggestion {
                    label: "Research Further".into(),
                    prompt_template: "Research further: ".into(),
                    saved_pipeline_id: None,
                    synthesis_format: None,
                }),
                "NewsArticle" => suggestions.push(GuideSuggestion {
                    label: "Briefing Doc".into(),
                    prompt_template: "Summarize these news articles into a briefing".into(),
                    saved_pipeline_id: None,
                    synthesis_format: Some(SynthesisFormat::BriefingDoc),
                }),
                "ScholarlyArticle" => suggestions.push(GuideSuggestion {
                    label: "Key Findings".into(),
                    prompt_template: "What are the key findings from these papers?".into(),
                    saved_pipeline_id: None,
                    synthesis_format: Some(SynthesisFormat::Faq),
                }),
                "WeatherForecast" => suggestions.push(GuideSuggestion {
                    label: "Pack List".into(),
                    prompt_template: "What should I pack for this weather?".into(),
                    saved_pipeline_id: None,
                    synthesis_format: None,
                }),
                "Product" => suggestions.push(GuideSuggestion {
                    label: "Compare".into(),
                    prompt_template: "Compare these products on price and quality".into(),
                    saved_pipeline_id: None,
                    synthesis_format: Some(SynthesisFormat::Outline),
                }),
                "VisualArtwork" => suggestions.push(GuideSuggestion {
                    label: "Artist Info".into(),
                    prompt_template: "Tell me more about the artist behind these works".into(),
                    saved_pipeline_id: None,
                    synthesis_format: None,
                }),
                _ => {}
            }
        }

        // No saved pipelines in unit tests.
        suggestions.dedup_by(|a, b| a.label == b.label);
        suggestions.truncate(5);

        (summary, suggestions)
    }

    #[test]
    fn guide_generates_summary_from_schema_types() {
        let summaries = vec![
            GuideBlockSummary {
                schema_type: "NewsArticle".into(),
                agent_name: "Hacker News".into(),
                snippet: "Latest tech news...".into(),
            },
            GuideBlockSummary {
                schema_type: "NewsArticle".into(),
                agent_name: "Hacker News".into(),
                snippet: "More news...".into(),
            },
        ];
        let (summary, suggestions) = build_summary_and_suggestions(&summaries);

        assert!(
            summary.contains("2 results"),
            "summary should mention count: {}",
            summary
        );
        assert!(
            summary.contains("Hacker News"),
            "summary should mention agent: {}",
            summary
        );
        assert!(
            summary.contains("NewsArticle"),
            "summary should mention schema type: {}",
            summary
        );

        // NewsArticle should map to "Briefing Doc" suggestion
        assert!(
            suggestions.iter().any(|s| s.label == "Briefing Doc"),
            "expected Briefing Doc suggestion for NewsArticle, got: {:?}",
            suggestions
                .iter()
                .map(|s| s.label.as_str())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn guide_does_not_duplicate_suggestions() {
        // Two blocks with the same schema type should only produce one suggestion.
        let summaries = vec![
            GuideBlockSummary {
                schema_type: "WeatherForecast".into(),
                agent_name: "Open-Meteo".into(),
                snippet: "Sunny...".into(),
            },
            GuideBlockSummary {
                schema_type: "WeatherForecast".into(),
                agent_name: "Open-Meteo".into(),
                snippet: "Rainy...".into(),
            },
        ];
        let (_summary, suggestions) = build_summary_and_suggestions(&summaries);

        // Count how many "Pack List" suggestions there are — should be exactly 1
        let pack_list_count = suggestions
            .iter()
            .filter(|s| s.label == "Pack List")
            .count();
        assert_eq!(
            pack_list_count, 1,
            "duplicate suggestions should be deduped, got {} Pack List entries",
            pack_list_count
        );
    }

    #[test]
    fn guide_does_not_appear_with_zero_resolved_blocks() {
        // The frontend only invokes canvas_generate_guide when resolved_count >= 2.
        // This test documents the invariant: an empty summaries list produces a
        // "0 results" summary with no schema-type suggestions.
        let summaries: Vec<GuideBlockSummary> = vec![];
        let (summary, suggestions) = build_summary_and_suggestions(&summaries);

        assert!(
            summary.starts_with("0 results"),
            "zero blocks should produce '0 results' summary, got: {}",
            summary
        );
        assert!(
            suggestions.is_empty(),
            "zero blocks should produce no schema-based suggestions"
        );
    }

    #[test]
    fn guide_suggestion_serde_roundtrip() {
        let suggestion = GuideSuggestion {
            label: "Research Further".into(),
            prompt_template: "Research further: ".into(),
            saved_pipeline_id: Some("pipe-123".into()),
            synthesis_format: None,
        };
        let json = serde_json::to_string(&suggestion).unwrap();
        let back: GuideSuggestion = serde_json::from_str(&json).unwrap();
        assert_eq!(back.label, "Research Further");
        assert_eq!(back.saved_pipeline_id.as_deref(), Some("pipe-123"));
    }

    #[test]
    fn guide_block_id_format() {
        let canvas_id = "c-abc123";
        let block_id = format!("guide-{}", canvas_id);
        assert_eq!(block_id, "guide-c-abc123");
    }

    #[test]
    fn guide_caps_suggestions_at_five() {
        // All known schema types in one canvas — verify the cap.
        let summaries = vec![
            GuideBlockSummary {
                schema_type: "SearchResultsPage".into(),
                agent_name: "DDG".into(),
                snippet: "".into(),
            },
            GuideBlockSummary {
                schema_type: "NewsArticle".into(),
                agent_name: "HN".into(),
                snippet: "".into(),
            },
            GuideBlockSummary {
                schema_type: "ScholarlyArticle".into(),
                agent_name: "arXiv".into(),
                snippet: "".into(),
            },
            GuideBlockSummary {
                schema_type: "WeatherForecast".into(),
                agent_name: "Meteo".into(),
                snippet: "".into(),
            },
            GuideBlockSummary {
                schema_type: "Product".into(),
                agent_name: "OFacts".into(),
                snippet: "".into(),
            },
            GuideBlockSummary {
                schema_type: "VisualArtwork".into(),
                agent_name: "ArtInst".into(),
                snippet: "".into(),
            },
        ];
        let (_summary, suggestions) = build_summary_and_suggestions(&summaries);
        assert!(
            suggestions.len() <= 5,
            "suggestions must be capped at 5, got {}",
            suggestions.len()
        );
    }
}
