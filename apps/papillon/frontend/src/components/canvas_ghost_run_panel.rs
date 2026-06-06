use std::collections::{BTreeMap, HashMap};

use leptos::prelude::*;
use papillon_shared::{AgentCandidate, BlockState, CanvasBlock, IntentPlan, OrchestratorStatus};
use wasm_bindgen_futures::spawn_local;

use crate::components::canvas_chat_thread::CanvasChatThread;
use crate::components::canvas_workflow_pipeline::derive_block_trace;
use crate::state::canvas::{filter_messages_by_canvas, CanvasSide, CanvasState};
use crate::state::orchestrator::OrchestratorState;
use crate::workflow_labels::{humanize_schema_term, render_label_for_schema, workflow_port_label};

#[derive(Clone, PartialEq)]
struct ApprovalGroup {
    id: String,
    action: String,
    disclosure_props: Vec<String>,
    return_types: Vec<String>,
    candidates: Vec<GroupCandidate>,
    items: Vec<ApprovalGroupItem>,
    ttl_hours: u32,
}

#[derive(Clone, PartialEq)]
struct GroupCandidate {
    name: String,
    did: String,
    disclosure_props: Vec<String>,
    return_types: Vec<String>,
}

#[derive(Clone, PartialEq)]
struct ApprovalGroupItem {
    block_id: String,
    approval_request_id: String,
    prompt: String,
    candidate_names: Vec<String>,
}

#[component]
pub fn CanvasGhostRunPanel(#[prop(optional)] compact: bool) -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let orchestrator = expect_context::<OrchestratorState>();

    let active_blocks = move || canvas_state.current_canvas_blocks().get();

    let active_messages = move || {
        let active_id = canvas_state.current_canvas_id.get();
        filter_messages_by_canvas(&canvas_state.canvas_messages.get(), active_id.as_deref())
    };

    let approvals = move || {
        active_blocks()
            .into_iter()
            .filter_map(|block| match block.state.clone() {
                BlockState::AwaitingApproval { plan } => Some((block, plan)),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    let approval_groups = move || grouped_approvals(active_blocks());

    let trace_blocks = move || {
        active_blocks()
            .into_iter()
            .filter(|block| !matches!(block.state, BlockState::Guide { .. }))
            .collect::<Vec<_>>()
    };

    let summary = move || {
        let blocks = active_blocks();
        let total = blocks.len();
        let resolving = blocks
            .iter()
            .filter(|b| {
                matches!(
                    b.state,
                    BlockState::Resolving { .. } | BlockState::Ghost { .. }
                )
            })
            .count();
        let approvals = blocks
            .iter()
            .filter(|b| matches!(b.state, BlockState::AwaitingApproval { .. }))
            .count();
        let resolved = blocks
            .iter()
            .filter(|b| matches!(b.state, BlockState::Resolved | BlockState::Outcome { .. }))
            .count();
        (total, resolving, approvals, resolved)
    };

    let orchestrator_badge = move || match orchestrator.status.get() {
        OrchestratorStatus::Ready => ("status-ready".to_string(), "ready".to_string()),
        OrchestratorStatus::Disconnected => {
            ("status-disconnected".to_string(), "offline".to_string())
        }
        OrchestratorStatus::Unconfigured => (
            "status-unconfigured".to_string(),
            "setup needed".to_string(),
        ),
        OrchestratorStatus::Downloading { progress_pct } => {
            if progress_pct >= 100 {
                ("status-disconnected".to_string(), "loading".to_string())
            } else {
                ("status-downloading".to_string(), format!("{progress_pct}%"))
            }
        }
    };

    view! {
        <div class="ghost-run-panel" class:compact=compact>
            <Show when=move || !compact>
                <div class="ghost-run-hero">
                    <div>
                        <div class="ghost-run-kicker">"Orchestrator"</div>
                        <h3 class="ghost-run-title">
                            "Papillon makes the workflow visible before anything is rendered."
                        </h3>
                        <p class="ghost-run-copy">
                            "Agent matches, requested disclosures, workflow steps, and activity stay here so the rendered surface only shows approved values."
                        </p>
                    </div>
                    <span class=move || format!("ghost-run-status {}", orchestrator_badge().0)>
                        {move || orchestrator_badge().1.clone()}
                    </span>
                </div>

                <div class="ghost-run-metrics">
                    <GhostMetric label="Steps" value=move || summary().0 />
                    <GhostMetric label="Working" value=move || summary().1 />
                    <GhostMetric label="Approvals" value=move || summary().2 />
                    <GhostMetric label="Rendered" value=move || summary().3 />
                </div>
            </Show>

            <Show when=move || !approvals().is_empty()>
                <section class="ghost-run-section">
                    <div class="ghost-run-section-header">
                        <span class="ghost-run-section-label">"Intent groups"</span>
                        <span class="ghost-run-section-count">{move || approval_groups().len()}</span>
                    </div>
                    <div class="ghost-run-approvals">
                        <For
                            each=approval_groups
                            key=|group| group.id.clone()
                            children=move |group| view! { <GroupedApprovalCard group=group /> }
                        />
                    </div>
                </section>
            </Show>

            <section class="ghost-run-section">
                <div class="ghost-run-section-header">
                    <span class="ghost-run-section-label">"Workflow activity"</span>
                    <span class="ghost-run-section-count">{move || trace_blocks().len()}</span>
                </div>
                <Show
                    when=move || !trace_blocks().is_empty()
                    fallback=move || view! {
                        <div class="ghost-run-empty">
                            "Ask Papillon to browse, resolve, or build something and the workflow activity will appear here."
                        </div>
                    }
                >
                    <div class="ghost-run-trace">
                        <For
                            each=trace_blocks
                            key=|block| block.id.clone()
                            children=move |block| {
                                let (trace_class, badge, detail) = derive_block_trace(&block);
                                view! {
                                    <article class=format!("ghost-trace-card {trace_class}")>
                                        <div class="ghost-trace-header">
                                            <div class="ghost-trace-prompt">
                                                {block.prompt_text.clone().unwrap_or_else(|| "Workflow step".into())}
                                            </div>
                                            <span class="ghost-trace-badge">{badge}</span>
                                        </div>
                                        {detail.map(|text| view! {
                                            <div class="ghost-trace-detail">{text}</div>
                                        })}
                                    </article>
                                }
                            }
                        />
                    </div>
                </Show>
            </section>

            <section class="ghost-run-section ghost-run-activity">
                <div class="ghost-run-section-header">
                    <span class="ghost-run-section-label">"Orchestrator activity"</span>
                    <span class="ghost-run-section-count">{move || active_messages().len()}</span>
                </div>
                <CanvasChatThread compact=compact />
            </section>
        </div>
    }
}

#[component]
fn GhostMetric<F>(label: &'static str, value: F) -> impl IntoView
where
    F: Fn() -> usize + Send + Sync + 'static,
{
    view! {
        <div class="ghost-metric">
            <div class="ghost-metric-value">{value}</div>
            <div class="ghost-metric-label">{label}</div>
        </div>
    }
}

#[component]
fn GroupedApprovalCard(group: ApprovalGroup) -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let selected_agents = RwSignal::new(
        group
            .candidates
            .iter()
            .map(|candidate| candidate.name.clone())
            .collect::<Vec<_>>(),
    );
    let has_disclosures = !group.disclosure_props.is_empty();
    let filled_values: RwSignal<HashMap<String, String>> = RwSignal::new(HashMap::new());
    let attributes_loading = RwSignal::new(has_disclosures && crate::bridge::tauri_available());

    if has_disclosures && crate::bridge::tauri_available() {
        let values = filled_values;
        let loading = attributes_loading;
        spawn_local(async move {
            if let Ok(attrs) = crate::bridge::invoke::<_, HashMap<String, String>>(
                "get_principal_attributes",
                &serde_json::json!({}),
            )
            .await
            {
                values.set(attrs);
            }
            loading.set(false);
        });
    }

    let action_label = humanize_schema_term(&group.action);
    let return_label = readable_returns(&group.return_types);
    let candidate_count = group.candidates.len();
    let item_count = group.items.len();
    let ttl_hours = group.ttl_hours;
    let group_for_render = group.clone();
    let group_for_deny = group.clone();
    let canvas_for_render = canvas_state;
    let canvas_for_deny = canvas_state;
    let candidate_views = group
        .candidates
        .clone()
        .into_iter()
        .map(|candidate| {
            let candidate_name = candidate.name.clone();
            let detail_text = candidate_detail(&candidate);
            let candidate_name_for_checked = candidate_name.clone();
            let candidate_name_for_change = candidate_name.clone();
            view! {
                <label class="ghost-agent-choice">
                    <input
                        type="checkbox"
                        prop:checked=move || {
                            selected_agents.get().contains(&candidate_name_for_checked)
                        }
                        on:change=move |event| {
                            use wasm_bindgen::JsCast;
                            let checked = event
                                .target()
                                .and_then(|target| target.dyn_into::<web_sys::HtmlInputElement>().ok())
                                .map(|input| input.checked())
                                .unwrap_or(false);
                            let name = candidate_name_for_change.clone();
                            selected_agents.update(|agents| {
                                if checked {
                                    if !agents.contains(&name) {
                                        agents.push(name.clone());
                                    }
                                } else {
                                    agents.retain(|agent| agent != &name);
                                }
                            });
                        }
                    />
                    <span class="ghost-agent-choice-body">
                        <span class="ghost-agent-choice-name">{candidate_name}</span>
                        <span class="ghost-agent-choice-detail">{detail_text}</span>
                    </span>
                </label>
            }
        })
        .collect::<Vec<_>>();
    let candidate_list_view = view! {
        <div class="ghost-agent-choice-list">{candidate_views}</div>
    }
    .into_any();

    let disclosure_view = if has_disclosures {
        let disclosure_field_views = group
            .disclosure_props
            .clone()
            .into_iter()
            .map(|prop| {
                let field_key = prop.clone();
                let field_key_for_input = prop.clone();
                let label = workflow_port_label(&prop);
                view! {
                    <label class="ghost-disclosure-field">
                        <span>{label.clone()}</span>
                        <input
                            type="text"
                            placeholder=label
                            prop:disabled=move || attributes_loading.get()
                            prop:value=move || {
                                filled_values
                                    .get()
                                    .get(&field_key)
                                    .cloned()
                                    .unwrap_or_default()
                            }
                            on:input=move |event| {
                                use wasm_bindgen::JsCast;
                                let value = event
                                    .target()
                                    .and_then(|target| target.dyn_into::<web_sys::HtmlInputElement>().ok())
                                    .map(|input| input.value())
                                    .unwrap_or_default();
                                let key = field_key_for_input.clone();
                                filled_values.update(|values| {
                                    values.insert(key, value);
                                });
                            }
                        />
                    </label>
                }
            })
            .collect::<Vec<_>>();
        view! {
            <div class="ghost-disclosure-stack">
                <Show when=move || attributes_loading.get()>
                    <div class="ghost-disclosure-loading">"Loading saved fields"</div>
                </Show>
                <div class="ghost-disclosure-grid">{disclosure_field_views}</div>
            </div>
        }
        .into_any()
    } else {
        view! {
            <div class="ghost-zero-disclosure">"No personal fields requested."</div>
        }
        .into_any()
    };

    let prompts_view = if item_count > 0 {
        let prompt_views = group
            .items
            .clone()
            .into_iter()
            .map(|item| view! { <div class="ghost-approval-prompt">{item.prompt}</div> })
            .collect::<Vec<_>>();
        view! {
            <div class="ghost-approval-prompts">{prompt_views}</div>
        }
        .into_any()
    } else {
        view! { <></> }.into_any()
    };

    view! {
        <article class="ghost-approval-card ghost-approval-group">
            <div class="ghost-approval-group-header">
                <div>
                    <div class="ghost-approval-kicker">"Dry-run group"</div>
                    <div class="ghost-approval-title">{action_label}</div>
                </div>
                <div class="ghost-approval-meta">
                    {format!(
                        "{} · {}",
                        pluralize(item_count, "intent"),
                        pluralize(candidate_count, "agent")
                    )}
                </div>
            </div>

            <div class="ghost-approval-summary">
                <div class="ghost-approval-summary-item">
                    <span>"Will render"</span>
                    <strong>{return_label}</strong>
                </div>
                <div class="ghost-approval-summary-item">
                    <span>"Permission"</span>
                    <strong>{if has_disclosures { "Disclosure required" } else { "Zero disclosure" }}</strong>
                </div>
                <div class="ghost-approval-summary-item">
                    <span>"Valid for"</span>
                    <strong>{format!("{ttl_hours}h")}</strong>
                </div>
            </div>

            <div class="ghost-approval-subsection">
                <div class="ghost-approval-subhead">"Agents to run"</div>
                {candidate_list_view}
            </div>

            <div class="ghost-approval-subsection">
                <div class="ghost-approval-subhead">"Will need from you"</div>
                {disclosure_view}
            </div>

            {prompts_view}

            <div class="ghost-approval-actions">
                <button
                    class="ghost-approval-btn ghost-approval-deny"
                    type="button"
                    on:click=move |_| {
                        for item in &group_for_deny.items {
                            canvas_for_deny.reject_block(
                                item.block_id.clone(),
                                item.approval_request_id.clone(),
                            );
                        }
                    }
                >
                    "Deny group"
                </button>
                <button
                    class="ghost-approval-btn ghost-approval-render"
                    type="button"
                    prop:disabled=move || {
                        selected_agents.get().is_empty() || attributes_loading.get()
                    }
                    on:click=move |_| {
                        let selected = selected_agents.get();
                        let values = filtered_disclosure_values(
                            &filled_values.get(),
                            &group_for_render.disclosure_props,
                        );
                        for item in &group_for_render.items {
                            let item_selected = selected
                                .iter()
                                .filter(|name| item.candidate_names.contains(name))
                                .cloned()
                                .collect::<Vec<_>>();
                            if item_selected.is_empty() {
                                continue;
                            }
                            canvas_for_render.approve_block(
                                item.block_id.clone(),
                                item.approval_request_id.clone(),
                                values.clone(),
                                item_selected,
                            );
                        }
                        canvas_for_render.canvas_side.set(CanvasSide::Front);
                    }
                >
                    {move || {
                        if attributes_loading.get() {
                            "Loading disclosures"
                        } else {
                            "Render selected"
                        }
                    }}
                </button>
            </div>
        </article>
    }
}

fn grouped_approvals(blocks: Vec<CanvasBlock>) -> Vec<ApprovalGroup> {
    let mut groups = BTreeMap::<String, ApprovalGroup>::new();

    for block in blocks {
        let BlockState::AwaitingApproval { plan } = block.state.clone() else {
            continue;
        };
        let key = approval_group_key(&plan);
        let candidates = plan_candidates(&plan);
        let group = groups.entry(key.clone()).or_insert_with(|| ApprovalGroup {
            id: key,
            action: plan.action.clone(),
            disclosure_props: normalized_unique(plan.requires_disclosure.clone()),
            return_types: Vec::new(),
            candidates: Vec::new(),
            items: Vec::new(),
            ttl_hours: plan.ttl_hours,
        });

        merge_unique(&mut group.return_types, plan.returns.clone());
        group.ttl_hours = group.ttl_hours.min(plan.ttl_hours);

        for candidate in &candidates {
            if !group
                .candidates
                .iter()
                .any(|existing| existing.name == candidate.name)
            {
                group.candidates.push(GroupCandidate {
                    name: candidate.name.clone(),
                    did: candidate.did.clone(),
                    disclosure_props: normalized_unique(candidate.requires_disclosure.clone()),
                    return_types: normalized_unique(candidate.returns.clone()),
                });
            }
        }

        group.items.push(ApprovalGroupItem {
            block_id: block.id,
            approval_request_id: plan.approval_request_id,
            prompt: block
                .prompt_text
                .unwrap_or_else(|| "Pending approval".to_string()),
            candidate_names: candidates
                .into_iter()
                .map(|candidate| candidate.name)
                .collect(),
        });
    }

    groups.into_values().collect()
}

fn approval_group_key(plan: &IntentPlan) -> String {
    let disclosures = normalized_unique(plan.requires_disclosure.clone()).join(",");
    format!("{}|{}", plan.action, disclosures)
}

fn plan_candidates(plan: &IntentPlan) -> Vec<AgentCandidate> {
    if plan.candidates.is_empty() {
        vec![AgentCandidate {
            name: plan.selected_agent_name.clone(),
            did: plan.selected_agent_did.clone().unwrap_or_default(),
            requires_disclosure: plan.requires_disclosure.clone(),
            returns: plan.returns.clone(),
        }]
    } else {
        plan.candidates.clone()
    }
}

fn normalized_unique(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

fn merge_unique(target: &mut Vec<String>, values: Vec<String>) {
    for value in values {
        if !target.contains(&value) {
            target.push(value);
        }
    }
}

fn filtered_disclosure_values(
    values: &HashMap<String, String>,
    allowed_props: &[String],
) -> HashMap<String, String> {
    allowed_props
        .iter()
        .filter_map(|prop| values.get(prop).map(|value| (prop.clone(), value.clone())))
        .collect()
}

fn readable_returns(types: &[String]) -> String {
    if types.is_empty() {
        return "Structured result".into();
    }
    let mut labels = types
        .iter()
        .map(|schema| render_label_for_schema(schema))
        .collect::<Vec<_>>();
    labels.sort();
    labels.dedup();
    if labels.len() > 2 {
        format!("{} +{}", labels[..2].join(", "), labels.len() - 2)
    } else {
        labels.join(", ")
    }
}

fn candidate_detail(candidate: &GroupCandidate) -> String {
    let returns = readable_returns(&candidate.return_types);
    if candidate.disclosure_props.is_empty() {
        format!("{returns} · zero disclosure")
    } else {
        format!(
            "{} · needs {}",
            returns,
            candidate
                .disclosure_props
                .iter()
                .map(|prop| workflow_port_label(prop))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

fn pluralize(count: usize, singular: &str) -> String {
    if count == 1 {
        format!("1 {singular}")
    } else {
        format!("{count} {singular}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    fn candidate(name: &str, did: &str, disclosures: &[&str], returns: &[&str]) -> AgentCandidate {
        AgentCandidate {
            name: name.to_string(),
            did: did.to_string(),
            requires_disclosure: strings(disclosures),
            returns: strings(returns),
        }
    }

    fn plan(
        action: &str,
        disclosures: &[&str],
        returns: &[&str],
        candidates: Vec<AgentCandidate>,
        ttl_hours: u32,
        approval_request_id: &str,
    ) -> IntentPlan {
        let selected_agent_name = candidates
            .first()
            .map(|candidate| candidate.name.clone())
            .unwrap_or_else(|| "Legacy agent".to_string());
        let selected_agent_did = candidates.first().map(|candidate| candidate.did.clone());

        IntentPlan {
            action: action.to_string(),
            selected_agent_name,
            selected_agent_did,
            requires_disclosure: strings(disclosures),
            returns: strings(returns),
            approval_request_id: approval_request_id.to_string(),
            ttl_hours,
            candidates,
        }
    }

    fn block(id: &str, prompt: &str, plan: IntentPlan) -> CanvasBlock {
        CanvasBlock {
            id: id.to_string(),
            prompt_id: format!("prompt-{id}"),
            prompt_text: Some(prompt.to_string()),
            state: BlockState::AwaitingApproval { plan },
            schema_type: None,
            content: None,
            linked_block_ids: Vec::new(),
            agent_did: None,
            created_at: "2026-06-05T00:00:00Z".to_string(),
            updated_at: "2026-06-05T00:00:00Z".to_string(),
            mandate_expires_at: None,
            preference_guided: false,
            auto_expand: false,
            retention_warning: None,
        }
    }

    #[test]
    fn grouped_approvals_merges_same_action_and_disclosures() {
        let ddg = candidate(
            "DuckDuckGo",
            "did:pap:ddg",
            &["schema:query"],
            &["SearchResultsPage"],
        );
        let google = candidate(
            "Google",
            "did:pap:google",
            &["schema:query"],
            &["SearchResultsPage"],
        );

        let groups = grouped_approvals(vec![
            block(
                "block-1",
                "Search the web",
                plan(
                    "schema:SearchAction",
                    &["schema:query"],
                    &["SearchResultsPage"],
                    vec![ddg],
                    8,
                    "approval-1",
                ),
            ),
            block(
                "block-2",
                "Search again",
                plan(
                    "schema:SearchAction",
                    &["schema:query"],
                    &["SearchResultsPage"],
                    vec![google],
                    4,
                    "approval-2",
                ),
            ),
        ]);

        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].action, "schema:SearchAction");
        assert_eq!(groups[0].ttl_hours, 4);
        assert_eq!(groups[0].items.len(), 2);
        assert_eq!(groups[0].candidates.len(), 2);
        assert_eq!(groups[0].disclosure_props, strings(&["schema:query"]));
    }

    #[test]
    fn grouped_approvals_separates_different_disclosures() {
        let groups = grouped_approvals(vec![
            block(
                "block-1",
                "Search without disclosure",
                plan(
                    "schema:SearchAction",
                    &[],
                    &["SearchResultsPage"],
                    vec![candidate(
                        "Zero",
                        "did:pap:zero",
                        &[],
                        &["SearchResultsPage"],
                    )],
                    8,
                    "approval-1",
                ),
            ),
            block(
                "block-2",
                "Search with query",
                plan(
                    "schema:SearchAction",
                    &["schema:query"],
                    &["SearchResultsPage"],
                    vec![candidate(
                        "Query",
                        "did:pap:query",
                        &["schema:query"],
                        &["SearchResultsPage"],
                    )],
                    8,
                    "approval-2",
                ),
            ),
        ]);

        assert_eq!(groups.len(), 2);
        assert!(groups.iter().any(|group| group.disclosure_props.is_empty()));
        assert!(groups
            .iter()
            .any(|group| group.disclosure_props == strings(&["schema:query"])));
    }

    #[test]
    fn plan_candidates_falls_back_to_selected_agent_fields() {
        let plan = IntentPlan {
            action: "schema:SearchAction".to_string(),
            selected_agent_name: "Legacy search".to_string(),
            selected_agent_did: Some("did:pap:legacy".to_string()),
            requires_disclosure: strings(&["schema:query"]),
            returns: strings(&["SearchResultsPage"]),
            approval_request_id: "approval-legacy".to_string(),
            ttl_hours: 8,
            candidates: Vec::new(),
        };

        let candidates = plan_candidates(&plan);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].name, "Legacy search");
        assert_eq!(candidates[0].did, "did:pap:legacy");
        assert_eq!(
            candidates[0].requires_disclosure,
            strings(&["schema:query"])
        );
    }

    #[test]
    fn filtered_disclosure_values_keeps_only_declared_fields() {
        let values = HashMap::from([
            ("schema:query".to_string(), "papillon".to_string()),
            ("schema:email".to_string(), "hidden@example.com".to_string()),
        ]);

        let filtered = filtered_disclosure_values(&values, &strings(&["schema:query"]));

        assert_eq!(filtered.len(), 1);
        assert_eq!(
            filtered.get("schema:query").map(String::as_str),
            Some("papillon")
        );
        assert!(!filtered.contains_key("schema:email"));
    }
}
