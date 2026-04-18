//! P99 / tail-latency benchmarks.
//!
//! Criterion only reports p50 (median) by default. This harness collects
//! 2000 raw samples for the three most latency-sensitive operations, computes
//! p50 / p99 / p999, and writes the results to `target/p99_results.json`.
//!
//! Run:
//!   cargo bench -p pap-bench --bench p99
//!
//! The output file is consumed by `benches/check_regression.sh`.

#![allow(clippy::unwrap_used)]

use chrono::{Duration, Utc};
use std::time::Instant;

use pap_core::mandate::{Mandate, MandateChain};
use pap_core::receipt::TransactionReceipt;
use pap_core::scope::{DisclosureSet, Scope, ScopeAction};
use pap_core::session::{CapabilityToken, Session};
use pap_test_utils::{did_from_key, make_keypair};

const WARMUP: usize = 200;
const SAMPLES: usize = 2000;

/// Collect `n` raw nanosecond timings by calling `f` repeatedly.
fn collect_ns<F: FnMut()>(mut f: F, warmup: usize, n: usize) -> Vec<u64> {
    // Warmup — not recorded.
    for _ in 0..warmup {
        f();
    }
    let mut timings = Vec::with_capacity(n);
    for _ in 0..n {
        let t0 = Instant::now();
        f();
        timings.push(t0.elapsed().as_nanos() as u64);
    }
    timings
}

/// Compute p50, p99, p999 from a sorted slice.
fn percentile(sorted: &[u64], pct: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64 * pct / 100.0).ceil() as usize).min(sorted.len() - 1);
    sorted[idx]
}

fn bench_session_open_p99() -> (u64, u64, u64) {
    let issuer_key = make_keypair();
    let issuer_did = did_from_key(&issuer_key);
    let target_did = did_from_key(&make_keypair());

    let mut timings = collect_ns(
        || {
            let ttl = Utc::now() + Duration::hours(1);
            let mut token = CapabilityToken::mint(
                target_did.clone(),
                "schema:SearchAction".into(),
                issuer_did.clone(),
                ttl,
            );
            token
                .sign(&issuer_key)
                .expect("Ed25519 is always supported");

            let mut session =
                Session::initiate(&token, &target_did, &issuer_key.verifying_key()).unwrap();

            let init_sess = pap_did::SessionKeypair::generate();
            let recv_sess = pap_did::SessionKeypair::generate();
            session.open(init_sess.did(), recv_sess.did()).unwrap();
            session.execute().unwrap();
            session.close().unwrap();
        },
        WARMUP,
        SAMPLES,
    );
    timings.sort_unstable();
    (
        percentile(&timings, 50.0),
        percentile(&timings, 99.0),
        percentile(&timings, 99.9),
    )
}

fn bench_mandate_chain_p99() -> (u64, u64, u64) {
    let principal_key = make_keypair();
    let orchestrator_key = make_keypair();
    let leaf_key = make_keypair();

    let principal_did = did_from_key(&principal_key);
    let orchestrator_did = did_from_key(&orchestrator_key);
    let leaf_did = did_from_key(&leaf_key);

    let ttl = Utc::now() + Duration::hours(1);
    let root_scope = Scope::new(vec![ScopeAction::new("schema:SearchAction")]);
    let sub_scope = root_scope.clone();
    let leaf_scope = root_scope.clone();
    let disclosure = DisclosureSet::empty();

    let mut root = Mandate::issue_root(
        principal_did.clone(),
        orchestrator_did.clone(),
        root_scope,
        disclosure.clone(),
        ttl,
    );
    root.sign(&principal_key).unwrap();

    let mut sub = root
        .delegate(leaf_did.clone(), sub_scope, disclosure.clone(), ttl)
        .unwrap();
    sub.sign(&orchestrator_key).unwrap();

    let mut leaf = sub
        .delegate(leaf_did.clone(), leaf_scope, disclosure, ttl)
        .unwrap();
    leaf.sign(&leaf_key).unwrap();

    let mut chain = MandateChain::new(root);
    chain.push(sub);
    chain.push(leaf);
    let verify_keys = vec![
        principal_key.verifying_key(),
        orchestrator_key.verifying_key(),
        leaf_key.verifying_key(),
    ];

    let mut timings = collect_ns(
        || {
            chain.verify_chain(&verify_keys).unwrap();
        },
        WARMUP,
        SAMPLES,
    );
    timings.sort_unstable();
    (
        percentile(&timings, 50.0),
        percentile(&timings, 99.0),
        percentile(&timings, 99.9),
    )
}

fn bench_receipt_cosign_p99() -> (u64, u64, u64) {
    let issuer_key = make_keypair();
    let issuer_did = did_from_key(&issuer_key);
    let target_did = did_from_key(&make_keypair());
    let init_key = make_keypair();
    let recv_key = make_keypair();

    let ttl = Utc::now() + Duration::hours(1);
    let mut token = CapabilityToken::mint(
        target_did.clone(),
        "schema:SearchAction".into(),
        issuer_did,
        ttl,
    );
    token
        .sign(&issuer_key)
        .expect("Ed25519 is always supported");

    let mut session = Session::initiate(&token, &target_did, &issuer_key.verifying_key()).unwrap();
    session
        .open("did:key:zinit".into(), "did:key:zrecv".into())
        .unwrap();
    session.execute().unwrap();

    let mut timings = collect_ns(
        || {
            let mut receipt = TransactionReceipt::from_session(
                &session,
                vec!["schema:Person.name".into()],
                vec!["operator:search_executed".into()],
                "schema:SearchAction executed".into(),
                "schema:SearchResult returned".into(),
            )
            .unwrap();
            receipt.co_sign(&init_key);
            receipt.co_sign(&recv_key);
        },
        WARMUP,
        SAMPLES,
    );
    timings.sort_unstable();
    (
        percentile(&timings, 50.0),
        percentile(&timings, 99.0),
        percentile(&timings, 99.9),
    )
}

fn main() {
    eprintln!("Running p99 benchmarks ({SAMPLES} samples, {WARMUP} warmup)…");

    let (s_p50, s_p99, s_p999) = bench_session_open_p99();
    let (m_p50, m_p99, m_p999) = bench_mandate_chain_p99();
    let (r_p50, r_p99, r_p999) = bench_receipt_cosign_p99();

    eprintln!("session_open_full_lifecycle   p50={s_p50}ns  p99={s_p99}ns  p999={s_p999}ns");
    eprintln!("mandate_chain_verify_depth3   p50={m_p50}ns  p99={m_p99}ns  p999={m_p999}ns");
    eprintln!("receipt_create_cosign         p50={r_p50}ns  p99={r_p99}ns  p999={r_p999}ns");

    let json = format!(
        r#"{{
  "_comment": "p99/p999 tail-latency measurements ({SAMPLES} samples, release build). Generated by `cargo bench -p pap-bench --bench p99`.",
  "session_open_full_lifecycle": {{ "p50_ns": {s_p50}, "p99_ns": {s_p99}, "p999_ns": {s_p999} }},
  "mandate_chain_verify_depth3": {{ "p50_ns": {m_p50}, "p99_ns": {m_p99}, "p999_ns": {m_p999} }},
  "receipt_create_cosign":       {{ "p50_ns": {r_p50}, "p99_ns": {r_p99}, "p999_ns": {r_p999} }}
}}
"#
    );

    // Write to workspace root target/ so check_regression.sh (run from workspace root) can find it.
    // env!("CARGO_MANIFEST_DIR") is the benches/ package dir; its parent is the workspace root.
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("bench crate must be inside workspace");
    let out = workspace_root.join("target").join("p99_results.json");
    std::fs::create_dir_all(out.parent().unwrap()).ok();
    std::fs::write(&out, &json).expect("failed to write p99_results.json");

    eprintln!("Wrote {}", out.display());
}
