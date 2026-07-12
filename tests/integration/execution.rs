//! #5: execution — the demand chain (artifact-model lockdown §4 gates) (carved out of the former monolithic `tests/integration.rs`).

use crate::common::*;
// ──────────────── #5: execution — the demand chain (artifact-model lockdown §4 gates) ────────────────
// The old hand-bridge (clone the template out of the CT value, build an ActionKey by hand, request it) is
// DELETED: requesting TARGET_COMPLETION (or an output ARTIFACT) IS the build — CT → ARTIFACT → ACTION →
// spawn → digests, all engine edges. No test below constructs an ActionKey or clones a template.

const ACTION_RULES: &[u8] = b"NumberInfo = provider(\"NumberInfo\", fields = [\"x\"])\n\
def _impl(ctx):\n\
\x20   ctx.actions.run(mnemonic = \"Compile\", executable = \"cc\", arguments = [\"-o\", \"out\"], outputs = [\"app/out.txt\"], inputs = [\"app/in.txt\"])\n\
\x20   return [NumberInfo(x = 1)]\n\
my_rule = rule(implementation = _impl, attrs = {})\n";

// Two actions in ONE target: Pack consumes Gen's declared output (the derived-input materialization exam).
const PIPELINE_RULES: &[u8] = b"NumberInfo = provider(\"NumberInfo\", fields = [\"x\"])\n\
def _impl(ctx):\n\
\x20   ctx.actions.run(mnemonic = \"Gen\", executable = \"gen\", outputs = [\"app/mid.txt\"], inputs = [\"app/in.txt\"])\n\
\x20   ctx.actions.run(mnemonic = \"Pack\", executable = \"pack\", outputs = [\"app/out.txt\"], inputs = [\"app/mid.txt\"])\n\
\x20   return [NumberInfo(x = 1)]\n\
my_rule = rule(implementation = _impl, attrs = {})\n";

fn exec_fixture(rules: &[u8], strategy: Arc<dyn SpawnStrategy>) -> (Arc<MutFs>, razel_engine::Engine) {
    let fs = Arc::new(MutFs::new());
    fs.set("/w/app/rules.bzl", rules, 1);
    fs.set("/w/app/BUILD.bazel", b"load(\":rules.bzl\", \"my_rule\")\nmy_rule(name = \"t\")\n", 1);
    fs.set("/w/app/in.txt", b"input-v1", 1);
    let engine = build_execution_engine(fs.clone(), HostPath::new("/w"), strategy);
    (fs, engine)
}

#[test]
fn action_runs_as_graph_consequence_of_target_output() {
    // THE HEADLINE (lockdown §4; RazelV3PitfallReview #5's stated ◐→✅ promotion criterion): request
    // TARGET_COMPLETION{//app:t} and assert the action RAN — this test constructs NO ActionKey and clones
    // NO template. Under `mutant_completion_skips_artifact_demand` the sentinel is published without
    // demanding the outputs, nothing builds, and the inspect assertions go red.
    let (_fs, engine) = exec_fixture(ACTION_RULES, Arc::new(FakeStrategy));

    // The ONE top-level demand — the dep requests ARE the build.
    engine.request(&completion("app", "t")).unwrap();

    // Graph consequence, asserted READ-ONLY (inspect demands nothing): the ACTION and its output ARTIFACT
    // were built because completion demanded them.
    assert!(engine.inspect(&action_node("app", "t", 0)).is_some(),
        "the ACTION node must exist as a consequence of TARGET_COMPLETION (no hand bridge)");
    assert!(engine.inspect(&derived_artifact("app", "t", 0, "app/out.txt")).is_some(),
        "the output ARTIFACT node must exist as a consequence of TARGET_COMPLETION");

    // It really went THROUGH the strategy over the MATERIALIZED source input: the digest is the
    // FakeStrategy's deterministic content for (declared action, in.txt bytes) — assembled from literals
    // here, never from the CT value.
    let out = artifact_val(&engine.request(&derived_artifact("app", "t", 0, "app/out.txt")).unwrap());
    let req = spawn_req("Compile", &["cc", "-o", "out"], vec![in_art("app/in.txt", b"input-v1")], &["app/out.txt"]);
    assert_eq!(out.digest, Digest::of(&fake_output_content(&req, "app/out.txt")),
        "the ARTIFACT digest IS the strategy's output over the graph-materialized input");
    let av = action_value(&engine.request(&action_node("app", "t", 0)).unwrap());
    assert_eq!(av.exit_code, 0, "the action ran via the strategy and exited zero");
}

#[test]
fn output_digest_recorded_matches_artifact_projection() {
    // Lockdown §4: ArtifactValue.digest == ActionValue.output(path).digest == Digest::of(strategy bytes) —
    // the three-way pin extending the old `action_executes_and_produces_expected_output` property across
    // the projection.
    let (_fs, engine) = exec_fixture(ACTION_RULES, Arc::new(FakeStrategy));
    engine.request(&completion("app", "t")).unwrap();
    let art = artifact_val(&engine.request(&derived_artifact("app", "t", 0, "app/out.txt")).unwrap());
    let act = action_value(&engine.request(&action_node("app", "t", 0)).unwrap());
    let req = spawn_req("Compile", &["cc", "-o", "out"], vec![in_art("app/in.txt", b"input-v1")], &["app/out.txt"]);
    let strategy_digest = Digest::of(&fake_output_content(&req, "app/out.txt"));
    assert_eq!(act.output("app/out.txt").unwrap().digest, strategy_digest, "ActionValue records the strategy bytes' digest");
    assert_eq!(art.digest, strategy_digest, "the ARTIFACT projection serves the SAME digest");
}

#[test]
fn derived_input_materializes_from_producer() {
    // Lockdown §4: two actions in one target, Pack consumes Gen's declared output. Requesting Pack's
    // output runs Gen FIRST (a pure graph consequence), and Pack's spawn request carries Gen's PRODUCED
    // bytes (digest match through ARTIFACT → BlobStore). Under
    // `mutant_artifact_projection_fabricates_digest` the mid ARTIFACT digest is fabricated, the BlobStore
    // has no such bytes, and the chain fails closed — this test reds.
    let (_fs, engine) = exec_fixture(PIPELINE_RULES, Arc::new(FakeStrategy));

    // Demand ONLY the downstream output's ARTIFACT (the "or the output ARTIFACT" form of the headline).
    let out = artifact_val(&engine.request(&derived_artifact("app", "t", 1, "app/out.txt")).unwrap());

    // Gen ran first, as a graph consequence of Pack's input edge.
    assert!(engine.inspect(&action_node("app", "t", 0)).is_some(), "the producer action ran as a graph consequence");

    // Pack's request carried Gen's produced bytes: recompute the expected chain from literals.
    let gen_req = spawn_req("Gen", &["gen"], vec![in_art("app/in.txt", b"input-v1")], &["app/mid.txt"]);
    let mid_bytes = fake_output_content(&gen_req, "app/mid.txt");
    let pack_req = spawn_req("Pack", &["pack"], vec![InputArtifact { path: "app/mid.txt".into(), content: mid_bytes }], &["app/out.txt"]);
    assert_eq!(out.digest, Digest::of(&fake_output_content(&pack_req, "app/out.txt")),
        "the consumer's spawn carried the producer's PRODUCED bytes (materialized via ARTIFACT → BlobStore)");
}

#[test]
fn input_edit_reruns_downstream_action() {
    // Lockdown §4 (end-to-end at last — the pitfall-#5 "pending the artifact materializer" half): edit a
    // consumed source file → FILE → ARTIFACT → ACTION re-runs → the downstream consumer re-runs; touch
    // with identical bytes → cutoff (bounded recomputes, NO spawn). Under
    // `mutant_action_skips_input_artifact_edges` the input edges are dropped after the first build and the
    // edit yields STALE bytes — the digest assertions red.
    let spawns = Arc::new(AtomicUsize::new(0));
    let (fs, engine) = exec_fixture(PIPELINE_RULES, Arc::new(CountingStrategy(spawns.clone())));
    let tc = completion("app", "t");

    engine.request(&tc).unwrap();
    assert_eq!(spawns.load(Ordering::SeqCst), 2, "cold build: Gen and Pack each spawned once");
    let out_v1 = artifact_val(&engine.request(&derived_artifact("app", "t", 1, "app/out.txt")).unwrap());

    // EDIT the consumed source file's bytes → the whole downstream chain re-runs.
    fs.set("/w/app/in.txt", b"input-v2", 2);
    engine.evaluate(&[tc.clone()], FailurePolicy::FailFast, Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(fskey("app/in.txt"))] });
    assert_eq!(spawns.load(Ordering::SeqCst), 4, "the edit re-ran BOTH the action and its downstream consumer");
    let out_v2 = artifact_val(&engine.request(&derived_artifact("app", "t", 1, "app/out.txt")).unwrap());
    assert_ne!(out_v1.digest, out_v2.digest, "the downstream output digest must change with the input edit");
    // ...and it changed to exactly the recomputed chain over the NEW bytes (end-to-end, from literals).
    let gen_req = spawn_req("Gen", &["gen"], vec![in_art("app/in.txt", b"input-v2")], &["app/mid.txt"]);
    let mid_bytes = fake_output_content(&gen_req, "app/mid.txt");
    let pack_req = spawn_req("Pack", &["pack"], vec![InputArtifact { path: "app/mid.txt".into(), content: mid_bytes }], &["app/out.txt"]);
    assert_eq!(out_v2.digest, Digest::of(&fake_output_content(&pack_req, "app/out.txt")));

    // TOUCH (same bytes, new mtime) → FILE early-cuts → NOTHING above re-runs, no spawn.
    let act_before = engine.inspect(&action_node("app", "t", 0)).unwrap().version;
    fs.set("/w/app/in.txt", b"input-v2", 999);
    let rep = engine.evaluate(&[tc.clone()], FailurePolicy::FailFast, Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(fskey("app/in.txt"))] });
    assert_eq!(spawns.load(Ordering::SeqCst), 4, "a touch with unchanged content must NOT re-spawn anything");
    assert_eq!(rep.recomputes, 2, "recomputes bounded: FILE_STATE re-stats + FILE re-reads, then cutoff");
    let act_after = engine.inspect(&action_node("app", "t", 0)).unwrap().version;
    assert_eq!(act_after.last_changed, act_before.last_changed,
        "the ACTION node was dirty-checked clean, never rebuilt (its last_changed holds)");
}

#[test]
fn action_node_dirties_in_place_no_key_churn() {
    // Lockdown §4 (decision B): an impl edit that changes the template recomputes the SAME
    // ACTION{owner,0} node key — dirty-in-place, no key churn. A provider-only CT edit with unchanged
    // template + inputs re-spawns in v1 (correct-but-slower, no action cache yet) but downstream ARTIFACT
    // consumers cut off via value_eq.
    let impl_v1: &[u8] = b"NumberInfo = provider(\"NumberInfo\", fields = [\"x\"])\n\
def _impl(ctx):\n\
\x20   ctx.actions.run(mnemonic = \"Compile\", executable = \"cc\", arguments = [\"-o\", \"out\"], outputs = [\"app/out.txt\"], inputs = [\"app/in.txt\"])\n\
\x20   return [NumberInfo(x = 1)]\n\
my_rule = rule(implementation = _impl, attrs = {})\n";
    // v2: the TEMPLATE changes (argv gains -O2) — same provider.
    let impl_v2: &[u8] = b"NumberInfo = provider(\"NumberInfo\", fields = [\"x\"])\n\
def _impl(ctx):\n\
\x20   ctx.actions.run(mnemonic = \"Compile\", executable = \"cc\", arguments = [\"-O2\", \"-o\", \"out\"], outputs = [\"app/out.txt\"], inputs = [\"app/in.txt\"])\n\
\x20   return [NumberInfo(x = 1)]\n\
my_rule = rule(implementation = _impl, attrs = {})\n";
    // v3: PROVIDER-ONLY change (x = 2) — template + inputs identical to v2.
    let impl_v3: &[u8] = b"NumberInfo = provider(\"NumberInfo\", fields = [\"x\"])\n\
def _impl(ctx):\n\
\x20   ctx.actions.run(mnemonic = \"Compile\", executable = \"cc\", arguments = [\"-O2\", \"-o\", \"out\"], outputs = [\"app/out.txt\"], inputs = [\"app/in.txt\"])\n\
\x20   return [NumberInfo(x = 2)]\n\
my_rule = rule(implementation = _impl, attrs = {})\n";

    let spawns = Arc::new(AtomicUsize::new(0));
    let (fs, engine) = exec_fixture(impl_v1, Arc::new(CountingStrategy(spawns.clone())));
    let tc = completion("app", "t");
    let act = action_node("app", "t", 0);
    let art = derived_artifact("app", "t", 0, "app/out.txt");

    engine.request(&tc).unwrap();
    assert_eq!(spawns.load(Ordering::SeqCst), 1);
    let (act_v1, art_v1) = (engine.inspect(&act).unwrap().version, engine.inspect(&art).unwrap().version);

    // (a) the template edit: the SAME positional node key re-runs and its value changes — dirty-in-place.
    fs.set("/w/app/rules.bzl", impl_v2, 2);
    engine.evaluate(&[tc.clone()], FailurePolicy::FailFast, Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(fskey("app/rules.bzl"))] });
    let (act_v2, art_v2) = (engine.inspect(&act).unwrap().version, engine.inspect(&art).unwrap().version);
    assert!(act_v2.last_changed > act_v1.last_changed,
        "the SAME ACTION{{owner,0}} key must recompute with a changed value (dirty-in-place, no key churn)");
    assert!(art_v2.last_changed > art_v1.last_changed, "the new argv produced new output content");
    assert_eq!(spawns.load(Ordering::SeqCst), 2);

    // (b) the provider-only edit: the CT value changes → the ACTION re-runs and RE-SPAWNS in v1 (no action
    // cache yet — same fingerprint, correct-but-slower)... but its outputs are byte-identical, so the
    // ACTION value is unchanged and every downstream ARTIFACT consumer cuts off via value_eq.
    fs.set("/w/app/rules.bzl", impl_v3, 3);
    engine.evaluate(&[tc.clone()], FailurePolicy::FailFast, Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(fskey("app/rules.bzl"))] });
    let (act_v3, art_v3) = (engine.inspect(&act).unwrap().version, engine.inspect(&art).unwrap().version);
    assert_eq!(spawns.load(Ordering::SeqCst), 3, "v1 re-spawns on a same-template CT change (no AC yet)");
    assert!(act_v3.last_evaluated > act_v2.last_evaluated, "the ACTION was re-evaluated this round");
    assert_eq!(act_v3.last_changed, act_v2.last_changed, "byte-identical outputs → the ACTION value is unchanged");
    assert_eq!(art_v3.last_changed, art_v2.last_changed, "the downstream ARTIFACT cut off via value_eq");
}

#[test]
fn duplicate_output_conflict_fail_closed() {
    // Lockdown §4 (R8): two templates declaring the same exec path → a typed Conflict at demand time,
    // never last-writer-wins. `mutant_dup_output_last_writer_wins` silently keeps the later producer and
    // the build "succeeds" — this test reds.
    let dup_rules: &[u8] = b"NumberInfo = provider(\"NumberInfo\", fields = [\"x\"])\n\
def _impl(ctx):\n\
\x20   ctx.actions.run(mnemonic = \"A\", executable = \"a\", outputs = [\"app/dup.txt\"])\n\
\x20   ctx.actions.run(mnemonic = \"B\", executable = \"b\", outputs = [\"app/dup.txt\"])\n\
\x20   return [NumberInfo(x = 1)]\n\
my_rule = rule(implementation = _impl, attrs = {})\n";
    let (_fs, engine) = exec_fixture(dup_rules, Arc::new(FakeStrategy));
    assert!(
        matches!(engine.request(&completion("app", "t")), Err(razel_core::Error::Conflict { .. })),
        "a duplicate declared output across a CT's actions must be a typed Conflict, never last-writer-wins"
    );
}

#[test]
fn unresolvable_input_fails_closed() {
    // Lockdown §4: an input path the resolver cannot map (absolute) and a Derived ref with an
    // out-of-range index are typed errors — NEVER empty content or a skipped edge. Under
    // `mutant_input_resolver_absorbs_unknown` the absolute input is absorbed into a fabricated empty input
    // and the build "succeeds" — the first assertion reds.
    let abs_rules: &[u8] = b"NumberInfo = provider(\"NumberInfo\", fields = [\"x\"])\n\
def _impl(ctx):\n\
\x20   ctx.actions.run(mnemonic = \"Abs\", executable = \"a\", outputs = [\"app/o.txt\"], inputs = [\"/etc/passwd\"])\n\
\x20   return [NumberInfo(x = 1)]\n\
my_rule = rule(implementation = _impl, attrs = {})\n";
    let (_fs, engine) = exec_fixture(abs_rules, Arc::new(FakeStrategy));
    assert!(
        matches!(engine.request(&completion("app", "t")), Err(razel_core::Error::Unsupported { .. })),
        "an unresolvable input form must fail the build closed (typed), never run on a fabricated empty input"
    );
    // A positional key whose index is out of range (the CT declares ONE action) is a typed Invalid.
    assert!(
        matches!(engine.request(&action_node("app", "t", 9)), Err(razel_core::Error::Invalid { .. })),
        "an out-of-range action index must be a typed error"
    );
}

#[test]
fn action_with_dropped_output_is_fail_closed() {
    // The strategy that drops the declared output → the failure surfaces through the WHOLE chain
    // (completion → artifact → action), never a silent empty success. Same rules, same wiring — only the
    // host's strategy choice changes.
    let (_fs, engine) = exec_fixture(ACTION_RULES, Arc::new(DroppingStrategy { drop: "app/out.txt".into() }));
    assert!(
        engine.request(&completion("app", "t")).is_err(),
        "a strategy that drops the declared output must fail the build closed through the demand chain"
    );
}

#[test]
fn configured_target_dep_cycle_is_detected() {
    // a → b → a (via deps) must surface as a typed Cycle, inherited from the engine.
    let fs = Arc::new(MutFs::new());
    fs.set("/w/pkg/rules.bzl", SUM_RULES, 1);
    fs.set(
        "/w/pkg/BUILD.bazel",
        b"load(\":rules.bzl\", \"my_rule\")\n\
          my_rule(name = \"a\", value = 1, deps = [\":b\"])\n\
          my_rule(name = \"b\", value = 1, deps = [\":a\"])\n",
        1,
    );
    let engine = build_analysis_engine(fs, HostPath::new("/w"));
    assert!(
        matches!(engine.request(&ctkey("pkg", "a")), Err(razel_core::Error::Cycle { .. })),
        "a configured-target dependency cycle must be a typed Cycle error"
    );
}
