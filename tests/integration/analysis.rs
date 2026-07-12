//! A4: de-nativized rule impls run + providers propagate granularly (carved out of the former monolithic `tests/integration.rs`).

use crate::common::*;
// ──────────────── A4: the analysis exam — de-nativized rule impls run + providers propagate granularly ────

#[test]
fn configured_target_runs_rule_and_sums_providers() {
    let fs = Arc::new(MutFs::new());
    fs.set("/w/pkg/rules.bzl", SUM_RULES, 1);
    fs.set(
        "/w/pkg/BUILD.bazel",
        b"load(\":rules.bzl\", \"my_rule\")\n\
          my_rule(name = \"leaf\", value = 5)\n\
          my_rule(name = \"mid\", value = 10, deps = [\":leaf\"])\n\
          my_rule(name = \"root\", value = 100, deps = [\":mid\"])\n",
        1,
    );
    let engine = build_analysis_engine(fs, HostPath::new("/w"));
    assert_eq!(ct_total(&engine.request(&ctkey("pkg", "leaf")).unwrap()), 5, "leaf: 5, no deps");
    assert_eq!(ct_total(&engine.request(&ctkey("pkg", "mid")).unwrap()), 15, "mid: 10 + leaf(5)");
    assert_eq!(
        ct_total(&engine.request(&ctkey("pkg", "root")).unwrap()),
        115,
        "root: 100 + mid(10 + 5) = 115 — a REAL .bzl rule impl ran and providers propagated along edges"
    );
}

#[test]
fn analysis_propagates_granularly() {
    // Edit one target's value → its providers + its rdep's change; its DEP and an UNRELATED target cut off.
    let fs = Arc::new(MutFs::new());
    fs.set("/w/pkg/rules.bzl", SUM_RULES, 1);
    let build_v1 = b"load(\":rules.bzl\", \"my_rule\")\n\
        my_rule(name = \"leaf\", value = 5)\n\
        my_rule(name = \"mid\", value = 10, deps = [\":leaf\"])\n\
        my_rule(name = \"root\", value = 100, deps = [\":mid\"])\n\
        my_rule(name = \"other\", value = 1)\n";
    fs.set("/w/pkg/BUILD.bazel", build_v1, 1);
    let engine = build_analysis_engine(fs.clone(), HostPath::new("/w"));
    let roots = [ctkey("pkg", "leaf"), ctkey("pkg", "mid"), ctkey("pkg", "root"), ctkey("pkg", "other")];
    for r in &roots {
        engine.request(r).unwrap();
    }
    let v = |n: &str| engine.inspect(&ctkey("pkg", n)).unwrap().version;
    let (bl, bm, br, bo) = (v("leaf"), v("mid"), v("root"), v("other"));

    // Edit ONLY mid's value (10 → 20).
    fs.set(
        "/w/pkg/BUILD.bazel",
        b"load(\":rules.bzl\", \"my_rule\")\n\
          my_rule(name = \"leaf\", value = 5)\n\
          my_rule(name = \"mid\", value = 20, deps = [\":leaf\"])\n\
          my_rule(name = \"root\", value = 100, deps = [\":mid\"])\n\
          my_rule(name = \"other\", value = 1)\n",
        2,
    );
    engine.evaluate(&roots, FailurePolicy::FailFast, Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(fskey("pkg/BUILD.bazel"))] });

    let (al, am, ar, ao) = (v("leaf"), v("mid"), v("root"), v("other"));
    assert!(am.last_changed > bm.last_changed, "mid's value changed → its providers change");
    assert!(ar.last_changed > br.last_changed, "root depends on mid → it re-analyzes (providers propagate up)");
    assert_eq!(al.last_changed, bl.last_changed, "leaf is mid's DEP, not its rdep → unchanged (early cutoff)");
    assert_eq!(ao.last_changed, bo.last_changed, "other is unrelated → unchanged (early cutoff)");
    assert_eq!(ct_total(&engine.request(&ctkey("pkg", "root")).unwrap()), 125, "root now 100 + (20 + 5)");
}

#[test]
fn editing_rule_impl_reevaluates_configured_target() {
    // Editing the rule's IMPL (not its schema) must re-analyze: BZL_LOAD's value (the RuleDef schema) is
    // unchanged, so CONFIGURED_TARGET's dependency on the rule .bzl's CONTENT (FILE) is what catches it.
    let fs = Arc::new(MutFs::new());
    let impl_v1 = b"NumberInfo = provider(\"NumberInfo\", fields = [\"total\"])\n\
        def _impl(ctx):\n\
        \x20   return [NumberInfo(total = ctx.attr.value)]\n\
        my_rule = rule(implementation = _impl, attrs = {\"value\": attr.int()})\n";
    fs.set("/w/pkg/rules.bzl", impl_v1, 1);
    fs.set("/w/pkg/BUILD.bazel", b"load(\":rules.bzl\", \"my_rule\")\nmy_rule(name = \"t\", value = 5)\n", 1);
    let engine = build_analysis_engine(fs.clone(), HostPath::new("/w"));
    assert_eq!(ct_total(&engine.request(&ctkey("pkg", "t")).unwrap()), 5);
    let before = engine.inspect(&ctkey("pkg", "t")).unwrap().version;

    // Same schema (value attr), different impl: total = value + 1000.
    let impl_v2 = b"NumberInfo = provider(\"NumberInfo\", fields = [\"total\"])\n\
        def _impl(ctx):\n\
        \x20   return [NumberInfo(total = ctx.attr.value + 1000)]\n\
        my_rule = rule(implementation = _impl, attrs = {\"value\": attr.int()})\n";
    fs.set("/w/pkg/rules.bzl", impl_v2, 2);
    engine.evaluate(&[ctkey("pkg", "t")], FailurePolicy::FailFast, Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(fskey("pkg/rules.bzl"))] });

    let after = engine.inspect(&ctkey("pkg", "t")).unwrap().version;
    assert!(after.last_changed > before.last_changed, "an impl edit re-analyzes (FILE content dep, not just BZL_LOAD schema)");
    assert_eq!(ct_total(&engine.request(&ctkey("pkg", "t")).unwrap()), 1005, "the new impl ran");
}

#[test]
fn analyze_target_without_rule_is_fail_closed() {
    // A generic target() placeholder has no rule origin → there is no impl to run → Unsupported (never empty).
    let fs = Arc::new(MutFs::new());
    fs.set("/w/p/BUILD.bazel", b"target(kind = \"x\", name = \"t\")\n", 1);
    let engine = build_analysis_engine(fs, HostPath::new("/w"));
    assert!(
        matches!(engine.request(&ctkey("p", "t")), Err(razel_core::Error::Unsupported { .. })),
        "analyzing a target with no rule definition must fail closed (Unsupported)"
    );
}

#[test]
fn rule_impl_reaching_for_deferred_ctx_capability_fails_closed() {
    // `ctx.actions`/`ctx.toolchains` NOW exist (T17-C wired ctx.actions). A STILL-deferred capability
    // (`ctx.fragments` — configuration fragments) must FAIL CLOSED (Starlark raises on a missing struct
    // field), never silently get None — the fail-closed ctx surface holds for what's genuinely unbuilt.
    let fs = Arc::new(MutFs::new());
    fs.set(
        "/w/pkg/rules.bzl",
        b"NumberInfo = provider(\"NumberInfo\", fields = [\"total\"])\n\
          def _impl(ctx):\n\
          \x20   x = ctx.fragments\n\
          \x20   return [NumberInfo(total = 0)]\n\
          my_rule = rule(implementation = _impl, attrs = {})\n",
        1,
    );
    fs.set("/w/pkg/BUILD.bazel", b"load(\":rules.bzl\", \"my_rule\")\nmy_rule(name = \"t\")\n", 1);
    let engine = build_analysis_engine(fs, HostPath::new("/w"));
    assert!(
        engine.request(&ctkey("pkg", "t")).is_err(),
        "reaching for an unprovided ctx capability must fail closed (loud), not silently yield None"
    );
}

#[test]
fn rule_bzl_load_closure_threads_into_analysis() {
    // T20 R-analyze: the rule .bzl's own `load()`s ARE now threaded into `evaluate_rule` (previously deferred —
    // real rulesets like rules_rust `load()` ~20 sibling modules). A rule .bzl that `load()`s a constant
    // ANALYZES correctly: the loaded `K = 7` threads through the impl, so `NumberInfo(total = K)` = 7. (A
    // SELF-CONTAINED rule .bzl still analyzes byte-identically — load_targets is empty.)
    let fs = Arc::new(MutFs::new());
    fs.set("/w/pkg/helper.bzl", b"K = 7\n", 1);
    fs.set(
        "/w/pkg/rules.bzl",
        b"load(\":helper.bzl\", \"K\")\n\
          NumberInfo = provider(\"NumberInfo\", fields = [\"total\"])\n\
          def _impl(ctx):\n\
          \x20   return [NumberInfo(total = K)]\n\
          my_rule = rule(implementation = _impl, attrs = {})\n",
        1,
    );
    fs.set("/w/pkg/BUILD.bazel", b"load(\":rules.bzl\", \"my_rule\")\nmy_rule(name = \"t\")\n", 1);
    let engine = build_analysis_engine(fs, HostPath::new("/w"));
    assert_eq!(
        ct_total(&engine.request(&ctkey("pkg", "t")).expect("a rule .bzl with its own load() now analyzes")),
        7,
        "the loaded constant K=7 threads through the rule impl (load-closure threading landed)"
    );
}
