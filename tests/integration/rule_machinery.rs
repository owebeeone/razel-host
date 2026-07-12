//! A1: rule() machinery — a target instantiated by a .bzl-defined rule (carved out of the former monolithic `tests/integration.rs`).

use crate::common::*;
// ──────────────── A1: rule() machinery — a target instantiated by a .bzl-defined rule ────────────────

#[test]
fn package_target_from_rule_records_origin() {
    // The full chain: a .bzl defines a rule; the BUILD load()s + calls it; PACKAGE records the target with
    // its rule ORIGIN (the link the analysis phase follows to run the impl).
    let fs = Arc::new(MutFs::new());
    fs.set(
        "/w/app/rules.bzl",
        b"def _impl(ctx):\n    pass\n\
          my_rule = rule(implementation = _impl, attrs = {\"deps\": attr.label_list(), \"value\": attr.int()})\n",
        1,
    );
    fs.set(
        "/w/app/BUILD.bazel",
        b"load(\":rules.bzl\", \"my_rule\")\nmy_rule(name = \"lib\", value = 7, deps = [\":other\"])\n",
        1,
    );
    let engine = build_loading_engine(fs, HostPath::new("/w"));
    let p = pkg(&engine.request(&pkey("app")).unwrap());
    assert_eq!(p.targets.len(), 1);
    let t = p.get("lib").unwrap();
    assert_eq!(t.kind, "my_rule");
    assert_eq!(
        t.origin,
        Some(RuleOrigin { bzl: "app/rules.bzl".to_string(), name: "my_rule".to_string() }),
        "the target records where its rule is defined (the analysis link)"
    );
    assert_eq!(
        t.attrs,
        vec![
            ("deps".to_string(), BzlValue::List(vec![BzlValue::Str(":other".into())])),
            ("value".to_string(), BzlValue::Int(7)),
        ]
    );
}

#[test]
fn rule_schema_edit_rechecks_but_cuts_off_package() {
    // Loading/analysis separation: a target records its rule ORIGIN + attr VALUES, not the rule's schema. So
    // editing the rule's .bzl schema (here: adding an unused attr) re-checks the package but does NOT change
    // its value — PACKAGE re-evaluates and cuts off. (The schema change is analysis's concern, not loading's.)
    let fs = Arc::new(MutFs::new());
    fs.set(
        "/w/app/rules.bzl",
        b"def _impl(ctx):\n    pass\nmy_rule = rule(implementation = _impl, attrs = {\"value\": attr.int()})\n",
        1,
    );
    fs.set("/w/app/BUILD.bazel", b"load(\":rules.bzl\", \"my_rule\")\nmy_rule(name = \"lib\", value = 7)\n", 1);
    let engine = build_loading_engine(fs.clone(), HostPath::new("/w"));
    engine.request(&pkey("app")).unwrap(); // warm
    let before = engine.inspect(&pkey("app")).unwrap().version;

    // Add an unused attr to the rule schema — changes BZL_LOAD's value, but not the instantiated target.
    fs.set(
        "/w/app/rules.bzl",
        b"def _impl(ctx):\n    pass\nmy_rule = rule(implementation = _impl, attrs = {\"value\": attr.int(), \"extra\": attr.string()})\n",
        2,
    );
    engine.evaluate(&[pkey("app")], FailurePolicy::FailFast, Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(fskey("app/rules.bzl"))] });

    let after = engine.inspect(&pkey("app")).unwrap().version;
    assert!(after.last_evaluated > before.last_evaluated, "PACKAGE re-evaluates (its loaded .bzl changed)");
    assert_eq!(after.last_changed, before.last_changed, "but the package value is unchanged → early cutoff (schema is analysis's concern, not loading's)");
}
