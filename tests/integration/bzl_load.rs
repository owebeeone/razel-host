//! BZL_LOAD: a Starlark .bzl as an incremental node (carved out of the former monolithic `tests/integration.rs`).

use crate::common::*;
// ──────────────── BZL_LOAD: a Starlark .bzl as an incremental node (the spike) ────────────────

#[test]
fn bzl_evaluates_as_a_node() {
    let fs = Arc::new(MutFs::new());
    fs.set("/w/rules.bzl", b"x = 1 + 2\ny = \"hi\"\nz = [True, 4]\n", 1);
    let engine = build_loading_engine(fs, HostPath::new("/w"));
    let v = engine.request(&bkey("rules.bzl")).unwrap();
    assert_eq!(bget(&v, "x"), Some(BzlValue::Int(3)), "starlark arithmetic folds: 1 + 2 = 3");
    assert_eq!(bget(&v, "y"), Some(BzlValue::Str("hi".into())));
    assert_eq!(bget(&v, "z"), Some(BzlValue::List(vec![BzlValue::Bool(true), BzlValue::Int(4)])));
}

#[test]
fn editing_bzl_reevaluates() {
    let fs = Arc::new(MutFs::new());
    fs.set("/w/rules.bzl", b"x = 1\n", 1);
    let engine = build_loading_engine(fs.clone(), HostPath::new("/w"));
    engine.request(&bkey("rules.bzl")).unwrap(); // warm
    let before = engine.inspect(&bkey("rules.bzl")).unwrap().version;

    fs.set("/w/rules.bzl", b"x = 99\n", 2); // genuine source change
    engine.evaluate(&[bkey("rules.bzl")], FailurePolicy::FailFast, Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(fskey("rules.bzl"))] });

    let after = engine.inspect(&bkey("rules.bzl")).unwrap().version;
    assert!(after.last_changed > before.last_changed, "a .bzl source change re-evaluates BZL_LOAD");
    assert_eq!(bget(&engine.request(&bkey("rules.bzl")).unwrap(), "x"), Some(BzlValue::Int(99)));
}

#[test]
fn touching_bzl_does_not_reevaluate() {
    let fs = Arc::new(MutFs::new());
    fs.set("/w/rules.bzl", b"x = 1\n", 1);
    let engine = build_loading_engine(fs.clone(), HostPath::new("/w"));
    engine.request(&bkey("rules.bzl")).unwrap(); // warm
    let before = engine.inspect(&bkey("rules.bzl")).unwrap().version;

    fs.set("/w/rules.bzl", b"x = 1\n", 999); // TOUCH: new mtime, identical source bytes
    engine.evaluate(&[bkey("rules.bzl")], FailurePolicy::FailFast, Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(fskey("rules.bzl"))] });

    let after = engine.inspect(&bkey("rules.bzl")).unwrap().version;
    assert_eq!(after.last_changed, before.last_changed, "a touch (same bytes) must NOT re-parse the .bzl — the FILE content-cutoff propagates");
    assert!(after.last_evaluated > before.last_evaluated, "BZL_LOAD is re-checked this round, just not recomputed");
}

#[test]
fn load_resolves_across_bzls() {
    let fs = Arc::new(MutFs::new());
    fs.set("/w/pkg/b.bzl", b"y = 40\n", 1);
    fs.set("/w/pkg/a.bzl", b"load(\":b.bzl\", \"y\")\nx = y + 2\n", 1);
    let engine = build_loading_engine(fs, HostPath::new("/w"));
    let v = engine.request(&bkey("pkg/a.bzl")).unwrap();
    assert_eq!(bget(&v, "x"), Some(BzlValue::Int(42)), "a.bzl loads y=40 from b.bzl: x = y + 2 = 42");
}

#[test]
fn editing_loaded_bzl_propagates_to_loader() {
    let fs = Arc::new(MutFs::new());
    fs.set("/w/pkg/b.bzl", b"y = 40\n", 1);
    fs.set("/w/pkg/a.bzl", b"load(\":b.bzl\", \"y\")\nx = y + 2\n", 1);
    let engine = build_loading_engine(fs.clone(), HostPath::new("/w"));
    engine.request(&bkey("pkg/a.bzl")).unwrap(); // warm: BZL_LOAD(a) now depends on BZL_LOAD(b)
    let before = engine.inspect(&bkey("pkg/a.bzl")).unwrap().version;

    fs.set("/w/pkg/b.bzl", b"y = 100\n", 2); // edit the LOADED .bzl, not the loader
    engine.evaluate(&[bkey("pkg/a.bzl")], FailurePolicy::FailFast, Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(fskey("pkg/b.bzl"))] });

    let after = engine.inspect(&bkey("pkg/a.bzl")).unwrap().version;
    assert!(after.last_changed > before.last_changed, "editing a loaded .bzl re-evaluates its loader (transitive through the load graph)");
    assert_eq!(bget(&engine.request(&bkey("pkg/a.bzl")).unwrap(), "x"), Some(BzlValue::Int(102)));
}

#[test]
fn load_cycle_is_detected() {
    let fs = Arc::new(MutFs::new());
    fs.set("/w/pkg/a.bzl", b"load(\":b.bzl\", \"y\")\nx = 1\n", 1);
    fs.set("/w/pkg/b.bzl", b"load(\":a.bzl\", \"x\")\ny = 1\n", 1);
    let engine = build_loading_engine(fs, HostPath::new("/w"));
    assert!(
        matches!(engine.request(&bkey("pkg/a.bzl")), Err(razel_core::Error::Cycle { .. })),
        "an a→b→a load() cycle must surface as a typed Cycle error"
    );
}

#[test]
fn self_load_is_detected() {
    let fs = Arc::new(MutFs::new());
    fs.set("/w/a.bzl", b"load(\":a.bzl\", \"x\")\ny = 1\n", 1);
    let engine = build_loading_engine(fs, HostPath::new("/w"));
    assert!(
        matches!(engine.request(&bkey("a.bzl")), Err(razel_core::Error::Cycle { .. })),
        "a self-load (a.bzl loads \":a.bzl\") must be detected as a cycle"
    );
}

#[test]
fn unsupported_load_form_is_rejected() {
    // The specimen moved with the rust-rules wave: `//pkg:file.bzl` is now a SUPPORTED absolute form
    // (razel-load's C8 first slice — see tests/pkg_loads.rs), so the still-unsupported REPO-MAPPED form
    // (`@repo//...` — no repo mapping in v1) carries this pin now. The property is unchanged: an
    // unsupported load form fails loudly (Unsupported), never silently mis-resolves to a wrong path.
    let fs = Arc::new(MutFs::new());
    fs.set("/w/pkg/a.bzl", b"load(\"@repo//other:f.bzl\", \"z\")\nx = 1\n", 1);
    let engine = build_loading_engine(fs, HostPath::new("/w"));
    assert!(
        matches!(engine.request(&bkey("pkg/a.bzl")), Err(razel_core::Error::Unsupported { .. })),
        "a repo-mapped load form must fail loudly (Unsupported), never silently mis-resolve to a wrong path"
    );
}

#[test]
fn nonexistent_loaded_bzl_errors() {
    let fs = Arc::new(MutFs::new());
    fs.set("/w/pkg/a.bzl", b"load(\":ghost.bzl\", \"z\")\nx = 1\n", 1);
    let engine = build_loading_engine(fs, HostPath::new("/w"));
    assert!(
        matches!(engine.request(&bkey("pkg/a.bzl")), Err(razel_core::Error::NotFound { .. })),
        "loading a nonexistent .bzl must surface a typed NotFound, not a silent empty"
    );
}

#[test]
fn loaded_symbol_not_reexported_across_three_bzls() {
    // d.bzl defines z; a.bzl loads z; c.bzl tries to load z FROM a — must fail (a does not re-export z).
    let fs = Arc::new(MutFs::new());
    fs.set("/w/p/d.bzl", b"z = 5\n", 1);
    fs.set("/w/p/a.bzl", b"load(\":d.bzl\", \"z\")\nq = z\n", 1);
    fs.set("/w/p/c.bzl", b"load(\":a.bzl\", \"z\")\nbad = z\n", 1); // z is NOT exported by a
    let engine = build_loading_engine(fs, HostPath::new("/w"));
    assert!(
        engine.request(&bkey("p/c.bzl")).is_err(),
        "c.bzl must NOT be able to load z transitively from a.bzl — load()ed symbols are not re-exported"
    );
}

#[test]
fn diamond_load_resolves_shared_dep() {
    let fs = Arc::new(MutFs::new());
    fs.set("/w/p/d.bzl", b"z = 100\n", 1);
    fs.set("/w/p/b.bzl", b"load(\":d.bzl\", \"z\")\nx = z + 1\n", 1);
    fs.set("/w/p/c.bzl", b"load(\":d.bzl\", \"z\")\ny = z + 2\n", 1);
    fs.set("/w/p/a.bzl", b"load(\":b.bzl\", \"x\")\nload(\":c.bzl\", \"y\")\nresult = x + y\n", 1);
    let engine = build_loading_engine(fs, HostPath::new("/w"));
    let v = engine.request(&bkey("p/a.bzl")).unwrap();
    assert_eq!(bget(&v, "result"), Some(BzlValue::Int(203)), "diamond (a→b,c→d): shared d resolves once, no false cycle (x=101, y=102)");
}
