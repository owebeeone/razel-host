//! PACKAGE: a BUILD file as an incremental node (target-as-data) (carved out of the former monolithic `tests/integration.rs`).

use crate::common::*;
// ──────────────── PACKAGE: a BUILD file as an incremental node (target-as-data) ────────────────

#[test]
fn package_instantiates_targets() {
    let fs = Arc::new(MutFs::new());
    fs.set(
        "/w/app/BUILD.bazel",
        b"target(kind = \"my_rule\", name = \"lib\", srcs = [\"a.txt\", \"b.txt\"])\n\
          target(kind = \"my_rule\", name = \"bin\", deps = [\":lib\"])\n",
        1,
    );
    let engine = build_loading_engine(fs, HostPath::new("/w"));
    let p = pkg(&engine.request(&pkey("app")).unwrap());
    assert_eq!(p.targets.len(), 2);
    // canonical: sorted by name → bin before lib.
    assert_eq!(p.targets[0].name, "bin");
    assert_eq!(p.targets[1].name, "lib");
    let lib = p.get("lib").unwrap();
    assert_eq!(lib.kind, "my_rule");
    assert_eq!(
        lib.attrs,
        vec![("srcs".to_string(), BzlValue::List(vec![BzlValue::Str("a.txt".into()), BzlValue::Str("b.txt".into())]))],
        "the target's attrs are recorded as data (the rule _impl is NOT run)"
    );
}

#[test]
fn missing_build_is_error() {
    let fs = Arc::new(MutFs::new());
    let engine = build_loading_engine(fs, HostPath::new("/w"));
    assert!(
        matches!(engine.request(&pkey("ghost")), Err(razel_core::Error::NotFound { .. })),
        "a package with no BUILD.bazel must be a typed NotFound, never an empty package"
    );
}

#[test]
fn duplicate_target_name_is_rejected() {
    let fs = Arc::new(MutFs::new());
    fs.set(
        "/w/p/BUILD.bazel",
        b"target(kind = \"r\", name = \"x\")\ntarget(kind = \"r\", name = \"x\")\n",
        1,
    );
    let engine = build_loading_engine(fs, HostPath::new("/w"));
    assert!(
        engine.request(&pkey("p")).is_err(),
        "two targets named 'x' must fail (a package is keyed by name), never silently coalesce"
    );
}

#[test]
fn editing_build_reevaluates_package() {
    let fs = Arc::new(MutFs::new());
    fs.set("/w/p/BUILD.bazel", b"target(kind = \"r\", name = \"a\")\n", 1);
    let engine = build_loading_engine(fs.clone(), HostPath::new("/w"));
    engine.request(&pkey("p")).unwrap(); // warm
    let before = engine.inspect(&pkey("p")).unwrap().version;

    fs.set("/w/p/BUILD.bazel", b"target(kind = \"r\", name = \"a\")\ntarget(kind = \"r\", name = \"b\")\n", 2);
    engine.evaluate(&[pkey("p")], FailurePolicy::FailFast, Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(fskey("p/BUILD.bazel"))] });

    let after = engine.inspect(&pkey("p")).unwrap().version;
    assert!(after.last_changed > before.last_changed, "a BUILD edit (new target) re-evaluates the package");
    assert_eq!(pkg(&engine.request(&pkey("p")).unwrap()).targets.len(), 2);
}

#[test]
fn touching_build_does_not_reevaluate_package() {
    let fs = Arc::new(MutFs::new());
    fs.set("/w/p/BUILD.bazel", b"target(kind = \"r\", name = \"a\")\n", 1);
    let engine = build_loading_engine(fs.clone(), HostPath::new("/w"));
    engine.request(&pkey("p")).unwrap(); // warm
    let before = engine.inspect(&pkey("p")).unwrap().version;

    fs.set("/w/p/BUILD.bazel", b"target(kind = \"r\", name = \"a\")\n", 999); // TOUCH: new mtime, same bytes
    engine.evaluate(&[pkey("p")], FailurePolicy::FailFast, Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(fskey("p/BUILD.bazel"))] });

    let after = engine.inspect(&pkey("p")).unwrap().version;
    assert_eq!(after.last_changed, before.last_changed, "a touch (same BUILD bytes) must NOT re-evaluate the package — FILE content-cutoff propagates");
    assert!(after.last_evaluated > before.last_evaluated, "PACKAGE is re-checked this round, just not recomputed");
}

#[test]
fn package_uses_loaded_constant() {
    // The BUILD load()s a constant from a sibling .bzl and uses it as an attr value. This proves PACKAGE
    // depends on BZL_LOAD (and is the property the `mutant_package_ignore_loads` mutant breaks).
    let fs = Arc::new(MutFs::new());
    fs.set("/w/p/defs.bzl", b"SRCS = [\"gen.txt\"]\n", 1);
    fs.set("/w/p/BUILD.bazel", b"load(\":defs.bzl\", \"SRCS\")\ntarget(kind = \"r\", name = \"a\", srcs = SRCS)\n", 1);
    let engine = build_loading_engine(fs, HostPath::new("/w"));
    let p = pkg(&engine.request(&pkey("p")).unwrap());
    assert_eq!(
        p.get("a").unwrap().attrs,
        vec![("srcs".to_string(), BzlValue::List(vec![BzlValue::Str("gen.txt".into())]))],
        "the loaded constant SRCS resolves into the target's attrs"
    );
}

#[test]
fn editing_loaded_bzl_propagates_to_package() {
    // Editing a .bzl the BUILD loads must re-evaluate the package (transitive through the load graph), but a
    // touch of that .bzl (same bytes) must be cut off.
    let fs = Arc::new(MutFs::new());
    fs.set("/w/p/defs.bzl", b"SRCS = [\"v1.txt\"]\n", 1);
    fs.set("/w/p/BUILD.bazel", b"load(\":defs.bzl\", \"SRCS\")\ntarget(kind = \"r\", name = \"a\", srcs = SRCS)\n", 1);
    let engine = build_loading_engine(fs.clone(), HostPath::new("/w"));
    engine.request(&pkey("p")).unwrap(); // warm: PACKAGE(p) now depends on BZL_LOAD(p/defs.bzl)
    let before = engine.inspect(&pkey("p")).unwrap().version;

    fs.set("/w/p/defs.bzl", b"SRCS = [\"v2.txt\"]\n", 2); // edit the LOADED .bzl, not the BUILD
    engine.evaluate(&[pkey("p")], FailurePolicy::FailFast, Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(fskey("p/defs.bzl"))] });

    let after = engine.inspect(&pkey("p")).unwrap().version;
    assert!(after.last_changed > before.last_changed, "editing a loaded .bzl re-evaluates the package (transitive)");
    assert_eq!(
        pkg(&engine.request(&pkey("p")).unwrap()).get("a").unwrap().attrs,
        vec![("srcs".to_string(), BzlValue::List(vec![BzlValue::Str("v2.txt".into())]))]
    );
}

#[test]
fn root_package_loads_root_build() {
    // A package at the workspace root (dir == "") reads BUILD.bazel at the root, not "/BUILD.bazel".
    let fs = Arc::new(MutFs::new());
    fs.set("/w/BUILD.bazel", b"target(kind = \"r\", name = \"root_t\")\n", 1);
    let engine = build_loading_engine(fs, HostPath::new("/w"));
    let p = pkg(&engine.request(&pkey("")).unwrap());
    assert_eq!(p.targets.len(), 1);
    assert_eq!(p.targets[0].name, "root_t");
}
