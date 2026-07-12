//! T20 TF-unblocker A: the BUILD-file `glob()` builtin, end-to-end over the REAL source graph.
//!
//! `glob()` runs in the two-pass Globber shape (razel-package): a COLLECT pass records each call's patterns,
//! the PACKAGE node resolves them against `DIRECTORY_LISTING` nodes (restart-driven recursive descent, pruned
//! by `dir_prefix_viable`), and a RESOLVED pass returns the sorted package-relative file list. These drive a
//! real on-disk tree through `DarwinSystem` (directories are only observable through a real filesystem — the
//! in-memory `MutFs` used elsewhere has no dir kind), so `src/**/*.rs` recursion, the `*.rs` extension gate,
//! `exclude`, and the `allow_empty` default-disallow are all exercised against actual `list_dir`/`stat`.
//!
//! Red-first mutant: `mutant_glob_ignores_exclude` (razel-package) drops the exclude filter →
//! `glob_recursive_matches_extension_and_honors_exclude` goes RED (the excluded generated file leaks in).

use razel_bzl_api::BzlValue;
use razel_core::NodeKey;
use razel_engine_api::DemandEngine;
use razel_host::build_loading_engine;
use razel_ids::RootRelativePath;
use razel_os_api::{HostPath, System};
use razel_os_darwin::DarwinSystem;
use razel_package::{Package, PackageKey};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_root() -> String {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    format!("/tmp/razel-glob-{nanos}-{n}")
}

/// Write a file under `root/rel` THROUGH the `System` seam (`write_atomic` creates parent directories), so the
/// on-disk tree has REAL directories the recursive glob walk descends via `DIRECTORY_LISTING` — and the test
/// stays inside the razel-os seam (the raw-OS wall bans `std::fs` even in tests).
fn write(sys: &dyn System, root: &str, rel: &str, content: &[u8]) {
    sys.write_atomic(&HostPath::new(format!("{root}/{rel}")), content).expect("write fixture file");
}

fn package(engine: &dyn DemandEngine, pkg: &str) -> Result<Package, razel_core::Error> {
    engine
        .request(&NodeKey::from_key(&PackageKey(RootRelativePath(pkg.into()))))
        .map(|v| v.as_any().downcast_ref::<Package>().expect("a Package value").clone())
}

/// Extract a target's `srcs` attribute as a Vec<String> (the globbed, package-relative source list).
fn srcs_of(pkg: &Package, target: &str) -> Vec<String> {
    let t = pkg.get(target).unwrap_or_else(|| panic!("target '{target}' present"));
    match t.attrs.iter().find(|(k, _)| k == "srcs").map(|(_, v)| v) {
        Some(BzlValue::List(items)) => items
            .iter()
            .map(|i| match i {
                BzlValue::Str(s) => s.clone(),
                other => panic!("srcs entry not a string: {other:?}"),
            })
            .collect(),
        other => panic!("srcs is not a list: {other:?}"),
    }
}

/// The headline: `glob(["src/**/*.rs"], exclude=["src/gen/*.rs"])` matches recursively, is gated to `.rs`
/// (a sibling `.md` is dropped), and honors the exclude (a generated file under src/gen is removed). RED
/// under `mutant_glob_ignores_exclude` (the excluded file leaks into srcs).
#[test]
fn glob_recursive_matches_extension_and_honors_exclude() {
    let sys: Arc<dyn System> = Arc::new(DarwinSystem);
    let root = unique_root();
    write(
        sys.as_ref(),
        &root,
        "app/BUILD.bazel",
        b"target(kind = \"filegroup\", name = \"lib\", srcs = glob([\"src/**/*.rs\"], exclude = [\"src/gen/*.rs\"]))\n",
    );
    write(sys.as_ref(), &root, "app/src/a.rs", b"// a\n"); // direct child (** matches zero segments)
    write(sys.as_ref(), &root, "app/src/sub/b.rs", b"// b\n"); // nested (** matches one+ segments)
    write(sys.as_ref(), &root, "app/src/gen/skip.rs", b"// generated\n"); // EXCLUDED by src/gen/*.rs
    write(sys.as_ref(), &root, "app/src/readme.md", b"docs\n"); // wrong extension — not matched

    let engine = build_loading_engine(sys, HostPath::new(root));
    let p = package(&engine, "app").expect("the glob package builds");
    assert_eq!(
        srcs_of(&p, "lib"),
        vec!["src/a.rs".to_string(), "src/sub/b.rs".to_string()],
        "glob is recursive (**), extension-gated (.rs only), and exclude-honoring (src/gen dropped), sorted"
    );
}

/// A single-segment `*` does NOT cross a `/`: `glob(["src/*.rs"])` matches only the immediate children of
/// src, never the nested file. Proves the segment boundary of the path matcher end-to-end.
#[test]
fn glob_single_star_is_one_level() {
    let sys: Arc<dyn System> = Arc::new(DarwinSystem);
    let root = unique_root();
    write(sys.as_ref(), &root, "p/BUILD.bazel", b"target(kind = \"filegroup\", name = \"x\", srcs = glob([\"src/*.rs\"]))\n");
    write(sys.as_ref(), &root, "p/src/top.rs", b"1\n");
    write(sys.as_ref(), &root, "p/src/deep/nested.rs", b"2\n"); // NOT matched by a single-level *
    let engine = build_loading_engine(sys, HostPath::new(root));
    let p = package(&engine, "p").expect("builds");
    assert_eq!(srcs_of(&p, "x"), vec!["src/top.rs".to_string()], "src/*.rs matches only the one directory level");
}

/// Bazel's `allow_empty` default (False since Bazel 7's `--incompatible_disallow_empty_glob`, kept in Bazel
/// 9): a glob matching nothing is a typed PACKAGE error unless `allow_empty = True` is set.
#[test]
fn glob_empty_default_disallows_but_allow_empty_permits() {
    let sys: Arc<dyn System> = Arc::new(DarwinSystem);
    // (a) empty match, allow_empty unset → the PACKAGE fails closed.
    let root = unique_root();
    write(sys.as_ref(), &root, "e/BUILD.bazel", b"target(kind = \"filegroup\", name = \"x\", srcs = glob([\"nope/*.rs\"]))\n");
    let engine = build_loading_engine(sys.clone(), HostPath::new(root));
    assert!(
        package(&engine, "e").is_err(),
        "an empty glob with allow_empty unset is a typed error (Bazel default-disallow)"
    );

    // (b) the SAME empty glob with allow_empty = True → legal, an empty srcs list.
    let root2 = unique_root();
    write(
        sys.as_ref(),
        &root2,
        "e/BUILD.bazel",
        b"target(kind = \"filegroup\", name = \"x\", srcs = glob([\"nope/*.rs\"], allow_empty = True))\n",
    );
    let engine2 = build_loading_engine(sys, HostPath::new(root2));
    let p = package(&engine2, "e").expect("allow_empty = True makes an empty glob legal");
    assert_eq!(srcs_of(&p, "x"), Vec::<String>::new(), "allow_empty = True yields an empty (not errored) srcs");
}

/// A BUILD with NO glob() is unaffected (the single-eval fast path): plain `target()` srcs pass through.
#[test]
fn no_glob_build_is_unchanged() {
    let sys: Arc<dyn System> = Arc::new(DarwinSystem);
    let root = unique_root();
    write(sys.as_ref(), &root, "n/BUILD.bazel", b"target(kind = \"filegroup\", name = \"x\", srcs = [\"lib.rs\"])\n");
    let engine = build_loading_engine(sys, HostPath::new(root));
    let p = package(&engine, "n").expect("builds");
    assert_eq!(srcs_of(&p, "x"), vec!["lib.rs".to_string()], "a glob-less BUILD is byte-identical (no globber pass)");
}
