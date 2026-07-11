//! Cross-package `load()` over the composition root (rust-rules wave item 1 — the C8 first slice): a
//! `//pkg/path:file.bzl` load target resolves to the workspace-relative `pkg/path/file.bzl` as a sibling
//! `BZL_LOAD` dep (the six-dim key's `path` dim carries it — NO key reshape), from BOTH loaders: a `.bzl`
//! module and a BUILD file. Invalidation is TRANSITIVE ACROSS PACKAGES (edit the loaded file → the loading
//! module + package re-evaluate; touch → cutoff at FILE), and cross-package load CYCLES still surface as
//! the engine's typed `Error::Cycle`.
//!
//! Row red-first mutant (tools/gate.sh runs it unfiltered and requires RED):
//!   mutant_load_pkg_resolution_absorbs → a rejected load form (`@repo//...`) is ABSORBED into a
//!     wrong-but-plausible workspace path instead of a typed error; with a decoy module sitting at the
//!     absorbed path, `unsupported_load_form_fails_closed_over_the_root` observes Ok-with-wrong-module
//!     where the contract demands Err(Unsupported) → RED (binary-level red, unfiltered-terminating).
//!     (The unit half lives in razel-load: `pkg_load_unsupported_forms_fail_closed`.)
//!
//! No subprocesses run here (pure in-memory Starlark over the real DarwinSystem file seam), so no
//! hang-proof harness is needed — every body terminates by construction.

use razel_bzl_api::BzlValue;
use razel_bzl_starlark::StarlarkEvaluator;
use razel_core::{Error, NodeKey};
use razel_engine_api::{ChangedLeaf, DemandEngine, Diff, FailurePolicy};
use razel_host::build_loading_engine;
use razel_ids::RootRelativePath;
use razel_load::{BzlLoadKey, BzlModuleValue};
use razel_os_api::{HostPath, System};
use razel_os_darwin::DarwinSystem;
use razel_package::{Package, PackageKey};
use razel_source::FileStateKey;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_root() -> String {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    format!("/tmp/razel-pkgload-{nanos}-{n}")
}

fn bzl_load_key(path: &str) -> NodeKey {
    // The evaluator serves deterministic env ids, so a fresh instance builds the SAME contract key the
    // engine's own evaluator serves (requester-independent identity).
    let k = BzlLoadKey::v1(RootRelativePath(path.into()), &StarlarkEvaluator::new()).expect("v1 load key");
    NodeKey::from_key(&k)
}
fn fskey(p: &str) -> NodeKey {
    NodeKey::from_key(&FileStateKey(RootRelativePath(p.into())))
}
fn module_of(v: &razel_core::NodeValue) -> &razel_bzl_api::BzlModule {
    &v.as_any().downcast_ref::<BzlModuleValue>().expect("a BzlModuleValue").0
}

#[test]
fn cross_package_load_evaluates_and_invalidates_transitively() {
    let sys: Arc<dyn System> = Arc::new(DarwinSystem);
    let root = unique_root();
    // pa/a.bzl loads //pb:lib.bzl (ABSOLUTE package-relative — a different package) and derives a value;
    // pc/BUILD.bazel loads the same //pb:lib.bzl and instantiates a target named from it.
    sys.write_atomic(&HostPath::new(format!("{root}/pb/lib.bzl")), b"BASE = 41\n").expect("write pb/lib.bzl");
    sys.write_atomic(
        &HostPath::new(format!("{root}/pa/a.bzl")),
        b"load(\"//pb:lib.bzl\", \"BASE\")\nDERIVED = BASE + 1\n",
    )
    .expect("write pa/a.bzl");
    sys.write_atomic(
        &HostPath::new(format!("{root}/pc/BUILD.bazel")),
        b"load(\"//pb:lib.bzl\", \"BASE\")\ntarget(kind = \"k\", name = \"t\" + str(BASE))\n",
    )
    .expect("write pc/BUILD.bazel");

    let engine = build_loading_engine(sys.clone(), HostPath::new(root.clone()));
    let a_key = bzl_load_key("pa/a.bzl");
    let pkg_key = NodeKey::from_key(&PackageKey(RootRelativePath("pc".into())));

    // (1) the .bzl loader: //pb:lib.bzl resolved cross-package, value derived.
    let a1 = engine.request(&a_key).expect("pa/a.bzl evaluates (its //pb:lib.bzl load resolves)");
    assert_eq!(module_of(&a1).get("DERIVED"), Some(&BzlValue::Int(42)), "DERIVED = BASE(41) + 1 across packages");
    // ...and the BUILD loader through the SAME resolve_load logic.
    let p1 = engine.request(&pkg_key).expect("pc/BUILD.bazel evaluates (its //pb:lib.bzl load resolves)");
    let pkg1 = p1.as_any().downcast_ref::<Package>().expect("a Package");
    assert!(pkg1.get("t41").is_some(), "the BUILD used the cross-package constant (target 't41')");

    // (2) TRANSITIVE invalidation ACROSS packages: edit pb/lib.bzl (longer bytes) → both re-evaluate.
    sys.write_atomic(&HostPath::new(format!("{root}/pb/lib.bzl")), b"BASE = 4100\n").expect("edit pb/lib.bzl");
    engine.evaluate(
        &[a_key.clone(), pkg_key.clone()],
        FailurePolicy::FailFast,
        Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(fskey("pb/lib.bzl"))] },
    );
    let a2 = engine.request(&a_key).expect("re-request after the cross-package edit");
    assert_eq!(
        module_of(&a2).get("DERIVED"),
        Some(&BzlValue::Int(4101)),
        "the pb edit re-evaluated pa/a.bzl (invalidation crossed the package boundary)"
    );
    let p2 = engine.request(&pkg_key).expect("re-request the package");
    let pkg2 = p2.as_any().downcast_ref::<Package>().expect("a Package");
    assert!(pkg2.get("t4100").is_some(), "the pb edit re-evaluated pc's BUILD too");

    // (3) TOUCH (identical bytes) → content cutoff at FILE: the loading module's value does not change.
    let a_ver = engine.inspect(&a_key).expect("inspect a.bzl").version;
    sys.write_atomic(&HostPath::new(format!("{root}/pb/lib.bzl")), b"BASE = 4100\n").expect("touch pb/lib.bzl");
    engine.evaluate(
        &[a_key.clone()],
        FailurePolicy::FailFast,
        Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(fskey("pb/lib.bzl"))] },
    );
    let a_ver2 = engine.inspect(&a_key).expect("inspect a.bzl again").version;
    assert_eq!(
        a_ver.last_changed, a_ver2.last_changed,
        "a touch (identical bytes) must cut off at FILE — the cross-package module does not re-change"
    );

    let _ = sys.remove_dir_all(&HostPath::new(root));
}

#[test]
fn unsupported_load_form_fails_closed_over_the_root() {
    // The fail-closed law at the load-resolution boundary, observed OVER the composition root: a
    // repo-mapped load (`@decoy//pb:lib.bzl` — v1 has no repo mapping) is a typed `Unsupported` error,
    // NEVER a mis-resolution into this workspace. The DECOY: `pb/lib.bzl` EXISTS with plausible content —
    // under `mutant_load_pkg_resolution_absorbs` the loader silently loads it (Ok with wrong provenance)
    // and this test reds on the error assertion. Fail-closed means the decoy is never touched.
    let sys: Arc<dyn System> = Arc::new(DarwinSystem);
    let root = unique_root();
    sys.write_atomic(&HostPath::new(format!("{root}/pb/lib.bzl")), b"BASE = 41\n").expect("write the decoy");
    sys.write_atomic(
        &HostPath::new(format!("{root}/pa/a.bzl")),
        b"load(\"@decoy//pb:lib.bzl\", \"BASE\")\nDERIVED = BASE + 1\n",
    )
    .expect("write pa/a.bzl");

    let engine = build_loading_engine(sys.clone(), HostPath::new(root.clone()));
    match engine.request(&bzl_load_key("pa/a.bzl")) {
        Err(Error::Unsupported { what, detail }) => {
            assert_eq!(what, "load target form", "the error names the load-form contract");
            assert!(detail.contains("@decoy//pb:lib.bzl"), "the error names the offending target: {detail}");
        }
        Ok(v) => {
            let derived = module_of(&v).get("DERIVED").cloned();
            panic!(
                "a repo-mapped load MUST fail closed, not silently resolve into this workspace \
                 (evaluated with DERIVED = {derived:?} — the decoy was absorbed)"
            );
        }
        Err(e) => panic!("expected a typed Unsupported for the load form, got {e:?}"),
    }

    let _ = sys.remove_dir_all(&HostPath::new(root));
}

#[test]
fn cross_package_load_cycle_fails_closed() {
    let sys: Arc<dyn System> = Arc::new(DarwinSystem);
    let root = unique_root();
    // pa/a.bzl → //pb:b.bzl → //pa:a.bzl — a cycle THROUGH the absolute-load form.
    sys.write_atomic(&HostPath::new(format!("{root}/pa/a.bzl")), b"load(\"//pb:b.bzl\", \"B\")\nA = 1\n")
        .expect("write pa/a.bzl");
    sys.write_atomic(&HostPath::new(format!("{root}/pb/b.bzl")), b"load(\"//pa:a.bzl\", \"A\")\nB = 2\n")
        .expect("write pb/b.bzl");

    let engine = build_loading_engine(sys.clone(), HostPath::new(root.clone()));
    match engine.request(&bzl_load_key("pa/a.bzl")) {
        Err(Error::Cycle { keys }) => {
            assert!(!keys.is_empty(), "the cycle error names the participating keys");
        }
        Ok(_) => panic!("a cross-package load cycle must be a typed Error::Cycle, not a value"),
        Err(e) => panic!("expected Error::Cycle, got {e:?}"),
    }

    let _ = sys.remove_dir_all(&HostPath::new(root));
}
