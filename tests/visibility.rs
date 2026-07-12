//! THE C7 VISIBILITY PROOF (D7): over the composition root + real engine, a CROSS-package dep edge to a
//! private (default) target is a typed analysis error naming both labels; a `//visibility:public` target is
//! visible everywhere; a SAME-package edge is always allowed. Pure analysis (no rustc) — the enforcement is
//! at `CONFIGURED_TARGET`.
//!
//! Row red-first mutant (tools/gate.sh, unfiltered, requires RED):
//!   mutant_visibility_ignored → the cross-package enforcement is skipped, so a private cross-package dep
//!     silently resolves → the fail-closed assertion reds.

use razel_analysis::{ConfiguredTargetKey, CONFIGURED_TARGET};
use razel_core::NodeKey;
use razel_engine_api::DemandEngine;
use razel_host::build_analysis_engine;
use razel_os_api::{HostPath, System};
use razel_os_darwin::DarwinSystem;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_root() -> String {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    format!("/tmp/razel-vis-{nanos}-{n}")
}

// A trivial provider-returning rule with a label_list `deps` — enough to form a dep EDGE (analysis resolves
// it), no actions/toolchains/rustc.
const RULES: &[u8] = b"Info = provider(\"Info\", fields = [\"x\"])\n\
def _impl(ctx):\n\
\x20   return [Info(x = 1)]\n\
my_rule = rule(implementation = _impl, attrs = {\"deps\": attr.label_list()})\n";

fn write(sys: &dyn System, p: &str, b: &[u8]) {
    sys.write_atomic(&HostPath::new(p.to_string()), b).unwrap_or_else(|e| panic!("write {p}: {e:?}"));
}

/// Stage a workspace: a root `rules.bzl`; package `b` with target `lib` (visibility per `lib_vis`); package
/// `a` with `app` depending on `//b:lib`; and `a`'s own private same-package `sib` + `app2` depending on it.
fn stage(sys: &dyn System, root: &str, lib_vis: &str) {
    write(sys, &format!("{root}/rules.bzl"), RULES);
    write(sys, &format!("{root}/b/BUILD.bazel"), format!("load(\"//:rules.bzl\", \"my_rule\")\nmy_rule(name = \"lib\"{lib_vis})\n").as_bytes());
    write(
        sys,
        &format!("{root}/a/BUILD.bazel"),
        b"load(\"//:rules.bzl\", \"my_rule\")\n\
my_rule(name = \"app\", deps = [\"//b:lib\"])\n\
my_rule(name = \"sib\")\n\
my_rule(name = \"app2\", deps = [\":sib\"])\n",
    );
}

fn ct(pkg: &str, name: &str) -> NodeKey {
    NodeKey::from_key(&ConfiguredTargetKey {
        package: pkg.into(),
        name: name.into(),
        configuration: None,
        exec_platform: None,
        rule_transition: None,
    })
}

#[test]
fn private_cross_package_dep_fails_closed() {
    let sys: Arc<dyn System> = Arc::new(DarwinSystem);
    let root = unique_root();
    stage(sys.as_ref(), &root, ""); // //b:lib is PRIVATE (no visibility attr)
    let engine = build_analysis_engine(sys.clone(), HostPath::new(root.clone()));

    // //a:app depends CROSS-package on the private //b:lib → a typed analysis error (RED under the mutant).
    // (Match rather than `{:?}` the Result — `Arc<dyn Value>` in the Ok arm has no Debug.)
    match engine.request(&ct("a", "app")) {
        Err(_) => {}
        Ok(_) => panic!("a cross-package dep on the PRIVATE //b:lib must fail closed — RED under mutant_visibility_ignored"),
    }

    // …but the SAME-package edge //a:app2 → //a:sib (also private) is always allowed.
    assert!(engine.request(&ct("a", "app2")).is_ok(), "a same-package edge to a private target is always visible");
    assert_eq!(CONFIGURED_TARGET, razel_core::KindId(40), "the analysis row is frozen");
    let _ = sys.remove_dir_all(&HostPath::new(root));
}

#[test]
fn public_cross_package_dep_resolves() {
    let sys: Arc<dyn System> = Arc::new(DarwinSystem);
    let root = unique_root();
    stage(sys.as_ref(), &root, ", visibility = [\"//visibility:public\"]"); // //b:lib is PUBLIC
    let engine = build_analysis_engine(sys.clone(), HostPath::new(root.clone()));
    assert!(
        engine.request(&ct("a", "app")).is_ok(),
        "a cross-package dep on the PUBLIC //b:lib resolves (visibility = //visibility:public)"
    );
    let _ = sys.remove_dir_all(&HostPath::new(root));
}
