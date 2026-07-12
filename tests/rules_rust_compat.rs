//! T20 rules_rust compat — R1 fixture proofs + the R-load leading-red gate (dev-docs/RazelRulesRustCompatPlan.md).
//!
//! R1 landed: razel resolves + reads the REAL vendored rules_rust 0.70.0 oracle as an EXTERNAL repo that ships
//! its OWN BUILD/.bzl files (no overlay — the honest `new_local_repository` semantic). Two GREEN proofs:
//!   (A) `module_bazel_mounts_rules_rust_own_builds` — a MODULE.bazel `new_local_repository(name, path)` with
//!       NO `build_file` maps to an `ExternalRepo{build_file: None}` (own-BUILD mount), alongside a taut-shape
//!       overlay repo (`build_file: Some`) — the ONE declaration surface handles BOTH mount modes.
//!   (B) `rules_rust_defs_bzl_is_readable_as_is` — the registry (directly injected, the other valid mount)
//!       resolves the exec-space `external/rules_rust/rust/defs.bzl` back to the vendored repo root and reads
//!       the REAL defs.bzl bytes AS-IS (no synthesized overlay).
//! And the NEXT leading-red gate (R-load, `#[ignore]`, run explicitly by tools/gate.sh as xfail-that-runs):
//!   (C) `rules_rust_defs_bzl_evaluates` — `@rules_rust//rust:defs.bzl` + its transitive `//rust/private/…`
//!       closure EVALUATE under razel's loader without a typed error. RED until rows 3–5 land (the loader
//!       resolves the loads within rules_rust — row 3, DONE — then hits the first absent core builtin /
//!       unseeded transitive repo). Promotes to GREEN when the closure evaluates; then R-analyze wires next.
//!
//! The oracle is a PROGRAM FIXTURE (the workspace-local `rules-rust/` gwz member), never a product dep —
//! SKIP-with-reason when absent so the suite is portable. Pure in-memory Starlark over the real file seam; hang-proofed.

use razel_analysis::ConfiguredTargetKey;
use razel_bzl_api::{BzlEvaluator, BzlValue, LoadKind, ProviderId, ProviderInstance};
use razel_bzl_starlark::StarlarkEvaluator;
use razel_core::NodeKey;
use razel_engine_api::DemandEngine;
use razel_host::{
    build_execution_engine_with_toolchains_and_repos, build_loading_engine_with_repos, module_external_repos,
    ExternalRepo, ExternalRepos, LocalSpawnStrategy,
};
use razel_ids::{ConfigId, RootRelativePath};
use razel_load::{BzlLoadKey, BzlModuleValue};
use razel_os_api::{HostPath, System};
use razel_os_darwin::DarwinSystem;
use razel_source::resolve_source_path;
use razel_toolchain::{Platform, RegisteredExecPlatform, RegisteredToolchain, ToolchainType};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const HANG_DEADLINE: Duration = Duration::from_secs(60);

fn hang_proof<T: Send + 'static>(body: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(body());
    });
    match rx.recv_timeout(HANG_DEADLINE) {
        Ok(v) => v,
        Err(RecvTimeoutError::Disconnected) => panic!("test body panicked (see the failure output above)"),
        Err(RecvTimeoutError::Timeout) => panic!("hang-proof deadline exceeded: the .bzl closure never terminated"),
    }
}

fn unique_root() -> String {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    format!("/tmp/razel-t20-{nanos}-{n}")
}

fn repo_root() -> String {
    let manifest = env!("CARGO_MANIFEST_DIR"); // <repo>/razel-host
    manifest.rsplit_once('/').map(|(p, _)| p.to_string()).unwrap_or_else(|| manifest.to_string())
}

/// The pinned rules_rust 0.70.0 oracle — the workspace-local `rules-rust/` gwz member (a T20 program
/// FIXTURE, not a product dep, so it is NEVER hardcoded at a composition root). `None` (SKIP) when absent.
fn vendored_rules_rust(sys: &dyn System) -> Option<String> {
    let path = format!("{}/rules-rust", repo_root());
    match sys.stat(&HostPath::new(format!("{path}/rust/defs.bzl"))) {
        Ok(_) => Some(path),
        Err(e) => {
            eprintln!("SKIP rules_rust_compat: vendored oracle not found at {path}: {e:?}");
            None
        }
    }
}

/// The workspace root — the base under which the rules_rust-closure oracle repos live as gwz members
/// (`rules-rust/`, `bazel-skylib/`, `rules-cc/`). `None` (SKIP) when absent — keeps the suite portable.
fn vendored_repos_base(sys: &dyn System) -> Option<String> {
    let path = repo_root();
    match sys.stat(&HostPath::new(format!("{path}/rules-rust/rust/defs.bzl"))) {
        Ok(_) => Some(path),
        Err(e) => {
            eprintln!("SKIP rules_rust_compat: vendored oracle repos not found under {path}: {e:?}");
            None
        }
    }
}

/// Seed the R-load transitive-repo registry the `@rules_rust//rust:defs.bzl` closure demands, DEMAND-ORDERED
/// (each row was added when the leading-red test surfaced its undeclared-repo typed error, never speculatively).
/// Every entry is an OWN-BUILD external repo (`build_file = None` — a real Bazel module that ships its own
/// BUILD/.bzl files, read AS-IS; the R1 own-BUILD mount). The apparent repo NAME (the `@name` in the load) maps
/// to its vendored DIR (hyphenated for skylib). Version drift vs the oracle's bzlmod resolution is recorded in
/// RazelRulesRustCompatPlan §R-load. `None` (SKIP) if the vendored tree is absent OR a demanded repo has no
/// local source (fail-closed — the suite never downloads).
fn defs_bzl_closure_repos(sys: &dyn System) -> Option<ExternalRepos> {
    let tp = vendored_repos_base(sys)?;
    // (apparent @repo name, workspace-local gwz-member dir). Grown strictly by the demand trace.
    const VENDORED: &[(&str, &str)] = &[
        ("rules_rust", "rules-rust"),
        ("bazel_skylib", "bazel-skylib"), // demand #1: @bazel_skylib//rules:common_settings.bzl
        ("rules_cc", "rules-cc"),         // demand #2: @rules_cc//cc/common:cc_common.bzl (HEAD-drifted vs 0.2.4)
    ];
    // Repo-phase-GENERATED or Bazel-EMBEDDED repos razel cannot materialize (it runs no repo rules) — vendored
    // as MINIMAL fixture-local stub repos under tests/fixtures/. Each provides ONLY the load-time symbols the
    // defs.bzl closure binds; real behavior is R-analyze (row 7). See the fixture files for scope rationale.
    // `(apparent @repo name, fixture dir under tests/fixtures/)` — the dir differs from the name where the
    // stub is explicitly a stand-in (`bazel_tools` → `bazel_tools_stub`).
    // demand #3: @cc_compatibility_proxy//:symbols.bzl (generated by rules_cc's compatibility_proxy extension).
    // demand #4: @bazel_tools//tools/build_defs/cc:action_names.bzl (Bazel-EMBEDDED repo; reached transitively
    //            through rules_rust's rust/private/rustc.bzl for the link-action-name constants).
    const FIXTURE_STUBS: &[(&str, &str)] = &[
        ("cc_compatibility_proxy", "cc_compatibility_proxy"),
        ("bazel_tools", "bazel_tools_stub"),
    ];

    let mut pairs = Vec::new();
    for (name, dir) in VENDORED {
        let root = format!("{tp}/{dir}");
        // Verify the vendored source is present — a missing demanded repo is a SKIP (never a download).
        if sys.stat(&HostPath::new(root.clone())).is_err() {
            eprintln!("SKIP rules_rust_compat: demanded repo '@{name}' not vendored at {root}");
            return None;
        }
        pairs.push((name.to_string(), ExternalRepo { root: HostPath::new(root), build_file: None }));
    }
    for (name, dir) in FIXTURE_STUBS {
        let root = format!("{}/razel-host/tests/fixtures/{dir}", repo_root());
        pairs.push((name.to_string(), ExternalRepo { root: HostPath::new(root), build_file: None }));
    }
    Some(ExternalRepos::from_pairs(pairs))
}

/// R1 proof (A): the ONE declaration surface (MODULE.bazel `new_local_repository`) mounts BOTH an own-BUILD
/// repo (rules_rust — no `build_file`, read AS-IS) and an overlay repo (taut-shape — `build_file` Some). The
/// optional-overlay decision is exercised through the real parser + composition-root mapping.
#[test]
fn module_bazel_mounts_rules_rust_own_builds() {
    let root = unique_root();
    // A MODULE.bazel declaring rules_rust with NO build_file (own BUILDs) + taut-shape WITH an overlay.
    let module_src = "module(name = \"t20\", version = \"0.0.1\")\n\
new_local_repository = use_repo_rule(\"@bazel_tools//tools/build_defs/repo:local.bzl\", \"new_local_repository\")\n\
new_local_repository(name = \"rules_rust\", path = \"rules-rust\")\n\
new_local_repository(name = \"taut-shape\", path = \"ext/taut-shape\", build_file = \"//overlays/taut-shape:BUILD.bazel\")\n";
    let module = BzlEvaluator::evaluate_module_file(&StarlarkEvaluator::new(), module_src).expect("MODULE.bazel evaluates");
    let repos = module_external_repos(&module, &HostPath::new(root.clone())).expect("repos map");

    let rr = repos.get("rules_rust").expect("rules_rust is mounted");
    assert!(rr.build_file.is_none(), "an own-BUILD repo (no build_file) mounts with build_file = None (read AS-IS)");
    assert!(rr.root.as_str().ends_with("/rules-rust"), "its root resolves under the workspace: {}", rr.root.as_str());

    let ts = repos.get("taut-shape").expect("taut-shape is mounted");
    assert_eq!(
        ts.build_file,
        Some(RootRelativePath("overlays/taut-shape/BUILD.bazel".into())),
        "a BUILD-less repo keeps its main-root overlay (build_file = Some) — both modes on one surface"
    );
}

/// R1 proof (B): a repo that ships its own BUILD/.bzl files is readable AS-IS. The injected registry maps the
/// D1 exec-space path `external/rules_rust/rust/defs.bzl` back to the vendored repo root, and the REAL bytes
/// of rules_rust's `rust/defs.bzl` are read — no overlay synthesized. The mount the `.bzl` load path consumes.
#[test]
fn rules_rust_defs_bzl_is_readable_as_is() {
    let sys: Arc<dyn System> = Arc::new(DarwinSystem);
    let Some(vendored) = vendored_rules_rust(sys.as_ref()) else { return };
    let repos = ExternalRepos::from_pairs([(
        "rules_rust".to_string(),
        ExternalRepo { root: HostPath::new(vendored.clone()), build_file: None },
    )]);
    // Exec-space path (what resolve_load produces for @rules_rust//rust:defs.bzl) → the vendored repo root.
    let exec = RootRelativePath("external/rules_rust/rust/defs.bzl".into());
    let host = resolve_source_path(&HostPath::new(unique_root()), &repos, &exec).expect("resolves to the repo root");
    assert_eq!(host.as_str(), format!("{vendored}/rust/defs.bzl"), "own-BUILD repo reads from its own root");
    let bytes = sys.read(&host).expect("read the REAL vendored defs.bzl");
    let text = String::from_utf8(bytes).expect("utf-8");
    assert!(
        text.contains("Public entry point to all Rust rules"),
        "the REAL rules_rust defs.bzl is read AS-IS through the registry (no overlay)"
    );
}

/// R-LOAD LEADING RED (T20, `#[ignore]`; tools/gate.sh runs it explicitly as xfail-that-runs + inverse
/// promote-on-green). `@rules_rust//rust:defs.bzl` and its transitive `//rust/private/…` closure must EVALUATE
/// under razel's loader without a typed error. Row 3 (per-repo load context) resolves the `//`-loads WITHIN
/// rules_rust; this gate then burns down the remaining transitive evaluation (rows 4–5 core builtins +
/// any unseeded `@bazel_skylib`/`@rules_cc` transitive repos). Flips GREEN when the closure evaluates.
#[test]
#[ignore = "T20 R-load leading red — @rules_rust//rust:defs.bzl transitive closure must EVALUATE (rows 3–5)"]
fn rules_rust_defs_bzl_evaluates() {
    hang_proof(|| {
        let sys: Arc<dyn System> = Arc::new(DarwinSystem);
        let Some(repos) = defs_bzl_closure_repos(sys.as_ref()) else { return };
        let root = unique_root();
        let engine = build_loading_engine_with_repos(sys.clone(), HostPath::new(root.clone()), repos);

        // Demand defs.bzl as a file INSIDE rules_rust (context Some("rules_rust")) — its own //-loads scope
        // to the repo (row 3). The dep KIND/env-id are the evaluator's Build-load row.
        let eval = StarlarkEvaluator::new();
        let key = BzlLoadKey::for_kind_in_context(
            RootRelativePath("external/rules_rust/rust/defs.bzl".into()),
            LoadKind::Build { is_prelude: false },
            Some("rules_rust".to_string()),
            &eval,
        )
        .expect("build the defs.bzl load key");

        match engine.request(&NodeKey::from_key(&key)) {
            Ok(v) => {
                let m = &v.as_any().downcast_ref::<BzlModuleValue>().expect("a BzlModuleValue").0;
                assert!(
                    m.bindings.iter().any(|(n, _)| n == "rust_library"),
                    "defs.bzl exports rust_library once its closure evaluates"
                );
            }
            Err(e) => panic!(
                "R-load not landed: @rules_rust//rust:defs.bzl closure does not yet evaluate — first typed error: {e:?}"
            ),
        }
    });
}

/// R-ANALYZE LEADING RED (T20, `#[ignore]`; tools/gate.sh runs it explicitly as xfail-that-runs). A REAL
/// `rust_library` from the vendored `@rules_rust//rust:defs.bzl` must ANALYZE under razel — CT with
/// CrateInfo/DepInfo/CcInfo produced. This wave landed the cc-INDEPENDENT analysis surface — row 6 Target
/// model, row 8 Args full, row 9 ctx scalars + `ctx.toolchains[Label]` — PLUS the analysis-infra enablers the
/// probe demanded (threading the rule `.bzl`'s `load()` closure into `evaluate_rule`; the live-module bridge
/// available during rule eval). With those, the rust_library IMPL now RUNS: `_rust_library_impl` →
/// `_rust_library_common` → `find_toolchain(ctx)` (`ctx.toolchains[Label("//rust:toolchain_type")]` resolves)
/// → `compute_crate_name(ctx.workspace_name, ctx.label, toolchain, …)`. The frontier is now the rust_toolchain
/// FIELD CONTENT (`toolchain._rename_first_party_crates` etc.) — the TOOLCHAIN-UNDER-RAZEL design point
/// (R-build: a real rust_toolchain has ~40 fields, some File/depset over a materialized sysroot), NOT a
/// ctx/Target surface. cc_common (the `@cc_compatibility_proxy` fail-closed `None`) is behind THAT, and is
/// R-analyze-2. The FIRST typed error quoted here is the current R-analyze frontier.
#[test]
#[ignore = "T20 R-analyze leading red — a real rust_library must ANALYZE (frontier: rust_toolchain content → cc_common)"]
fn rules_rust_library_analyzes() {
    hang_proof(|| {
        let sys: Arc<dyn System> = Arc::new(DarwinSystem);
        let Some(repos) = defs_bzl_closure_repos(sys.as_ref()) else { return };
        let root = unique_root();
        // The probe package: a REAL `rust_library` instantiated from the vendored defs.bzl.
        let build = "load(\"@rules_rust//rust:defs.bzl\", \"rust_library\")\n\
rust_library(name = \"probe\", srcs = [\"lib.rs\"], edition = \"2021\")\n";
        sys.write_atomic(&HostPath::new(format!("{root}/probe_pkg/BUILD.bazel")), build.as_bytes())
            .expect("write probe BUILD");
        sys.write_atomic(&HostPath::new(format!("{root}/probe_pkg/lib.rs")), b"pub fn p() {}\n")
            .expect("write probe src");

        // The full loading→analysis→toolchain→execution stack over the vendored repos. Toolchains for BOTH
        // types the real rust_library requires are injected (rust + cpp) so toolchain resolution is not the
        // frontier — a minimal schemaless `ToolchainInfo` each (the rich rust_toolchain shape is R-build's
        // toolchain-under-razel design point; enough here to let analysis reach the rule impl).
        let mut platforms = HashMap::new();
        platforms.insert("host".to_string(), Platform { constraints: Vec::new() });
        let (engine, registry) = build_execution_engine_with_toolchains_and_repos(
            sys.clone(),
            HostPath::new(root.clone()),
            repos,
            Arc::new(LocalSpawnStrategy::new(sys.clone())), // never invoked — the probe demands the CT, not execution
            Arc::new(razel_action::SameTargetOrSourceResolver),
            Arc::new(razel_action::InMemoryBlobStore::new()),
            platforms,
            RegisteredExecPlatform { name: "host".to_string(), constraints: Vec::new() },
        );
        let tinfo = |fields: Vec<(String, BzlValue)>| ProviderInstance {
            provider: ProviderId::from_name("ToolchainInfo"),
            fields,
        };
        registry.set_toolchains(
            &ConfigId("host".to_string()),
            vec![
                RegisteredToolchain {
                    // The required type string is `//rust:toolchain_type` (relative — razel's `Label()` does
                    // not repo-resolve a rules_rust-internal label to `@rules_rust//…` this wave), so the
                    // injected type must match it exactly for resolution to succeed.
                    toolchain_type: ToolchainType("//rust:toolchain_type".to_string()),
                    target_compatible_with: Vec::new(),
                    exec_compatible_with: Vec::new(),
                    info: tinfo(vec![("rustc".to_string(), BzlValue::Str("/usr/bin/rustc".to_string()))]),
                },
                RegisteredToolchain {
                    toolchain_type: ToolchainType("@bazel_tools//tools/cpp:toolchain_type".to_string()),
                    target_compatible_with: Vec::new(),
                    exec_compatible_with: Vec::new(),
                    info: tinfo(Vec::new()),
                },
            ],
        );

        let ctk = ConfiguredTargetKey {
            package: "probe_pkg".to_string(),
            name: "probe".to_string(),
            configuration: Some("host".to_string()),
            exec_platform: None,
            rule_transition: None,
        };
        match engine.request(&NodeKey::from_key(&ctk)) {
            Ok(_) => { /* GREEN = R-analyze reached (cc_common produced CcInfo) — promote per gate.sh. */ }
            Err(e) => panic!(
                "R-analyze not landed: a real rust_library does not yet analyze — first typed error (R-analyze frontier): {e:?}"
            ),
        }
    });
}
