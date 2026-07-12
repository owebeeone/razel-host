//! T20 select() DRIVING PROOFS — `select()` per Bazel semantics, resolvable under razel for the two driving
//! shapes, over the REAL engine (loading → analysis → toolchain → execution):
//!
//!   (a) A crate_universe-style select over rules_rust PLATFORM TRIPLES — the condition's `config_setting`
//!       carries `constraint_values = triple_to_constraint_set("aarch64-apple-darwin")` loaded from the REAL
//!       vendored `@rules_rust//rust/platform:triple_mappings.bzl` (rules_rust's own triple→constraint code).
//!       The select resolves to the darwin-arm branch under the darwin host and the crate BUILDS with real
//!       rustc. (The FULL `@rules_rust//rust/platform:BUILD` sweep — `declare_config_settings()` — additionally
//!       needs `native.platform`/`selects.config_setting_group`/`package_group`/`bzl_library`, which are out of
//!       THIS wave's scope; the honest gap is documented in the report. The triple→constraint LOGIC that
//!       decides the darwin-arm set is real rules_rust code, exercised here.)
//!   (b) A TF-shaped select over a LOCAL `config_setting(values = {"cpu": …})`, matched against the injected
//!       host `values` (the `--cpu` surface) — resolves + BUILDS.
//!   (c) The fail-closed trio, over the real engine: no-match-no-default, ambiguous, and an unknown `values`
//!       key are each a typed build error (never a silent branch).
//!
//! HANG-PROOF (rustc is a real subprocess) + SKIP-with-reason when no rustc / no vendored rules_rust.

use razel_analysis::{ConfiguredTargetKey, SelectConfig};
use razel_core::NodeKey;
use razel_engine_api::DemandEngine;
use razel_host::rust_toolchain::{discover_rustc, rust_toolchain, HOST_CONFIG};
use razel_host::{
    build_execution_engine_with_toolchains_repos_and_select, run_build_configured, ExternalRepo, ExternalRepos,
    LocalSpawnStrategy,
};
use razel_ids::ConfigId;
use razel_os_api::{HostPath, System};
use razel_os_darwin::DarwinSystem;
use razel_toolchain::{Constraint, Platform, RegisteredExecPlatform};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const HANG_DEADLINE: Duration = Duration::from_secs(120);

fn hang_proof<T: Send + 'static>(body: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(body());
    });
    match rx.recv_timeout(HANG_DEADLINE) {
        Ok(v) => v,
        Err(RecvTimeoutError::Disconnected) => panic!("test body panicked (see the failure output above)"),
        Err(RecvTimeoutError::Timeout) => panic!("hang-proof deadline exceeded: a real rustc subprocess never completed"),
    }
}

fn unique_root() -> String {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    format!("/tmp/razel-t20-select-{nanos}-{n}")
}

fn repo_root() -> String {
    let manifest = env!("CARGO_MANIFEST_DIR"); // <repo>/razel-host
    manifest.rsplit_once('/').map(|(p, _)| p.to_string()).unwrap_or_else(|| manifest.to_string())
}

/// The pinned rules_rust 0.70.0 oracle (`rules-rust/` gwz member) — a program FIXTURE. `None` (SKIP) if absent.
fn vendored_rules_rust(sys: &dyn System) -> Option<String> {
    let path = format!("{}/rules-rust", repo_root());
    match sys.stat(&HostPath::new(format!("{path}/rust/platform/triple_mappings.bzl"))) {
        Ok(_) => Some(path),
        Err(e) => {
            eprintln!("SKIP select (a): vendored rules_rust triple_mappings.bzl not found at {path}: {e:?}");
            None
        }
    }
}

fn rustc_or_skip(sys: &dyn System) -> Option<HostPath> {
    match discover_rustc(sys) {
        Ok(p) => Some(p),
        Err(e) => {
            eprintln!("SKIP select: no rustc discoverable: {e:?}");
            None
        }
    }
}

/// A MINIMAL single-crate rust ruleset (the proven rust_rules shape, trimmed): `rust_library` compiles
/// `srcs[0]` to an rlib via the discovered rustc. `srcs` is configurable (a select target).
const RUST_BZL: &str = r#"def _impl(ctx):
    tc = ctx.toolchains["//rules/rust:toolchain_type"]
    srcs = ctx.files.srcs
    if not srcs:
        fail("rust_library needs a src: %s" % ctx.label)
    out = ctx.actions.declare_file("lib%s.rlib" % ctx.label.name)
    args = ctx.actions.args()
    args.add("--edition=2021")
    args.add("--crate-type=rlib")
    args.add("--crate-name", ctx.label.name)
    args.add(srcs[0].path)
    args.add("-o", out.path)
    ctx.actions.run(
        executable = tc.rustc,
        arguments = [args],
        inputs = depset(direct = srcs),
        outputs = [out],
        mnemonic = "Rustc",
        env = {"PATH": "/usr/bin:/bin"},
        use_default_shell_env = False,
    )
    return [DefaultInfo(files = depset([out]))]

rust_library = rule(
    implementation = _impl,
    attrs = {"srcs": attr.label_list(allow_files = [".rs"])},
    toolchains = ["//rules/rust:toolchain_type"],
)
"#;

const GOOD_RS: &str = "pub fn darwin_arm_path() -> u32 { 42 }\n";
// Invalid rust: if the WRONG select branch were taken, the compile would fail — so a green build proves the
// darwin branch was chosen.
const BAD_RS: &str = "@@@ this is not valid rust — the non-darwin branch must NOT be compiled @@@\n";

fn write_rules(sys: &dyn System, root: &str) {
    sys.write_atomic(&HostPath::new(format!("{root}/rules/rust/rust.bzl")), RUST_BZL.as_bytes()).expect("write rust.bzl");
}
fn write_srcs(sys: &dyn System, root: &str, pkg: &str) {
    sys.write_atomic(&HostPath::new(format!("{root}/{pkg}/good.rs")), GOOD_RS.as_bytes()).expect("write good.rs");
    sys.write_atomic(&HostPath::new(format!("{root}/{pkg}/bad.rs")), BAD_RS.as_bytes()).expect("write bad.rs");
}

/// The darwin host constraint set (what `triple_to_constraint_set("aarch64-apple-darwin")` produces).
fn darwin_constraints() -> Vec<String> {
    vec!["@platforms//cpu:aarch64".to_string(), "@platforms//os:osx".to_string()]
}

/// Assemble the full stack with the host config injected: `platforms[host]` carries the darwin constraint set
/// (serving BOTH toolchain + select constraint resolution), plus an explicit `SelectConfig` (constraints
/// mirror the platform; `values` seed the `--cpu` surface). The discovered rustc is registered under HOST_CONFIG.
fn make_engine(
    sys: Arc<dyn System>,
    root: &str,
    rustc: Option<&HostPath>,
    repos: ExternalRepos,
    constraints: Vec<String>,
    values: BTreeMap<String, String>,
) -> (razel_engine::Engine, Arc<razel_action::InMemoryBlobStore>) {
    let blobs = Arc::new(razel_action::InMemoryBlobStore::new());
    let mut platforms = HashMap::new();
    platforms.insert(HOST_CONFIG.to_string(), Platform { constraints: constraints.iter().cloned().map(Constraint).collect() });
    let select_config = SelectConfig {
        platforms: HashMap::from([(HOST_CONFIG.to_string(), constraints)]),
        values: HashMap::from([(HOST_CONFIG.to_string(), values)]),
    };
    let (engine, registry) = build_execution_engine_with_toolchains_repos_and_select(
        sys.clone(),
        HostPath::new(root.to_string()),
        repos,
        Arc::new(LocalSpawnStrategy::new(sys.clone())),
        Arc::new(razel_action::SameTargetOrSourceResolver),
        blobs.clone(),
        platforms,
        RegisteredExecPlatform { name: "host".to_string(), constraints: Vec::new() },
        select_config,
    );
    if let Some(rustc) = rustc {
        registry.set_toolchains(&ConfigId(HOST_CONFIG.to_string()), vec![rust_toolchain(rustc)]);
    }
    (engine, blobs)
}

fn ct(pkg: &str, name: &str) -> ConfiguredTargetKey {
    ConfiguredTargetKey {
        package: pkg.into(),
        name: name.into(),
        configuration: Some(HOST_CONFIG.into()),
        exec_platform: None,
        rule_transition: None,
    }
}

/// (a) crate_universe-style select over rules_rust platform triples: the `:darwin_arm` config_setting's
/// constraint set comes from the REAL vendored `triple_to_constraint_set("aarch64-apple-darwin")`; the select
/// resolves to the darwin branch under the darwin host and the crate BUILDS with real rustc.
#[test]
fn select_over_rules_rust_platform_triple_resolves_and_builds() {
    hang_proof(|| {
        let sys: Arc<dyn System> = Arc::new(DarwinSystem);
        let Some(rustc) = rustc_or_skip(sys.as_ref()) else { return };
        let Some(vendored) = vendored_rules_rust(sys.as_ref()) else { return };
        let root = unique_root();
        write_rules(sys.as_ref(), &root);
        write_srcs(sys.as_ref(), &root, "crate_pkg");
        // A VERBATIM-shaped crate_universe select: the condition is the rules_rust platform triple, whose
        // config_setting constraint set is produced by rules_rust's OWN triple_mappings code.
        let build = "\
load(\"@rules_rust//rust/platform:triple_mappings.bzl\", \"triple_to_constraint_set\")\n\
load(\"//rules/rust:rust.bzl\", \"rust_library\")\n\
config_setting(name = \"darwin_arm\", constraint_values = triple_to_constraint_set(\"aarch64-apple-darwin\"))\n\
rust_library(name = \"cfglib\", srcs = select({\":darwin_arm\": [\"good.rs\"], \"//conditions:default\": [\"bad.rs\"]}))\n";
        sys.write_atomic(&HostPath::new(format!("{root}/crate_pkg/BUILD.bazel")), build.as_bytes()).expect("write BUILD");

        let repos = ExternalRepos::from_pairs([(
            "rules_rust".to_string(),
            ExternalRepo { root: HostPath::new(vendored), build_file: None },
        )]);
        let (engine, blobs) = make_engine(sys.clone(), &root, Some(&rustc), repos, darwin_constraints(), BTreeMap::new());

        let built = run_build_configured(&engine, blobs.as_ref(), sys.as_ref(), &HostPath::new(root.clone()), "//crate_pkg:cfglib", Some(HOST_CONFIG))
            .expect("the select resolves to the darwin branch (good.rs) and the crate BUILDS through real rules_rust triple constraints");
        assert_eq!(built.len(), 1, "one rlib output");
        let bytes = sys.read(&built[0].host_path).expect("read the emitted rlib");
        assert!(bytes.starts_with(b"!<arch>"), "the rlib is REAL rustc output (good.rs compiled) — the darwin branch was chosen, not bad.rs");
    });
}

/// (b) TF-shaped select over a LOCAL `config_setting(values = {"cpu": …})` matched against the injected host
/// `--cpu` value — resolves + BUILDS.
#[test]
fn select_over_local_config_setting_values_resolves_and_builds() {
    hang_proof(|| {
        let sys: Arc<dyn System> = Arc::new(DarwinSystem);
        let Some(rustc) = rustc_or_skip(sys.as_ref()) else { return };
        let root = unique_root();
        write_rules(sys.as_ref(), &root);
        write_srcs(sys.as_ref(), &root, "tf_pkg");
        let build = "\
load(\"//rules/rust:rust.bzl\", \"rust_library\")\n\
config_setting(name = \"cpu_arm\", values = {\"cpu\": \"darwin_arm64\"})\n\
rust_library(name = \"cfglib\", srcs = select({\":cpu_arm\": [\"good.rs\"], \"//conditions:default\": [\"bad.rs\"]}))\n";
        sys.write_atomic(&HostPath::new(format!("{root}/tf_pkg/BUILD.bazel")), build.as_bytes()).expect("write BUILD");

        let values = BTreeMap::from([("cpu".to_string(), "darwin_arm64".to_string())]);
        let (engine, blobs) = make_engine(sys.clone(), &root, Some(&rustc), ExternalRepos::empty(), darwin_constraints(), values);

        let built = run_build_configured(&engine, blobs.as_ref(), sys.as_ref(), &HostPath::new(root.clone()), "//tf_pkg:cfglib", Some(HOST_CONFIG))
            .expect("a config_setting(values={cpu}) select resolves against the host cpu and BUILDS");
        let bytes = sys.read(&built[0].host_path).expect("read the emitted rlib");
        assert!(bytes.starts_with(b"!<arch>"), "the rlib is REAL rustc output — the cpu=darwin_arm64 branch (good.rs) was chosen");
    });
}

/// (c) The fail-closed trio over the real engine: no-match-no-default, ambiguous, unknown values key. Each is
/// a typed build error at analysis (before any rustc spawn), never a silent branch. No rustc needed (the
/// select fails before the compile action).
#[test]
fn select_fail_closed_trio_over_the_engine() {
    hang_proof(|| {
        let sys: Arc<dyn System> = Arc::new(DarwinSystem);
        let case = |pkg: &str, build: &str, values: BTreeMap<String, String>| -> Result<(), razel_core::Error> {
            let root = unique_root();
            write_rules(sys.as_ref(), &root);
            write_srcs(sys.as_ref(), &root, pkg);
            sys.write_atomic(&HostPath::new(format!("{root}/{pkg}/BUILD.bazel")), build.as_bytes()).expect("write BUILD");
            // No toolchain registered — the select error fires at analysis (step 1d) before toolchain/rustc.
            let (engine, _blobs) = make_engine(sys.clone(), &root, None, ExternalRepos::empty(), darwin_constraints(), values);
            engine.request(&NodeKey::from_key(&ct(pkg, "cfglib"))).map(|_| ())
        };

        // no-match-no-default: `:linux` (os:linux ∉ the darwin host) with no //conditions:default.
        let no_match = "\
load(\"//rules/rust:rust.bzl\", \"rust_library\")\n\
config_setting(name = \"linux\", constraint_values = [\"@platforms//os:linux\"])\n\
rust_library(name = \"cfglib\", srcs = select({\":linux\": [\"good.rs\"]}))\n";
        assert!(case("nm_pkg", no_match, BTreeMap::new()).is_err(), "no matching condition + no default is a typed build error");

        // ambiguous: `:osx` (os:osx) and `:arm` (cpu:aarch64) BOTH match the host, neither specializes.
        let ambiguous = "\
load(\"//rules/rust:rust.bzl\", \"rust_library\")\n\
config_setting(name = \"osx\", constraint_values = [\"@platforms//os:osx\"])\n\
config_setting(name = \"arm\", constraint_values = [\"@platforms//cpu:aarch64\"])\n\
rust_library(name = \"cfglib\", srcs = select({\":osx\": [\"good.rs\"], \"//conditions:default\": [\"bad.rs\"], \":arm\": [\"good.rs\"]}))\n";
        assert!(case("amb_pkg", ambiguous, BTreeMap::new()).is_err(), "two incomparable matching conditions is a typed ambiguity error");

        // unknown values key: `apple_platform_type` (a real TF key razel does not support in v1).
        let unknown = "\
load(\"//rules/rust:rust.bzl\", \"rust_library\")\n\
config_setting(name = \"apl\", values = {\"apple_platform_type\": \"macos\"})\n\
rust_library(name = \"cfglib\", srcs = select({\":apl\": [\"good.rs\"], \"//conditions:default\": [\"bad.rs\"]}))\n";
        assert!(case("unk_pkg", unknown, BTreeMap::new()).is_err(), "an unknown config_setting values key fails closed");
    });
}
