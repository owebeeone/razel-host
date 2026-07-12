//! THE RUST-RULES WAVE PROOF: `razel build //hello_rs:hello_bin` — a `rust_library` compiled by REAL
//! `rustc` into an rlib, a `rust_binary` linking it via `--extern`, emitted to real disk and RUN (via
//! `System::spawn`; stdout redirected to a file, exit asserted) — with CHAINING-GRANULAR incrementality:
//! edit the lib source → BOTH actions re-compile; edit the bin source → ONLY the bin re-links; touch
//! (identical bytes) → ZERO re-spawns (early cutoff at FILE).
//!
//! The three wave items compose here, all data-driven:
//!   (1) `//pkg:file.bzl` loads — `hello_rs/BUILD.bazel` loads `//rules/rust:rust.bzl` (cross-package).
//!   (2) files-chaining — the lib's impl returns `DefaultInfo(files = [rlib])`; the bin's impl lists the
//!       dep rlib (read from `dep[DefaultInfo].files`) as an action INPUT; analysis stamps the owner CT's
//!       `dep_outputs` map (exec_path → producing action) from the dep CT's declared actions; the
//!       `SameTargetOrSourceResolver` maps the input to `ArtifactRef::Derived{exec_path, producer}` — the
//!       Bazel analysis-knows-the-producer shape, fail-closed (an unmapped path falls to Source and a
//!       missing source file is a typed NotFound, never absorbed).
//!   (3) the "rust" toolchain — discovered rustc registered in the ADR-0010 host-injected registry; the
//!       rules require `toolchains = ["rust"]` and read `ctx.toolchains["rust"].rustc`.
//!
//! Row red-first mutant (tools/gate.sh runs it unfiltered and requires RED):
//!   mutant_chain_drops_dep_files → the dep's DefaultInfo files never reach the dependent action's inputs
//!     as Derived refs → the rlib resolves to Source → typed NotFound ("source artifact
//!     hello_rs/libhello_lib.rlib") → the build fails closed → RED (both tests, terminating).
//!   (mutant_load_pkg_resolution_absorbs gates in tests/pkg_loads.rs + the razel-load unit — supported
//!   //pkg forms like this file's //rules/rust:rust.bzl resolve identically under it, by design.)
//!
//! HANG-PROOF: every body runs under a bounded deadline (rustc is a real subprocess) so a wedged compile
//! becomes a terminating RED, never a hung binary. If no rustc is discoverable the tests SKIP with a
//! reason (this is the documented fail-closed skip, not an absorb — the build itself never defaults).

use razel_action::{
    ArtifactProducer, ArtifactRef, BlobStore, GeneratingActionKey, InMemoryBlobStore, OutputSelection,
    SameTargetOrSourceResolver, TargetCompletionKey,
};
use razel_analysis::ConfiguredTargetKey;
use razel_core::NodeKey;
use razel_engine_api::{ChangedLeaf, DemandEngine, Diff, FailurePolicy};
use razel_exec_api::{ExecError, SpawnRequest, SpawnResult, SpawnStrategy};
use razel_host::rust_toolchain::{discover_rustc, rust_toolchain, HOST_CONFIG};
use razel_host::{build_execution_engine_with_toolchains, run_build_configured, LocalSpawnStrategy};
use razel_ids::{ConfigId, RootRelativePath};
use razel_os_api::{EnvMap, HostPath, ProcessSpec, System};
use razel_os_darwin::DarwinSystem;
use razel_source::FileStateKey;
use razel_toolchain::{Platform, RegisteredExecPlatform};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ──────────────── hang-proof harness (the local_exec.rs pattern; rustc needs a wider deadline) ────────────────
const HANG_DEADLINE: Duration = Duration::from_secs(120);

fn hang_proof<T: Send + 'static>(body: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(body());
    });
    match rx.recv_timeout(HANG_DEADLINE) {
        Ok(v) => v,
        Err(RecvTimeoutError::Disconnected) => panic!("test body panicked (see the failure output above)"),
        Err(RecvTimeoutError::Timeout) => {
            panic!("hang-proof deadline exceeded ({HANG_DEADLINE:?}): a real rustc subprocess never completed — failing RED instead of hanging")
        }
    }
}

/// A unique real-workspace root per test (tests run concurrently).
fn unique_root() -> String {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    format!("/tmp/razel-rust-{nanos}-{n}")
}

// ──────────────── a spawn-RECORDING wrapper around the REAL LocalSpawnStrategy ────────────────
// The granularity oracle: every real subprocess passes through here; we record each spawn's (single)
// declared output path, so the test can assert exactly WHICH actions re-ran, in order.
struct RecordingLocal {
    inner: LocalSpawnStrategy,
    spawned: Arc<Mutex<Vec<String>>>,
}
impl SpawnStrategy for RecordingLocal {
    fn spawn(&self, req: &SpawnRequest) -> Result<SpawnResult, ExecError> {
        self.spawned.lock().unwrap().push(req.outputs.first().cloned().unwrap_or_default());
        self.inner.spawn(req)
    }
}

// ──────────────── the fixture: rules/rust/rust.bzl (a REAL cross-package ruleset) + hello_rs ────────────────
// The .bzl is REAL data: `rust_library` compiles one src to an rlib (`--crate-type=rlib`) and returns
// `DefaultInfo(files = [rlib])`; `rust_binary` links its deps' rlibs via `--extern <crate>=<rlib>` +
// `-L dependency=<dir>`, listing them as action INPUTS (read from `dep[DefaultInfo].files` — the chaining
// carrier). argv[0] is the toolchain's ABSOLUTE rustc (the /bin/sh precedent — no PATH lookup at spawn);
// the declared env carries `PATH=/usr/bin:/bin` for rustc's linker discovery (declared data, in the 8-dim
// fingerprint; no host inheritance). Single-file srcs this wave (multi-file/module crates = next wave):
// a multi-src call fails LOUD in the impl.
const RUST_BZL: &str = r#"RustInfo = provider(
    doc = "Transitive rlib propagation for the hand-written rust ruleset.",
    fields = {"crate_name": "", "rlib": "", "transitive_rlibs": ""},
)

_RUST_ENV = {"PATH": "/usr/bin:/bin"}

def _compile(ctx, crate_type, out):
    tc = ctx.toolchains["//rules/rust:toolchain_type"]
    srcs = ctx.files.srcs
    if not srcs:
        fail("rust rule needs at least one src (crate root listed first): %s" % ctx.label)
    crate_root = srcs[0]
    extern_args = []
    dep_transitive = []
    for dep in ctx.attr.deps:
        info = dep[RustInfo]
        extern_args.append("--extern")
        extern_args.append("%s=%s" % (info.crate_name, info.rlib.path))
        dep_transitive.append(info.transitive_rlibs)
    dep_rlibs = depset(transitive = dep_transitive)
    lib_dir_args = []
    seen = {}
    for f in dep_rlibs.to_list():
        d = f.dirname
        if d not in seen:
            seen[d] = True
            lib_dir_args.append("-L")
            lib_dir_args.append("dependency=%s" % d)
    args = ctx.actions.args()
    args.add("--edition=2021")
    args.add("--crate-type=" + crate_type)
    args.add("--crate-name", ctx.label.name)
    args.add(crate_root.path)
    args.add("-o", out.path)
    args.add_all(extern_args)
    args.add_all(lib_dir_args)
    ctx.actions.run(
        executable = tc.rustc,
        arguments = [args],
        inputs = depset(direct = srcs, transitive = dep_transitive),
        outputs = [out],
        mnemonic = "Rustc",
        progress_message = "Rustc %s %s" % (crate_type, ctx.label),
        env = _RUST_ENV,
        use_default_shell_env = False,
    )

def _rust_library_impl(ctx):
    out = ctx.actions.declare_file("lib%s.rlib" % ctx.label.name)
    _compile(ctx, "rlib", out)
    transitive = depset(
        direct = [out],
        transitive = [dep[RustInfo].transitive_rlibs for dep in ctx.attr.deps],
    )
    return [
        DefaultInfo(files = depset([out])),
        RustInfo(crate_name = ctx.label.name, rlib = out, transitive_rlibs = transitive),
    ]

def _rust_binary_impl(ctx):
    out = ctx.actions.declare_file(ctx.label.name)
    _compile(ctx, "bin", out)
    return [DefaultInfo(files = depset([out]), executable = out)]

_ATTRS = {
    "srcs": attr.label_list(allow_files = [".rs"]),
    "deps": attr.label_list(providers = [RustInfo]),
}

rust_library = rule(implementation = _rust_library_impl, attrs = _ATTRS,
                    toolchains = ["//rules/rust:toolchain_type"])
rust_binary = rule(implementation = _rust_binary_impl, attrs = _ATTRS,
                   toolchains = ["//rules/rust:toolchain_type"], executable = True)
"#;

const HELLO_BUILD: &str = r#"load("//rules/rust:rust.bzl", "rust_binary", "rust_library")
rust_library(name = "hello_lib", srcs = ["hello_lib.rs"])
rust_binary(name = "hello_bin", srcs = ["main.rs"], deps = [":hello_lib"])
"#;

const LIB_V1: &str = "pub fn greet() -> String {\n    \"hello from razel rust v1\".to_string()\n}\n";
// v2 differs in LENGTH (FILE_STATE dirty-check fires regardless of mtime resolution) AND in the emitted
// string literal (the rlib bytes MUST change so the downstream link re-runs — not just the source).
const LIB_V2: &str =
    "pub fn greet() -> String {\n    \"hello from razel rust v2 — a longer edited revision\".to_string()\n}\n";
const MAIN_V1: &str = "fn main() {\n    println!(\"{}\", hello_lib::greet());\n}\n";
const MAIN_V2: &str = "fn main() {\n    println!(\"bin-v2 says: {}\", hello_lib::greet());\n}\n";

fn write_fixture(sys: &dyn System, root: &str) {
    sys.write_atomic(&HostPath::new(format!("{root}/rules/rust/rust.bzl")), RUST_BZL.as_bytes()).expect("write rust.bzl");
    sys.write_atomic(&HostPath::new(format!("{root}/hello_rs/BUILD.bazel")), HELLO_BUILD.as_bytes()).expect("write BUILD");
    sys.write_atomic(&HostPath::new(format!("{root}/hello_rs/hello_lib.rs")), LIB_V1.as_bytes()).expect("write lib src");
    sys.write_atomic(&HostPath::new(format!("{root}/hello_rs/main.rs")), MAIN_V1.as_bytes()).expect("write bin src");
}

// ──────────────── keys (all carry the session configuration — toolchain resolution requires it) ────────────────
fn ct(name: &str) -> ConfiguredTargetKey {
    ConfiguredTargetKey {
        package: "hello_rs".into(),
        name: name.into(),
        configuration: Some(HOST_CONFIG.into()),
        exec_platform: None,
        rule_transition: None,
    }
}
fn completion(name: &str) -> NodeKey {
    NodeKey::from_key(&TargetCompletionKey { ct: ct(name), outputs: OutputSelection::Default })
}
fn rlib_artifact() -> NodeKey {
    NodeKey::from_key(&ArtifactRef {
        exec_path: "hello_rs/libhello_lib.rlib".into(),
        producer: ArtifactProducer::Derived(GeneratingActionKey { owner: ct("hello_lib"), action_index: 0 }),
    })
}
fn fskey(p: &str) -> NodeKey {
    NodeKey::from_key(&FileStateKey(RootRelativePath(p.into())))
}

/// Assemble the toolchain-enabled execution engine over the REAL DarwinSystem with the recording strategy;
/// seed the "rust" toolchain (discovered rustc) under the HOST_CONFIG registration.
fn make_engine(
    sys: Arc<dyn System>,
    root: &str,
    rustc: &HostPath,
    spawned: Arc<Mutex<Vec<String>>>,
) -> (razel_engine::Engine, Arc<InMemoryBlobStore>) {
    let blobs = Arc::new(InMemoryBlobStore::new());
    let strategy = Arc::new(RecordingLocal { inner: LocalSpawnStrategy::new(sys.clone()), spawned });
    let mut platforms = HashMap::new();
    platforms.insert(HOST_CONFIG.to_string(), Platform { constraints: Vec::new() });
    let (engine, registry) = build_execution_engine_with_toolchains(
        sys,
        HostPath::new(root.to_string()),
        strategy,
        Arc::new(SameTargetOrSourceResolver),
        blobs.clone(),
        platforms,
        RegisteredExecPlatform { name: "host".to_string(), constraints: Vec::new() },
    );
    registry.set_toolchains(&ConfigId(HOST_CONFIG.to_string()), vec![rust_toolchain(rustc)]);
    (engine, blobs)
}

/// Run the EMITTED binary via `System::spawn` (never std::process): `/bin/sh -c` chmods it executable
/// (emit writes bytes, not modes — v1) and redirects its stdout to a file; returns (exit code, stdout bytes).
fn run_emitted_bin(sys: &dyn System, root: &str) -> (i32, Vec<u8>) {
    let spec = ProcessSpec {
        program: HostPath::new("/bin/sh"),
        args: vec![
            "-c".into(),
            "/bin/chmod +x hello_rs/hello_bin && ./hello_rs/hello_bin > hello_rs/run_out.txt".into(),
        ],
        env: EnvMap::new(),
        cwd: HostPath::new(root.to_string()),
    };
    let status = sys.spawn(&spec).expect("spawn the built rust binary");
    let out = sys.read(&HostPath::new(format!("{root}/hello_rs/run_out.txt"))).expect("read the binary's stdout file");
    (status.code, out)
}

/// SKIP-with-reason when no rustc is discoverable (documented; this machine has cargo, so in practice the
/// proof always runs — the skip is never an absorb inside the build itself).
fn rustc_or_skip(sys: &dyn System) -> Option<HostPath> {
    match discover_rustc(sys) {
        Ok(p) => Some(p),
        Err(e) => {
            eprintln!("SKIP rust_rules: no rustc discoverable on this machine: {e:?}");
            None
        }
    }
}

#[test]
fn rust_bin_compiles_links_and_runs() {
    hang_proof(|| {
        let sys: Arc<dyn System> = Arc::new(DarwinSystem);
        let Some(rustc) = rustc_or_skip(sys.as_ref()) else { return };
        let root = unique_root();
        write_fixture(sys.as_ref(), &root);

        let spawned = Arc::new(Mutex::new(Vec::new()));
        let (engine, blobs) = make_engine(sys.clone(), &root, &rustc, spawned.clone());

        // THE build: `razel build //hello_rs:hello_bin` — the //pkg load resolves rules/rust/rust.bzl, the
        // lib compiles to an rlib, the chaining map feeds it to the bin's --extern link, and the binary is
        // emitted to real disk. All of it a pure graph consequence of ONE pattern.
        let built = run_build_configured(
            &engine,
            blobs.as_ref(),
            sys.as_ref(),
            &HostPath::new(root.clone()),
            "//hello_rs:hello_bin",
            Some(HOST_CONFIG),
        )
        .expect("razel build //hello_rs:hello_bin succeeds");
        assert_eq!(built.len(), 1, "the bin target has ONE default output");
        assert_eq!(built[0].exec_path, "hello_rs/hello_bin");

        // Exactly two REAL rustc spawns, in dependency order: the rlib compile, then the bin link.
        assert_eq!(
            *spawned.lock().unwrap(),
            vec!["hello_rs/libhello_lib.rlib".to_string(), "hello_rs/hello_bin".to_string()],
            "cold build = the lib compile then the bin link (real rustc, dependency-ordered)"
        );

        // The rlib is REAL rustc output: an ar archive ("!<arch>") in the CAS, projected through ARTIFACT.
        let rlib_digest = {
            let v = engine.request(&rlib_artifact()).expect("the rlib ARTIFACT projects");
            v.as_any().downcast_ref::<razel_action::ArtifactValue>().expect("an ArtifactValue").digest
        };
        let rlib_bytes = blobs.get(&rlib_digest).expect("rlib bytes in the ONE home");
        assert!(rlib_bytes.starts_with(b"!<arch>"), "the rlib is a REAL rustc archive (ar magic), not fabricated");

        // RUN the emitted binary (System::spawn): exit 0 + the lib's string on stdout — the rlib was really
        // linked in via --extern (the chaining proof is OBSERVABLE program behavior, not just node states).
        let (code, out) = run_emitted_bin(sys.as_ref(), &root);
        assert_eq!(code, 0, "the built binary runs and exits zero");
        assert_eq!(
            out,
            b"hello from razel rust v1\n".to_vec(),
            "the binary prints the LIB's string — the rust_library was compiled and linked via --extern"
        );

        let _ = sys.remove_dir_all(&HostPath::new(root));
    });
}

#[test]
fn rust_chaining_granular_incrementality() {
    hang_proof(|| {
        let sys: Arc<dyn System> = Arc::new(DarwinSystem);
        let Some(rustc) = rustc_or_skip(sys.as_ref()) else { return };
        let root = unique_root();
        write_fixture(sys.as_ref(), &root);

        let spawned = Arc::new(Mutex::new(Vec::new()));
        let (engine, blobs) = make_engine(sys.clone(), &root, &rustc, spawned.clone());
        let tc = completion("hello_bin");
        let seq = || spawned.lock().unwrap().clone();

        // cold: lib compile + bin link.
        engine.request(&tc).expect("cold build");
        assert_eq!(
            seq(),
            vec!["hello_rs/libhello_lib.rlib".to_string(), "hello_rs/hello_bin".to_string()],
            "cold: exactly the two rustc actions"
        );

        // (a) EDIT the LIB source (string literal changes → new rlib bytes) → BOTH re-compile: the lib
        // action re-runs on its changed source ARTIFACT; the bin action re-runs because its INPUT (the
        // rlib ARTIFACT, resolved through the chaining map) changed digest.
        sys.write_atomic(&HostPath::new(format!("{root}/hello_rs/hello_lib.rs")), LIB_V2.as_bytes()).expect("edit lib");
        engine.evaluate(
            &[tc.clone()],
            FailurePolicy::FailFast,
            Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(fskey("hello_rs/hello_lib.rs"))] },
        );
        assert_eq!(
            seq()[2..],
            [
                "hello_rs/libhello_lib.rlib".to_string(),
                "hello_rs/hello_bin".to_string()
            ],
            "a LIB edit re-runs BOTH: the rlib re-compiles and the bin re-links against the new rlib"
        );

        // (b) EDIT the BIN source → ONLY the bin re-links (the lib's FILE/ARTIFACT/ACTION are untouched;
        // the rlib digest is unchanged so the bin's OTHER input edge stays clean).
        sys.write_atomic(&HostPath::new(format!("{root}/hello_rs/main.rs")), MAIN_V2.as_bytes()).expect("edit bin src");
        engine.evaluate(
            &[tc.clone()],
            FailurePolicy::FailFast,
            Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(fskey("hello_rs/main.rs"))] },
        );
        assert_eq!(
            seq()[4..],
            ["hello_rs/hello_bin".to_string()],
            "a BIN-source edit re-runs ONLY the bin link — the lib does NOT recompile (chaining-granular)"
        );

        // (c) TOUCH the lib source (identical bytes) → FILE content digest unchanged → ZERO re-spawns.
        sys.write_atomic(&HostPath::new(format!("{root}/hello_rs/hello_lib.rs")), LIB_V2.as_bytes()).expect("touch lib");
        engine.evaluate(
            &[tc.clone()],
            FailurePolicy::FailFast,
            Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(fskey("hello_rs/hello_lib.rs"))] },
        );
        assert_eq!(seq().len(), 5, "a touch (identical bytes) must NOT re-spawn anything — early cutoff at FILE");

        // Re-emit + RUN: the rebuilt binary carries BOTH edits (bin-v2 text wrapping the lib-v2 string).
        run_build_configured(
            &engine,
            blobs.as_ref(),
            sys.as_ref(),
            &HostPath::new(root.clone()),
            "//hello_rs:hello_bin",
            Some(HOST_CONFIG),
        )
        .expect("re-emit after edits");
        let (code, out) = run_emitted_bin(sys.as_ref(), &root);
        assert_eq!(code, 0);
        assert_eq!(
            out,
            "bin-v2 says: hello from razel rust v2 — a longer edited revision\n".as_bytes().to_vec(),
            "the re-run binary observes BOTH source edits through the incremental rebuild"
        );

        let _ = sys.remove_dir_all(&HostPath::new(root));
    });
}

#[test]
fn rust_bzl_content_edit_preserving_templates_recompiles_zero() {
    // T17-C RECOMPUTE MEASUREMENT: the rust.bzl conversion (declare_action → ctx.actions.run + Label/File)
    // is a .bzl CONTENT change that projects the SAME frozen ActionTemplates. So a warm rebuild after editing
    // rust.bzl (here a template-preserving comment append) must re-run ZERO rustc actions — any CT
    // re-analysis early-cuts at the unchanged action fingerprints. This directly measures the claim.
    hang_proof(|| {
        let sys: Arc<dyn System> = Arc::new(DarwinSystem);
        let Some(rustc) = rustc_or_skip(sys.as_ref()) else { return };
        let root = unique_root();
        write_fixture(sys.as_ref(), &root);

        let spawned = Arc::new(Mutex::new(Vec::new()));
        let (engine, _blobs) = make_engine(sys.clone(), &root, &rustc, spawned.clone());
        let tc = completion("hello_bin");

        engine.request(&tc).expect("cold build");
        let cold = spawned.lock().unwrap().len();
        assert_eq!(cold, 2, "cold: exactly the two rustc actions (lib + bin)");

        // Edit rust.bzl: content bytes change, the projected templates do NOT.
        let edited = format!("{}\n# T17-C: template-preserving comment edit\n", RUST_BZL);
        sys.write_atomic(&HostPath::new(format!("{root}/rules/rust/rust.bzl")), edited.as_bytes()).expect("edit rust.bzl");
        engine.evaluate(
            &[tc.clone()],
            FailurePolicy::FailFast,
            Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(fskey("rules/rust/rust.bzl"))] },
        );
        let recompiled = spawned.lock().unwrap().len() - cold;
        assert_eq!(
            recompiled, 0,
            "a template-preserving rust.bzl edit re-runs ZERO rustc — early cutoff at the unchanged action \
             templates (measured: {recompiled} rustc re-spawns)"
        );

        let _ = sys.remove_dir_all(&HostPath::new(root));
    });
}
