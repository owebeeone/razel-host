//! T19 P1 PROOFS — the three fat-self-host capabilities added to the shared `rules/rust/rust.bzl`, each
//! exercised END TO END through REAL `rustc` (compile → emit → RUN), data-driven off ONE `razel build`:
//!
//!   (P1a proc-macro) `proc_macro_derive_expands_and_runs` — a `rust_proc_macro` crate compiled with
//!     `--crate-type=proc-macro` to a host `lib<name>.dylib`, consumed by a `rust_binary` via
//!     `proc_macro_deps` (→ `--extern mac=<dylib>` + the dylib as an action input). The derive macro really
//!     EXPANDS: the emitted binary prints the generated method's value (42). RED under
//!     `mutant_ctx_actions_run_drops_arguments` (the `--extern` vanishes → the derive is unresolved) and
//!     `mutant_chain_drops_dep_files` (the dylib input can't resolve to its producer → typed NotFound).
//!
//!   (P1b features) `crate_features_gate_a_cfg_fn` — a `rust_library` with `crate_features = ["extra"]`
//!     emits `--cfg feature="extra"`, so a `#[cfg(feature = "extra")]`-gated fn is compiled and the dependent
//!     binary links + prints its value (7). RED under `mutant_string_list_attr_dropped` (the feature vanishes
//!     → the gated fn is not compiled → the dependent fails closed) and `mutant_attr_string_default_ignored`
//!     (any P1 build's `edition` collapses to "" → `--edition=` is rejected by rustc).
//!
//!   (P1b action-identity) `p1_attrs_unset_are_argv_invisible_recompiles_zero` — build a plain
//!     `rust_library`+`rust_binary` under the PRE-P1 ruleset, then SWAP in the P1 ruleset (the new
//!     `edition`/`crate_features`/`rustc_flags`/`proc_macro_deps` attrs, all UNSET on the targets). The
//!     projected rustc argv is byte-identical (edition default "2021" keeps `--edition=2021` in place; the
//!     empty lists add nothing), so the warm rebuild re-runs ZERO rustc — early cutoff at the unchanged
//!     action templates. This is the recompute-0 measurement of "unset P1 attrs widen the argv by nothing".
//!
//! HANG-PROOF (the rust_rules.rs pattern): every body runs under a bounded deadline so a wedged real rustc
//! becomes a terminating RED, never a hang. No rustc discoverable ⇒ SKIP-with-reason (never an absorb).

use razel_action::{
    ArtifactProducer, ArtifactRef, ArtifactValue, BlobStore, GeneratingActionKey, InMemoryBlobStore,
    OutputSelection, SameTargetOrSourceResolver, TargetCompletionKey,
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

fn unique_root() -> String {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    format!("/tmp/razel-p1-{nanos}-{n}")
}

// ──────────────── the P1 ruleset (the exact shape of the real rules/rust/rust.bzl, minus the injected
// toolchain rule) — proc_macro_deps threading, per-crate edition/crate_features/rustc_flags ────────────────
const P1_RUST_BZL: &str = r#"RustInfo = provider(
    doc = "Transitive rlib propagation for the hand-written rust ruleset.",
    fields = {"crate_name": "", "rlib": "", "transitive_rlibs": ""},
)

BuildScriptInfo = provider(
    "BuildScriptInfo",
    fields = {"rustc_flags": "", "rustc_env": ""},
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
    pm_extern = []
    pm_inputs = []
    for pm in ctx.attr.proc_macro_deps:
        info = pm[RustInfo]
        pm_extern.append("--extern")
        pm_extern.append("%s=%s" % (info.crate_name, info.rlib.path))
        pm_inputs.append(info.rlib)
    rust_env = dict(_RUST_ENV)
    bs_flags = []
    for bs in ctx.attr.build_script_deps:
        bsi = bs[BuildScriptInfo]
        bs_flags.extend(bsi.rustc_flags)
        for kv in bsi.rustc_env:
            parts = kv.split("=", 1)
            rust_env[parts[0]] = parts[1]
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
    args.add("--edition=" + ctx.attr.edition)
    args.add("--crate-type=" + crate_type)
    if crate_type == "proc-macro":
        args.add("--extern")
        args.add("proc_macro")
    args.add("--crate-name", ctx.label.name)
    args.add(crate_root.path)
    args.add("-o", out.path)
    args.add_all(extern_args)
    args.add_all(pm_extern)
    args.add_all(lib_dir_args)
    for feature in sorted(ctx.attr.crate_features):
        args.add("--cfg")
        args.add("feature=\"%s\"" % feature)
    args.add_all(ctx.attr.rustc_flags)
    args.add_all(bs_flags)
    ctx.actions.run(
        executable = tc.rustc,
        arguments = [args],
        inputs = depset(direct = srcs + pm_inputs, transitive = dep_transitive),
        outputs = [out],
        mnemonic = "Rustc",
        progress_message = "Rustc %s %s" % (crate_type, ctx.label),
        env = rust_env,
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

def _rust_proc_macro_impl(ctx):
    out = ctx.actions.declare_file("lib%s.dylib" % ctx.label.name)
    _compile(ctx, "proc-macro", out)
    return [
        DefaultInfo(files = depset([out])),
        RustInfo(crate_name = ctx.label.name, rlib = out, transitive_rlibs = depset([out])),
    ]

def _cargo_build_script_impl(ctx):
    return [BuildScriptInfo(rustc_flags = ctx.attr.rustc_flags, rustc_env = ctx.attr.rustc_env)]

cargo_build_script = rule(
    implementation = _cargo_build_script_impl,
    attrs = {
        "srcs": attr.label_list(allow_files = [".rs"]),
        "rustc_flags": attr.string_list(),
        "rustc_env": attr.string_list(),
    },
)

_ATTRS = {
    "srcs": attr.label_list(allow_files = [".rs"]),
    "deps": attr.label_list(providers = [RustInfo]),
    "proc_macro_deps": attr.label_list(providers = [RustInfo]),
    "build_script_deps": attr.label_list(providers = [BuildScriptInfo]),
    "edition": attr.string(default = "2021"),
    "crate_features": attr.string_list(),
    "rustc_flags": attr.string_list(),
}

rust_library = rule(implementation = _rust_library_impl, attrs = _ATTRS,
                    toolchains = ["//rules/rust:toolchain_type"])
rust_binary = rule(implementation = _rust_binary_impl, attrs = _ATTRS,
                   toolchains = ["//rules/rust:toolchain_type"], executable = True)
rust_proc_macro = rule(implementation = _rust_proc_macro_impl, attrs = _ATTRS,
                       toolchains = ["//rules/rust:toolchain_type"])
"#;

// The PRE-P1 ruleset (hardcoded `--edition=2021`, srcs+deps only, no proc-macro/feature threading) — the
// baseline for the recompute-0 proof. A plain rust_library/rust_binary is IDENTICAL under both rulesets.
const PRE_P1_RUST_BZL: &str = r#"RustInfo = provider(
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

// ──────────────── fixtures ────────────────
// P1a: a trivial derive macro (ignores its input; emits an impl for the fixed `Thing`) consumed via
// `#[derive(mac::Answer)]`. The emitted binary prints the generated method's value.
const MAC_RS: &str = r#"use proc_macro::TokenStream;

#[proc_macro_derive(Answer)]
pub fn derive_answer(_input: TokenStream) -> TokenStream {
    "impl Answer for Thing { fn answer(&self) -> u32 { 42 } }".parse().unwrap()
}
"#;
const PM_MAIN_RS: &str = r#"trait Answer { fn answer(&self) -> u32; }

#[derive(mac::Answer)]
struct Thing;

fn main() {
    println!("{}", Thing.answer());
}
"#;
const PM_BUILD: &str = r#"load("//rules/rust:rust.bzl", "rust_binary", "rust_proc_macro")
rust_proc_macro(name = "mac", srcs = ["mac.rs"])
rust_binary(name = "user", srcs = ["main.rs"], proc_macro_deps = [":mac"])
"#;

// P1b: a `#[cfg(feature = "extra")]`-gated fn compiled ONLY when `crate_features = ["extra"]` emits the cfg.
const FEATLIB_RS: &str = r#"#[cfg(feature = "extra")]
pub fn extra_value() -> u32 {
    7
}
"#;
const FEAT_MAIN_RS: &str = r#"fn main() {
    println!("{}", featlib::extra_value());
}
"#;
const FEAT_BUILD: &str = r#"load("//rules/rust:rust.bzl", "rust_binary", "rust_library")
rust_library(name = "featlib", srcs = ["featlib.rs"], crate_features = ["extra"])
rust_binary(name = "fuser", srcs = ["main.rs"], deps = [":featlib"])
"#;

// P1c: a cargo_build_script publishes PRE-COMPUTED directives (a `--cfg has_thing` and a `BS_MSG` env). The
// build.rs is RECORDED (its `println!` documents the provenance) but NOT executed — razel has no stdout
// capture. The dependent library APPLIES the directives: the cfg-gated fn compiles + `env!("BS_MSG")` resolves.
const BS_BUILD_RS: &str = "fn main() {\n    println!(\"cargo:rustc-cfg=has_thing\");\n    println!(\"cargo:rustc-env=BS_MSG=hi\");\n}\n";
const BSLIB_RS: &str = r#"#[cfg(has_thing)]
pub fn thing() -> u32 {
    5
}

pub const MSG: &str = env!("BS_MSG");
"#;
const BS_MAIN_RS: &str = r#"fn main() {
    println!("{} {}", bslib::thing(), bslib::MSG);
}
"#;
const BS_BUILD: &str = r#"load("//rules/rust:rust.bzl", "cargo_build_script", "rust_binary", "rust_library")
cargo_build_script(name = "bs", srcs = ["build.rs"], rustc_flags = ["--cfg", "has_thing"], rustc_env = ["BS_MSG=hi"])
rust_library(name = "bslib", srcs = ["bslib.rs"], build_script_deps = [":bs"])
rust_binary(name = "bsuser", srcs = ["main.rs"], deps = [":bslib"])
"#;

// Plain hello (no P1 attrs) — the recompute-0 baseline.
const HELLO_BUILD: &str = r#"load("//rules/rust:rust.bzl", "rust_binary", "rust_library")
rust_library(name = "hello_lib", srcs = ["hello_lib.rs"])
rust_binary(name = "hello_bin", srcs = ["main.rs"], deps = [":hello_lib"])
"#;
const HELLO_LIB_RS: &str = "pub fn greet() -> u32 {\n    99\n}\n";
const HELLO_MAIN_RS: &str = "fn main() {\n    println!(\"{}\", hello_lib::greet());\n}\n";

fn write(sys: &dyn System, path: &str, bytes: &[u8]) {
    sys.write_atomic(&HostPath::new(path.to_string()), bytes).unwrap_or_else(|e| panic!("write {path}: {e:?}"));
}

// ──────────────── keys (all carry the session configuration — toolchain resolution requires it) ────────────────
fn ct(pkg: &str, name: &str) -> ConfiguredTargetKey {
    ConfiguredTargetKey {
        package: pkg.into(),
        name: name.into(),
        configuration: Some(HOST_CONFIG.into()),
        exec_platform: None,
        rule_transition: None,
    }
}
fn completion(pkg: &str, name: &str) -> NodeKey {
    NodeKey::from_key(&TargetCompletionKey { ct: ct(pkg, name), outputs: OutputSelection::Default })
}
fn fskey(p: &str) -> NodeKey {
    NodeKey::from_key(&FileStateKey(RootRelativePath(p.into())))
}

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

/// Emit + RUN the built binary (via `System::spawn`, never std::process): chmod +x, run, capture stdout.
fn run_bin(sys: &dyn System, root: &str, pkg: &str, name: &str) -> (i32, Vec<u8>) {
    let spec = ProcessSpec {
        program: HostPath::new("/bin/sh"),
        args: vec![
            "-c".into(),
            format!("/bin/chmod +x {pkg}/{name} && ./{pkg}/{name} > {pkg}/{name}.out.txt"),
        ],
        env: EnvMap::new(),
        cwd: HostPath::new(root.to_string()),
    };
    let status = sys.spawn(&spec).expect("spawn the built rust binary");
    let out = sys.read(&HostPath::new(format!("{root}/{pkg}/{name}.out.txt"))).expect("read the binary's stdout file");
    (status.code, out)
}

fn rustc_or_skip(sys: &dyn System, what: &str) -> Option<HostPath> {
    match discover_rustc(sys) {
        Ok(p) => Some(p),
        Err(e) => {
            eprintln!("SKIP {what}: no rustc discoverable on this machine: {e:?}");
            None
        }
    }
}

#[test]
fn proc_macro_derive_expands_and_runs() {
    hang_proof(|| {
        let sys: Arc<dyn System> = Arc::new(DarwinSystem);
        let Some(rustc) = rustc_or_skip(sys.as_ref(), "proc_macro") else { return };
        let root = unique_root();
        write(sys.as_ref(), &format!("{root}/rules/rust/rust.bzl"), P1_RUST_BZL.as_bytes());
        write(sys.as_ref(), &format!("{root}/pm/BUILD.bazel"), PM_BUILD.as_bytes());
        write(sys.as_ref(), &format!("{root}/pm/mac.rs"), MAC_RS.as_bytes());
        write(sys.as_ref(), &format!("{root}/pm/main.rs"), PM_MAIN_RS.as_bytes());

        let spawned = Arc::new(Mutex::new(Vec::new()));
        let (engine, blobs) = make_engine(sys.clone(), &root, &rustc, spawned.clone());

        // THE build: the proc-macro compiles to a host dylib, then the binary links against it via --extern.
        let built = run_build_configured(
            &engine,
            blobs.as_ref(),
            sys.as_ref(),
            &HostPath::new(root.clone()),
            "//pm:user",
            Some(HOST_CONFIG),
        )
        .expect("razel build //pm:user succeeds (proc-macro compiled + threaded as --extern)");
        assert_eq!(built.len(), 1);
        assert_eq!(built[0].exec_path, "pm/user");

        // Two rustc spawns, in dependency order: the proc-macro dylib, then the consumer binary.
        assert_eq!(
            *spawned.lock().unwrap(),
            vec!["pm/libmac.dylib".to_string(), "pm/user".to_string()],
            "cold: the proc-macro compiles to a dylib, then the binary links against it"
        );

        // The proc-macro output is a real Mach-O dynamic library (not an ar archive) in the CAS. Its exec path
        // is `pm/libmac.dylib` but the PRODUCER is the `mac` target's action #0 (declare_file names the file).
        let mac_ref = NodeKey::from_key(&ArtifactRef {
            exec_path: "pm/libmac.dylib".into(),
            producer: ArtifactProducer::Derived(GeneratingActionKey { owner: ct("pm", "mac"), action_index: 0 }),
        });
        let mac_digest = {
            let v = engine.request(&mac_ref).expect("the proc-macro dylib projects");
            v.as_any().downcast_ref::<ArtifactValue>().expect("an ArtifactValue").digest
        };
        let mac_bytes = blobs.get(&mac_digest).expect("proc-macro dylib bytes in the ONE home");
        assert!(is_macho(&mac_bytes), "the proc-macro output is a real Mach-O dylib (proc-macro crate-type)");

        // RUN the emitted binary: the derive really EXPANDED (the generated `answer()` returns 42).
        let (code, out) = run_bin(sys.as_ref(), &root, "pm", "user");
        assert_eq!(code, 0, "the proc-macro-consuming binary runs and exits zero");
        assert_eq!(out, b"42\n".to_vec(), "the derive macro expanded: the generated method returns 42");

        let _ = sys.remove_dir_all(&HostPath::new(root));
    });
}

#[test]
fn crate_features_gate_a_cfg_fn() {
    hang_proof(|| {
        let sys: Arc<dyn System> = Arc::new(DarwinSystem);
        let Some(rustc) = rustc_or_skip(sys.as_ref(), "crate_features") else { return };
        let root = unique_root();
        write(sys.as_ref(), &format!("{root}/rules/rust/rust.bzl"), P1_RUST_BZL.as_bytes());
        write(sys.as_ref(), &format!("{root}/feat/BUILD.bazel"), FEAT_BUILD.as_bytes());
        write(sys.as_ref(), &format!("{root}/feat/featlib.rs"), FEATLIB_RS.as_bytes());
        write(sys.as_ref(), &format!("{root}/feat/main.rs"), FEAT_MAIN_RS.as_bytes());

        let spawned = Arc::new(Mutex::new(Vec::new()));
        let (engine, blobs) = make_engine(sys.clone(), &root, &rustc, spawned.clone());

        // The library's `crate_features = ["extra"]` emits `--cfg feature="extra"`, so `extra_value()` is
        // compiled and the dependent binary links against it. (RED under `mutant_string_list_attr_dropped`:
        // the feature vanishes → `extra_value` is not compiled → the bin fails to resolve it.)
        run_build_configured(
            &engine,
            blobs.as_ref(),
            sys.as_ref(),
            &HostPath::new(root.clone()),
            "//feat:fuser",
            Some(HOST_CONFIG),
        )
        .expect("razel build //feat:fuser succeeds (crate_features enabled the cfg-gated fn)");

        let (code, out) = run_bin(sys.as_ref(), &root, "feat", "fuser");
        assert_eq!(code, 0, "the feature-gated binary runs and exits zero");
        assert_eq!(out, b"7\n".to_vec(), "the `#[cfg(feature=\"extra\")]` fn was compiled — crate_features reached rustc");

        let _ = sys.remove_dir_all(&HostPath::new(root));
    });
}

#[test]
fn build_script_directives_apply_cfg_and_env() {
    // P1c: a `cargo_build_script` publishes PRE-COMPUTED directives (rustc-cfg + rustc-env). A dependent
    // `rust_library` with `build_script_deps = [":bs"]` applies them: `--cfg has_thing` compiles the gated
    // `thing()` and the `BS_MSG` env resolves `env!("BS_MSG")`. The binary prints both. (RED under
    // `mutant_string_list_attr_dropped`: the build script's rustc_flags/rustc_env vanish → neither the gated
    // fn nor the env! is available → the library fails closed.)
    hang_proof(|| {
        let sys: Arc<dyn System> = Arc::new(DarwinSystem);
        let Some(rustc) = rustc_or_skip(sys.as_ref(), "build_script") else { return };
        let root = unique_root();
        write(sys.as_ref(), &format!("{root}/rules/rust/rust.bzl"), P1_RUST_BZL.as_bytes());
        write(sys.as_ref(), &format!("{root}/bs/BUILD.bazel"), BS_BUILD.as_bytes());
        write(sys.as_ref(), &format!("{root}/bs/build.rs"), BS_BUILD_RS.as_bytes());
        write(sys.as_ref(), &format!("{root}/bs/bslib.rs"), BSLIB_RS.as_bytes());
        write(sys.as_ref(), &format!("{root}/bs/main.rs"), BS_MAIN_RS.as_bytes());

        let spawned = Arc::new(Mutex::new(Vec::new()));
        let (engine, blobs) = make_engine(sys.clone(), &root, &rustc, spawned.clone());

        run_build_configured(
            &engine,
            blobs.as_ref(),
            sys.as_ref(),
            &HostPath::new(root.clone()),
            "//bs:bsuser",
            Some(HOST_CONFIG),
        )
        .expect("razel build //bs:bsuser succeeds (build-script directives applied to the dependent's rustc)");

        // ONLY the library + binary compile — the `cargo_build_script` publishes data, it does NOT run rustc.
        assert_eq!(
            *spawned.lock().unwrap(),
            vec!["bs/libbslib.rlib".to_string(), "bs/bsuser".to_string()],
            "the build script emits no action (directives are data); only the lib + bin compile"
        );

        let (code, out) = run_bin(sys.as_ref(), &root, "bs", "bsuser");
        assert_eq!(code, 0, "the build-script-configured binary runs and exits zero");
        assert_eq!(
            out,
            b"5 hi\n".to_vec(),
            "the `--cfg has_thing` compiled `thing()` (→5) AND the rustc-env `BS_MSG=hi` reached `env!` (→hi)"
        );

        let _ = sys.remove_dir_all(&HostPath::new(root));
    });
}

#[test]
fn p1_attrs_unset_are_argv_invisible_recompiles_zero() {
    // Build a plain rust_library+binary under the PRE-P1 ruleset, then SWAP to the P1 ruleset (new
    // edition/crate_features/rustc_flags/proc_macro_deps attrs, all UNSET). The projected rustc argv is
    // byte-identical (edition default "2021" keeps `--edition=2021`; empty lists add nothing), so the warm
    // rebuild re-runs ZERO rustc — the recompute-0 measurement of "unset P1 attrs widen the argv by nothing".
    hang_proof(|| {
        let sys: Arc<dyn System> = Arc::new(DarwinSystem);
        let Some(rustc) = rustc_or_skip(sys.as_ref(), "recompute0") else { return };
        let root = unique_root();
        write(sys.as_ref(), &format!("{root}/rules/rust/rust.bzl"), PRE_P1_RUST_BZL.as_bytes());
        write(sys.as_ref(), &format!("{root}/hello_rs/BUILD.bazel"), HELLO_BUILD.as_bytes());
        write(sys.as_ref(), &format!("{root}/hello_rs/hello_lib.rs"), HELLO_LIB_RS.as_bytes());
        write(sys.as_ref(), &format!("{root}/hello_rs/main.rs"), HELLO_MAIN_RS.as_bytes());

        let spawned = Arc::new(Mutex::new(Vec::new()));
        let (engine, _blobs) = make_engine(sys.clone(), &root, &rustc, spawned.clone());
        let tc = completion("hello_rs", "hello_bin");

        // COLD under PRE-P1: exactly the two rustc actions (lib + bin).
        engine.request(&tc).expect("cold build under the pre-P1 ruleset");
        let cold = spawned.lock().unwrap().len();
        assert_eq!(cold, 2, "cold: exactly the lib compile + the bin link");

        // SWAP in the P1 ruleset: the targets set NONE of the new attrs. edition defaults to "2021" (same
        // `--edition=2021`); crate_features/rustc_flags/proc_macro_deps are empty (add nothing). The action
        // templates are byte-identical → the warm rebuild re-runs ZERO rustc.
        write(sys.as_ref(), &format!("{root}/rules/rust/rust.bzl"), P1_RUST_BZL.as_bytes());
        engine.evaluate(
            &[tc.clone()],
            FailurePolicy::FailFast,
            Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(fskey("rules/rust/rust.bzl"))] },
        );
        let after = spawned.lock().unwrap().len() - cold;
        assert_eq!(
            after, 0,
            "swapping in the P1 ruleset re-runs ZERO rustc for targets that set no P1 attr — the unset attrs \
             are argv-invisible (measured: {after} rustc re-spawns)"
        );

        let _ = sys.remove_dir_all(&HostPath::new(root));
    });
}

/// Mach-O magic (macOS executables + dylibs): 64-bit / 32-bit thin (LE) + the universal wrappers.
fn is_macho(b: &[u8]) -> bool {
    b.len() >= 4
        && matches!(
            [b[0], b[1], b[2], b[3]],
            [0xCF, 0xFA, 0xED, 0xFE] | [0xCE, 0xFA, 0xED, 0xFE] | [0xCA, 0xFE, 0xBA, 0xBE] | [0xBF, 0xBA, 0xFE, 0xCA]
        )
}
