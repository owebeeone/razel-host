//! T19-P3 THE FAT SELF-HOST ACCEPTANCE — `razel build //razel-daemon:razel`: razel building the SHIPPED
//! product binary (`razel`, the client+daemon multi-call) over its FULL closure with REAL rustc — ~14
//! first-party crates + the EXTERNAL taut-shape root + the ~150-crate vendored third-party tree (reached
//! through razel-host → razel-bzl-starlark → starlark). This is the whole razelv4 self-host as a pure graph
//! consequence: the generated third-party layer (tools/crates_gen), the first-party BUILD files, the shipped
//! rules/rust/rust.bzl (P1 + P3: extern renames + re-exported-proc-macro `-L`), and the injected toolchain +
//! taut-shape external root, all composed by razel.
//!
//! Two proofs:
//!   (ACCEPTANCE) `fat_selfhost_builds_and_runs_razel` — READ-ONLY over the REAL repo root with the REAL
//!     taut-shape root injected. razel compiles the entire closure with real rustc, the linked `razel` Mach-O
//!     lands in the ONE CAS (>1MB), and it EXECUTES (through the System::spawn seam — the wall bans
//!     std::process even in tests): run with no args it prints its usage banner and exits 0. A warm re-request
//!     recompiles ZERO (the whole graph is memoized). BIG build (~170 rustc actions, single-threaded) ⇒ a wide
//!     hang-proof deadline; a wedged rustc is a terminating RED, never a hang. No rustc / no generated tree ⇒
//!     SKIP-with-reason (never a false green).
//!   (MUTANT fixture) `extern_rename_resolves_through_the_rename_attr` — a SMALL 2-crate fixture (NOT the giant
//!     closure): a consumer whose source `use libc_errno::…` reaches a crate named `errno_like` via
//!     `extern_renames = ["libc_errno"]`. GREEN normally; RED under `mutant_extern_rename_dropped` (the test
//!     neuters rust.bzl's rename branch → `--extern errno_like` → `use libc_errno` fails E0432 → build fails).

use razel_action::{
    ArtifactProducer, ArtifactRef, ArtifactValue, BlobStore, GeneratingActionKey, InMemoryBlobStore,
    OutputSelection, SameTargetOrSourceResolver, TargetCompletionKey,
};
use razel_analysis::ConfiguredTargetKey;
use razel_core::NodeKey;
use razel_engine_api::DemandEngine;
use razel_exec_api::{ExecError, SpawnRequest, SpawnResult, SpawnStrategy};
use razel_host::rust_toolchain::{discover_rustc, rust_toolchain, HOST_CONFIG};
use razel_host::{
    build_execution_engine_with_toolchains, build_execution_engine_with_toolchains_and_repos, run_build_configured,
    taut_shape_repos, ExternalRepos, LocalSpawnStrategy,
};
use razel_ids::ConfigId;
use razel_os_api::{EnvMap, EnvName, HostPath, OsValue, ProcessSpec, System};
use razel_os_darwin::DarwinSystem;
use razel_toolchain::{Platform, RegisteredExecPlatform};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// The fat closure is ~170 rustc actions run single-threaded — a wide deadline (this is a SAFETY net for a
// wedged subprocess, not the expected duration; a healthy cold build is many minutes of real rustc).
const FAT_DEADLINE: Duration = Duration::from_secs(1500);
const SMALL_DEADLINE: Duration = Duration::from_secs(180);

fn hang_proof<T: Send + 'static>(deadline: Duration, body: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(body());
    });
    match rx.recv_timeout(deadline) {
        Ok(v) => v,
        Err(RecvTimeoutError::Disconnected) => panic!("test body panicked (see the failure output above)"),
        Err(RecvTimeoutError::Timeout) => {
            panic!("hang-proof deadline exceeded ({deadline:?}): a real rustc subprocess never completed — failing RED instead of hanging")
        }
    }
}

fn unique_dir(tag: &str) -> String {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    format!("/tmp/razel-fat-{tag}-{nanos}-{n}")
}

/// The REAL repo root (razel-dev): `CARGO_MANIFEST_DIR` is `<repo>/razel-host`; strip the last segment.
fn repo_root() -> String {
    let manifest = env!("CARGO_MANIFEST_DIR");
    match manifest.rfind('/') {
        Some(i) => manifest[..i].to_string(),
        None => manifest.to_string(),
    }
}

fn write(sys: &dyn System, path: &str, bytes: &[u8]) {
    sys.write_atomic(&HostPath::new(path.to_string()), bytes).unwrap_or_else(|e| panic!("write {path}: {e:?}"));
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
fn bin_artifact(pkg: &str, name: &str) -> NodeKey {
    NodeKey::from_key(&ArtifactRef {
        exec_path: format!("{pkg}/{name}"),
        producer: ArtifactProducer::Derived(GeneratingActionKey { owner: ct(pkg, name), action_index: 0 }),
    })
}

fn make_engine(
    sys: Arc<dyn System>,
    root: &str,
    repos: Option<ExternalRepos>,
    rustc: &HostPath,
    spawned: Arc<Mutex<Vec<String>>>,
) -> (razel_engine::Engine, Arc<InMemoryBlobStore>) {
    let blobs = Arc::new(InMemoryBlobStore::new());
    let strategy = Arc::new(RecordingLocal { inner: LocalSpawnStrategy::new(sys.clone()), spawned });
    let resolver = Arc::new(SameTargetOrSourceResolver);
    let mut platforms = HashMap::new();
    platforms.insert(HOST_CONFIG.to_string(), Platform { constraints: Vec::new() });
    let exec = RegisteredExecPlatform { name: "host".to_string(), constraints: Vec::new() };
    let (engine, registry) = match repos {
        Some(repos) => build_execution_engine_with_toolchains_and_repos(
            sys,
            HostPath::new(root.to_string()),
            repos,
            strategy,
            resolver,
            blobs.clone(),
            platforms,
            exec,
        ),
        None => build_execution_engine_with_toolchains(
            sys,
            HostPath::new(root.to_string()),
            strategy,
            resolver,
            blobs.clone(),
            platforms,
            exec,
        ),
    };
    registry.set_toolchains(&ConfigId(HOST_CONFIG.to_string()), vec![rust_toolchain(rustc)]);
    (engine, blobs)
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

/// Mach-O magic (macOS executables + dylibs): 64-bit / 32-bit thin (LE) + the universal wrappers.
fn is_macho(b: &[u8]) -> bool {
    b.len() >= 4
        && matches!(
            [b[0], b[1], b[2], b[3]],
            [0xCF, 0xFA, 0xED, 0xFE] | [0xCE, 0xFA, 0xED, 0xFE] | [0xCA, 0xFE, 0xBA, 0xBE] | [0xBF, 0xBA, 0xFE, 0xCA]
        )
}

// ──────────────── THE fat acceptance ────────────────

#[test]
fn fat_selfhost_builds_and_runs_razel() {
    hang_proof(FAT_DEADLINE, || {
        let sys: Arc<dyn System> = Arc::new(DarwinSystem);
        let Some(rustc) = rustc_or_skip(sys.as_ref(), "fat self-host") else { return };
        let repo = repo_root();
        // Requires the generated vendored layer (run `python3 tools/crates_gen`); absent ⇒ SKIP, never a false green.
        if !sys.exists(&HostPath::new(format!("{repo}/crates/BUILD.bazel"))).unwrap_or(false) {
            eprintln!("SKIP fat self-host: crates not generated — run `python3 tools/crates_gen`");
            return;
        }

        let spawned = Arc::new(Mutex::new(Vec::new()));
        let (engine, blobs) = make_engine(sys.clone(), &repo, Some(taut_shape_repos()), &rustc, spawned.clone());

        // THE build: the whole closure as a pure graph consequence. On failure, surface the exact frontier
        // (the failing action names its crate) — a partial closure that stops at a named crate is a reportable
        // outcome, never a silent wrong link.
        match engine.request(&completion("razel-daemon", "razel")) {
            Ok(_) => {}
            Err(e) => panic!(
                "razel build //razel-daemon:razel FAILED at the fat-closure frontier ({} crate actions ran before the stop): {e:?}",
                spawned.lock().unwrap().len()
            ),
        }
        let cold = spawned.lock().unwrap().len();
        eprintln!("fat self-host: cold build ran {cold} rustc actions over the full closure");

        // The shipped binary: a real Mach-O executable in the CAS, >1MB (the fat multi-call product carries real code).
        let bin_digest = {
            let v = engine.request(&bin_artifact("razel-daemon", "razel")).expect("the razel binary projects");
            v.as_any().downcast_ref::<ArtifactValue>().expect("an ArtifactValue").digest
        };
        let bin_bytes = blobs.get(&bin_digest).expect("the razel binary bytes in the ONE CAS home");
        assert!(is_macho(&bin_bytes), "the linked `razel` is a real Mach-O executable, not fabricated");
        assert!(
            bin_bytes.len() > 1_000_000,
            "the fat `razel` binary carries the full closure's code (>1MB); got {} bytes",
            bin_bytes.len()
        );

        // EXECUTE it (through the System::spawn seam — the wall bans std::process even in tests). No args ⇒ the
        // multi-call client prints its usage banner and exits 0 (a stable, side-effect-free invocation).
        let out = unique_dir("run");
        let bin_path = format!("{out}/razel");
        let cap = format!("{out}/razel.stdout");
        sys.write_atomic(&HostPath::new(bin_path.clone()), &bin_bytes).expect("emit the built binary");
        let env: EnvMap = [(EnvName("PATH".to_string()), OsValue("/usr/bin:/bin".to_string()))].into_iter().collect();
        let spec = ProcessSpec {
            program: HostPath::new("/bin/sh"),
            args: vec!["-c".to_string(), format!("/bin/chmod +x '{bin_path}' && '{bin_path}' > '{cap}' 2>&1")],
            env,
            cwd: HostPath::new(out.clone()),
        };
        let status = sys.spawn(&spec).expect("spawn the built razel binary");
        let captured = sys.read(&HostPath::new(cap)).expect("read captured stdout");
        let captured = String::from_utf8_lossy(&captured);
        assert_eq!(status.code, 0, "the fat `razel` binary runs (no args → usage) and exits 0; output: {captured:?}");
        assert!(
            captured.contains("a Bazel-compatible build tool"),
            "the built binary really ran and printed its multi-call usage banner; got: {captured:?}"
        );

        // Warm incrementality spot-check: re-request the SAME completion → the whole graph is memoized, ZERO new rustc.
        engine.request(&completion("razel-daemon", "razel")).expect("warm re-request");
        let warm_delta = spawned.lock().unwrap().len() - cold;
        assert_eq!(warm_delta, 0, "a warm re-request recompiles ZERO ({warm_delta} rustc re-spawns) — the fat build is incremental");

        let _ = sys.remove_dir_all(&HostPath::new(out));
    });
}

// ──────────────── the extern-rename mutant fixture (SMALL — never the giant closure) ────────────────

const ERRNO_LIKE_BUILD: &str = r#"load("//rules/rust:rust.bzl", "rust_library")
rust_library(name = "errno_like", srcs = ["lib.rs"], visibility = ["//visibility:public"])
"#;
const ERRNO_LIKE_LIB: &str = "pub fn code() -> u32 {\n    7\n}\n";

// The consumer's SOURCE names the dep by its RENAMED extern (`libc_errno`), mirroring rustix's
// `use libc_errno::errno` over the `errno` crate. The dep TARGET is `errno_like` (crate_name `errno_like`);
// `extern_renames = ["libc_errno"]` (index-parallel to `deps`) rewrites its `--extern` name to `libc_errno`.
const APP_BUILD: &str = r#"load("//rules/rust:rust.bzl", "rust_binary")
rust_binary(
    name = "app",
    srcs = ["main.rs"],
    deps = ["//errno_like:errno_like"],
    extern_renames = ["libc_errno"],
)
"#;
const APP_MAIN: &str = "fn main() {\n    println!(\"renamed: {}\", libc_errno::code());\n}\n";

/// Stage the shipped rust.bzl — MUTATED under `mutant_extern_rename_dropped` (neuter the rename branch). The
/// marker assertion is stale-proof: if rust.bzl's rename branch is reshaped, the mutant fails LOUDLY here
/// rather than silently no-op'ing into a false GREEN.
fn stage_rust_bzl(sys: &dyn System, repo: &str, ws: &str) {
    let real = sys.read(&HostPath::new(format!("{repo}/rules/rust/rust.bzl"))).expect("read rules/rust/rust.bzl");
    let bytes = if cfg!(feature = "mutant_extern_rename_dropped") {
        let s = String::from_utf8(real).expect("rust.bzl is utf-8");
        let marker = "if i < len(renames) and renames[i]:";
        assert!(
            s.contains(marker),
            "MUTANT STALE: rust.bzl's extern-rename branch marker ({marker:?}) not found — update mutant_extern_rename_dropped"
        );
        // Force the rename branch dead: the dep keeps its crate_name (`errno_like`) and `use libc_errno` fails.
        s.replace(marker, "if False and i < len(renames) and renames[i]:").into_bytes()
    } else {
        real
    };
    write(sys, &format!("{ws}/rules/rust/rust.bzl"), &bytes);
}

#[test]
fn extern_rename_resolves_through_the_rename_attr() {
    hang_proof(SMALL_DEADLINE, || {
        let sys: Arc<dyn System> = Arc::new(DarwinSystem);
        let Some(rustc) = rustc_or_skip(sys.as_ref(), "extern-rename fixture") else { return };
        let repo = repo_root();
        let ws = unique_dir("rename");

        stage_rust_bzl(sys.as_ref(), &repo, &ws);
        write(sys.as_ref(), &format!("{ws}/errno_like/BUILD.bazel"), ERRNO_LIKE_BUILD.as_bytes());
        write(sys.as_ref(), &format!("{ws}/errno_like/lib.rs"), ERRNO_LIKE_LIB.as_bytes());
        write(sys.as_ref(), &format!("{ws}/app/BUILD.bazel"), APP_BUILD.as_bytes());
        write(sys.as_ref(), &format!("{ws}/app/main.rs"), APP_MAIN.as_bytes());

        let spawned = Arc::new(Mutex::new(Vec::new()));
        let (engine, blobs) = make_engine(sys.clone(), &ws, None, &rustc, spawned.clone());

        let built = run_build_configured(
            &engine,
            blobs.as_ref(),
            sys.as_ref(),
            &HostPath::new(ws.clone()),
            "//app:app",
            Some(HOST_CONFIG),
        );
        // GREEN: the rename resolves `use libc_errno`. RED under mutant_extern_rename_dropped: `--extern
        // errno_like` is emitted instead, `use libc_errno` fails E0432, and the build fails closed.
        built.expect("razel build //app:app succeeds — the extern_renames attr rewrites --extern errno_like → libc_errno");

        // Prove it actually linked + runs (not a vacuous green): the binary prints the renamed call's result.
        let bin = copy_and_run(sys.as_ref(), &ws, "app", "app");
        assert_eq!(bin.0, 0, "the renamed-dep binary runs and exits 0");
        assert_eq!(String::from_utf8_lossy(&bin.1).trim(), "renamed: 7", "the renamed extern linked and ran");

        let _ = sys.remove_dir_all(&HostPath::new(ws));
    });
}

/// chmod +x the emitted binary and run it via the System seam, capturing stdout.
fn copy_and_run(sys: &dyn System, root: &str, pkg: &str, name: &str) -> (i32, Vec<u8>) {
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
    let out = sys.read(&HostPath::new(format!("{root}/{pkg}/{name}.out.txt"))).expect("read the binary's stdout");
    (status.code, out)
}
