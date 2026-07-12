//! T19-P2 PILOT — the vendored third-party layer + the `alias` hub, built END TO END through REAL `rustc`.
//!
//! A consumer `rust_binary` depends on FIVE vendored crates SOLELY through the `//crates:<crate>`
//! hub ALIASES (never the versioned packages directly). The generated tree + the shipped `rules/rust/rust.bzl`
//! are staged verbatim from the repo (this test exercises the GENERATOR'S OUTPUT + the SHIPPED ruleset, not a
//! hand-written fixture). The build compiles all five crates + the consumer with real rustc; the emitted
//! binary RUNS and prints `pilot ok: 11`. It exercises, through the alias:
//!   * `cfg-if` — a trivial leaf `rust_library` (edition 2018, no deps, no build script).
//!   * `anyhow` — a dependency-free real std crate (a build.rs with NO consumable directives on this host).
//!   * `memoffset` — the BUILD-SCRIPT-DIRECTIVES proof: its `cargo_build_script` bakes `--cfg maybe_uninit`
//!     &c. harvested from cargo's own build output, so `offset_of!` compiles (edition 2015).
//!   * `crossbeam-utils` — a mid-complexity real crate (replacing blake3, which the closure resolves with NEON
//!     asm + a cc-compiled static lib — no native-cc in razel P1; SKIPPED, see the generator MANIFEST).
//!   * `paste` — a PROC-MACRO crate (`rust_proc_macro` → host dylib) consumed via `proc_macro_deps`.
//!
//! ALIAS PROVIDER-PASSTHROUGH is the property under test: the consumer reads each dep's `RustInfo` through the
//! alias. RED under `mutant_alias_breaks_provider_passthrough` — the alias forwards EMPTY providers, the
//! consumer's `dep[RustInfo]` read fails, and the build fails closed (the gate drives it `--features … expect_red`).
//!
//! HANG-PROOF (the rust_p1.rs pattern): a bounded deadline turns a wedged rustc into a terminating RED. No
//! rustc discoverable ⇒ SKIP-with-reason. Third-party crates are MAIN-REPO packages, so the INTERNAL engine
//! builder is used (no ExternalRepos) and the toolchain is injected at the composition root.

use razel_action::{InMemoryBlobStore, SameTargetOrSourceResolver};
use razel_exec_api::{ExecError, SpawnRequest, SpawnResult, SpawnStrategy};
use razel_host::rust_toolchain::{discover_rustc, rust_toolchain, HOST_CONFIG};
use razel_host::{build_execution_engine_with_toolchains, run_build_configured, LocalSpawnStrategy};
use razel_ids::ConfigId;
use razel_os_api::{EnvMap, FileKind, HostPath, ProcessSpec, System};
use razel_os_darwin::DarwinSystem;
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
    format!("/tmp/razel-tp-{nanos}-{n}")
}

/// The repo root (razel-dev): `CARGO_MANIFEST_DIR` is `.../razel-host`; the generated tree + ruleset live one
/// dir up. The generator must have produced `crates/` (run `python3 tools/crates_gen`); absent it,
/// the test SKIPs-with-reason (never a false green).
fn repo_root() -> String {
    format!("{}/..", env!("CARGO_MANIFEST_DIR"))
}

fn write(sys: &dyn System, path: &str, bytes: &[u8]) {
    sys.write_atomic(&HostPath::new(path.to_string()), bytes).unwrap_or_else(|e| panic!("write {path}: {e:?}"));
}

/// Recursively copy a source tree into the staged workspace THROUGH the System seam (`list_dir` is
/// byte-sorted deterministic) — the razel-idiomatic copy (no std::fs; the raw-OS wall stays clean).
fn copy_tree(sys: &dyn System, src: &str, dst: &str) {
    sys.create_dir_all(&HostPath::new(dst.to_string())).unwrap_or_else(|e| panic!("mkdir {dst}: {e:?}"));
    for frag in sys.list_dir(&HostPath::new(src.to_string())).unwrap_or_else(|e| panic!("list {src}: {e:?}")) {
        let name = frag.as_str();
        let s = format!("{src}/{name}");
        let d = format!("{dst}/{name}");
        let is_dir = sys.stat(&HostPath::new(s.clone())).map(|m| m.kind == FileKind::Dir).unwrap_or(false);
        if is_dir {
            copy_tree(sys, &s, &d);
        } else {
            let bytes = sys.read(&HostPath::new(s.clone())).unwrap_or_else(|e| panic!("read {s}: {e:?}"));
            write(sys, &d, &bytes);
        }
    }
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
    let out = sys.read(&HostPath::new(format!("{root}/{pkg}/{name}.out.txt"))).expect("read the binary's stdout");
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

/// The pilot crates (versioned dir names in the generated tree). Chosen to cover the machinery: a trivial leaf,
/// a dependency-free real crate, a build-script-cfg crate, a mid-complexity crate, and a proc-macro. See the
/// module doc for why blake3 is SKIPPED (native-cc) and this set stands in.
const PILOT_CRATES: &[&str] =
    &["cfg-if-1.0.4", "anyhow-1.0.103", "memoffset-0.9.1", "crossbeam-utils-0.8.21", "paste-1.0.15"];

const CONSUMER_BUILD: &str = r#"load("//rules/rust:rust.bzl", "rust_binary")
rust_binary(
    name = "app",
    srcs = ["main.rs"],
    deps = [
        "//crates:anyhow",
        "//crates:cfg-if",
        "//crates:crossbeam-utils",
        "//crates:memoffset",
    ],
    proc_macro_deps = ["//crates:paste"],
)
"#;

// Uses every dep so the rlibs + the proc-macro dylib are genuinely linked: paste! expands a fn, memoffset's
// offset_of! (needs the baked `--cfg maybe_uninit` &c.) returns 4, anyhow wraps the result → "pilot ok: 11".
const CONSUMER_MAIN: &str = r#"use paste::paste;
paste! { fn [<hello_ world>]() -> u32 { 7 } }
struct Pt { _x: u32, y: u32 }
fn main() {
    cfg_if::cfg_if! { if #[cfg(unix)] { let _plat = "unix"; } else { let _plat = "other"; } }
    let off = memoffset::offset_of!(Pt, y);
    let _cu: crossbeam_utils::CachePadded<u32> = crossbeam_utils::CachePadded::new(1);
    let r: anyhow::Result<u32> = Ok(hello_world() + off as u32);
    println!("pilot ok: {}", r.unwrap());
}
"#;

/// Stage the generated tree + the shipped ruleset + the consumer into a fresh workspace. Returns false (SKIP)
/// if the generator has not produced `crates/` yet.
fn stage_pilot(sys: &dyn System, ws: &str) -> bool {
    let repo = repo_root();
    let tp = format!("{repo}/crates");
    if !sys.exists(&HostPath::new(format!("{tp}/BUILD.bazel"))).unwrap_or(false) {
        eprintln!("SKIP: {tp} not generated — run `python3 tools/crates_gen` first (the vendored layer)");
        return false;
    }
    // the SHIPPED ruleset (copied verbatim — the test proves the generated BUILDs work with the real rust.bzl).
    let rust_bzl = sys.read(&HostPath::new(format!("{repo}/rules/rust/rust.bzl"))).expect("read rules/rust/rust.bzl");
    write(sys, &format!("{ws}/rules/rust/rust.bzl"), &rust_bzl);
    // the hub package (all aliases; only the pilot ones get analyzed) + the pilot crate packages.
    let hub = sys.read(&HostPath::new(format!("{tp}/BUILD.bazel"))).expect("read hub BUILD");
    write(sys, &format!("{ws}/crates/BUILD.bazel"), &hub);
    for c in PILOT_CRATES {
        copy_tree(sys, &format!("{tp}/{c}"), &format!("{ws}/crates/{c}"));
    }
    write(sys, &format!("{ws}/consumer/BUILD.bazel"), CONSUMER_BUILD.as_bytes());
    write(sys, &format!("{ws}/consumer/main.rs"), CONSUMER_MAIN.as_bytes());
    true
}

#[test]
fn vendored_crates_hub_alias_builds_pilot_end_to_end() {
    hang_proof(|| {
        let sys: Arc<dyn System> = Arc::new(DarwinSystem);
        let Some(rustc) = rustc_or_skip(sys.as_ref(), "third-party pilot") else { return };
        let ws = unique_root();
        if !stage_pilot(sys.as_ref(), &ws) {
            return;
        }

        let spawned = Arc::new(Mutex::new(Vec::new()));
        let (engine, blobs) = make_engine(sys.clone(), &ws, &rustc, spawned.clone());

        // THE build: the consumer reaches all five crates ONLY through the `//crates:<crate>`
        // hub aliases. The alias forwards each actual crate's `RustInfo` (crate_name + rlib + transitive_rlibs)
        // AND its dep-output chaining, so the consumer's rustc gets `--extern <crate>=<rlib>` and the rlib
        // resolves to its producing action. (RED under `mutant_alias_breaks_provider_passthrough`: the alias
        // drops the providers, `dep[RustInfo]` in rust.bzl fails, and this build errors — the gate drives it.)
        run_build_configured(
            &engine,
            blobs.as_ref(),
            sys.as_ref(),
            &HostPath::new(ws.clone()),
            "//consumer:app",
            Some(HOST_CONFIG),
        )
        .expect("razel build //consumer:app succeeds through the hub aliases (alias provider-passthrough)");

        let (code, out) = run_bin(sys.as_ref(), &ws, "consumer", "app");
        assert_eq!(code, 0, "the pilot binary runs and exits zero");
        assert_eq!(
            String::from_utf8_lossy(&out).trim(),
            "pilot ok: 11",
            "the binary links all five vendored crates through the alias hub (paste! + offset_of! + anyhow)"
        );

        let _ = sys.remove_dir_all(&HostPath::new(ws));
    });
}
