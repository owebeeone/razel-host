//! THE T17 PHASE-A ACCEPTANCE PROOF (external source roots, ADR-0011 "new_local_repository parity"):
//! `razel build //razel-cli:razel_client_stub` — razel linking its OWN real CLI stub binary, whose `razel-comms` leg
//! genuinely `use taut_shape::…` from an EXTERNAL crate that lives OUTSIDE the workspace
//! (`taut-dev/taut-shape-rs/crates/taut-shape`, read-only, NEVER modified). This closes the fork that
//! `self_host.rs` stopped one hop short of (it proved up to `//razel-wire-cbor`; the cli needs the external
//! taut-shape leg through `razel-comms`).
//!
//! Two proofs:
//!   (BAR-A, acceptance) `self_host_builds_and_runs_real_razel_cli` — builds `//razel-cli:razel_client_stub` READ-ONLY
//!     against the REAL workspace + REAL taut-shape root (injected `ExternalRepos`), verifies the linked
//!     binary is a real Mach-O executable in the ONE CAS, then EXECUTES it (through the `System::spawn`
//!     seam — the raw-OS wall bans `std::process` even in tests) and asserts its skeleton behaviour.
//!   (incrementality) `external_root_edit_touch_granularity` — over a COPIED fixture with a FAKE external
//!     repo in a temp dir (taut-dev is never touched): editing the EXTERNAL source re-runs it + its
//!     dependent (the external FileState edge works); editing the internal dependent re-runs ONLY it (the
//!     external upstream rlib is stable); a TOUCH (identical bytes) re-runs NOTHING (early cutoff at FILE).
//!
//! HANG-PROOF: every body runs under a bounded deadline (the cli link is ~8 real rustc subprocesses) so a
//! wedged compile is a terminating RED, never a hang. No rustc discoverable ⇒ SKIP-with-reason.

use razel_action::{
    ArtifactProducer, ArtifactRef, ArtifactValue, BlobStore, GeneratingActionKey, InMemoryBlobStore,
    OutputSelection, SameTargetOrSourceResolver, TargetCompletionKey,
};
use razel_analysis::ConfiguredTargetKey;
use razel_core::NodeKey;
use razel_engine_api::{ChangedLeaf, DemandEngine, Diff, FailurePolicy};
use razel_exec_api::{ExecError, SpawnRequest, SpawnResult, SpawnStrategy};
use razel_host::rust_toolchain::{discover_rustc, rust_toolchain, HOST_CONFIG};
use razel_host::{build_execution_engine_with_toolchains_and_repos, taut_shape_repos, ExternalRepo, ExternalRepos, LocalSpawnStrategy};
use razel_ids::{ConfigId, RootRelativePath};
use razel_os_api::{EnvMap, EnvName, HostPath, OsValue, ProcessSpec, System};
use razel_os_darwin::DarwinSystem;
use razel_source::FileStateKey;
use razel_toolchain::{Platform, RegisteredExecPlatform};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ──────────────── hang-proof harness (self_host.rs twin; the cli link needs a wide deadline) ────────────────
const HANG_DEADLINE: Duration = Duration::from_secs(300);

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

fn unique_dir(tag: &str) -> String {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    format!("/tmp/razel-t17-{tag}-{nanos}-{n}")
}

/// The REAL repo root: `CARGO_MANIFEST_DIR` is `<repo>/razel-host`; strip the last segment. Pure string.
fn repo_root() -> String {
    let manifest = env!("CARGO_MANIFEST_DIR");
    match manifest.rfind('/') {
        Some(i) => manifest[..i].to_string(),
        None => manifest.to_string(),
    }
}

// ──────────────── a spawn-RECORDING wrapper around the REAL LocalSpawnStrategy (the granularity oracle) ────────────────
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
    // A rust_binary's single default output: exec-path `<pkg>/<name>`, produced by the target's action #0.
    NodeKey::from_key(&ArtifactRef {
        exec_path: format!("{pkg}/{name}"),
        producer: ArtifactProducer::Derived(GeneratingActionKey { owner: ct(pkg, name), action_index: 0 }),
    })
}
fn fskey(p: &str) -> NodeKey {
    NodeKey::from_key(&FileStateKey(RootRelativePath(p.into())))
}

fn make_engine(
    sys: Arc<dyn System>,
    root: &str,
    repos: ExternalRepos,
    rustc: &HostPath,
    spawned: Arc<Mutex<Vec<String>>>,
) -> (razel_engine::Engine, Arc<InMemoryBlobStore>) {
    let blobs = Arc::new(InMemoryBlobStore::new());
    let strategy = Arc::new(RecordingLocal { inner: LocalSpawnStrategy::new(sys.clone()), spawned });
    let mut platforms = HashMap::new();
    platforms.insert(HOST_CONFIG.to_string(), Platform { constraints: Vec::new() });
    let (engine, registry) = build_execution_engine_with_toolchains_and_repos(
        sys,
        HostPath::new(root.to_string()),
        repos,
        strategy,
        Arc::new(SameTargetOrSourceResolver),
        blobs.clone(),
        platforms,
        RegisteredExecPlatform { name: "host".to_string(), constraints: Vec::new() },
    );
    registry.set_toolchains(&ConfigId(HOST_CONFIG.to_string()), vec![rust_toolchain(rustc)]);
    (engine, blobs)
}

fn rustc_or_skip(sys: &dyn System) -> Option<HostPath> {
    match discover_rustc(sys) {
        Ok(p) => Some(p),
        Err(e) => {
            eprintln!("SKIP external_roots: no rustc discoverable on this machine: {e:?}");
            None
        }
    }
}

/// Mach-O magic (macOS executables/objects): 64-bit and 32-bit thin (little-endian on Apple platforms) plus
/// the universal/fat wrappers. A real linked binary starts with one of these.
fn is_macho(b: &[u8]) -> bool {
    b.len() >= 4
        && matches!(
            [b[0], b[1], b[2], b[3]],
            [0xCF, 0xFA, 0xED, 0xFE] // MH_MAGIC_64 (arm64 / x86_64, LE)
                | [0xCE, 0xFA, 0xED, 0xFE] // MH_MAGIC (32-bit, LE)
                | [0xCA, 0xFE, 0xBA, 0xBE] // FAT_MAGIC (universal, BE)
                | [0xBF, 0xBA, 0xFE, 0xCA] // FAT_MAGIC_64 (LE variant)
        )
}

#[test]
fn self_host_builds_and_runs_real_razel_cli() {
    hang_proof(|| {
        let sys: Arc<dyn System> = Arc::new(DarwinSystem);
        let Some(rustc) = rustc_or_skip(sys.as_ref()) else { return };
        // Build over the REAL repo root, READ-ONLY, with the REAL taut-shape external root injected. razel
        // compiles its own committed crates in place AND the external taut-shape crate from the sibling
        // taut-dev checkout (read-only) — the whole `//razel-cli:razel_client_stub` closure as a pure graph consequence.
        let repo = repo_root();
        let repos = taut_shape_repos(); // the real seed: taut-shape → taut-dev/…/crates/taut-shape

        let spawned = Arc::new(Mutex::new(Vec::new()));
        let (engine, blobs) = make_engine(sys.clone(), &repo, repos, &rustc, spawned.clone());

        // THE build: request completion of the headline target. The external taut-shape leg
        // (razel-comms → @taut-shape//:taut_shape) is now resolvable, so the whole closure links.
        engine
            .request(&completion("razel-cli", "razel_client_stub"))
            .expect("razel build //razel-cli:razel_client_stub succeeds (external taut-shape leg resolves)");

        // The external taut-shape rlib was really compiled — its bytes are a real ar archive in the ONE CAS,
        // proving the external source root fed rustc the true sources. NB the D1 two-space split: the ARTIFACT
        // exec_path is EXEC space (`external/taut-shape/…`) while the producing CT owner is LABEL space
        // (`@taut-shape//`) — they are deliberately different strings for the same target.
        let taut_rlib = NodeKey::from_key(&ArtifactRef {
            exec_path: "external/taut-shape/libtaut_shape.rlib".to_string(),
            producer: ArtifactProducer::Derived(GeneratingActionKey {
                owner: ct("@taut-shape//", "taut_shape"),
                action_index: 0,
            }),
        });
        let taut_digest = {
            let v = engine.request(&taut_rlib).expect("taut_shape rlib projects");
            v.as_any().downcast_ref::<ArtifactValue>().expect("an ArtifactValue").digest
        };
        let taut_bytes = blobs.get(&taut_digest).expect("taut_shape rlib bytes in the ONE home");
        assert!(taut_bytes.starts_with(b"!<arch>"), "the EXTERNAL taut-shape rlib is a real rustc archive (ar magic)");

        // The headline binary: a real Mach-O executable in the CAS (razel really LINKED its own cli stub).
        let bin_digest = {
            let v = engine.request(&bin_artifact("razel-cli", "razel_client_stub")).expect("razel stub bin projects");
            v.as_any().downcast_ref::<ArtifactValue>().expect("an ArtifactValue").digest
        };
        let bin_bytes = blobs.get(&bin_digest).expect("razel bin bytes in the ONE home");
        assert!(is_macho(&bin_bytes), "the linked `razel` binary is a real Mach-O executable, not fabricated");
        assert!(bin_bytes.len() > 4096, "the linked binary carries real code (non-trivial size)");

        // EXECUTE it (through the System seam — the wall bans std::process even in tests). write_atomic emits
        // mode 0644, so `/bin/sh` sets +x then runs it, capturing stdout to a file we read back via the seam.
        let out = unique_dir("run");
        let bin_path = format!("{out}/razel");
        let cap = format!("{out}/razel.stdout");
        sys.write_atomic(&HostPath::new(bin_path.clone()), &bin_bytes).expect("emit the built binary");
        let env: EnvMap = [(EnvName("PATH".to_string()), OsValue("/usr/bin:/bin".to_string()))].into_iter().collect();
        let spec = ProcessSpec {
            program: HostPath::new("/bin/sh"),
            args: vec![
                "-c".to_string(),
                format!("/bin/chmod +x '{bin_path}' && '{bin_path}' > '{cap}' 2>&1"),
            ],
            env,
            cwd: HostPath::new(out.clone()),
        };
        let status = sys.spawn(&spec).expect("spawn the built razel binary");
        assert_eq!(status.code, 0, "the razel cli skeleton binary runs and exits 0");
        let captured = sys.read(&HostPath::new(cap)).expect("read captured stdout");
        let captured = String::from_utf8_lossy(&captured);
        assert!(
            captured.contains("razel-cli skeleton"),
            "the built binary really ran and printed its banner; got: {captured:?}"
        );

        let _ = sys.remove_dir_all(&HostPath::new(out));
    });
}

// ──────────────── fixture incrementality: a FAKE external repo in a temp dir (taut-dev untouched) ────────────────
fn write(sys: &dyn System, path: &str, bytes: &[u8]) {
    sys.write_atomic(&HostPath::new(path.to_string()), bytes).unwrap_or_else(|e| panic!("write {path}: {e:?}"));
}

#[test]
fn external_root_edit_touch_granularity() {
    hang_proof(|| {
        let sys: Arc<dyn System> = Arc::new(DarwinSystem);
        let Some(rustc) = rustc_or_skip(sys.as_ref()) else { return };
        let repo = repo_root();

        // A private workspace + a SEPARATE fake external repo dir (edits below hit these copies only).
        let ws = unique_dir("ws");
        let ext = unique_dir("ext");

        // The real ruleset (copied, so the fixture reads the SAME rust.bzl the product ships).
        let rust_bzl = sys.read(&HostPath::new(format!("{repo}/rules/rust/rust.bzl"))).expect("read rust.bzl");
        write(sys.as_ref(), &format!("{ws}/rules/rust/rust.bzl"), &rust_bzl);
        // The overlay BUILD for the fake external repo (MAIN-root relative — the overlay wins).
        write(
            sys.as_ref(),
            &format!("{ws}/overlays/fake/BUILD.bazel"),
            b"load(\"//rules/rust:rust.bzl\", \"rust_library\")\nrust_library(name = \"fakelib\", srcs = [\"src/lib.rs\"], visibility = [\"//visibility:public\"])\n",
        );
        // An internal app that DEPENDS on the external crate (extern name = the dep target name `fakelib`).
        write(
            sys.as_ref(),
            &format!("{ws}/app/BUILD.bazel"),
            b"load(\"//rules/rust:rust.bzl\", \"rust_library\")\nrust_library(name = \"app\", srcs = [\"src/lib.rs\"], deps = [\"@fake//:fakelib\"])\n",
        );
        write(sys.as_ref(), &format!("{ws}/app/src/lib.rs"), b"pub fn go() -> u8 { fakelib::v() }\n");
        // The FAKE external source lives in the external root (NOT under the workspace).
        write(sys.as_ref(), &format!("{ext}/src/lib.rs"), b"pub fn v() -> u8 { 1 }\n");

        let repos = ExternalRepos::from_pairs([(
            "fake".to_string(),
            ExternalRepo {
                root: HostPath::new(ext.clone()),
                build_file: Some(RootRelativePath("overlays/fake/BUILD.bazel".to_string())),
            },
        )]);

        let spawned = Arc::new(Mutex::new(Vec::new()));
        let (engine, _blobs) = make_engine(sys.clone(), &ws, repos, &rustc, spawned.clone());
        let tc = completion("app", "app");
        let seq = || spawned.lock().unwrap().clone();

        // The exec paths (D1: `@fake//:fakelib` → exec prefix `external/fake`).
        let fake_rlib = "external/fake/libfakelib.rlib".to_string();
        let app_rlib = "app/libapp.rlib".to_string();

        // cold: both compile, external dep FIRST (dep order) — proving the external source read + link work.
        engine.request(&tc).expect("cold external-root build");
        assert_eq!(seq(), vec![fake_rlib.clone(), app_rlib.clone()], "cold: external fakelib, then app");

        // (a) edit the EXTERNAL source → its FileState (keyed by the exec path) dirties, fakelib re-compiles,
        // its rlib bytes change, and app re-links against the new rlib. The external invalidation edge works.
        write(sys.as_ref(), &format!("{ext}/src/lib.rs"), b"pub fn v() -> u8 { 1 }\npub fn __probe() -> u8 { 9 }\n");
        engine.evaluate(
            &[tc.clone()],
            FailurePolicy::FailFast,
            Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(fskey("external/fake/src/lib.rs"))] },
        );
        assert_eq!(
            seq()[2..],
            [fake_rlib.clone(), app_rlib.clone()],
            "an EXTERNAL-source edit re-runs fakelib + its dependent app (external FileState edge works)"
        );

        // (b) edit the INTERNAL dependent → ONLY app re-compiles; the external upstream rlib is unchanged, so
        // fakelib does NOT re-run (granular re-run across the external boundary).
        write(sys.as_ref(), &format!("{ws}/app/src/lib.rs"), b"pub fn go() -> u8 { fakelib::v() + 0 }\n");
        engine.evaluate(
            &[tc.clone()],
            FailurePolicy::FailFast,
            Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(fskey("app/src/lib.rs"))] },
        );
        assert_eq!(seq()[4..], [app_rlib.clone()], "an INTERNAL edit re-runs ONLY app — the external upstream is stable");

        // (c) TOUCH the external source (write IDENTICAL bytes) → FileState dirties but FILE content is
        // unchanged → ZERO re-compiles (early cutoff at FILE, over the external path).
        write(sys.as_ref(), &format!("{ext}/src/lib.rs"), b"pub fn v() -> u8 { 1 }\npub fn __probe() -> u8 { 9 }\n");
        engine.evaluate(
            &[tc.clone()],
            FailurePolicy::FailFast,
            Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(fskey("external/fake/src/lib.rs"))] },
        );
        assert_eq!(seq().len(), 5, "a TOUCH of the external source re-compiles NOTHING — early cutoff at FILE");

        let _ = sys.remove_dir_all(&HostPath::new(ws));
        let _ = sys.remove_dir_all(&HostPath::new(ext));
    });
}
