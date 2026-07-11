//! THE SELF-HOST PROOF (rust-rules wave 2): `razel build //razel-wire-cbor:razel_wire_cbor` — razel
//! compiling its OWN real crates through its own graph with REAL `rustc`. The deepest FULLY-IN-WORKSPACE
//! chain of razel-cli's build closure:
//!
//!   //razel-wire-cbor:razel_wire_cbor  (rust_library, src/lib.rs — `use razel_wire_api` only)
//!     └─ //razel-wire-api:razel_wire_api  (rust_library, 4 srcs incl. nested src/protocol/generated.rs)
//!          └─ //razel-core:razel_core     (rust_library, src/lib.rs + src/mock.rs — the spine, NO deps)
//!
//! This composes wave 2's four items over the REAL committed `rules/rust/rust.bzl` + per-crate `BUILD.bazel`:
//!   (1) MULTI-FILE crates — razel-core (2 srcs) and razel-wire-api (4 srcs, a NESTED module dir) stage their
//!       whole module tree into the exec root (relative layout preserved) and compile from the crate root.
//!   (2) TRANSITIVE rlib propagation — razel-wire-cbor's source names ONLY razel_wire_api, so razel_core
//!       reaches its link ONLY transitively (rustc gets `--extern razel_wire_api` + `-L dependency=` for
//!       BOTH razel-wire-api's AND razel-core's dirs). razel_core's rlib is a dep-of-dep INPUT of
//!       razel-wire-cbor's action, resolved through the CT's TRANSITIVELY-merged `dep_outputs` map.
//!   (4) PROOF + incrementality — real ar-magic rlibs, and MULTI-LEVEL granularity: a LEAF (razel-core) edit
//!       re-compiles the whole chain; a MID (razel-wire-api) edit re-compiles only it + its dependent; a
//!       TOUCH (identical bytes) re-compiles nothing.
//!
//! Row red-first mutant (tools/gate.sh, unfiltered, requires RED):
//!   mutant_transitive_outputs_not_merged → the transitive `dep_outputs` merge is dropped, so razel-core's
//!     rlib (a dep-of-dep of razel-wire-cbor) can no longer resolve to its producer; it falls to Source, the
//!     file is absent on disk, and `razel build //razel-wire-cbor:razel_wire_cbor` fails closed (typed
//!     NotFound) — this whole chain proof goes RED (terminating).
//!
//! HANG-PROOF: every body runs under a bounded deadline (three real rustc subprocesses) so a wedged compile
//! is a terminating RED, never a hang. No rustc discoverable ⇒ SKIP-with-reason (the documented fail-closed
//! skip, never an absorb inside the build).

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
use razel_os_api::{HostPath, System};
use razel_os_darwin::DarwinSystem;
use razel_source::FileStateKey;
use razel_toolchain::{Platform, RegisteredExecPlatform};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ──────────────── hang-proof harness (rust_rules.rs twin; three rustc compiles need the wide deadline) ────────────────
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
    format!("/tmp/razel-selfhost-{nanos}-{n}")
}

/// The REAL repo root: `CARGO_MANIFEST_DIR` is `<repo>/razel-host`; strip the last segment. Pure string —
/// no `..` in the path, no host I/O here.
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

// ──────────────── the in-workspace chain (real committed BUILD/srcs — no synthetic fixture) ────────────────
// The files razel READS to build the chain. Every path is a REAL committed file; the incrementality test
// STAGES copies of these into a private temp root (so its edits never touch the repo). rules/rust/BUILD.bazel
// is intentionally omitted — the razel v1 loader resolves the `.bzl` directly, it is never read for a build.
const CHAIN_FILES: &[&str] = &[
    "rules/rust/rust.bzl",
    "razel-core/BUILD.bazel",
    "razel-core/src/lib.rs",
    "razel-core/src/mock.rs",
    "razel-wire-api/BUILD.bazel",
    "razel-wire-api/src/lib.rs",
    "razel-wire-api/src/cbor.rs",
    "razel-wire-api/src/protocol.rs",
    "razel-wire-api/src/protocol/generated.rs",
    "razel-wire-cbor/BUILD.bazel",
    "razel-wire-cbor/src/lib.rs",
];

/// Read one repo file through the System seam (no raw `std::fs` — the raw-OS wall holds even in tests).
fn read_repo(sys: &dyn System, repo: &str, rel: &str) -> Vec<u8> {
    sys.read(&HostPath::new(format!("{repo}/{rel}"))).unwrap_or_else(|e| panic!("read repo file {rel}: {e:?}"))
}

/// Copy the whole chain (real crates + real rules + real BUILD files) into a private temp root, so the
/// incrementality test can edit COPIES. `write_atomic` materializes the nested module dirs.
fn stage_chain(sys: &dyn System, repo: &str, tmp: &str) {
    for rel in CHAIN_FILES {
        let bytes = read_repo(sys, repo, rel);
        sys.write_atomic(&HostPath::new(format!("{tmp}/{rel}")), &bytes).unwrap_or_else(|e| panic!("stage {rel}: {e:?}"));
    }
}

// ──────────────── keys (all carry the HOST_CONFIG session configuration — toolchain resolution needs it) ────────────────
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
/// The rlib ARTIFACT key of a `rust_library` target: exec-path `<pkg>/lib<name>.rlib`, produced by the
/// target's action #0.
fn rlib_artifact(pkg: &str, name: &str) -> NodeKey {
    NodeKey::from_key(&ArtifactRef {
        exec_path: format!("{pkg}/lib{name}.rlib"),
        producer: ArtifactProducer::Derived(GeneratingActionKey { owner: ct(pkg, name), action_index: 0 }),
    })
}
fn fskey(p: &str) -> NodeKey {
    NodeKey::from_key(&FileStateKey(RootRelativePath(p.into())))
}

/// Assemble the toolchain-enabled execution engine over the REAL DarwinSystem + the recording strategy,
/// rooted at `root`; seed the "rust" toolchain (discovered rustc) under HOST_CONFIG.
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

/// SKIP-with-reason when no rustc is discoverable (documented fail-closed skip; this machine has cargo, so
/// the proof runs in practice).
fn rustc_or_skip(sys: &dyn System) -> Option<HostPath> {
    match discover_rustc(sys) {
        Ok(p) => Some(p),
        Err(e) => {
            eprintln!("SKIP self_host: no rustc discoverable on this machine: {e:?}");
            None
        }
    }
}

/// The three rlib outputs of the chain, in dependency (compile) order.
const CHAIN_SPAWNS: [&str; 3] = [
    "razel-core/librazel_core.rlib",
    "razel-wire-api/librazel_wire_api.rlib",
    "razel-wire-cbor/librazel_wire_cbor.rlib",
];

#[test]
fn self_host_builds_real_wire_cbor_chain() {
    hang_proof(|| {
        let sys: Arc<dyn System> = Arc::new(DarwinSystem);
        let Some(rustc) = rustc_or_skip(sys.as_ref()) else { return };
        // Build over the REAL repo root, READ-ONLY: razel compiles its own committed crates in place
        // (real BUILD files, real srcs, real rules/rust/rust.bzl). No disk emit, no repo mutation — the
        // proof is the graph consequence + the real rlib bytes in the CAS.
        let repo = repo_root();

        let spawned = Arc::new(Mutex::new(Vec::new()));
        let (engine, blobs) = make_engine(sys.clone(), &repo, &rustc, spawned.clone());

        // THE build: request completion of the deepest in-workspace target. The whole chain
        // (core → wire-api → wire-cbor) builds as a pure graph consequence — three REAL rustc subprocesses.
        engine
            .request(&completion("razel-wire-cbor", "razel_wire_cbor"))
            .expect("razel build //razel-wire-cbor:razel_wire_cbor succeeds");

        // Exactly three rustc spawns, in dependency order (the spine first, the codec impl last).
        assert_eq!(
            *spawned.lock().unwrap(),
            CHAIN_SPAWNS.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            "cold self-host build = razel_core, then razel_wire_api, then razel_wire_cbor (real rustc, dep-ordered)"
        );

        // Each of the THREE rlibs is REAL rustc output — an ar archive ("!<arch>") in the ONE CAS home,
        // projected through ARTIFACT (razel really compiled its own crates, nothing fabricated).
        for (pkg, name) in [
            ("razel-core", "razel_core"),
            ("razel-wire-api", "razel_wire_api"),
            ("razel-wire-cbor", "razel_wire_cbor"),
        ] {
            let digest = {
                let v = engine.request(&rlib_artifact(pkg, name)).unwrap_or_else(|e| panic!("{pkg} rlib projects: {e:?}"));
                v.as_any().downcast_ref::<razel_action::ArtifactValue>().expect("an ArtifactValue").digest
            };
            let bytes = blobs.get(&digest).expect("rlib bytes in the ONE home");
            assert!(
                bytes.starts_with(b"!<arch>"),
                "{pkg}'s rlib is a REAL rustc archive (ar magic), not fabricated"
            );
            assert!(bytes.len() > 1024, "{pkg}'s rlib carries real compiled metadata (non-trivial size)");
        }
    });
}

#[test]
fn self_host_emits_headline_rlib_to_disk() {
    hang_proof(|| {
        let sys: Arc<dyn System> = Arc::new(DarwinSystem);
        let Some(rustc) = rustc_or_skip(sys.as_ref()) else { return };
        // Stage the chain into a private temp root so the EMIT writes there (never into the repo), then run
        // the full `build` verb (request TARGET_COMPLETION + emit the default output to disk).
        let repo = repo_root();
        let root = unique_root();
        stage_chain(sys.as_ref(), &repo, &root);

        let spawned = Arc::new(Mutex::new(Vec::new()));
        let (engine, blobs) = make_engine(sys.clone(), &root, &rustc, spawned.clone());

        let built = run_build_configured(
            &engine,
            blobs.as_ref(),
            sys.as_ref(),
            &HostPath::new(root.clone()),
            "//razel-wire-cbor:razel_wire_cbor",
            Some(HOST_CONFIG),
        )
        .expect("razel build //razel-wire-cbor:razel_wire_cbor emits");
        assert_eq!(built.len(), 1, "the library target has ONE default output (its own rlib)");
        assert_eq!(built[0].exec_path, "razel-wire-cbor/librazel_wire_cbor.rlib");

        // The emitted file on real disk is the REAL rustc rlib (ar magic).
        let on_disk = sys.read(&HostPath::new(built[0].host_path_str().to_string())).expect("read emitted rlib");
        assert!(on_disk.starts_with(b"!<arch>"), "the emitted headline rlib is a real ar archive on disk");

        let _ = sys.remove_dir_all(&HostPath::new(root));
    });
}

#[test]
fn self_host_multi_level_incrementality() {
    hang_proof(|| {
        let sys: Arc<dyn System> = Arc::new(DarwinSystem);
        let Some(rustc) = rustc_or_skip(sys.as_ref()) else { return };
        // A private temp copy of the chain — edits below hit COPIES, never the repo.
        let repo = repo_root();
        let root = unique_root();
        stage_chain(sys.as_ref(), &repo, &root);

        let spawned = Arc::new(Mutex::new(Vec::new()));
        let (engine, _blobs) = make_engine(sys.clone(), &root, &rustc, spawned.clone());
        let tc = completion("razel-wire-cbor", "razel_wire_cbor");
        let seq = || spawned.lock().unwrap().clone();

        // The two files this test edits — read the staged base so a probe append rides the real source.
        let mock_base = read_repo(sys.as_ref(), &root, "razel-core/src/mock.rs");
        let cbor_base = read_repo(sys.as_ref(), &root, "razel-wire-api/src/cbor.rs");
        let mock_v2 = [mock_base.as_slice(), b"\npub fn __selfhost_probe() -> u8 { 42 }\n"].concat();
        let cbor_v2 = [cbor_base.as_slice(), b"\npub fn __selfhost_probe_mid() -> u8 { 7 }\n"].concat();

        // cold: the whole chain compiles, in dependency order.
        engine.request(&tc).expect("cold self-host build");
        assert_eq!(seq(), CHAIN_SPAWNS.iter().map(|s| s.to_string()).collect::<Vec<_>>(), "cold: the three chain compiles");

        // (a) edit the LEAF crate (razel-core, a module source) → the WHOLE chain re-compiles: core's rlib
        // bytes change → wire-api re-compiles against the new rlib → its rlib changes → wire-cbor re-links.
        // (Empirically: rustc propagates the leaf metadata hash through every downstream rlib.)
        sys.write_atomic(&HostPath::new(format!("{root}/razel-core/src/mock.rs")), &mock_v2).expect("edit leaf");
        engine.evaluate(
            &[tc.clone()],
            FailurePolicy::FailFast,
            Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(fskey("razel-core/src/mock.rs"))] },
        );
        assert_eq!(
            seq()[3..],
            CHAIN_SPAWNS,
            "a LEAF (razel-core) edit re-compiles the WHOLE chain: core, wire-api, then wire-cbor"
        );

        // (b) edit a MID crate (razel-wire-api, a module source) → ONLY it + its dependent re-compile; the
        // LEAF (razel-core) is upstream and its rlib is unchanged, so it does NOT re-compile.
        sys.write_atomic(&HostPath::new(format!("{root}/razel-wire-api/src/cbor.rs")), &cbor_v2).expect("edit mid");
        engine.evaluate(
            &[tc.clone()],
            FailurePolicy::FailFast,
            Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(fskey("razel-wire-api/src/cbor.rs"))] },
        );
        assert_eq!(
            seq()[6..],
            [
                "razel-wire-api/librazel_wire_api.rlib".to_string(),
                "razel-wire-cbor/librazel_wire_cbor.rlib".to_string()
            ],
            "a MID (razel-wire-api) edit re-compiles ONLY it + its dependent — razel-core does NOT re-compile"
        );

        // (c) TOUCH the leaf (write IDENTICAL bytes to the already-edited mock.rs) → FILE content digest is
        // unchanged → ZERO re-compiles (early cutoff at FILE — the rlib determinism proven empirically).
        sys.write_atomic(&HostPath::new(format!("{root}/razel-core/src/mock.rs")), &mock_v2).expect("touch leaf");
        engine.evaluate(
            &[tc.clone()],
            FailurePolicy::FailFast,
            Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(fskey("razel-core/src/mock.rs"))] },
        );
        assert_eq!(seq().len(), 8, "a TOUCH (identical bytes) re-compiles NOTHING — early cutoff at FILE");

        let _ = sys.remove_dir_all(&HostPath::new(root));
    });
}
