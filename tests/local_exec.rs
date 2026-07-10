//! THE real-execution proof (the last architectural piece on the self-host path): a genrule-style action
//! runs an ACTUAL subprocess (`/bin/sh -c '/bin/cat genrule/in.txt > genrule/out.txt'`) end to end over the
//! REAL `DarwinSystem` — inputs resolved from a real source file through InputResolver → ARTIFACT →
//! BlobStore → DISK STAGING (the reserved expander, now built) → `System::spawn`, outputs collected off
//! disk. Execution is a pure GRAPH CONSEQUENCE of requesting `TARGET_COMPLETION` (no hand bridge, no
//! fabricated output), and INCREMENTALITY holds: an input edit re-runs the subprocess; an unchanged touch
//! early-cuts at FILE with ZERO re-spawn.
//!
//! Row red-first mutants (tools/gate.sh runs each unfiltered and requires RED):
//!   mutant_stage_drops_input        → the subprocess can't read its staged input → fails closed → RED
//!   mutant_collect_fabricates_output → collect returns fabricated bytes ≠ the subprocess's output → RED
//!
//! HANG-PROOF: every body runs under a bounded deadline so a wedged subprocess becomes a terminating RED,
//! never a hung binary (the hang lesson — a `cat` of a staged file always terminates, but the deadline is
//! cheap insurance for the unfiltered per-mutant runs).

use razel_action::{
    ActionValue, ArtifactProducer, ArtifactRef, ArtifactValue, GeneratingActionKey, OutputSelection,
    TargetCompletionKey,
};
use razel_analysis::ConfiguredTargetKey;
use razel_core::{Digest, NodeKey, NodeValue};
use razel_engine_api::{ChangedLeaf, DemandEngine, Diff, FailurePolicy};
use razel_exec_api::{ExecError, SpawnRequest, SpawnResult, SpawnStrategy};
use razel_host::{build_execution_engine, LocalSpawnStrategy};
use razel_ids::RootRelativePath;
use razel_os_api::{HostPath, System};
use razel_os_darwin::DarwinSystem;
use razel_source::FileStateKey;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ──────────────── hang-proof harness ────────────────
const HANG_DEADLINE: Duration = Duration::from_secs(20);

fn hang_proof<T: Send + 'static>(body: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(body());
    });
    match rx.recv_timeout(HANG_DEADLINE) {
        Ok(v) => v,
        Err(RecvTimeoutError::Disconnected) => panic!("test body panicked (see the failure output above)"),
        Err(RecvTimeoutError::Timeout) => {
            panic!("hang-proof deadline exceeded ({HANG_DEADLINE:?}): a real subprocess never completed — failing RED instead of hanging")
        }
    }
}

/// A unique real-workspace root per test (tests run concurrently) — distinct even within one nanosecond.
fn unique_root() -> String {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    format!("/tmp/razel-genrule-{nanos}-{n}")
}

// ──────────────── a spawn-counting wrapper around the REAL LocalSpawnStrategy ────────────────
// The oracle for "did the action actually re-run / early-cut": every real subprocess passes through here.
struct CountingLocal {
    inner: LocalSpawnStrategy,
    count: Arc<AtomicUsize>,
}
impl SpawnStrategy for CountingLocal {
    fn spawn(&self, req: &SpawnRequest) -> Result<SpawnResult, ExecError> {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.inner.spawn(req)
    }
}

// ──────────────── key + value helpers (the positional artifact-model keys) ────────────────
fn owner_ct(pkg: &str, name: &str) -> ConfiguredTargetKey {
    ConfiguredTargetKey {
        package: pkg.into(),
        name: name.into(),
        configuration: None,
        exec_platform: None,
        rule_transition: None,
    }
}
fn completion(pkg: &str, name: &str) -> NodeKey {
    NodeKey::from_key(&TargetCompletionKey { ct: owner_ct(pkg, name), outputs: OutputSelection::Default })
}
fn derived_artifact(pkg: &str, name: &str, idx: u32, path: &str) -> NodeKey {
    NodeKey::from_key(&ArtifactRef {
        exec_path: path.into(),
        producer: ArtifactProducer::Derived(GeneratingActionKey { owner: owner_ct(pkg, name), action_index: idx }),
    })
}
fn action_node(pkg: &str, name: &str, idx: u32) -> NodeKey {
    NodeKey::from_key(&GeneratingActionKey { owner: owner_ct(pkg, name), action_index: idx })
}
fn fskey(p: &str) -> NodeKey {
    NodeKey::from_key(&FileStateKey(RootRelativePath(p.into())))
}
fn artifact_val(v: &NodeValue) -> ArtifactValue {
    v.as_any().downcast_ref::<ArtifactValue>().unwrap().clone()
}
fn action_value(v: &NodeValue) -> ActionValue {
    v.as_any().downcast_ref::<ActionValue>().unwrap().clone()
}

// ──────────────── the genrule fixture: a REAL .bzl declaring a spawn action ────────────────
// `/bin/sh -c '/bin/cat genrule/in.txt > genrule/out.txt'` — the classic genrule shell-redirect: it reads
// the STAGED input (exec-relative `genrule/in.txt`, materialized under the exec root) and writes the
// declared output (`genrule/out.txt`) which the strategy collects. `/bin/cat` is absolute (PATH-independent,
// exact-env-spawn safe).
const GENRULE_RULES: &[u8] = b"NumberInfo = provider(\"NumberInfo\", fields = [\"x\"])\n\
def _impl(ctx):\n\
\x20   declare_action(mnemonic = \"Genrule\", argv = [\"/bin/sh\", \"-c\", \"/bin/cat genrule/in.txt > genrule/out.txt\"], outputs = [\"genrule/out.txt\"], inputs = [\"genrule/in.txt\"])\n\
\x20   return [NumberInfo(x = 1)]\n\
my_rule = rule(implementation = _impl, attrs = {})\n";
const GENRULE_BUILD: &[u8] = b"load(\":rules.bzl\", \"my_rule\")\nmy_rule(name = \"out.txt\")\n";

fn write_fixture(sys: &dyn System, root: &str, in_bytes: &[u8]) {
    sys.write_atomic(&HostPath::new(format!("{root}/genrule/rules.bzl")), GENRULE_RULES).expect("write rules.bzl");
    sys.write_atomic(&HostPath::new(format!("{root}/genrule/BUILD.bazel")), GENRULE_BUILD).expect("write BUILD.bazel");
    sys.write_atomic(&HostPath::new(format!("{root}/genrule/in.txt")), in_bytes).expect("write in.txt");
}

fn make_engine(sys: Arc<dyn System>, root: &str, spawns: Arc<AtomicUsize>) -> razel_engine::Engine {
    let strategy = Arc::new(CountingLocal { inner: LocalSpawnStrategy::new(sys.clone()), count: spawns });
    build_execution_engine(sys, HostPath::new(root.to_string()), strategy)
}

#[test]
fn genrule_runs_a_real_subprocess() {
    hang_proof(|| {
        let sys: Arc<dyn System> = Arc::new(DarwinSystem);
        let root = unique_root();
        let in_v1: &[u8] = b"hello from a real source file\n";
        write_fixture(sys.as_ref(), &root, in_v1);

        let spawns = Arc::new(AtomicUsize::new(0));
        let engine = make_engine(sys.clone(), &root, spawns.clone());

        // THE PROOF — the ONE top-level demand IS the build: CT → ARTIFACT → ACTION → REAL /bin/sh subprocess
        // → collected output. Under `mutant_stage_drops_input` the cat can't read its (unstaged) input, exits
        // nonzero, and this `.expect` panics RED.
        engine.request(&completion("genrule", "out.txt")).expect("the genrule builds as a graph consequence");
        assert_eq!(spawns.load(Ordering::SeqCst), 1, "the genrule action spawned exactly once (cold)");

        // The collected output bytes ARE the subprocess's output: `cat in > out` ⇒ out == in. Under
        // `mutant_collect_fabricates_output` the collected bytes are fabricated ≠ the input → this reds.
        let out = artifact_val(&engine.request(&derived_artifact("genrule", "out.txt", 0, "genrule/out.txt")).unwrap());
        assert_eq!(out.digest, Digest::of(in_v1),
            "the output digest IS the digest of the REAL subprocess's output (cat in > out ⇒ out == in)");
        let av = action_value(&engine.request(&action_node("genrule", "out.txt", 0)).unwrap());
        assert_eq!(av.exit_code, 0, "the real subprocess ran via the strategy and exited zero");

        let _ = sys.remove_dir_all(&HostPath::new(root)); // tidy the workspace (best-effort)
    });
}

#[test]
fn genrule_incrementality_edit_reruns_touch_cuts_off() {
    hang_proof(|| {
        let sys: Arc<dyn System> = Arc::new(DarwinSystem);
        let root = unique_root();
        // v1/v2 differ in LENGTH so the FILE_STATE dirty-check fires regardless of real-FS mtime resolution.
        let in_v1: &[u8] = b"first content\n";
        let in_v2: &[u8] = b"a different and longer second content revision\n";
        write_fixture(sys.as_ref(), &root, in_v1);

        let spawns = Arc::new(AtomicUsize::new(0));
        let engine = make_engine(sys.clone(), &root, spawns.clone());
        let tc = completion("genrule", "out.txt");
        let art = derived_artifact("genrule", "out.txt", 0, "genrule/out.txt");

        // cold build → one real spawn, output == input.
        engine.request(&tc).expect("cold build");
        assert_eq!(spawns.load(Ordering::SeqCst), 1, "cold: one real subprocess");
        let d1 = artifact_val(&engine.request(&art).unwrap()).digest;
        assert_eq!(d1, Digest::of(in_v1));

        // EDIT the source bytes → the whole chain re-runs (a NEW real subprocess over the new input).
        sys.write_atomic(&HostPath::new(format!("{root}/genrule/in.txt")), in_v2).expect("edit in.txt");
        engine.evaluate(
            &[tc.clone()],
            FailurePolicy::FailFast,
            Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(fskey("genrule/in.txt"))] },
        );
        assert_eq!(spawns.load(Ordering::SeqCst), 2, "the input edit re-ran the genrule subprocess");
        let d2 = artifact_val(&engine.request(&art).unwrap()).digest;
        assert_ne!(d1, d2, "the output digest changed with the input edit");
        assert_eq!(d2, Digest::of(in_v2), "the new output IS the real subprocess's output over the new input");

        // TOUCH (same bytes) → FILE content digest unchanged → NOTHING above re-runs: ZERO new spawn.
        sys.write_atomic(&HostPath::new(format!("{root}/genrule/in.txt")), in_v2).expect("touch in.txt");
        engine.evaluate(
            &[tc.clone()],
            FailurePolicy::FailFast,
            Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(fskey("genrule/in.txt"))] },
        );
        assert_eq!(spawns.load(Ordering::SeqCst), 2, "a touch (identical bytes) must NOT re-spawn — early-cutoff at FILE");

        let _ = sys.remove_dir_all(&HostPath::new(root));
    });
}
