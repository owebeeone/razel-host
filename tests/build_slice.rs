//! The `build` slice's INCREMENTALITY half over the composition root (BAR-FIRST-SLICE execution leg): the
//! write-action's declared content rides the FROZEN `argv` fingerprint dimension, so an unchanged rebuild
//! early-cuts (0 productive recomputes, no re-emit) and a content edit re-runs the write-action and changes
//! the emitted bytes. This lives in razel-host (not razel-daemon) because the assertions inspect engine /
//! action node state — types host may name but the protocol-root daemon may not. The end-to-end
//! cli→transport→daemon→host emit proof is `razel-daemon/tests/build_slice.rs`; here we drive the
//! `razel_host::BuildSession` directly. A NEW test file (integration.rs is already ~1371 LOC).

use razel_action::{ArtifactProducer, ArtifactRef, GeneratingActionKey};
use razel_analysis::ConfiguredTargetKey;
use razel_core::NodeKey;
use razel_engine_api::{ChangedLeaf, DemandEngine, Diff, FailurePolicy};
use razel_host::BuildSession;
use razel_ids::RootRelativePath;
use razel_os_api::{
    EnvName, ExitStatus, FileKind, HostPath, Metadata, OsError, OsPathFragment, OsPathPolicy, OsValue,
    ProcessSpec, RawSymlinkTarget, System,
};
use razel_source::{FileKey, FileStateKey};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

// ──────────────── a mutable in-memory System whose write_atomic records + counts (emit observability) ────────────────
struct TestPolicy;
impl OsPathPolicy for TestPolicy {
    fn canonicalize_alias(&self, p: &HostPath) -> HostPath { p.clone() }
    fn normalize_fragment(&self, raw: &str) -> Result<OsPathFragment, OsError> {
        if raw.contains('/') || raw.contains("..") {
            return Err(OsError::Invalid { what: "fragment".into(), detail: raw.into() });
        }
        Ok(OsPathFragment::new_unchecked(raw))
    }
}
struct RecordingFs {
    files: Mutex<HashMap<String, (Vec<u8>, i128)>>,
    tick: Mutex<i128>,
    writes: AtomicUsize,
    policy: TestPolicy,
}
impl RecordingFs {
    fn new() -> Self {
        Self { files: Mutex::new(HashMap::new()), tick: Mutex::new(1), writes: AtomicUsize::new(0), policy: TestPolicy }
    }
    fn set(&self, path: &str, content: &[u8], mtime: i128) {
        self.files.lock().unwrap().insert(path.into(), (content.to_vec(), mtime));
    }
    fn get(&self, path: &str) -> Option<Vec<u8>> {
        self.files.lock().unwrap().get(path).map(|(c, _)| c.clone())
    }
    fn write_count(&self) -> usize { self.writes.load(Ordering::SeqCst) }
}
impl System for RecordingFs {
    fn read(&self, p: &HostPath) -> Result<Vec<u8>, OsError> {
        self.files.lock().unwrap().get(p.as_str()).map(|(c, _)| c.clone())
            .ok_or_else(|| OsError::NotFound { path: p.as_str().into() })
    }
    fn write_atomic(&self, p: &HostPath, bytes: &[u8]) -> Result<(), OsError> {
        let mut tick = self.tick.lock().unwrap();
        *tick += 1;
        self.files.lock().unwrap().insert(p.as_str().into(), (bytes.to_vec(), *tick));
        self.writes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn exists(&self, p: &HostPath) -> Result<bool, OsError> { Ok(self.files.lock().unwrap().contains_key(p.as_str())) }
    fn stat(&self, p: &HostPath) -> Result<Metadata, OsError> {
        let g = self.files.lock().unwrap();
        let (c, mtime) = g.get(p.as_str()).ok_or_else(|| OsError::NotFound { path: p.as_str().into() })?;
        Ok(Metadata { kind: FileKind::File, len: c.len() as u64, mtime_nanos: *mtime, file_id: 0 })
    }
    fn lstat(&self, p: &HostPath) -> Result<Metadata, OsError> { self.stat(p) }
    fn list_dir(&self, p: &HostPath) -> Result<Vec<OsPathFragment>, OsError> {
        let prefix = format!("{}/", p.as_str());
        let g = self.files.lock().unwrap();
        let mut out: Vec<OsPathFragment> = g
            .keys()
            .filter_map(|k| k.strip_prefix(&prefix).filter(|r| !r.contains('/')))
            .map(OsPathFragment::new_unchecked)
            .collect();
        out.sort_by(|a, b| a.as_str().as_bytes().cmp(b.as_str().as_bytes()));
        Ok(out)
    }
    fn read_link(&self, p: &HostPath) -> Result<RawSymlinkTarget, OsError> {
        Err(OsError::NotFound { path: p.as_str().into() })
    }
    fn canonicalize(&self, p: &HostPath) -> Result<HostPath, OsError> { Ok(p.clone()) }
    fn raw_env(&self, _n: &EnvName) -> Option<OsValue> { None }
    fn spawn(&self, _s: &ProcessSpec) -> Result<ExitStatus, OsError> {
        Err(OsError::Unsupported { op: "spawn", detail: "test".into() })
    }
    fn path_policy(&self) -> &dyn OsPathPolicy { &self.policy }
}

fn hello_rules(content_literal: &str) -> Vec<u8> {
    // A rule whose impl declares a write-action producing hello/out.txt with the given content.
    format!(
        "NumberInfo = provider(\"NumberInfo\", fields = [\"x\"])\n\
         def _impl(ctx):\n\
         \x20   out = ctx.actions.declare_file(\"out.txt\")\n\
         \x20   ctx.actions.write(output = out, content = \"{content_literal}\")\n\
         \x20   return [NumberInfo(x = 1)]\n\
         my_rule = rule(implementation = _impl, attrs = {{}})\n"
    )
    .into_bytes()
}
fn hello_fs(content_literal: &str) -> Arc<RecordingFs> {
    let fs = Arc::new(RecordingFs::new());
    fs.set("/w/hello/rules.bzl", &hello_rules(content_literal), 1);
    fs.set("/w/hello/BUILD.bazel", b"load(\":rules.bzl\", \"my_rule\")\nmy_rule(name = \"out.txt\")\n", 1);
    fs
}
/// The output ARTIFACT node (action #0's declared output) — read-only inspected as the incrementality oracle.
fn out_artifact() -> NodeKey {
    NodeKey::from_key(&ArtifactRef {
        exec_path: "hello/out.txt".into(),
        producer: ArtifactProducer::Derived(GeneratingActionKey {
            owner: ConfiguredTargetKey {
                package: "hello".into(),
                name: "out.txt".into(),
                configuration: None,
                exec_platform: None,
                rule_transition: None,
            },
            action_index: 0,
        }),
    })
}

#[test]
fn build_slice_produces_hello_content() {
    // The host-level headline (no cli/daemon): BuildSession.build produces hello/out.txt == "hello\n".
    let fs = hello_fs("hello\\n");
    let session = BuildSession::new_write(fs.clone(), HostPath::new("/w"));
    let built = session.build("//hello:out.txt").expect("build succeeds");
    assert_eq!(built.len(), 1);
    assert_eq!(built[0].exec_path, "hello/out.txt");
    assert_eq!(fs.get("/w/hello/out.txt"), Some(b"hello\n".to_vec()),
        "the declared content is written to disk via System::write_atomic");
}

#[test]
fn unchanged_rebuild_early_cuts_content_edit_reruns() {
    // The incrementality property the content-in-argv fingerprint buys.
    let fs = hello_fs("hello\\n");
    let session = BuildSession::new_write(fs.clone(), HostPath::new("/w"));
    let art = out_artifact();

    session.build("//hello:out.txt").expect("cold build");
    assert_eq!(fs.get("/w/hello/out.txt"), Some(b"hello\n".to_vec()));
    let cold_writes = fs.write_count();
    assert_eq!(cold_writes, 1, "cold build emits once");
    let art_v1 = session.engine().inspect(&art).unwrap().version;

    // (a) TOUCH the rule .bzl (identical bytes) → FILE content-cutoff → the write-action's fingerprint is
    // unchanged → 0 PRODUCTIVE recomputes above FILE, and the output artifact does not change.
    fs.set("/w/hello/rules.bzl", &hello_rules("hello\\n"), 999);
    session.engine().evaluate(
        &[art.clone()],
        FailurePolicy::FailFast,
        Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(NodeKey::from_key(&FileStateKey(RootRelativePath("hello/rules.bzl".into()))))] },
    );
    let art_touched = session.engine().inspect(&art).unwrap().version;
    assert_eq!(art_touched.last_changed, art_v1.last_changed,
        "a touch (identical declared content) must NOT change the output artifact — content-in-fingerprint early-cut");

    // (b) EDIT the declared content → the SAME write-action node re-runs (dirty-in-place) with a new value.
    fs.set("/w/hello/rules.bzl", &hello_rules("goodbye\\n"), 1000);
    session.engine().evaluate(
        &[art.clone()],
        FailurePolicy::FailFast,
        Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(NodeKey::from_key(&FileKey(RootRelativePath("hello/rules.bzl".into()))))] },
    );
    let art_edited = session.engine().inspect(&art).unwrap().version;
    assert!(art_edited.last_changed > art_v1.last_changed,
        "editing the declared content must re-run the write-action (a new output artifact value)");

    // ...and re-running the build verb emits the NEW content to disk.
    session.build("//hello:out.txt").expect("re-build after edit");
    assert_eq!(fs.get("/w/hello/out.txt"), Some(b"goodbye\n".to_vec()),
        "the edited declared content is the emitted bytes on disk");
}
