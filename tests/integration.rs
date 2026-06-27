//! Integration gate for the composition root: the real incremental file story over the `Engine` + source
//! node-kinds + a controllable in-memory `System`. This is where `FILE_STATE` (stat) and `FILE` (content)
//! meet the engine's two prunings — proving the headline guarantee: **a touch (mtime change, same bytes)
//! re-stats and re-reads, but the content digest is unchanged, so the rebuild stops at `FILE`.**

use razel_core::{Digest, NodeKey, NodeValue};
use razel_engine_api::{DemandEngine, Diff, FailurePolicy};
use razel_host::build_source_engine;
use razel_ids::RootRelativePath;
use razel_os_api::{
    EnvName, ExitStatus, FileKind, HostPath, Metadata, OsError, OsPathFragment, OsPathPolicy, OsValue,
    ProcessSpec, RawSymlinkTarget, System,
};
use razel_source::{FileKey, FileStateKey, FileValue};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// ──────────────── a mutable in-memory System (only stat/read carry real logic) ────────────────
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

struct MutFs {
    files: Mutex<HashMap<String, (Vec<u8>, i128)>>, // host path -> (content, mtime_nanos)
    policy: TestPolicy,
}
impl MutFs {
    fn new() -> Self { Self { files: Mutex::new(HashMap::new()), policy: TestPolicy } }
    fn set(&self, path: &str, content: &[u8], mtime: i128) {
        self.files.lock().unwrap().insert(path.into(), (content.to_vec(), mtime));
    }
}
impl System for MutFs {
    fn read(&self, p: &HostPath) -> Result<Vec<u8>, OsError> {
        self.files.lock().unwrap().get(p.as_str()).map(|(c, _)| c.clone())
            .ok_or_else(|| OsError::NotFound { path: p.as_str().into() })
    }
    fn write_atomic(&self, _p: &HostPath, _b: &[u8]) -> Result<(), OsError> {
        Err(OsError::Unsupported { op: "write_atomic", detail: "test".into() })
    }
    fn exists(&self, p: &HostPath) -> Result<bool, OsError> { Ok(self.files.lock().unwrap().contains_key(p.as_str())) }
    fn stat(&self, p: &HostPath) -> Result<Metadata, OsError> {
        let g = self.files.lock().unwrap();
        let (c, mtime) = g.get(p.as_str()).ok_or_else(|| OsError::NotFound { path: p.as_str().into() })?;
        Ok(Metadata { kind: FileKind::File, len: c.len() as u64, mtime_nanos: *mtime, file_id: 0 })
    }
    fn lstat(&self, p: &HostPath) -> Result<Metadata, OsError> { self.stat(p) }
    fn list_dir(&self, _p: &HostPath) -> Result<Vec<OsPathFragment>, OsError> {
        Err(OsError::Unsupported { op: "list_dir", detail: "test".into() })
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

// ──────────────── helpers ────────────────
fn fkey(p: &str) -> NodeKey { NodeKey::from_key(&FileKey(RootRelativePath(p.into()))) }
fn fskey(p: &str) -> NodeKey { NodeKey::from_key(&FileStateKey(RootRelativePath(p.into()))) }
fn fval(v: &NodeValue) -> FileValue { v.as_any().downcast_ref::<FileValue>().unwrap().clone() }

#[test]
fn file_reflects_content() {
    let fs = Arc::new(MutFs::new());
    fs.set("/w/a.txt", b"hello", 100);
    let engine = build_source_engine(fs, HostPath::new("/w"));
    let v = fval(&engine.request(&fkey("a.txt")).unwrap());
    assert!(v.exists);
    assert_eq!(v.content, Digest::of(b"hello"));
}

#[test]
fn nonexistent_file_is_valid() {
    let fs = Arc::new(MutFs::new());
    let engine = build_source_engine(fs, HostPath::new("/w"));
    let v = fval(&engine.request(&fkey("ghost")).unwrap());
    assert!(!v.exists, "a missing file is a valid FileValue(exists=false), never an error");
}

#[test]
fn content_change_propagates() {
    let fs = Arc::new(MutFs::new());
    fs.set("/w/a.txt", b"v1", 100);
    let engine = build_source_engine(fs.clone(), HostPath::new("/w"));
    engine.request(&fkey("a.txt")).unwrap(); // warm
    let before = engine.version(&fkey("a.txt")).unwrap();

    fs.set("/w/a.txt", b"v2-different", 200); // genuine content change (mtime too)
    engine.evaluate(&[fkey("a.txt")], FailurePolicy::FailFast, &Diff { changed_leaves: vec![fskey("a.txt")] });

    let after = engine.version(&fkey("a.txt")).unwrap();
    assert!(after.last_changed > before.last_changed, "content changed → FILE propagates");
    assert_eq!(fval(&engine.request(&fkey("a.txt")).unwrap()).content, Digest::of(b"v2-different"));
}

#[test]
fn touch_without_content_change_is_cut_off() {
    let fs = Arc::new(MutFs::new());
    fs.set("/w/a.txt", b"same", 100);
    let engine = build_source_engine(fs.clone(), HostPath::new("/w"));
    engine.request(&fkey("a.txt")).unwrap(); // warm
    let bf = engine.version(&fkey("a.txt")).unwrap();
    let bs = engine.version(&fskey("a.txt")).unwrap();

    fs.set("/w/a.txt", b"same", 999); // TOUCH: new mtime, identical content
    engine.evaluate(&[fkey("a.txt")], FailurePolicy::FailFast, &Diff { changed_leaves: vec![fskey("a.txt")] });

    let af = engine.version(&fkey("a.txt")).unwrap();
    let as_ = engine.version(&fskey("a.txt")).unwrap();
    assert!(as_.last_changed > bs.last_changed, "stat (mtime) changed → FILE_STATE advances");
    assert_eq!(af.last_changed, bf.last_changed, "content identical → FILE early-cutoff (no propagation)");
    assert!(af.last_evaluated > bf.last_evaluated, "but FILE was re-evaluated (re-read) this round");
}
