//! Integration gate for the composition root: the real incremental file story over the `Engine` + source
//! node-kinds + a controllable in-memory `System`. This is where `FILE_STATE` (stat) and `FILE` (content)
//! meet the engine's two prunings — proving the headline guarantee: **a touch (mtime change, same bytes)
//! re-stats and re-reads, but the content digest is unchanged, so the rebuild stops at `FILE`.**

use razel_core::{Digest, NodeKey, NodeValue};
use razel_engine_api::{DemandEngine, Diff, FailurePolicy};
use razel_bzl_api::BzlValue;
use razel_host::{build_loading_engine, build_source_engine};
use razel_ids::RootRelativePath;
use razel_load::{BzlLoadKey, BzlModuleValue};
use razel_os_api::{
    EnvName, ExitStatus, FileKind, HostPath, Metadata, OsError, OsPathFragment, OsPathPolicy, OsValue,
    ProcessSpec, RawSymlinkTarget, System,
};
use razel_source::{DirListingKey, FileKey, FileStateKey, FileValue, GlobKey, GlobMatch};
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
    fn remove(&self, path: &str) {
        self.files.lock().unwrap().remove(path);
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

// ──────────────── helpers ────────────────
fn fkey(p: &str) -> NodeKey { NodeKey::from_key(&FileKey(RootRelativePath(p.into()))) }
fn fskey(p: &str) -> NodeKey { NodeKey::from_key(&FileStateKey(RootRelativePath(p.into()))) }
fn dlkey(p: &str) -> NodeKey { NodeKey::from_key(&DirListingKey(RootRelativePath(p.into()))) }
fn gkey(dir: &str, pat: &str) -> NodeKey { NodeKey::from_key(&GlobKey { dir: RootRelativePath(dir.into()), pattern: pat.into() }) }
fn fval(v: &NodeValue) -> FileValue { v.as_any().downcast_ref::<FileValue>().unwrap().clone() }
fn gmatch(v: &NodeValue) -> Vec<String> { v.as_any().downcast_ref::<GlobMatch>().unwrap().0.clone() }
fn bkey(p: &str) -> NodeKey { NodeKey::from_key(&BzlLoadKey(RootRelativePath(p.into()))) }
fn bget(v: &NodeValue, name: &str) -> Option<BzlValue> {
    v.as_any().downcast_ref::<BzlModuleValue>().unwrap().0.get(name).cloned()
}

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

#[test]
fn glob_lists_matching_files() {
    let fs = Arc::new(MutFs::new());
    fs.set("/w/src/a.txt", b"a", 1);
    fs.set("/w/src/b.txt", b"b", 1);
    fs.set("/w/src/c.rs", b"c", 1);
    let engine = build_source_engine(fs, HostPath::new("/w"));
    assert_eq!(
        gmatch(&engine.request(&gkey("src", "*.txt")).unwrap()),
        vec!["src/a.txt".to_string(), "src/b.txt".to_string()],
        "glob matches *.txt, sorted, root-relative; c.rs excluded"
    );
}

#[test]
fn adding_a_file_reexpands_glob() {
    let fs = Arc::new(MutFs::new());
    fs.set("/w/src/a.txt", b"a", 1);
    fs.set("/w/src/b.txt", b"b", 1);
    let engine = build_source_engine(fs.clone(), HostPath::new("/w"));
    engine.request(&gkey("src", "*.txt")).unwrap(); // warm
    let before = engine.version(&gkey("src", "*.txt")).unwrap();

    fs.set("/w/src/d.txt", b"d", 1); // a new matching file appears in the directory
    engine.evaluate(&[gkey("src", "*.txt")], FailurePolicy::FailFast, &Diff { changed_leaves: vec![dlkey("src")] });

    let after = engine.version(&gkey("src", "*.txt")).unwrap();
    assert!(after.last_changed > before.last_changed, "a new matching file re-expands the glob");
    assert_eq!(
        gmatch(&engine.request(&gkey("src", "*.txt")).unwrap()),
        vec!["src/a.txt".to_string(), "src/b.txt".to_string(), "src/d.txt".to_string()]
    );
}

#[test]
fn content_change_does_not_disturb_glob() {
    let fs = Arc::new(MutFs::new());
    fs.set("/w/src/a.txt", b"a", 1);
    fs.set("/w/src/b.txt", b"b", 1);
    let engine = build_source_engine(fs.clone(), HostPath::new("/w"));
    engine.request(&gkey("src", "*.txt")).unwrap(); // warm

    // A matched file's CONTENT changes — but the directory's entry set does not. The glob is about WHICH
    // files exist, not their bytes, so it must not even be revisited (it never depends on file content).
    fs.set("/w/src/a.txt", b"a-changed-bigger", 2);
    let rep = engine.evaluate(&[gkey("src", "*.txt")], FailurePolicy::FailFast, &Diff { changed_leaves: vec![fskey("src/a.txt")] });

    assert_eq!(rep.recomputes, 0, "a file-content change must not recompute the glob (no content dependency)");
}

#[test]
fn over_broad_listing_invalidation_still_cuts_off_glob() {
    let fs = Arc::new(MutFs::new());
    fs.set("/w/src/a.txt", b"a", 1);
    fs.set("/w/src/b.txt", b"b", 1);
    let engine = build_source_engine(fs.clone(), HostPath::new("/w"));
    engine.request(&gkey("src", "*.txt")).unwrap(); // warm
    let g_before = engine.version(&gkey("src", "*.txt")).unwrap();
    let d_before = engine.version(&dlkey("src")).unwrap();

    // An over-broad monitor re-dirties the whole DIRECTORY_LISTING on a mere mtime change, but the entry
    // (name, is_dir) set is identical → the listing value is unchanged → the glob is pruned by cutoff.
    fs.set("/w/src/a.txt", b"a", 999);
    let rep = engine.evaluate(&[gkey("src", "*.txt")], FailurePolicy::FailFast, &Diff { changed_leaves: vec![dlkey("src")] });

    let g_after = engine.version(&gkey("src", "*.txt")).unwrap();
    let d_after = engine.version(&dlkey("src")).unwrap();
    assert_eq!(rep.recomputes, 1, "only DIRECTORY_LISTING recomputes; the glob is pruned");
    assert_eq!(d_after.last_changed, d_before.last_changed, "listing value-equal → last_changed not advanced");
    assert_eq!(g_after.last_changed, g_before.last_changed, "glob cut off → last_changed unchanged");
}

#[test]
fn removing_a_file_shrinks_glob() {
    let fs = Arc::new(MutFs::new());
    fs.set("/w/src/a.txt", b"a", 1);
    fs.set("/w/src/b.txt", b"b", 1);
    let engine = build_source_engine(fs.clone(), HostPath::new("/w"));
    assert_eq!(gmatch(&engine.request(&gkey("src", "*.txt")).unwrap()), vec!["src/a.txt".to_string(), "src/b.txt".to_string()]);

    fs.remove("/w/src/a.txt"); // a matching file disappears
    engine.evaluate(&[gkey("src", "*.txt")], FailurePolicy::FailFast, &Diff { changed_leaves: vec![dlkey("src")] });

    assert_eq!(gmatch(&engine.request(&gkey("src", "*.txt")).unwrap()), vec!["src/b.txt".to_string()], "removing a file shrinks the glob");
}

#[test]
fn root_dir_glob_finds_root_files() {
    let fs = Arc::new(MutFs::new());
    fs.set("/w/x.txt", b"x", 1);
    fs.set("/w/y.txt", b"y", 1);
    fs.set("/w/sub/z.txt", b"z", 1); // nested → not a root-level entry
    let engine = build_source_engine(fs, HostPath::new("/w"));
    assert_eq!(
        gmatch(&engine.request(&gkey("", "*.txt")).unwrap()),
        vec!["x.txt".to_string(), "y.txt".to_string()],
        "a glob at the workspace root (dir==\"\") lists root files, root-relative, not nested ones"
    );
}

// ──────────────── BZL_LOAD: a Starlark .bzl as an incremental node (the spike) ────────────────

#[test]
fn bzl_evaluates_as_a_node() {
    let fs = Arc::new(MutFs::new());
    fs.set("/w/rules.bzl", b"x = 1 + 2\ny = \"hi\"\nz = [True, 4]\n", 1);
    let engine = build_loading_engine(fs, HostPath::new("/w"));
    let v = engine.request(&bkey("rules.bzl")).unwrap();
    assert_eq!(bget(&v, "x"), Some(BzlValue::Int(3)), "starlark arithmetic folds: 1 + 2 = 3");
    assert_eq!(bget(&v, "y"), Some(BzlValue::Str("hi".into())));
    assert_eq!(bget(&v, "z"), Some(BzlValue::List(vec![BzlValue::Bool(true), BzlValue::Int(4)])));
}

#[test]
fn editing_bzl_reevaluates() {
    let fs = Arc::new(MutFs::new());
    fs.set("/w/rules.bzl", b"x = 1\n", 1);
    let engine = build_loading_engine(fs.clone(), HostPath::new("/w"));
    engine.request(&bkey("rules.bzl")).unwrap(); // warm
    let before = engine.version(&bkey("rules.bzl")).unwrap();

    fs.set("/w/rules.bzl", b"x = 99\n", 2); // genuine source change
    engine.evaluate(&[bkey("rules.bzl")], FailurePolicy::FailFast, &Diff { changed_leaves: vec![fskey("rules.bzl")] });

    let after = engine.version(&bkey("rules.bzl")).unwrap();
    assert!(after.last_changed > before.last_changed, "a .bzl source change re-evaluates BZL_LOAD");
    assert_eq!(bget(&engine.request(&bkey("rules.bzl")).unwrap(), "x"), Some(BzlValue::Int(99)));
}

#[test]
fn touching_bzl_does_not_reevaluate() {
    let fs = Arc::new(MutFs::new());
    fs.set("/w/rules.bzl", b"x = 1\n", 1);
    let engine = build_loading_engine(fs.clone(), HostPath::new("/w"));
    engine.request(&bkey("rules.bzl")).unwrap(); // warm
    let before = engine.version(&bkey("rules.bzl")).unwrap();

    fs.set("/w/rules.bzl", b"x = 1\n", 999); // TOUCH: new mtime, identical source bytes
    engine.evaluate(&[bkey("rules.bzl")], FailurePolicy::FailFast, &Diff { changed_leaves: vec![fskey("rules.bzl")] });

    let after = engine.version(&bkey("rules.bzl")).unwrap();
    assert_eq!(after.last_changed, before.last_changed, "a touch (same bytes) must NOT re-parse the .bzl — the FILE content-cutoff propagates");
    assert!(after.last_evaluated > before.last_evaluated, "BZL_LOAD is re-checked this round, just not recomputed");
}
