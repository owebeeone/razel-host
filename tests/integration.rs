//! Integration gate for the composition root: the real incremental file story over the `Engine` + source
//! node-kinds + a controllable in-memory `System`. This is where `FILE_STATE` (stat) and `FILE` (content)
//! meet the engine's two prunings — proving the headline guarantee: **a touch (mtime change, same bytes)
//! re-stats and re-reads, but the content digest is unchanged, so the rebuild stops at `FILE`.**

use razel_core::{Digest, NodeKey, NodeValue};
use razel_engine_api::{DemandEngine, Diff, FailurePolicy};
use razel_bzl_api::{BzlValue, RuleOrigin};
use razel_host::{build_analysis_engine, build_loading_engine, build_source_engine};
use razel_ids::RootRelativePath;
use razel_load::{BzlLoadKey, BzlModuleValue};
use razel_package::{Package, PackageKey};
use razel_analysis::{ConfiguredTarget, ConfiguredTargetKey};
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
fn pkey(pkg: &str) -> NodeKey { NodeKey::from_key(&PackageKey(RootRelativePath(pkg.into()))) }
fn pkg(v: &NodeValue) -> Package { v.as_any().downcast_ref::<Package>().unwrap().clone() }
fn ctkey(pkg: &str, name: &str) -> NodeKey {
    NodeKey::from_key(&ConfiguredTargetKey {
        package: pkg.into(),
        name: name.into(),
        configuration: None,
        exec_platform: None,
        rule_transition: None,
    })
}
fn ct_total(v: &NodeValue) -> i64 {
    let ct = v.as_any().downcast_ref::<ConfiguredTarget>().unwrap();
    match ct.provider("NumberInfo").and_then(|p| p.get("total")) {
        Some(BzlValue::Int(i)) => *i,
        other => panic!("expected NumberInfo.total: int, got {other:?}"),
    }
}

// The sum-provider rule (the de-nativized-rule exam): a target's NumberInfo.total = its own value + the sum of
// its deps' NumberInfo.total. A REAL .bzl impl, run through the Starlark seam — no Rust ruleset reimplementation.
const SUM_RULES: &[u8] = b"NumberInfo = provider(\"NumberInfo\", fields = [\"total\"])\n\
def _impl(ctx):\n\
\x20   t = ctx.attr.value\n\
\x20   for d in ctx.attr.deps:\n\
\x20       t += d[NumberInfo].total\n\
\x20   return [NumberInfo(total = t)]\n\
my_rule = rule(implementation = _impl, attrs = {\"value\": attr.int(), \"deps\": attr.label_list()})\n";

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

#[test]
fn load_resolves_across_bzls() {
    let fs = Arc::new(MutFs::new());
    fs.set("/w/pkg/b.bzl", b"y = 40\n", 1);
    fs.set("/w/pkg/a.bzl", b"load(\":b.bzl\", \"y\")\nx = y + 2\n", 1);
    let engine = build_loading_engine(fs, HostPath::new("/w"));
    let v = engine.request(&bkey("pkg/a.bzl")).unwrap();
    assert_eq!(bget(&v, "x"), Some(BzlValue::Int(42)), "a.bzl loads y=40 from b.bzl: x = y + 2 = 42");
}

#[test]
fn editing_loaded_bzl_propagates_to_loader() {
    let fs = Arc::new(MutFs::new());
    fs.set("/w/pkg/b.bzl", b"y = 40\n", 1);
    fs.set("/w/pkg/a.bzl", b"load(\":b.bzl\", \"y\")\nx = y + 2\n", 1);
    let engine = build_loading_engine(fs.clone(), HostPath::new("/w"));
    engine.request(&bkey("pkg/a.bzl")).unwrap(); // warm: BZL_LOAD(a) now depends on BZL_LOAD(b)
    let before = engine.version(&bkey("pkg/a.bzl")).unwrap();

    fs.set("/w/pkg/b.bzl", b"y = 100\n", 2); // edit the LOADED .bzl, not the loader
    engine.evaluate(&[bkey("pkg/a.bzl")], FailurePolicy::FailFast, &Diff { changed_leaves: vec![fskey("pkg/b.bzl")] });

    let after = engine.version(&bkey("pkg/a.bzl")).unwrap();
    assert!(after.last_changed > before.last_changed, "editing a loaded .bzl re-evaluates its loader (transitive through the load graph)");
    assert_eq!(bget(&engine.request(&bkey("pkg/a.bzl")).unwrap(), "x"), Some(BzlValue::Int(102)));
}

#[test]
fn load_cycle_is_detected() {
    let fs = Arc::new(MutFs::new());
    fs.set("/w/pkg/a.bzl", b"load(\":b.bzl\", \"y\")\nx = 1\n", 1);
    fs.set("/w/pkg/b.bzl", b"load(\":a.bzl\", \"x\")\ny = 1\n", 1);
    let engine = build_loading_engine(fs, HostPath::new("/w"));
    assert!(
        matches!(engine.request(&bkey("pkg/a.bzl")), Err(razel_core::Error::Cycle { .. })),
        "an a→b→a load() cycle must surface as a typed Cycle error"
    );
}

#[test]
fn self_load_is_detected() {
    let fs = Arc::new(MutFs::new());
    fs.set("/w/a.bzl", b"load(\":a.bzl\", \"x\")\ny = 1\n", 1);
    let engine = build_loading_engine(fs, HostPath::new("/w"));
    assert!(
        matches!(engine.request(&bkey("a.bzl")), Err(razel_core::Error::Cycle { .. })),
        "a self-load (a.bzl loads \":a.bzl\") must be detected as a cycle"
    );
}

#[test]
fn unsupported_load_form_is_rejected() {
    let fs = Arc::new(MutFs::new());
    fs.set("/w/pkg/a.bzl", b"load(\"//other:f.bzl\", \"z\")\nx = 1\n", 1);
    let engine = build_loading_engine(fs, HostPath::new("/w"));
    assert!(
        matches!(engine.request(&bkey("pkg/a.bzl")), Err(razel_core::Error::Unsupported { .. })),
        "a Bazel-label load form must fail loudly (Unsupported), never silently mis-resolve to a wrong path"
    );
}

#[test]
fn nonexistent_loaded_bzl_errors() {
    let fs = Arc::new(MutFs::new());
    fs.set("/w/pkg/a.bzl", b"load(\":ghost.bzl\", \"z\")\nx = 1\n", 1);
    let engine = build_loading_engine(fs, HostPath::new("/w"));
    assert!(
        matches!(engine.request(&bkey("pkg/a.bzl")), Err(razel_core::Error::NotFound { .. })),
        "loading a nonexistent .bzl must surface a typed NotFound, not a silent empty"
    );
}

#[test]
fn loaded_symbol_not_reexported_across_three_bzls() {
    // d.bzl defines z; a.bzl loads z; c.bzl tries to load z FROM a — must fail (a does not re-export z).
    let fs = Arc::new(MutFs::new());
    fs.set("/w/p/d.bzl", b"z = 5\n", 1);
    fs.set("/w/p/a.bzl", b"load(\":d.bzl\", \"z\")\nq = z\n", 1);
    fs.set("/w/p/c.bzl", b"load(\":a.bzl\", \"z\")\nbad = z\n", 1); // z is NOT exported by a
    let engine = build_loading_engine(fs, HostPath::new("/w"));
    assert!(
        engine.request(&bkey("p/c.bzl")).is_err(),
        "c.bzl must NOT be able to load z transitively from a.bzl — load()ed symbols are not re-exported"
    );
}

#[test]
fn diamond_load_resolves_shared_dep() {
    let fs = Arc::new(MutFs::new());
    fs.set("/w/p/d.bzl", b"z = 100\n", 1);
    fs.set("/w/p/b.bzl", b"load(\":d.bzl\", \"z\")\nx = z + 1\n", 1);
    fs.set("/w/p/c.bzl", b"load(\":d.bzl\", \"z\")\ny = z + 2\n", 1);
    fs.set("/w/p/a.bzl", b"load(\":b.bzl\", \"x\")\nload(\":c.bzl\", \"y\")\nresult = x + y\n", 1);
    let engine = build_loading_engine(fs, HostPath::new("/w"));
    let v = engine.request(&bkey("p/a.bzl")).unwrap();
    assert_eq!(bget(&v, "result"), Some(BzlValue::Int(203)), "diamond (a→b,c→d): shared d resolves once, no false cycle (x=101, y=102)");
}

// ──────────────── PACKAGE: a BUILD file as an incremental node (target-as-data) ────────────────

#[test]
fn package_instantiates_targets() {
    let fs = Arc::new(MutFs::new());
    fs.set(
        "/w/app/BUILD.bazel",
        b"target(kind = \"my_rule\", name = \"lib\", srcs = [\"a.txt\", \"b.txt\"])\n\
          target(kind = \"my_rule\", name = \"bin\", deps = [\":lib\"])\n",
        1,
    );
    let engine = build_loading_engine(fs, HostPath::new("/w"));
    let p = pkg(&engine.request(&pkey("app")).unwrap());
    assert_eq!(p.targets.len(), 2);
    // canonical: sorted by name → bin before lib.
    assert_eq!(p.targets[0].name, "bin");
    assert_eq!(p.targets[1].name, "lib");
    let lib = p.get("lib").unwrap();
    assert_eq!(lib.kind, "my_rule");
    assert_eq!(
        lib.attrs,
        vec![("srcs".to_string(), BzlValue::List(vec![BzlValue::Str("a.txt".into()), BzlValue::Str("b.txt".into())]))],
        "the target's attrs are recorded as data (the rule _impl is NOT run)"
    );
}

#[test]
fn missing_build_is_error() {
    let fs = Arc::new(MutFs::new());
    let engine = build_loading_engine(fs, HostPath::new("/w"));
    assert!(
        matches!(engine.request(&pkey("ghost")), Err(razel_core::Error::NotFound { .. })),
        "a package with no BUILD.bazel must be a typed NotFound, never an empty package"
    );
}

#[test]
fn duplicate_target_name_is_rejected() {
    let fs = Arc::new(MutFs::new());
    fs.set(
        "/w/p/BUILD.bazel",
        b"target(kind = \"r\", name = \"x\")\ntarget(kind = \"r\", name = \"x\")\n",
        1,
    );
    let engine = build_loading_engine(fs, HostPath::new("/w"));
    assert!(
        engine.request(&pkey("p")).is_err(),
        "two targets named 'x' must fail (a package is keyed by name), never silently coalesce"
    );
}

#[test]
fn editing_build_reevaluates_package() {
    let fs = Arc::new(MutFs::new());
    fs.set("/w/p/BUILD.bazel", b"target(kind = \"r\", name = \"a\")\n", 1);
    let engine = build_loading_engine(fs.clone(), HostPath::new("/w"));
    engine.request(&pkey("p")).unwrap(); // warm
    let before = engine.version(&pkey("p")).unwrap();

    fs.set("/w/p/BUILD.bazel", b"target(kind = \"r\", name = \"a\")\ntarget(kind = \"r\", name = \"b\")\n", 2);
    engine.evaluate(&[pkey("p")], FailurePolicy::FailFast, &Diff { changed_leaves: vec![fskey("p/BUILD.bazel")] });

    let after = engine.version(&pkey("p")).unwrap();
    assert!(after.last_changed > before.last_changed, "a BUILD edit (new target) re-evaluates the package");
    assert_eq!(pkg(&engine.request(&pkey("p")).unwrap()).targets.len(), 2);
}

#[test]
fn touching_build_does_not_reevaluate_package() {
    let fs = Arc::new(MutFs::new());
    fs.set("/w/p/BUILD.bazel", b"target(kind = \"r\", name = \"a\")\n", 1);
    let engine = build_loading_engine(fs.clone(), HostPath::new("/w"));
    engine.request(&pkey("p")).unwrap(); // warm
    let before = engine.version(&pkey("p")).unwrap();

    fs.set("/w/p/BUILD.bazel", b"target(kind = \"r\", name = \"a\")\n", 999); // TOUCH: new mtime, same bytes
    engine.evaluate(&[pkey("p")], FailurePolicy::FailFast, &Diff { changed_leaves: vec![fskey("p/BUILD.bazel")] });

    let after = engine.version(&pkey("p")).unwrap();
    assert_eq!(after.last_changed, before.last_changed, "a touch (same BUILD bytes) must NOT re-evaluate the package — FILE content-cutoff propagates");
    assert!(after.last_evaluated > before.last_evaluated, "PACKAGE is re-checked this round, just not recomputed");
}

#[test]
fn package_uses_loaded_constant() {
    // The BUILD load()s a constant from a sibling .bzl and uses it as an attr value. This proves PACKAGE
    // depends on BZL_LOAD (and is the property the `mutant_package_ignore_loads` mutant breaks).
    let fs = Arc::new(MutFs::new());
    fs.set("/w/p/defs.bzl", b"SRCS = [\"gen.txt\"]\n", 1);
    fs.set("/w/p/BUILD.bazel", b"load(\":defs.bzl\", \"SRCS\")\ntarget(kind = \"r\", name = \"a\", srcs = SRCS)\n", 1);
    let engine = build_loading_engine(fs, HostPath::new("/w"));
    let p = pkg(&engine.request(&pkey("p")).unwrap());
    assert_eq!(
        p.get("a").unwrap().attrs,
        vec![("srcs".to_string(), BzlValue::List(vec![BzlValue::Str("gen.txt".into())]))],
        "the loaded constant SRCS resolves into the target's attrs"
    );
}

#[test]
fn editing_loaded_bzl_propagates_to_package() {
    // Editing a .bzl the BUILD loads must re-evaluate the package (transitive through the load graph), but a
    // touch of that .bzl (same bytes) must be cut off.
    let fs = Arc::new(MutFs::new());
    fs.set("/w/p/defs.bzl", b"SRCS = [\"v1.txt\"]\n", 1);
    fs.set("/w/p/BUILD.bazel", b"load(\":defs.bzl\", \"SRCS\")\ntarget(kind = \"r\", name = \"a\", srcs = SRCS)\n", 1);
    let engine = build_loading_engine(fs.clone(), HostPath::new("/w"));
    engine.request(&pkey("p")).unwrap(); // warm: PACKAGE(p) now depends on BZL_LOAD(p/defs.bzl)
    let before = engine.version(&pkey("p")).unwrap();

    fs.set("/w/p/defs.bzl", b"SRCS = [\"v2.txt\"]\n", 2); // edit the LOADED .bzl, not the BUILD
    engine.evaluate(&[pkey("p")], FailurePolicy::FailFast, &Diff { changed_leaves: vec![fskey("p/defs.bzl")] });

    let after = engine.version(&pkey("p")).unwrap();
    assert!(after.last_changed > before.last_changed, "editing a loaded .bzl re-evaluates the package (transitive)");
    assert_eq!(
        pkg(&engine.request(&pkey("p")).unwrap()).get("a").unwrap().attrs,
        vec![("srcs".to_string(), BzlValue::List(vec![BzlValue::Str("v2.txt".into())]))]
    );
}

#[test]
fn root_package_loads_root_build() {
    // A package at the workspace root (dir == "") reads BUILD.bazel at the root, not "/BUILD.bazel".
    let fs = Arc::new(MutFs::new());
    fs.set("/w/BUILD.bazel", b"target(kind = \"r\", name = \"root_t\")\n", 1);
    let engine = build_loading_engine(fs, HostPath::new("/w"));
    let p = pkg(&engine.request(&pkey("")).unwrap());
    assert_eq!(p.targets.len(), 1);
    assert_eq!(p.targets[0].name, "root_t");
}

// ──────────────── A1: rule() machinery — a target instantiated by a .bzl-defined rule ────────────────

#[test]
fn package_target_from_rule_records_origin() {
    // The full chain: a .bzl defines a rule; the BUILD load()s + calls it; PACKAGE records the target with
    // its rule ORIGIN (the link the analysis phase follows to run the impl).
    let fs = Arc::new(MutFs::new());
    fs.set(
        "/w/app/rules.bzl",
        b"def _impl(ctx):\n    pass\n\
          my_rule = rule(implementation = _impl, attrs = {\"deps\": attr.label_list(), \"value\": attr.int()})\n",
        1,
    );
    fs.set(
        "/w/app/BUILD.bazel",
        b"load(\":rules.bzl\", \"my_rule\")\nmy_rule(name = \"lib\", value = 7, deps = [\":other\"])\n",
        1,
    );
    let engine = build_loading_engine(fs, HostPath::new("/w"));
    let p = pkg(&engine.request(&pkey("app")).unwrap());
    assert_eq!(p.targets.len(), 1);
    let t = p.get("lib").unwrap();
    assert_eq!(t.kind, "my_rule");
    assert_eq!(
        t.origin,
        Some(RuleOrigin { bzl: "app/rules.bzl".to_string(), name: "my_rule".to_string() }),
        "the target records where its rule is defined (the analysis link)"
    );
    assert_eq!(
        t.attrs,
        vec![
            ("deps".to_string(), BzlValue::List(vec![BzlValue::Str(":other".into())])),
            ("value".to_string(), BzlValue::Int(7)),
        ]
    );
}

#[test]
fn rule_schema_edit_rechecks_but_cuts_off_package() {
    // Loading/analysis separation: a target records its rule ORIGIN + attr VALUES, not the rule's schema. So
    // editing the rule's .bzl schema (here: adding an unused attr) re-checks the package but does NOT change
    // its value — PACKAGE re-evaluates and cuts off. (The schema change is analysis's concern, not loading's.)
    let fs = Arc::new(MutFs::new());
    fs.set(
        "/w/app/rules.bzl",
        b"def _impl(ctx):\n    pass\nmy_rule = rule(implementation = _impl, attrs = {\"value\": attr.int()})\n",
        1,
    );
    fs.set("/w/app/BUILD.bazel", b"load(\":rules.bzl\", \"my_rule\")\nmy_rule(name = \"lib\", value = 7)\n", 1);
    let engine = build_loading_engine(fs.clone(), HostPath::new("/w"));
    engine.request(&pkey("app")).unwrap(); // warm
    let before = engine.version(&pkey("app")).unwrap();

    // Add an unused attr to the rule schema — changes BZL_LOAD's value, but not the instantiated target.
    fs.set(
        "/w/app/rules.bzl",
        b"def _impl(ctx):\n    pass\nmy_rule = rule(implementation = _impl, attrs = {\"value\": attr.int(), \"extra\": attr.string()})\n",
        2,
    );
    engine.evaluate(&[pkey("app")], FailurePolicy::FailFast, &Diff { changed_leaves: vec![fskey("app/rules.bzl")] });

    let after = engine.version(&pkey("app")).unwrap();
    assert!(after.last_evaluated > before.last_evaluated, "PACKAGE re-evaluates (its loaded .bzl changed)");
    assert_eq!(after.last_changed, before.last_changed, "but the package value is unchanged → early cutoff (schema is analysis's concern, not loading's)");
}

// ──────────────── A4: the analysis exam — de-nativized rule impls run + providers propagate granularly ────

#[test]
fn configured_target_runs_rule_and_sums_providers() {
    let fs = Arc::new(MutFs::new());
    fs.set("/w/pkg/rules.bzl", SUM_RULES, 1);
    fs.set(
        "/w/pkg/BUILD.bazel",
        b"load(\":rules.bzl\", \"my_rule\")\n\
          my_rule(name = \"leaf\", value = 5)\n\
          my_rule(name = \"mid\", value = 10, deps = [\":leaf\"])\n\
          my_rule(name = \"root\", value = 100, deps = [\":mid\"])\n",
        1,
    );
    let engine = build_analysis_engine(fs, HostPath::new("/w"));
    assert_eq!(ct_total(&engine.request(&ctkey("pkg", "leaf")).unwrap()), 5, "leaf: 5, no deps");
    assert_eq!(ct_total(&engine.request(&ctkey("pkg", "mid")).unwrap()), 15, "mid: 10 + leaf(5)");
    assert_eq!(
        ct_total(&engine.request(&ctkey("pkg", "root")).unwrap()),
        115,
        "root: 100 + mid(10 + 5) = 115 — a REAL .bzl rule impl ran and providers propagated along edges"
    );
}

#[test]
fn analysis_propagates_granularly() {
    // Edit one target's value → its providers + its rdep's change; its DEP and an UNRELATED target cut off.
    let fs = Arc::new(MutFs::new());
    fs.set("/w/pkg/rules.bzl", SUM_RULES, 1);
    let build_v1 = b"load(\":rules.bzl\", \"my_rule\")\n\
        my_rule(name = \"leaf\", value = 5)\n\
        my_rule(name = \"mid\", value = 10, deps = [\":leaf\"])\n\
        my_rule(name = \"root\", value = 100, deps = [\":mid\"])\n\
        my_rule(name = \"other\", value = 1)\n";
    fs.set("/w/pkg/BUILD.bazel", build_v1, 1);
    let engine = build_analysis_engine(fs.clone(), HostPath::new("/w"));
    let roots = [ctkey("pkg", "leaf"), ctkey("pkg", "mid"), ctkey("pkg", "root"), ctkey("pkg", "other")];
    for r in &roots {
        engine.request(r).unwrap();
    }
    let v = |n: &str| engine.version(&ctkey("pkg", n)).unwrap();
    let (bl, bm, br, bo) = (v("leaf"), v("mid"), v("root"), v("other"));

    // Edit ONLY mid's value (10 → 20).
    fs.set(
        "/w/pkg/BUILD.bazel",
        b"load(\":rules.bzl\", \"my_rule\")\n\
          my_rule(name = \"leaf\", value = 5)\n\
          my_rule(name = \"mid\", value = 20, deps = [\":leaf\"])\n\
          my_rule(name = \"root\", value = 100, deps = [\":mid\"])\n\
          my_rule(name = \"other\", value = 1)\n",
        2,
    );
    engine.evaluate(&roots, FailurePolicy::FailFast, &Diff { changed_leaves: vec![fskey("pkg/BUILD.bazel")] });

    let (al, am, ar, ao) = (v("leaf"), v("mid"), v("root"), v("other"));
    assert!(am.last_changed > bm.last_changed, "mid's value changed → its providers change");
    assert!(ar.last_changed > br.last_changed, "root depends on mid → it re-analyzes (providers propagate up)");
    assert_eq!(al.last_changed, bl.last_changed, "leaf is mid's DEP, not its rdep → unchanged (early cutoff)");
    assert_eq!(ao.last_changed, bo.last_changed, "other is unrelated → unchanged (early cutoff)");
    assert_eq!(ct_total(&engine.request(&ctkey("pkg", "root")).unwrap()), 125, "root now 100 + (20 + 5)");
}

#[test]
fn editing_rule_impl_reevaluates_configured_target() {
    // Editing the rule's IMPL (not its schema) must re-analyze: BZL_LOAD's value (the RuleDef schema) is
    // unchanged, so CONFIGURED_TARGET's dependency on the rule .bzl's CONTENT (FILE) is what catches it.
    let fs = Arc::new(MutFs::new());
    let impl_v1 = b"NumberInfo = provider(\"NumberInfo\", fields = [\"total\"])\n\
        def _impl(ctx):\n\
        \x20   return [NumberInfo(total = ctx.attr.value)]\n\
        my_rule = rule(implementation = _impl, attrs = {\"value\": attr.int()})\n";
    fs.set("/w/pkg/rules.bzl", impl_v1, 1);
    fs.set("/w/pkg/BUILD.bazel", b"load(\":rules.bzl\", \"my_rule\")\nmy_rule(name = \"t\", value = 5)\n", 1);
    let engine = build_analysis_engine(fs.clone(), HostPath::new("/w"));
    assert_eq!(ct_total(&engine.request(&ctkey("pkg", "t")).unwrap()), 5);
    let before = engine.version(&ctkey("pkg", "t")).unwrap();

    // Same schema (value attr), different impl: total = value + 1000.
    let impl_v2 = b"NumberInfo = provider(\"NumberInfo\", fields = [\"total\"])\n\
        def _impl(ctx):\n\
        \x20   return [NumberInfo(total = ctx.attr.value + 1000)]\n\
        my_rule = rule(implementation = _impl, attrs = {\"value\": attr.int()})\n";
    fs.set("/w/pkg/rules.bzl", impl_v2, 2);
    engine.evaluate(&[ctkey("pkg", "t")], FailurePolicy::FailFast, &Diff { changed_leaves: vec![fskey("pkg/rules.bzl")] });

    let after = engine.version(&ctkey("pkg", "t")).unwrap();
    assert!(after.last_changed > before.last_changed, "an impl edit re-analyzes (FILE content dep, not just BZL_LOAD schema)");
    assert_eq!(ct_total(&engine.request(&ctkey("pkg", "t")).unwrap()), 1005, "the new impl ran");
}

#[test]
fn analyze_target_without_rule_is_fail_closed() {
    // A generic target() placeholder has no rule origin → there is no impl to run → Unsupported (never empty).
    let fs = Arc::new(MutFs::new());
    fs.set("/w/p/BUILD.bazel", b"target(kind = \"x\", name = \"t\")\n", 1);
    let engine = build_analysis_engine(fs, HostPath::new("/w"));
    assert!(
        matches!(engine.request(&ctkey("p", "t")), Err(razel_core::Error::Unsupported { .. })),
        "analyzing a target with no rule definition must fail closed (Unsupported)"
    );
}

#[test]
fn rule_impl_reaching_for_deferred_ctx_capability_fails_closed() {
    // Deferred capabilities (ctx.actions / ctx.toolchains — execution + pitfall #4) are NOT on ctx yet. An impl
    // that reaches for one must FAIL CLOSED (Starlark raises on a missing struct field), never silently get None.
    let fs = Arc::new(MutFs::new());
    fs.set(
        "/w/pkg/rules.bzl",
        b"NumberInfo = provider(\"NumberInfo\", fields = [\"total\"])\n\
          def _impl(ctx):\n\
          \x20   x = ctx.actions\n\
          \x20   return [NumberInfo(total = 0)]\n\
          my_rule = rule(implementation = _impl, attrs = {})\n",
        1,
    );
    fs.set("/w/pkg/BUILD.bazel", b"load(\":rules.bzl\", \"my_rule\")\nmy_rule(name = \"t\")\n", 1);
    let engine = build_analysis_engine(fs, HostPath::new("/w"));
    assert!(
        engine.request(&ctkey("pkg", "t")).is_err(),
        "reaching for an unprovided ctx capability must fail closed (loud), not silently yield None"
    );
}

#[test]
fn rule_bzl_with_load_fails_closed() {
    // Threading the rule .bzl's own load()s into evaluate_rule is deferred (self-contained rule .bzls only). A
    // rule .bzl that DOES load() must fail closed at analysis (empty loader → Eval error), never absorb to empty.
    let fs = Arc::new(MutFs::new());
    fs.set("/w/pkg/helper.bzl", b"K = 7\n", 1);
    fs.set(
        "/w/pkg/rules.bzl",
        b"load(\":helper.bzl\", \"K\")\n\
          NumberInfo = provider(\"NumberInfo\", fields = [\"total\"])\n\
          def _impl(ctx):\n\
          \x20   return [NumberInfo(total = K)]\n\
          my_rule = rule(implementation = _impl, attrs = {})\n",
        1,
    );
    fs.set("/w/pkg/BUILD.bazel", b"load(\":rules.bzl\", \"my_rule\")\nmy_rule(name = \"t\")\n", 1);
    let engine = build_analysis_engine(fs, HostPath::new("/w"));
    assert!(
        engine.request(&ctkey("pkg", "t")).is_err(),
        "a rule .bzl with its own load() must fail closed at analysis (deferred), not silently mis-evaluate"
    );
}

#[test]
fn configured_target_dep_cycle_is_detected() {
    // a → b → a (via deps) must surface as a typed Cycle, inherited from the engine.
    let fs = Arc::new(MutFs::new());
    fs.set("/w/pkg/rules.bzl", SUM_RULES, 1);
    fs.set(
        "/w/pkg/BUILD.bazel",
        b"load(\":rules.bzl\", \"my_rule\")\n\
          my_rule(name = \"a\", value = 1, deps = [\":b\"])\n\
          my_rule(name = \"b\", value = 1, deps = [\":a\"])\n",
        1,
    );
    let engine = build_analysis_engine(fs, HostPath::new("/w"));
    assert!(
        matches!(engine.request(&ctkey("pkg", "a")), Err(razel_core::Error::Cycle { .. })),
        "a configured-target dependency cycle must be a typed Cycle error"
    );
}
