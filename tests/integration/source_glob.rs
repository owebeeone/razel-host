//! FILE / FILE_STATE / glob incremental-source gate (carved out of the former monolithic `tests/integration.rs`).

use crate::common::*;
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
    let before = engine.inspect(&fkey("a.txt")).unwrap().version;

    fs.set("/w/a.txt", b"v2-different", 200); // genuine content change (mtime too)
    engine.evaluate(&[fkey("a.txt")], FailurePolicy::FailFast, Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(fskey("a.txt"))] });

    let after = engine.inspect(&fkey("a.txt")).unwrap().version;
    assert!(after.last_changed > before.last_changed, "content changed → FILE propagates");
    assert_eq!(fval(&engine.request(&fkey("a.txt")).unwrap()).content, Digest::of(b"v2-different"));
}

#[test]
fn touch_without_content_change_is_cut_off() {
    let fs = Arc::new(MutFs::new());
    fs.set("/w/a.txt", b"same", 100);
    let engine = build_source_engine(fs.clone(), HostPath::new("/w"));
    engine.request(&fkey("a.txt")).unwrap(); // warm
    let bf = engine.inspect(&fkey("a.txt")).unwrap().version;
    let bs = engine.inspect(&fskey("a.txt")).unwrap().version;

    fs.set("/w/a.txt", b"same", 999); // TOUCH: new mtime, identical content
    engine.evaluate(&[fkey("a.txt")], FailurePolicy::FailFast, Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(fskey("a.txt"))] });

    let af = engine.inspect(&fkey("a.txt")).unwrap().version;
    let as_ = engine.inspect(&fskey("a.txt")).unwrap().version;
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
    let before = engine.inspect(&gkey("src", "*.txt")).unwrap().version;

    fs.set("/w/src/d.txt", b"d", 1); // a new matching file appears in the directory
    engine.evaluate(&[gkey("src", "*.txt")], FailurePolicy::FailFast, Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(dlkey("src"))] });

    let after = engine.inspect(&gkey("src", "*.txt")).unwrap().version;
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
    let rep = engine.evaluate(&[gkey("src", "*.txt")], FailurePolicy::FailFast, Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(fskey("src/a.txt"))] });

    assert_eq!(rep.recomputes, 0, "a file-content change must not recompute the glob (no content dependency)");
}

#[test]
fn add_nonmatching_file_early_cuts_at_glob() {
    // REQ-SOURCE-002 over the root: adding a NON-matching file changes the DIRECTORY_LISTING value (new
    // entry), so the glob re-runs — but the GlobMatch is unchanged, so early cutoff stops propagation AT
    // the glob (its last_changed does not advance).
    let fs = Arc::new(MutFs::new());
    fs.set("/w/src/a.txt", b"a", 1);
    fs.set("/w/src/b.txt", b"b", 1);
    let engine = build_source_engine(fs.clone(), HostPath::new("/w"));
    engine.request(&gkey("src", "*.txt")).unwrap(); // warm
    let g_before = engine.inspect(&gkey("src", "*.txt")).unwrap().version;
    let d_before = engine.inspect(&dlkey("src")).unwrap().version;

    fs.set("/w/src/c.rs", b"c", 2); // a new NON-matching file appears
    engine.evaluate(&[gkey("src", "*.txt")], FailurePolicy::FailFast, Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(dlkey("src"))] });

    let g_after = engine.inspect(&gkey("src", "*.txt")).unwrap().version;
    let d_after = engine.inspect(&dlkey("src")).unwrap().version;
    assert!(d_after.last_changed > d_before.last_changed, "the listing's entry set changed → it propagates");
    assert!(g_after.last_evaluated > g_before.last_evaluated, "the glob re-runs (its listing changed)");
    assert_eq!(g_after.last_changed, g_before.last_changed, "but the match set is unchanged → early cutoff AT the glob");
    assert_eq!(
        gmatch(&engine.request(&gkey("src", "*.txt")).unwrap()),
        vec!["src/a.txt".to_string(), "src/b.txt".to_string()]
    );
}

#[test]
fn over_broad_listing_invalidation_still_cuts_off_glob() {
    let fs = Arc::new(MutFs::new());
    fs.set("/w/src/a.txt", b"a", 1);
    fs.set("/w/src/b.txt", b"b", 1);
    let engine = build_source_engine(fs.clone(), HostPath::new("/w"));
    engine.request(&gkey("src", "*.txt")).unwrap(); // warm
    let g_before = engine.inspect(&gkey("src", "*.txt")).unwrap().version;
    let d_before = engine.inspect(&dlkey("src")).unwrap().version;

    // An over-broad monitor re-dirties the whole DIRECTORY_LISTING on a mere mtime change, but the entry
    // (name, is_dir) set is identical → the listing value is unchanged → the glob is pruned by cutoff.
    fs.set("/w/src/a.txt", b"a", 999);
    let rep = engine.evaluate(&[gkey("src", "*.txt")], FailurePolicy::FailFast, Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(dlkey("src"))] });

    let g_after = engine.inspect(&gkey("src", "*.txt")).unwrap().version;
    let d_after = engine.inspect(&dlkey("src")).unwrap().version;
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
    engine.evaluate(&[gkey("src", "*.txt")], FailurePolicy::FailFast, Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(dlkey("src"))] });

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
