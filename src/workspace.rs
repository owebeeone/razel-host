//! `razel-host::workspace` — workspace-root DISCOVERY at the composition root (T17 Phase B2). Bazel roots a
//! build at the nearest enclosing directory that holds the bzlmod marker `MODULE.bazel`; razel now does the
//! same, replacing the pre-B2 "the root IS the cwd" shortcut. From a start directory (the daemon's cwd), the
//! walk climbs the parent chain to the filesystem root and returns the FIRST (nearest) directory that
//! contains the marker — so `razel build` works from a subdirectory exactly as `bazel build` does.
//!
//! Two disciplines this module keeps:
//!   * **System seam ONLY.** Every filesystem touch is a `System::stat` probe of `<dir>/MODULE.bazel` (the
//!     same seam `discover_rustc` probes through). No `std::fs`/`std::env` — the raw-OS wall. Parent
//!     computation is pure `str` arithmetic on the `HostPath` (string parsing is not a syscall).
//!   * **Fail-closed.** No marker anywhere up the chain is a typed `Error::NotFound` — the daemon then
//!     refuses to serve builds rootlessly, mirroring Bazel's "command is only supported from within a
//!     workspace", NEVER a silent fall-back to the bare cwd (that silent fall-back is the mutant below).

use razel_core::Error;
use razel_os_api::{HostPath, OsPathFragment, System};

/// The Bazel workspace marker filename (bzlmod). A directory that contains it is a module/workspace root.
/// Kept as the CANONICAL/primary marker name (bzlmod-native, what razel's own workspace ships).
pub const WORKSPACE_MARKER: &str = "MODULE.bazel";

/// Every filename Bazel accepts as a workspace-root marker: the bzlmod `MODULE.bazel` plus the legacy
/// `WORKSPACE.bazel` / `WORKSPACE` (ANY one present makes a directory a root). Root discovery is by directory
/// DEPTH (nearest wins) — the marker KIND does not change that. Ordered primary-first only for probe locality;
/// the nearest DIRECTORY wins regardless of which marker it holds. Many vendored third-party trees ship only
/// `WORKSPACE`, so razel must accept them to root a build inside a checked-out ruleset (the TF path).
pub const WORKSPACE_MARKERS: &[&str] = &["MODULE.bazel", "WORKSPACE.bazel", "WORKSPACE"];

/// Discover the workspace root: from `start`, walk UP directory by directory to the filesystem root and
/// return the FIRST directory containing ANY [`WORKSPACE_MARKERS`] file — `MODULE.bazel`, `WORKSPACE.bazel`,
/// or `WORKSPACE` (the NEAREST DIRECTORY wins, whichever marker it holds — Bazel's rule). Probes via
/// [`System::stat`] through the seam (no ambient filesystem). No marker anywhere up the chain → a typed
/// [`Error::NotFound`] (fail-closed — NEVER a silent bare-cwd fall-back).
///
/// Composition-root policy: the daemon passes its `System::cwd()` as `start`. razel-host's own test/builder
/// entry points inject a root explicitly and do NOT go through discovery.
pub fn discover_workspace_root(sys: &dyn System, start: &HostPath) -> Result<HostPath, Error> {
    // MUTANT `mutant_root_discovery_uses_bare_cwd`: skip the walk and return the start dir (the bare cwd)
    // directly — the pre-B2 "the root IS the cwd" shortcut this discovery replaces. A subdir start then
    // resolves to itself instead of the marked ancestor, and a marker-less chain "succeeds" instead of
    // failing closed. The `workspace.rs` tests below go RED under it. Never enable in a real build.
    if cfg!(feature = "mutant_root_discovery_uses_bare_cwd") {
        return Ok(start.clone());
    }

    let markers: Vec<OsPathFragment> = WORKSPACE_MARKERS.iter().map(|m| OsPathFragment::new_unchecked(*m)).collect();
    let mut dir = start.clone();
    loop {
        // A `stat` hit on `<dir>/<any marker>` marks the root (matches `discover_rustc`'s `stat(..).is_ok()`
        // probe form). `stat` follows the final symlink, so a symlinked marker resolves; a missing one Errs.
        // ANY marker (MODULE.bazel | WORKSPACE.bazel | WORKSPACE) roots this dir — the nearest DIRECTORY wins.
        if markers.iter().any(|m| sys.stat(&dir.join(m)).is_ok()) {
            return Ok(dir);
        }
        match parent_dir(&dir) {
            Some(parent) => dir = parent,
            None => {
                return Err(Error::NotFound {
                    what: "workspace root".into(),
                    detail: format!(
                        "no {WORKSPACE_MARKER} marker found walking up from '{}' to the filesystem root \
                         (a razel build is only supported from within a workspace)",
                        start.as_str()
                    ),
                });
            }
        }
    }
}

/// The parent directory of an absolute host path, as pure path-string arithmetic — NOT an OS call (the seam
/// ban is on filesystem/env access, not on parsing a path string). `/a/b/c` → `/a/b`; `/a` → `/`; `/` →
/// `None` (the filesystem root has no parent — this terminates the walk). A relative path with no separator
/// also yields `None` (defensive: a real cwd is absolute).
fn parent_dir(dir: &HostPath) -> Option<HostPath> {
    let s = dir.as_str();
    // Normalize a single trailing separator (except the root itself) so `/a/b/` behaves like `/a/b`.
    let s = if s.len() > 1 { s.strip_suffix('/').unwrap_or(s) } else { s };
    match s.rfind('/') {
        None => None,                                       // no separator → no parent to climb to
        Some(0) if s == "/" => None,                        // already at the filesystem root
        Some(0) => Some(HostPath::new("/")),                // parent IS the filesystem root
        Some(i) => Some(HostPath::new(s[..i].to_string())), // strip the last `/segment`
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use razel_os_api::conformance::FakeSystem;

    /// Running from a SUBDIRECTORY resolves the marked ancestor, not the cwd (the headline B2 behavior).
    /// RED under `mutant_root_discovery_uses_bare_cwd` (which returns the subdir itself).
    #[test]
    fn discovers_nearest_marker_from_subdir() {
        let sys = FakeSystem::default().with_file("/ws/MODULE.bazel", b"module(name = \"x\")\n");
        let root = discover_workspace_root(&sys, &HostPath::new("/ws/sub/dir")).expect("marker is up the chain");
        assert_eq!(root.as_str(), "/ws", "the walk must climb to the nearest MODULE.bazel, not stay at cwd");
    }

    /// The start dir itself being the root is the base case (running from the workspace root).
    #[test]
    fn start_dir_that_holds_the_marker_is_the_root() {
        let sys = FakeSystem::default().with_file("/ws/MODULE.bazel", b"module()\n");
        let root = discover_workspace_root(&sys, &HostPath::new("/ws")).expect("start dir holds the marker");
        assert_eq!(root.as_str(), "/ws");
    }

    /// No marker anywhere up the chain → a TYPED, fail-closed `NotFound` (never a silent bare-cwd success).
    /// RED under the mutant (which returns `Ok(start)` for a marker-less chain).
    #[test]
    fn no_marker_anywhere_is_typed_error_not_bare_cwd() {
        let sys = FakeSystem::default(); // empty tree: no MODULE.bazel anywhere
        match discover_workspace_root(&sys, &HostPath::new("/no/marker/here")) {
            Err(Error::NotFound { what, .. }) => assert_eq!(what, "workspace root"),
            other => panic!("a marker-less chain must be a typed NotFound (fail-closed), got {other:?}"),
        }
    }

    /// NESTED markers: the NEAREST enclosing marker wins (`/ws/sub`), not the outer one (`/ws`) — Bazel's
    /// rule. RED under the mutant (which returns the `/ws/sub/x` start dir).
    #[test]
    fn nearest_marker_wins_when_nested() {
        let sys = FakeSystem::default()
            .with_file("/ws/MODULE.bazel", b"module()\n")
            .with_file("/ws/sub/MODULE.bazel", b"module()\n");
        let root = discover_workspace_root(&sys, &HostPath::new("/ws/sub/x")).expect("nested marker present");
        assert_eq!(root.as_str(), "/ws/sub", "the NEAREST MODULE.bazel must win over an outer one");
    }

    /// The walk terminates at the filesystem root even from a deep chain with no marker (no infinite loop).
    #[test]
    fn walk_terminates_at_filesystem_root() {
        let sys = FakeSystem::default();
        assert!(discover_workspace_root(&sys, &HostPath::new("/a/b/c/d/e")).is_err());
        assert!(discover_workspace_root(&sys, &HostPath::new("/")).is_err(), "even a root start terminates");
    }

    /// T20 TF-unblocker B: a legacy WORKSPACE-only tree (no MODULE.bazel) is a valid root — many vendored
    /// third-party trees ship only `WORKSPACE`. RED before the marker set widened past MODULE.bazel.
    #[test]
    fn discovers_workspace_only_marker() {
        let sys = FakeSystem::default().with_file("/ws/WORKSPACE", b"workspace(name = \"x\")\n");
        let root = discover_workspace_root(&sys, &HostPath::new("/ws/sub/dir")).expect("WORKSPACE marks a root");
        assert_eq!(root.as_str(), "/ws", "a WORKSPACE-only dir is a workspace root (any marker, nearest wins)");
    }

    /// T20 TF-unblocker B: `WORKSPACE.bazel` (the `.bazel`-suffixed legacy marker) is equally a root marker.
    #[test]
    fn discovers_workspace_dot_bazel_marker() {
        let sys = FakeSystem::default().with_file("/ws/WORKSPACE.bazel", b"workspace(name = \"x\")\n");
        let root = discover_workspace_root(&sys, &HostPath::new("/ws/sub")).expect("WORKSPACE.bazel marks a root");
        assert_eq!(root.as_str(), "/ws");
    }

    /// Nearest wins ACROSS marker TYPES: an inner `WORKSPACE` beats an outer `MODULE.bazel` (root discovery is
    /// by directory depth; marker KIND does not change the nearest-wins rule). RED if only MODULE.bazel probed.
    #[test]
    fn nearest_marker_wins_across_marker_types() {
        let sys = FakeSystem::default()
            .with_file("/ws/MODULE.bazel", b"module()\n")
            .with_file("/ws/sub/WORKSPACE", b"workspace()\n");
        let root = discover_workspace_root(&sys, &HostPath::new("/ws/sub/x")).expect("nested marker present");
        assert_eq!(root.as_str(), "/ws/sub", "the NEAREST marker of ANY kind wins over an outer one");
    }
}
