//! `razel-host` — a composition root. The ONLY layer permitted to depend on impls (`role: "root"` in the
//! dependency-deny wall): it picks a `System` impl and the incremental `Engine`, registers the source
//! node-kinds, and hands back a running graph. First assembly proving the seams compose end-to-end —
//! a generic engine + an OS capability + build-domain node-kinds, wired with no consumer rewrite.

use razel_bzl_api::BzlEvaluator;
use razel_bzl_starlark::StarlarkEvaluator;
use razel_engine::Engine;
use razel_os_api::{HostPath, System};
use razel_toolchain::{Platform, RegisteredToolchain};
use std::collections::HashMap;
use std::sync::Arc;

/// Build an `Engine` with the source-graph node-kinds (`FILE_STATE` / `FILE` / `DIRECTORY_LISTING` / `GLOB`)
/// registered over `sys`, interpreting logical paths relative to `root`.
pub fn build_source_engine(sys: Arc<dyn System>, root: HostPath) -> Engine {
    let mut engine = Engine::new();
    razel_source::register_source_kinds(&mut engine, sys, root);
    engine
}

/// Build an `Engine` with the source-graph kinds AND the loading kinds (`BZL_LOAD` + `PACKAGE`), wiring the
/// real Starlark evaluator. This is the assembly that spans the OS seam, the engine, and the Starlark seam:
/// source files → `.bzl` modules → packages of targets, all on the one incremental engine.
pub fn build_loading_engine(sys: Arc<dyn System>, root: HostPath) -> Engine {
    let mut engine = Engine::new();
    razel_source::register_source_kinds(&mut engine, sys.clone(), root.clone());
    let eval: Arc<dyn BzlEvaluator> = Arc::new(StarlarkEvaluator::new());
    razel_load::register_load_kinds(&mut engine, sys.clone(), root.clone(), eval.clone());
    razel_package::register_package_kinds(&mut engine, sys, root, eval);
    engine
}

/// Build an `Engine` spanning loading AND analysis: source → `.bzl` → packages → `CONFIGURED_TARGET`. A target's
/// rule implementation runs over the engine, with providers propagating granularly across the dependency graph.
/// No toolchains registered — a rule requiring one resolves fail-closed (use `build_analysis_engine_with_toolchains`).
pub fn build_analysis_engine(sys: Arc<dyn System>, root: HostPath) -> Engine {
    build_analysis_engine_with_toolchains(sys, root, Vec::new(), HashMap::new())
}

/// Build an analysis engine AND register `TOOLCHAIN_CONTEXT` with the given registered toolchains + platforms.
/// A rule's `toolchains=[type]` resolves against this set, keyed by the target platform (the CONFIGURATION
/// dimension). SPIKE: the registry is supplied here; `.bzl` `toolchain()`/`platform()` declarations are deferred.
pub fn build_analysis_engine_with_toolchains(
    sys: Arc<dyn System>,
    root: HostPath,
    registered: Vec<RegisteredToolchain>,
    platforms: HashMap<String, Platform>,
) -> Engine {
    let mut engine = Engine::new();
    razel_source::register_source_kinds(&mut engine, sys.clone(), root.clone());
    let eval: Arc<dyn BzlEvaluator> = Arc::new(StarlarkEvaluator::new());
    razel_load::register_load_kinds(&mut engine, sys.clone(), root.clone(), eval.clone());
    razel_package::register_package_kinds(&mut engine, sys.clone(), root.clone(), eval.clone());
    razel_analysis::register_analysis_kinds(&mut engine, sys, root, eval);
    razel_toolchain::register_toolchain_kinds(&mut engine, registered, platforms);
    engine
}
