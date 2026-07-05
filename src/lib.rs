//! `razel-host` — a composition root. The ONLY layer permitted to depend on impls (`role: "root"` in the
//! dependency-deny wall): it picks a `System` impl and the incremental `Engine`, registers the source
//! node-kinds, and hands back a running graph. First assembly proving the seams compose end-to-end —
//! a generic engine + an OS capability + build-domain node-kinds, wired with no consumer rewrite.

use razel_bzl_api::BzlEvaluator;
use razel_bzl_starlark::StarlarkEvaluator;
use razel_engine::Engine;
use razel_exec_api::SpawnStrategy;
use razel_os_api::{HostPath, System};
use razel_toolchain::{Platform, RegisteredExecPlatform, ToolchainRegistry};
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
/// No registrations seeded and no platform definitions — a rule requiring a toolchain resolves fail-closed
/// (use `build_analysis_engine_with_toolchains` and seed the returned registry).
pub fn build_analysis_engine(sys: Arc<dyn System>, root: HostPath) -> Engine {
    build_analysis_engine_with_toolchains(
        sys,
        root,
        HashMap::new(),
        RegisteredExecPlatform { name: "host".to_string(), constraints: Vec::new() },
    )
    .0
}

/// Build an analysis engine AND register the toolchain node-kinds: `TOOLCHAIN_CONTEXT` plus the two
/// config-keyed registration nodes (`REGISTERED_TOOLCHAINS` / `REGISTERED_EXECUTION_PLATFORMS` — the
/// ADR-0010 lockdown's dependency edges). The registered sets are HOST-INJECTED in v1: they live in the
/// returned shared [`ToolchainRegistry`] handle, which the caller seeds (keyed by configuration) and may
/// MUTATE against the running engine — dirty the matching `RegisteredToolchainsKey`/
/// `RegisteredExecutionPlatformsKey` via `evaluate(.., Diff)` and invalidation flows through the edge.
/// `platforms` are the platform DEFINITIONS (name → constraints); `host_platform` is always appended as the
/// final execution-platform candidate. SPIKE: `.bzl` `toolchain()`/`platform()` producers are deferred and
/// will fill the same nodes behind the same edges.
pub fn build_analysis_engine_with_toolchains(
    sys: Arc<dyn System>,
    root: HostPath,
    platforms: HashMap<String, Platform>,
    host_platform: RegisteredExecPlatform,
) -> (Engine, Arc<ToolchainRegistry>) {
    let mut engine = Engine::new();
    razel_source::register_source_kinds(&mut engine, sys.clone(), root.clone());
    let eval: Arc<dyn BzlEvaluator> = Arc::new(StarlarkEvaluator::new());
    razel_load::register_load_kinds(&mut engine, sys.clone(), root.clone(), eval.clone());
    razel_package::register_package_kinds(&mut engine, sys.clone(), root.clone(), eval.clone());
    razel_analysis::register_analysis_kinds(&mut engine, sys, root, eval);
    let registry = Arc::new(ToolchainRegistry::new());
    razel_toolchain::register_toolchain_kinds(&mut engine, registry.clone(), platforms, host_platform);
    (engine, registry)
}

/// Build an `Engine` registering loading, analysis AND the execution node-kind: source → `.bzl` →
/// `CONFIGURED_TARGET`, plus `ACTION` over the supplied `SpawnStrategy` (local/sandbox/remote behind the one seam
/// — a host decision, no consumer rewrite). NOTE: there is no automatic `CONFIGURED_TARGET → ACTION` demand edge
/// yet — a rule's declared actions ride on the configured target as templates (`RuleResult.actions`), and the
/// caller turns each into an `ACTION` node via `razel_action::action_key_from_template`. Wiring that edge (and
/// resolving input PATHS → producer-output digests) is the deferred artifact-materializer step. Toolchains are
/// wired as in `build_analysis_engine`.
pub fn build_execution_engine(sys: Arc<dyn System>, root: HostPath, strategy: Arc<dyn SpawnStrategy>) -> Engine {
    let mut engine = build_analysis_engine(sys, root);
    razel_action::register_action_kinds(&mut engine, strategy);
    engine
}
