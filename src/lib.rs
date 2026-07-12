//! `razel-host` — a composition root. The ONLY layer permitted to depend on impls (`role: "root"` in the
//! dependency-deny wall): it picks a `System` impl and the incremental `Engine`, registers the source
//! node-kinds, and hands back a running graph. First assembly proving the seams compose end-to-end —
//! a generic engine + an OS capability + build-domain node-kinds, wired with no consumer rewrite.

use razel_action::{
    derived_outputs, ArtifactRef, ArtifactValue, BlobStore, OutputSelection, TargetCompletionKey,
};
use razel_analysis::{ConfiguredTarget, ConfiguredTargetKey, SelectConfig};
use razel_bzl_api::BzlEvaluator;
use razel_bzl_starlark::StarlarkEvaluator;
use razel_core::{Error, NodeKey};
use razel_engine::Engine;
use razel_engine_api::DemandEngine;
use razel_exec_api::SpawnStrategy;
use razel_ids::RootRelativePath;
use razel_os_api::{HostPath, System};
use razel_source::join_root;
use razel_toolchain::{Platform, RegisteredExecPlatform, ToolchainRegistry};
use std::collections::HashMap;
use std::sync::Arc;

pub mod local_exec;
pub use local_exec::{DispatchStrategy, ExecRootPolicy, LocalSpawnStrategy};
pub mod rust_toolchain;
pub use rust_toolchain::{discover_rustc, rust_toolchain, HOST_CONFIG, RUST_TOOLCHAIN_TYPE};
pub mod workspace;
pub use workspace::{discover_workspace_root, WORKSPACE_MARKER};
pub mod module_config;
pub use module_config::{
    module_external_repos, read_module_file, resolve_module_toolchains, workspace_repos, MODULE_FILE,
};

/// The external-source-roots registry vocabulary (T17), re-exported so a protocol root (`razel-daemon`) can
/// seed/inject it WITHOUT naming `razel-source` (keeps the daemon's dep surface to {cli, comms, host, wire}).
pub use razel_source::{ExternalRepo, ExternalRepos};

/// Build an `Engine` with the source-graph node-kinds (`FILE_STATE` / `FILE` / `DIRECTORY_LISTING` / `GLOB`)
/// registered over `sys`, interpreting logical paths relative to `root`.
pub fn build_source_engine(sys: Arc<dyn System>, root: HostPath) -> Engine {
    let mut engine = Engine::new();
    razel_source::register_source_kinds(&mut engine, sys, root, ExternalRepos::empty());
    engine
}

/// Build an `Engine` with the source-graph kinds AND the loading kinds (`BZL_LOAD` + `PACKAGE`), wiring the
/// real Starlark evaluator. This is the assembly that spans the OS seam, the engine, and the Starlark seam:
/// source files → `.bzl` modules → packages of targets, all on the one incremental engine.
pub fn build_loading_engine(sys: Arc<dyn System>, root: HostPath) -> Engine {
    build_loading_engine_with_repos(sys, root, ExternalRepos::empty())
}

/// [`build_loading_engine`] with the T17/T20 external-source-roots `repos` registry injected — the loading
/// slice (`FILE`/`BZL_LOAD`/`PACKAGE`) resolving `@<repo>//…` label loads + `external/<repo>/…` exec reads
/// through `repos`. Empty `repos` is byte-identical to `build_loading_engine`. Used to drive `.bzl` load
/// resolution over an injected ruleset registry (the T20 R1 `@rules_rust//rust:defs.bzl` path) without the
/// analysis/execution layers.
pub fn build_loading_engine_with_repos(sys: Arc<dyn System>, root: HostPath, repos: ExternalRepos) -> Engine {
    let mut engine = Engine::new();
    razel_source::register_source_kinds(&mut engine, sys.clone(), root.clone(), repos.clone());
    let eval: Arc<dyn BzlEvaluator> = Arc::new(StarlarkEvaluator::new());
    razel_load::register_load_kinds(&mut engine, sys.clone(), root.clone(), eval.clone(), repos.clone());
    razel_package::register_package_kinds(&mut engine, sys, root, eval, repos);
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
    analysis_engine_with_repos(sys, root, ExternalRepos::empty(), platforms, host_platform)
}

/// The loading+analysis+toolchain wiring, parameterized by the external-repo `repos` registry (the T17
/// external-source-roots injection point). The public `build_analysis_engine_with_toolchains` delegates here
/// with an EMPTY registry (so every existing internal-only caller is byte-identical); the `*_repos` execution
/// builders below thread a seeded registry through the SAME 5 registrars.
fn analysis_engine_with_repos(
    sys: Arc<dyn System>,
    root: HostPath,
    repos: ExternalRepos,
    platforms: HashMap<String, Platform>,
    host_platform: RegisteredExecPlatform,
) -> (Engine, Arc<ToolchainRegistry>) {
    // Default select-config: the per-configuration CONSTRAINT set derived from the SAME `platforms` map the
    // toolchain path uses (single source of truth — a config's target platform constraints serve BOTH
    // toolchain resolution and select()/config_setting matching), with EMPTY `values`. The `values`-based
    // TF path uses `analysis_engine_with_repos_and_select`.
    let select_config = select_config_from_platforms(&platforms);
    analysis_engine_with_repos_and_select(sys, root, repos, platforms, host_platform, select_config)
}

/// [`analysis_engine_with_repos`] with an EXPLICIT [`SelectConfig`] (T20 select) — the `values`-carrying path
/// (a `config_setting(values = {"cpu": …})` matches against the injected per-configuration values). The
/// constraint side still typically mirrors `platforms`; the caller composes both.
fn analysis_engine_with_repos_and_select(
    sys: Arc<dyn System>,
    root: HostPath,
    repos: ExternalRepos,
    platforms: HashMap<String, Platform>,
    host_platform: RegisteredExecPlatform,
    select_config: SelectConfig,
) -> (Engine, Arc<ToolchainRegistry>) {
    let mut engine = Engine::new();
    razel_source::register_source_kinds(&mut engine, sys.clone(), root.clone(), repos.clone());
    let eval: Arc<dyn BzlEvaluator> = Arc::new(StarlarkEvaluator::new());
    razel_load::register_load_kinds(&mut engine, sys.clone(), root.clone(), eval.clone(), repos.clone());
    razel_package::register_package_kinds(&mut engine, sys.clone(), root.clone(), eval.clone(), repos.clone());
    razel_analysis::register_analysis_kinds(&mut engine, sys, root, eval, repos, select_config);
    let registry = Arc::new(ToolchainRegistry::new());
    razel_toolchain::register_toolchain_kinds(&mut engine, registry.clone(), platforms, host_platform);
    (engine, registry)
}

/// Derive a [`SelectConfig`] from the platform DEFINITIONS: each configuration's constraint_value LABELS
/// become its select constraint set (the ONE source of truth — a config's constraints serve both toolchain
/// and select resolution). `values` are empty (the `--define`/`--cpu`-style path is injected explicitly).
fn select_config_from_platforms(platforms: &HashMap<String, Platform>) -> SelectConfig {
    SelectConfig {
        platforms: platforms
            .iter()
            .map(|(name, p)| (name.clone(), p.constraints.iter().map(|c| c.0.clone()).collect()))
            .collect(),
        values: HashMap::new(),
    }
}

/// Build an `Engine` registering loading, analysis AND the execution node-kinds of the artifact-model
/// lockdown: source → `.bzl` → `CONFIGURED_TARGET`, plus `ACTION` (positional `GeneratingActionKey`) +
/// `ARTIFACT` + `TARGET_COMPLETION` over the supplied `SpawnStrategy` (local/sandbox/remote behind the one
/// seam — a host decision, no consumer rewrite). Execution is ON the demand graph: requesting
/// `TARGET_COMPLETION{ct, Default}` (or an output's `ARTIFACT`) builds the target's outputs as a pure graph
/// consequence — CT → ARTIFACT → ACTION → spawn → digests — with no hand bridge. v1 injections: the
/// `SameTargetOrSourceResolver` input policy + an in-memory `BlobStore` (use
/// [`build_execution_engine_with`] to inject custom seam impls and keep a handle on the store). Toolchains
/// are wired as in `build_analysis_engine`.
pub fn build_execution_engine(sys: Arc<dyn System>, root: HostPath, strategy: Arc<dyn SpawnStrategy>) -> Engine {
    build_execution_engine_with(
        sys,
        root,
        strategy,
        Arc::new(razel_action::SameTargetOrSourceResolver),
        Arc::new(razel_action::InMemoryBlobStore::new()),
    )
}

/// [`build_execution_engine`] with the two materializer seams caller-injected: the `InputResolver`
/// (template input path → `ArtifactRef`, fail-closed) and the `BlobStore` (the ONE bytes home — callers
/// keep their `Arc` handle to read produced bytes by digest).
pub fn build_execution_engine_with(
    sys: Arc<dyn System>,
    root: HostPath,
    strategy: Arc<dyn SpawnStrategy>,
    resolver: Arc<dyn razel_action::InputResolver>,
    blobs: Arc<dyn razel_action::BlobStore>,
) -> Engine {
    let mut engine = build_analysis_engine(sys.clone(), root.clone());
    razel_action::register_action_kinds(&mut engine, strategy, resolver, blobs, sys, root, ExternalRepos::empty());
    engine
}

/// [`build_execution_engine_with`] plus the toolchain wiring of `build_analysis_engine_with_toolchains`:
/// the full stack (loading → analysis → toolchains → execution) with the registration registry handle
/// returned so the caller can SEED it (e.g. the discovered rust toolchain under [`rust_toolchain::HOST_CONFIG`])
/// and mutate it against the running engine.
#[allow(clippy::too_many_arguments)]
pub fn build_execution_engine_with_toolchains(
    sys: Arc<dyn System>,
    root: HostPath,
    strategy: Arc<dyn SpawnStrategy>,
    resolver: Arc<dyn razel_action::InputResolver>,
    blobs: Arc<dyn razel_action::BlobStore>,
    platforms: HashMap<String, Platform>,
    host_platform: RegisteredExecPlatform,
) -> (Engine, Arc<ToolchainRegistry>) {
    let (mut engine, registry) =
        build_analysis_engine_with_toolchains(sys.clone(), root.clone(), platforms, host_platform);
    razel_action::register_action_kinds(&mut engine, strategy, resolver, blobs, sys, root, ExternalRepos::empty());
    (engine, registry)
}

/// [`build_execution_engine_with_toolchains`] with the T17 external-source-roots registry injected — the
/// full stack (loading → analysis → toolchains → execution) resolving `@<repo>//…` labels + `external/<repo>/…`
/// exec paths through `repos`. The self-host acceptance build (`//razel-cli:razel`, whose `razel-comms` leg
/// depends on the external `taut-shape` crate) is driven through this builder; an empty `repos` is
/// byte-identical to `build_execution_engine_with_toolchains`.
#[allow(clippy::too_many_arguments)]
pub fn build_execution_engine_with_toolchains_and_repos(
    sys: Arc<dyn System>,
    root: HostPath,
    repos: ExternalRepos,
    strategy: Arc<dyn SpawnStrategy>,
    resolver: Arc<dyn razel_action::InputResolver>,
    blobs: Arc<dyn razel_action::BlobStore>,
    platforms: HashMap<String, Platform>,
    host_platform: RegisteredExecPlatform,
) -> (Engine, Arc<ToolchainRegistry>) {
    let (mut engine, registry) =
        analysis_engine_with_repos(sys.clone(), root.clone(), repos.clone(), platforms, host_platform);
    razel_action::register_action_kinds(&mut engine, strategy, resolver, blobs, sys, root, repos);
    (engine, registry)
}

/// [`build_execution_engine_with_toolchains_and_repos`] with an EXPLICIT [`SelectConfig`] (T20 select) — the
/// full stack (loading → analysis → toolchains → execution) resolving `select()`/`config_setting` against the
/// injected per-configuration constraint set + `values`. Used by the TF-shaped `values`-based driving proof
/// (and any build needing the `--cpu`/`--compilation_mode` match surface); the constraint-only path derives
/// its SelectConfig from `platforms` automatically via [`build_execution_engine_with_toolchains_and_repos`].
#[allow(clippy::too_many_arguments)]
pub fn build_execution_engine_with_toolchains_repos_and_select(
    sys: Arc<dyn System>,
    root: HostPath,
    repos: ExternalRepos,
    strategy: Arc<dyn SpawnStrategy>,
    resolver: Arc<dyn razel_action::InputResolver>,
    blobs: Arc<dyn razel_action::BlobStore>,
    platforms: HashMap<String, Platform>,
    host_platform: RegisteredExecPlatform,
    select_config: SelectConfig,
) -> (Engine, Arc<ToolchainRegistry>) {
    let (mut engine, registry) = analysis_engine_with_repos_and_select(
        sys.clone(),
        root.clone(),
        repos.clone(),
        platforms,
        host_platform,
        select_config,
    );
    razel_action::register_action_kinds(&mut engine, strategy, resolver, blobs, sys, root, repos);
    (engine, registry)
}

/// [`build_execution_engine_with`] with the T17 external-source-roots registry injected (no toolchains — the
/// write-action / non-rust leg, used by [`BuildSession::new_write`]/`new_local`). Empty `repos` is
/// byte-identical to `build_execution_engine_with`.
pub fn build_execution_engine_with_repos(
    sys: Arc<dyn System>,
    root: HostPath,
    repos: ExternalRepos,
    strategy: Arc<dyn SpawnStrategy>,
    resolver: Arc<dyn razel_action::InputResolver>,
    blobs: Arc<dyn razel_action::BlobStore>,
) -> Engine {
    let (mut engine, _registry) = analysis_engine_with_repos(
        sys.clone(),
        root.clone(),
        repos.clone(),
        HashMap::new(),
        RegisteredExecPlatform { name: "host".to_string(), constraints: Vec::new() },
    );
    razel_action::register_action_kinds(&mut engine, strategy, resolver, blobs, sys, root, repos);
    engine
}

/// The T17 Phase-A seed (D6: injected registry, seeded `taut-shape`). Maps the apparent repo `taut-shape` to
/// its external source root (`taut-shape-rs/crates/taut-shape`, anchored at the crate dir per D2) and the
/// MAIN-root overlay BUILD `overlays/taut-shape/BUILD.bazel` (the single source of truth both razel and
/// Bazel read). Composition-root policy — the hardcoded host path lives HERE, never in a logic crate. Tests
/// inject their own registry pointing at fixture dirs; a later phase (D6 C6) parses this from MODULE.bazel.
pub const TAUT_SHAPE_ROOT: &str = "/Users/owebeeone/limbo/taut-dev/taut-shape-rs/crates/taut-shape";
pub fn taut_shape_repos() -> ExternalRepos {
    ExternalRepos::from_pairs([(
        "taut-shape".to_string(),
        ExternalRepo {
            root: HostPath::new(TAUT_SHAPE_ROOT),
            // taut-shape is BUILD-less → the main-root overlay wins (Some).
            build_file: Some(RootRelativePath("overlays/taut-shape/BUILD.bazel".to_string())),
        },
    )])
}

// ──────────────── the `build` verb: request TARGET_COMPLETION, then EMIT the outputs to disk ────────────────

/// One emitted output of a `build`: its exec-relative logical path and the host path it was written to.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BuiltOutput {
    pub exec_path: String,
    pub host_path: HostPath,
}
impl BuiltOutput {
    /// The emit destination as a plain `&str` — so a protocol root can render it WITHOUT naming
    /// `razel_os_api::HostPath` (keeps `razel-daemon`'s non-test dep surface to {cli, comms, host, wire}).
    pub fn host_path_str(&self) -> &str {
        self.host_path.as_str()
    }
}

/// Parse a v1 target PATTERN into a [`ConfiguredTargetKey`] (default configuration). Only the two Bazel
/// forms the analysis layer already resolves are accepted — `//pkg:name` (absolute) and `//:name` (root
/// package). Fail-closed (a typed `Error::Unsupported`, never a guess): a bare/relative name, a `:name`
/// (this is a top-level pattern, not a dep label — no parent package to imply), and any recursive pattern
/// (`...`) are rejected — v1 has no target expansion. The parse mirrors `razel_analysis::resolve_dep`'s
/// `//pkg:name` split but is its own top-level entry point (that fn is analysis-private and dep-label-only).
pub fn parse_target_pattern(pattern: &str) -> Result<ConfiguredTargetKey, Error> {
    let unsupported = |detail: String| Error::Unsupported { what: "target pattern", detail };
    let rest = pattern.strip_prefix("//").ok_or_else(|| {
        unsupported(format!("expected an absolute label '//pkg:name', got '{pattern}' (v1 has no relative or bare-name patterns)"))
    })?;
    let (package, name) = match rest.split_once(':') {
        Some((p, n)) if !n.is_empty() => (p.to_string(), n.to_string()),
        _ => return Err(unsupported(format!("expected '//pkg:name', got '{pattern}'"))),
    };
    if package.contains("...") || name.contains("...") {
        return Err(unsupported(format!("recursive patterns ('...') are not supported in v1: '{pattern}'")));
    }
    Ok(ConfiguredTargetKey { package, name, configuration: None, exec_platform: None, rule_transition: None })
}

/// Run `build <pattern>` over an execution `engine`, then EMIT the target's default outputs to disk. This is
/// result-emission, NOT disk input-staging: v1 execution stays in-memory (R4) — only the FINAL requested
/// outputs' bytes touch disk, fetched from the `blobs` CAS by digest and written via `System::write_atomic`
/// (so it needs no os-system trait growth). The build itself is a pure graph consequence of requesting
/// `TARGET_COMPLETION{ct, Default}` (CT → ARTIFACT → ACTION → strategy → digests); this fn adds only the
/// emit leg. Fail-closed throughout: a bad pattern, a build error, an output whose digest the CAS never held
/// (no Absorb), or a failed write are all typed `Error`s. Returns the emitted outputs (sorted by exec path).
///
/// `out_sys` + `out_root` are the emit destination (the same `System`/root that fed the source tree in v1,
/// but taken explicitly so the emit target is never implicit). `blobs` is the handle the caller kept from
/// [`build_execution_engine_with`] — the ONE bytes home the produced outputs landed in.
pub fn run_build(
    engine: &Engine,
    blobs: &dyn BlobStore,
    out_sys: &dyn System,
    out_root: &HostPath,
    pattern: &str,
) -> Result<Vec<BuiltOutput>, Error> {
    run_build_configured(engine, blobs, out_sys, out_root, pattern, None)
}

/// [`run_build`] under an explicit session CONFIGURATION: the parsed pattern's `configuration` dimension is
/// set to `configuration` before the build (a toolchain-requiring target — e.g. a rust rule — cannot resolve
/// with `None`: the ratified fail-closed decision, never absorbed to a default inside analysis). Additive:
/// `run_build` delegates with `None`, keeping the pre-toolchain call shape byte-identical.
pub fn run_build_configured(
    engine: &Engine,
    blobs: &dyn BlobStore,
    out_sys: &dyn System,
    out_root: &HostPath,
    pattern: &str,
    configuration: Option<&str>,
) -> Result<Vec<BuiltOutput>, Error> {
    let mut ct = parse_target_pattern(pattern)?;
    ct.configuration = configuration.map(|s| s.to_string());

    // (1) THE build: request TARGET_COMPLETION — the dep requests ARE the build (no hand bridge). A build
    // error (analysis failure, dropped output, duplicate output, unresolvable input, …) surfaces here typed.
    let tck = TargetCompletionKey { ct: ct.clone(), outputs: OutputSelection::Default };
    engine.request(&NodeKey::from_key(&tck))?;

    if cfg!(feature = "mutant_build_skips_output_emit") {
        // MUTANT: the build verb requests TARGET_COMPLETION (so the graph builds) but DROPS the emit — the
        // requested outputs never reach disk. `build_emits_requested_output_to_disk` goes red: the file is
        // absent (read fails) and the content assertion never holds. The exact "we built it but never wrote
        // it" gap the emit leg closes. Never enable in a real build.
        return Ok(Vec::new());
    }

    // (2) enumerate the SAME default-output set completion built: request the CT, derive its outputs via the
    // ONE shared pure fn (the R8 conflict pass — already run inside completion, so this cannot introduce a
    // divergent set). This reuses the artifact model; it does not reshape it.
    let ctv = engine.request(&NodeKey::from_key(&ct))?;
    let configured = ctv.as_any().downcast_ref::<ConfiguredTarget>().ok_or_else(|| Error::Invalid {
        what: "CONFIGURED_TARGET value".into(),
        detail: format!("//{}:{} did not analyze to a ConfiguredTarget", ct.package, ct.name),
    })?;
    let refs: Vec<ArtifactRef> = derived_outputs(&ct, configured)?;

    // (3) EMIT: for each output, project its ARTIFACT digest, fetch the bytes from the ONE home, write to
    // disk. Fail-closed: a missing digest is a typed NotFound from the CAS (never empty bytes).
    let mut built: Vec<BuiltOutput> = Vec::with_capacity(refs.len());
    for aref in &refs {
        let av = engine.request(&NodeKey::from_key(aref))?;
        let artifact = av.as_any().downcast_ref::<ArtifactValue>().ok_or_else(|| Error::Invalid {
            what: "ARTIFACT value".into(),
            detail: format!("output '{}' did not project to an ArtifactValue", aref.exec_path),
        })?;
        let bytes = blobs.get(&artifact.digest)?;
        let host_path = join_root(out_root, &RootRelativePath(artifact.exec_path.clone()));
        out_sys.write_atomic(&host_path, &bytes).map_err(|e| Error::Invalid {
            what: "emit build output".into(),
            detail: format!("{}: {e:?}", artifact.exec_path),
        })?;
        built.push(BuiltOutput { exec_path: artifact.exec_path.clone(), host_path });
    }
    built.sort_by(|a, b| a.exec_path.cmp(&b.exec_path));
    Ok(built)
}

/// A ready-to-serve build session: the composition root's bundle of everything a `build` needs — the
/// execution `Engine`, the `BlobStore` handle (the ONE bytes home), and the emit `System` + root. The
/// protocol root (`razel-daemon`) holds ONE of these and drives it per request; it lets the daemon call
/// `session.build(pattern)` WITHOUT naming any engine / exec-api / os-api type (the wall holds at the
/// razel-host library seam — the daemon's allow set is just {razel-cli, razel-comms, razel-host, wire-api}).
///
/// v1 wiring: the [`razel_exec_api::conformance::WriteStrategy`] (content-write actions) + an in-memory
/// `BlobStore`. Swapping in a local/sandbox/remote strategy or an on-disk CAS is a host decision behind this
/// same seam — no daemon rewrite.
pub struct BuildSession {
    engine: Engine,
    blobs: Arc<dyn BlobStore>,
    sys: Arc<dyn System>,
    root: HostPath,
    /// The session's default CONFIGURATION, applied to every parsed pattern (`None` = the pre-toolchain
    /// shape; `Some(HOST_CONFIG)` for a toolchain-enabled session — resolution requires a configuration).
    configuration: Option<String>,
}
impl BuildSession {
    /// Build a session over `sys`/`root` wired with the `WriteStrategy` (the write-action slice) and an
    /// in-memory `BlobStore`. `sys` both feeds the source tree (reads) and receives the emitted outputs
    /// (`write_atomic`) — the one workspace filesystem.
    pub fn new_write(sys: Arc<dyn System>, root: HostPath) -> BuildSession {
        Self::new_write_with_repos(sys, root, ExternalRepos::empty())
    }

    /// [`BuildSession::new_write`] with the T17 external-source-roots `repos` registry injected at this
    /// composition root (empty = byte-identical to `new_write`). The daemon seeds `taut_shape_repos()` here.
    pub fn new_write_with_repos(sys: Arc<dyn System>, root: HostPath, repos: ExternalRepos) -> BuildSession {
        let blobs: Arc<dyn BlobStore> = Arc::new(razel_action::InMemoryBlobStore::new());
        let engine = build_execution_engine_with_repos(
            sys.clone(),
            root.clone(),
            repos,
            Arc::new(razel_exec_api::conformance::WriteStrategy),
            Arc::new(razel_action::SameTargetOrSourceResolver),
            blobs.clone(),
        );
        BuildSession { engine, blobs, sys, root, configuration: None }
    }

    /// Run `build <pattern>` to completion and emit the target's default outputs to disk (see [`run_build`]),
    /// under the session's configuration (if any).
    pub fn build(&self, pattern: &str) -> Result<Vec<BuiltOutput>, Error> {
        run_build_configured(
            &self.engine,
            self.blobs.as_ref(),
            self.sys.as_ref(),
            &self.root,
            pattern,
            self.configuration.as_deref(),
        )
    }

    /// Build a session wired with the [`DispatchStrategy`] (write-actions → `WriteStrategy`; spawn-actions →
    /// the REAL [`LocalSpawnStrategy`]) — the real-execution leg. `sys`/`root` feed the source tree (reads)
    /// AND back the per-execution EXEC ROOTS the local strategy stages into and spawns in
    /// (`temp_dir`/`create_dir_all`/`spawn`/`remove_dir_all`) AND receive the emitted outputs
    /// (`write_atomic`) — one workspace filesystem. A genrule-style spawn action therefore runs a REAL
    /// subprocess end to end (over the UDS socket via the daemon, incrementality intact); no consumer
    /// rewrite from [`BuildSession::new_write`], only the host's strategy choice changes.
    pub fn new_local(sys: Arc<dyn System>, root: HostPath) -> BuildSession {
        Self::new_local_with_repos(sys, root, ExternalRepos::empty())
    }

    /// [`BuildSession::new_local`] with the T17 external-source-roots `repos` registry injected (empty =
    /// byte-identical to `new_local`).
    pub fn new_local_with_repos(sys: Arc<dyn System>, root: HostPath, repos: ExternalRepos) -> BuildSession {
        let blobs: Arc<dyn BlobStore> = Arc::new(razel_action::InMemoryBlobStore::new());
        let engine = build_execution_engine_with_repos(
            sys.clone(),
            root.clone(),
            repos,
            Arc::new(local_exec::DispatchStrategy::new(sys.clone())),
            Arc::new(razel_action::SameTargetOrSourceResolver),
            blobs.clone(),
        );
        BuildSession { engine, blobs, sys, root, configuration: None }
    }

    /// [`BuildSession::new_local`] plus the RUST toolchain (the rust-rules wave): rustc is DISCOVERED at
    /// this composition root ([`discover_rustc`] — `$RUSTC` else the well-known probes, fail-closed typed
    /// error if none), registered as the `"rust"` toolchain type under [`rust_toolchain::HOST_CONFIG`], and
    /// the session configuration is set to `HOST_CONFIG` so toolchain resolution has the configuration it
    /// requires. A `rust_library`/`rust_binary` build (`rules/rust/rust.bzl` in the workspace) then runs
    /// REAL `rustc` subprocesses through the same DispatchStrategy → LocalSpawnStrategy leg — over the UDS
    /// socket via the daemon with no daemon rewrite (the strategy + registry are session wiring).
    pub fn new_local_rust(sys: Arc<dyn System>, root: HostPath) -> Result<BuildSession, Error> {
        Self::new_local_rust_with_repos(sys, root, ExternalRepos::empty())
    }

    /// [`BuildSession::new_local_rust`] with the T17 external-source-roots `repos` registry injected — the
    /// path that can build a target whose deps reach an external crate (`//razel-cli:razel` → `razel-comms`
    /// → `@taut-shape//:taut_shape`). Empty `repos` is byte-identical to `new_local_rust`.
    pub fn new_local_rust_with_repos(sys: Arc<dyn System>, root: HostPath, repos: ExternalRepos) -> Result<BuildSession, Error> {
        let rustc = rust_toolchain::discover_rustc(sys.as_ref())?;
        let blobs: Arc<dyn BlobStore> = Arc::new(razel_action::InMemoryBlobStore::new());
        let mut platforms = HashMap::new();
        platforms.insert(rust_toolchain::HOST_CONFIG.to_string(), Platform { constraints: Vec::new() });
        let (engine, registry) = build_execution_engine_with_toolchains_and_repos(
            sys.clone(),
            root.clone(),
            repos,
            Arc::new(local_exec::DispatchStrategy::new(sys.clone())),
            Arc::new(razel_action::SameTargetOrSourceResolver),
            blobs.clone(),
            platforms,
            RegisteredExecPlatform { name: "host".to_string(), constraints: Vec::new() },
        );
        registry.set_toolchains(
            &razel_ids::ConfigId(rust_toolchain::HOST_CONFIG.to_string()),
            vec![rust_toolchain::rust_toolchain(&rustc)],
        );
        Ok(BuildSession {
            engine,
            blobs,
            sys,
            root,
            configuration: Some(rust_toolchain::HOST_CONFIG.to_string()),
        })
    }

    /// [`BuildSession::new_local_rust`] driven ENTIRELY by the workspace MODULE.bazel (D6, C6 — the
    /// over-the-root path): the external-source-roots registry AND the registered-toolchain set are both
    /// sourced from MODULE.bazel (`new_local_repository` + `register_toolchains`), not hardcoded. The
    /// toolchains resolve THROUGH THE GRAPH ([`resolve_module_toolchains`]): each registered `toolchain()`
    /// target is demanded, its impl analyzed, and its `platform_common.ToolchainInfo` extracted. This is the
    /// single-declaration-surface path — razel and Bazel learn the workspace from the same file.
    pub fn new_local_rust_from_module(sys: Arc<dyn System>, root: HostPath) -> Result<BuildSession, Error> {
        let module = module_config::read_module_file(sys.as_ref(), &root)?;
        let repos = module_config::module_external_repos(&module, &root)?;
        let blobs: Arc<dyn BlobStore> = Arc::new(razel_action::InMemoryBlobStore::new());
        let mut platforms = HashMap::new();
        platforms.insert(rust_toolchain::HOST_CONFIG.to_string(), Platform { constraints: Vec::new() });
        let (engine, registry) = build_execution_engine_with_toolchains_and_repos(
            sys.clone(),
            root.clone(),
            repos,
            Arc::new(local_exec::DispatchStrategy::new(sys.clone())),
            Arc::new(razel_action::SameTargetOrSourceResolver),
            blobs.clone(),
            platforms,
            RegisteredExecPlatform { name: "host".to_string(), constraints: Vec::new() },
        );
        // Resolve the MODULE.bazel-registered toolchains through the engine graph and seed the registry.
        // MUTANT `mutant_toolchain_registration_ignores_module_bazel`: silently SKIP the MODULE.bazel-sourced
        // registration (the hardcoded-fallback shape) → no rust toolchain is registered under HOST_CONFIG →
        // a rust build's toolchain resolution fails closed → the over-the-root proof reds.
        if !cfg!(feature = "mutant_toolchain_registration_ignores_module_bazel") {
            let rows = module_config::resolve_module_toolchains(&engine, &module, rust_toolchain::HOST_CONFIG)?;
            registry.set_toolchains(&razel_ids::ConfigId(rust_toolchain::HOST_CONFIG.to_string()), rows);
        }
        Ok(BuildSession { engine, blobs, sys, root, configuration: Some(rust_toolchain::HOST_CONFIG.to_string()) })
    }

    /// Re-run after a source edit was signaled to the engine (the caller dirties the changed leaf via the
    /// engine `Diff`); exposed so incrementality can be exercised over a WARM session. Same emit semantics.
    pub fn engine(&self) -> &Engine {
        &self.engine
    }
}
