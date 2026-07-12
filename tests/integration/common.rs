//! Shared integration-test scaffolding: the mutable in-memory `MutFs` `System`, the node-key/value
//! helper constructors, the spawn-counting strategy, and the shared `SUM_RULES` .bzl. Re-exports the
//! external surface the topic modules use, so each `mod` needs only `use crate::common::*;`.
//! (Carved out of the former monolithic `tests/integration.rs`.)

pub(crate) use razel_core::{Digest, NodeKey, NodeValue};
pub(crate) use razel_engine_api::{ChangedLeaf, DemandEngine, Diff, FailurePolicy};
pub(crate) use razel_bzl_api::{BzlValue, ProviderId, ProviderInstance, RuleOrigin};
pub(crate) use razel_host::build_analysis_engine_with_toolchains;
pub(crate) use razel_toolchain::{
    Constraint, Platform, RegisteredExecPlatform, RegisteredExecutionPlatformsKey, RegisteredToolchain,
    RegisteredToolchainsKey, ToolchainContextKey, ToolchainType, ToolchainTypeReq,
};
pub(crate) use razel_host::{build_analysis_engine, build_loading_engine, build_source_engine};
pub(crate) use razel_ids::{ConfigId, RootRelativePath};
pub(crate) use razel_load::{BzlLoadKey, BzlModuleValue};
pub(crate) use razel_package::{Package, PackageKey};
pub(crate) use razel_analysis::{ConfiguredTarget, ConfiguredTargetKey};
pub(crate) use razel_os_api::{
    EnvName, ExitStatus, FileKind, HostPath, Metadata, OsError, OsPathFragment, OsPathPolicy, OsValue,
    ProcessSpec, RawSymlinkTarget, System,
};
pub(crate) use razel_source::{DirListingKey, FileKey, FileStateKey, FileValue, GlobKey, GlobMatch};
pub(crate) use razel_action::{
    ActionValue, ArtifactProducer, ArtifactRef, ArtifactValue, GeneratingActionKey, OutputSelection,
    TargetCompletionKey,
};
pub(crate) use razel_exec_api::conformance::{fake_output_content, DroppingStrategy, FakeStrategy};
pub(crate) use razel_exec_api::{ExecError, InputArtifact, SpawnRequest, SpawnResult, SpawnStrategy};
pub(crate) use razel_host::build_execution_engine;
pub(crate) use std::collections::{BTreeMap, HashMap};
pub(crate) use std::sync::atomic::{AtomicUsize, Ordering};
pub(crate) use std::sync::{Arc, Mutex};

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

pub(crate) struct MutFs {
    files: Mutex<HashMap<String, (Vec<u8>, i128)>>, // host path -> (content, mtime_nanos)
    policy: TestPolicy,
}
impl MutFs {
    pub(crate) fn new() -> Self { Self { files: Mutex::new(HashMap::new()), policy: TestPolicy } }
    pub(crate) fn set(&self, path: &str, content: &[u8], mtime: i128) {
        self.files.lock().unwrap().insert(path.into(), (content.to_vec(), mtime));
    }
    pub(crate) fn remove(&self, path: &str) {
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
pub(crate) fn fkey(p: &str) -> NodeKey { NodeKey::from_key(&FileKey(RootRelativePath(p.into()))) }
pub(crate) fn fskey(p: &str) -> NodeKey { NodeKey::from_key(&FileStateKey(RootRelativePath(p.into()))) }
pub(crate) fn dlkey(p: &str) -> NodeKey { NodeKey::from_key(&DirListingKey(RootRelativePath(p.into()))) }
pub(crate) fn gkey(dir: &str, pat: &str) -> NodeKey { NodeKey::from_key(&GlobKey { dir: RootRelativePath(dir.into()), pattern: pat.into() }) }
pub(crate) fn fval(v: &NodeValue) -> FileValue { v.as_any().downcast_ref::<FileValue>().unwrap().clone() }
pub(crate) fn gmatch(v: &NodeValue) -> Vec<String> { v.as_any().downcast_ref::<GlobMatch>().unwrap().0.clone() }
pub(crate) fn bkey(p: &str) -> NodeKey {
    // The six-dimension contract key at its v1 shape (Build{is_prelude:false}, the v1 semantics row, the
    // evaluator-served env id) — the SAME key the loading/analysis nodes construct, so tests share nodes.
    let eval = razel_bzl_starlark::StarlarkEvaluator::new();
    NodeKey::from_key(&BzlLoadKey::v1(RootRelativePath(p.into()), &eval).expect("v1 BZL_LOAD key"))
}
pub(crate) fn bget(v: &NodeValue, name: &str) -> Option<BzlValue> {
    v.as_any().downcast_ref::<BzlModuleValue>().unwrap().0.get(name).cloned()
}
pub(crate) fn pkey(pkg: &str) -> NodeKey { NodeKey::from_key(&PackageKey(RootRelativePath(pkg.into()))) }
pub(crate) fn pkg(v: &NodeValue) -> Package { v.as_any().downcast_ref::<Package>().unwrap().clone() }
pub(crate) fn ctkey(pkg: &str, name: &str) -> NodeKey {
    NodeKey::from_key(&ConfiguredTargetKey {
        package: pkg.into(),
        name: name.into(),
        configuration: None,
        exec_platform: None,
        rule_transition: None,
    })
}
pub(crate) fn ctkey_cfg(pkg: &str, name: &str, cfg: &str) -> NodeKey {
    NodeKey::from_key(&ConfiguredTargetKey {
        package: pkg.into(),
        name: name.into(),
        configuration: Some(cfg.into()),
        exec_platform: None,
        rule_transition: None,
    })
}
pub(crate) fn ct_total(v: &NodeValue) -> i64 {
    let ct = v.as_any().downcast_ref::<ConfiguredTarget>().unwrap();
    match ct.provider(&ProviderId::from_name("NumberInfo")).and_then(|p| p.get("total")) {
        Some(BzlValue::Int(i)) => *i,
        other => panic!("expected NumberInfo.total: int, got {other:?}"),
    }
}
pub(crate) fn action_value(v: &NodeValue) -> ActionValue {
    v.as_any().downcast_ref::<ActionValue>().unwrap().clone()
}
pub(crate) fn artifact_val(v: &NodeValue) -> ArtifactValue {
    v.as_any().downcast_ref::<ArtifactValue>().unwrap().clone()
}
/// The v1 configured-target key at its default shape (no configuration) — the OWNER of positional actions.
pub(crate) fn owner_ct(pkg: &str, name: &str) -> razel_analysis::ConfiguredTargetKey {
    razel_analysis::ConfiguredTargetKey {
        package: pkg.into(),
        name: name.into(),
        configuration: None,
        exec_platform: None,
        rule_transition: None,
    }
}
/// The positional ACTION node key (GeneratingActionKey — the artifact-model lockdown decision B).
pub(crate) fn action_node(pkg: &str, name: &str, idx: u32) -> NodeKey {
    NodeKey::from_key(&GeneratingActionKey { owner: owner_ct(pkg, name), action_index: idx })
}
/// A derived-output ARTIFACT node key (exec-path + stamped producer — decision A).
pub(crate) fn derived_artifact(pkg: &str, name: &str, idx: u32, path: &str) -> NodeKey {
    NodeKey::from_key(&ArtifactRef {
        exec_path: path.into(),
        producer: ArtifactProducer::Derived(GeneratingActionKey { owner: owner_ct(pkg, name), action_index: idx }),
    })
}
/// The TARGET_COMPLETION node key (Default output selection — R7's one v1 sentinel).
pub(crate) fn completion(pkg: &str, name: &str) -> NodeKey {
    NodeKey::from_key(&TargetCompletionKey { ct: owner_ct(pkg, name), outputs: OutputSelection::Default })
}
/// A FakeStrategy wrapper that COUNTS spawns — the "did the action actually re-run / early-cut" oracle.
pub(crate) struct CountingStrategy(pub(crate) Arc<AtomicUsize>);
impl SpawnStrategy for CountingStrategy {
    fn spawn(&self, req: &SpawnRequest) -> Result<SpawnResult, ExecError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        FakeStrategy.spawn(req)
    }
}
pub(crate) fn in_art(path: &str, content: &[u8]) -> InputArtifact {
    InputArtifact { path: path.into(), content: content.to_vec() }
}
pub(crate) fn spawn_req(mnemonic: &str, argv: &[&str], inputs: Vec<InputArtifact>, outputs: &[&str]) -> SpawnRequest {
    SpawnRequest::new(
        mnemonic,
        argv.iter().map(|s| s.to_string()).collect(),
        BTreeMap::new(),
        inputs,
        outputs.iter().map(|s| s.to_string()).collect(),
    )
}

// The sum-provider rule (the de-nativized-rule exam): a target's NumberInfo.total = its own value + the sum of
// its deps' NumberInfo.total. A REAL .bzl impl, run through the Starlark seam — no Rust ruleset reimplementation.
pub(crate) const SUM_RULES: &[u8] = b"NumberInfo = provider(\"NumberInfo\", fields = [\"total\"])\n\
def _impl(ctx):\n\
\x20   t = ctx.attr.value\n\
\x20   for d in ctx.attr.deps:\n\
\x20       t += d[NumberInfo].total\n\
\x20   return [NumberInfo(total = t)]\n\
my_rule = rule(implementation = _impl, attrs = {\"value\": attr.int(), \"deps\": attr.label_list()})\n";
