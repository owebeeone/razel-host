//! `razel-host::local_exec` — the REAL local-subprocess execution leg (the last architectural piece on the
//! self-host path). A [`LocalSpawnStrategy`] realizes the `razel-exec-api` fan-out seam over a real
//! subprocess: it allocates a per-execution EXEC ROOT via `System::temp_dir`, STAGES each `SpawnRequest`
//! input under it (the reserved no-I/O expander → `create_dir_all` + `write_atomic`), runs `System::spawn`
//! with `cwd` = the exec root, and COLLECTS each DECLARED output by READING the staged file back. Disk
//! staging is strategy-PRIVATE (decision G / R4): no engine contract ever sees a `HostPath` — the ACTION
//! node still hands the strategy a codec-neutral `SpawnRequest` and gets a `SpawnResult` of bytes.
//!
//! Fail-closed (the #1 rule): a missing exec-root allocation, a stage failure, a NONZERO exit, or a declared
//! output the subprocess did not produce are all typed `ExecError`s — the strategy NEVER fabricates a value
//! (the local-strategy kin of `mutant_exec_hardcodes_output`). The exec root is torn down on SUCCESS and
//! LEFT on failure for post-mortem diagnosis ([`ExecRootPolicy`]). stdout/stderr capture is NOT in
//! `ProcessSpec` v1 — deferred (outputs-as-files suffice for the genrule proof).
//!
//! [`DispatchStrategy`] lets `build_execution_engine` keep ONE injected strategy while a build MIXES
//! write-actions and spawn-actions: it routes the `WriteFile` mnemonic to the no-subprocess `WriteStrategy`
//! and everything else to `LocalSpawnStrategy`, both behind the SAME seam.

use razel_exec_api::conformance::{WriteStrategy, WRITE_FILE_MNEMONIC};
use razel_exec_api::{ExecError, OutputArtifact, SpawnRequest, SpawnResult, SpawnStatus, SpawnStrategy};
use razel_ids::RootRelativePath;
use razel_os_api::{EnvMap, EnvName, HostPath, OsValue, ProcessSpec, System};
use razel_source::join_root;
use std::sync::Arc;

/// The v1 exec-root policy: allocate a FRESH exec root per spawn via `System::temp_dir`, clean it on
/// SUCCESS, and LEAVE it on failure for post-mortem diagnosis. (A future policy could pin a stable root,
/// keep-all for debugging, or stage into a sandbox — the strategy is the only owner of this decision.)
#[derive(Clone, Copy, Debug)]
pub struct ExecRootPolicy {
    /// Leave the exec root on disk when a spawn FAILS (nonzero exit / missing output / stage error); always
    /// clean it on success.
    pub keep_on_failure: bool,
}
impl Default for ExecRootPolicy {
    fn default() -> Self {
        Self { keep_on_failure: true }
    }
}

/// The RESERVED no-I/O expander (lockdown decision G / R4), v1 realization: the SORTED exec-root-relative
/// input mapping the staging step consumes opaquely — Bazel's `SpawnInputExpander` ("performs no I/O
/// operations"). The lockdown's reserved signature is `{exec-rel path → digest}`; v1's `SpawnRequest`
/// carries INLINE bytes, so the mapping is `(exec-rel path → &bytes)`. `SpawnRequest::new` already
/// name-sorts `inputs`, so this is a pure, deterministic projection — no second ordering channel. When the
/// bytes→producer-digest encode swap lands, this fn's return type widens to carry digests; staging stays
/// its only consumer. (Unused under `mutant_stage_drops_input`, which skips staging entirely.)
#[cfg_attr(feature = "mutant_stage_drops_input", allow(dead_code))]
fn expand_inputs(req: &SpawnRequest) -> Vec<(&str, &[u8])> {
    req.inputs.iter().map(|i| (i.path.as_str(), i.content.as_slice())).collect()
}

/// The parent directory of a staged host path (string-level — host paths never round-trip through the OS
/// seam for this). `None` for a top-level path with no parent segment.
fn parent_of(host: &HostPath) -> Option<HostPath> {
    let s = host.as_str();
    s.rfind('/').map(|i| HostPath::new(&s[..i]))
}

/// A REAL local-subprocess `SpawnStrategy` — the `razel-exec-api` fan-out seam's local impl (the sibling of
/// the in-memory `FakeStrategy` / no-subprocess `WriteStrategy`). Holds an `Arc<dyn System>` (the OS seam)
/// + an [`ExecRootPolicy`].
pub struct LocalSpawnStrategy {
    sys: Arc<dyn System>,
    policy: ExecRootPolicy,
}
impl LocalSpawnStrategy {
    pub fn new(sys: Arc<dyn System>) -> Self {
        Self { sys, policy: ExecRootPolicy::default() }
    }
    pub fn with_policy(sys: Arc<dyn System>, policy: ExecRootPolicy) -> Self {
        Self { sys, policy }
    }

    /// Stage each input to disk under the exec root (create parent dirs, then write the bytes).
    fn stage_inputs(&self, exec_root: &HostPath, req: &SpawnRequest) -> Result<(), ExecError> {
        // MUTANT `mutant_stage_drops_input`: skip staging → the subprocess cannot read its input (a `cat` of
        // a missing file exits nonzero) → the spawn fails closed and the real-exec gate reds. Never real.
        #[cfg(feature = "mutant_stage_drops_input")]
        {
            let _ = (exec_root, req);
            return Ok(());
        }
        #[cfg(not(feature = "mutant_stage_drops_input"))]
        {
            for (rel, bytes) in expand_inputs(req) {
                let host = join_root(exec_root, &RootRelativePath(rel.to_string()));
                self.mkdir_parent(&host, req, "stage input")?;
                self.sys.write_atomic(&host, bytes).map_err(|e| ExecError::SpawnFailed {
                    mnemonic: req.mnemonic.clone(),
                    detail: format!("stage input '{rel}': {e:?}"),
                })?;
            }
            Ok(())
        }
    }

    /// Create the parent dir of each DECLARED output so the subprocess's redirect/write target exists
    /// (Bazel materializes output parent dirs before the spawn).
    fn ensure_output_dirs(&self, exec_root: &HostPath, req: &SpawnRequest) -> Result<(), ExecError> {
        for out in &req.outputs {
            let host = join_root(exec_root, &RootRelativePath(out.clone()));
            self.mkdir_parent(&host, req, "create output dir")?;
        }
        Ok(())
    }

    fn mkdir_parent(&self, host: &HostPath, req: &SpawnRequest, what: &str) -> Result<(), ExecError> {
        if let Some(parent) = parent_of(host) {
            self.sys.create_dir_all(&parent).map_err(|e| ExecError::SpawnFailed {
                mnemonic: req.mnemonic.clone(),
                detail: format!("{what} '{}': {e:?}", host.as_str()),
            })?;
        }
        Ok(())
    }

    /// Collect each DECLARED output by READING the staged file back. Fail-closed: a missing output file is
    /// `OutputNotProduced`, never a fabricated value (the node's `validate_outputs` also re-checks the set).
    fn collect_outputs(&self, exec_root: &HostPath, req: &SpawnRequest) -> Result<Vec<OutputArtifact>, ExecError> {
        let mut outputs = Vec::with_capacity(req.outputs.len());
        for out in &req.outputs {
            let host = join_root(exec_root, &RootRelativePath(out.clone()));
            // MUTANT `mutant_collect_fabricates_output`: return fabricated bytes instead of READING the
            // staged file → the collected content is not the subprocess's → the output-bytes gate reds (the
            // local-strategy kin of `mutant_exec_hardcodes_output`). Never real.
            #[cfg(feature = "mutant_collect_fabricates_output")]
            let content = {
                let _ = &host;
                b"FABRICATED".to_vec()
            };
            #[cfg(not(feature = "mutant_collect_fabricates_output"))]
            let content = self.sys.read(&host).map_err(|_e| ExecError::OutputNotProduced {
                mnemonic: req.mnemonic.clone(),
                path: out.clone(),
            })?;
            outputs.push(OutputArtifact { path: out.clone(), content });
        }
        outputs.sort_by(|a, b| a.path.cmp(&b.path)); // deterministic — same as FakeStrategy/WriteStrategy
        Ok(outputs)
    }

    /// Stage → spawn → collect, inside an already-allocated exec root (cleanup is handled by [`spawn`]).
    fn run_in_root(
        &self,
        exec_root: &HostPath,
        program: &HostPath,
        args: &[String],
        req: &SpawnRequest,
    ) -> Result<SpawnResult, ExecError> {
        self.stage_inputs(exec_root, req)?;
        self.ensure_output_dirs(exec_root, req)?;
        // env: the declared map VERBATIM (EXACT — REQ-SYSTEM-009; no host inherit). One env source.
        let env: EnvMap = req.env.iter().map(|(k, v)| (EnvName(k.clone()), OsValue(v.clone()))).collect();
        let spec = ProcessSpec { program: program.clone(), args: args.to_vec(), env, cwd: exec_root.clone() };
        let status = self.sys.spawn(&spec).map_err(|e| ExecError::SpawnFailed {
            mnemonic: req.mnemonic.clone(),
            detail: format!("{e:?}"),
        })?;
        // A NONZERO exit is fail-closed (carry the code): a shell redirect can leave an EMPTY output file
        // even on failure, so the exit code — not just output presence — is the fail-closed guard.
        if status.code != 0 {
            return Err(ExecError::SpawnFailed {
                mnemonic: req.mnemonic.clone(),
                detail: format!("subprocess exited with code {}", status.code),
            });
        }
        let outputs = self.collect_outputs(exec_root, req)?;
        Ok(SpawnResult { status: SpawnStatus { code: 0 }, outputs })
    }
}

impl SpawnStrategy for LocalSpawnStrategy {
    fn spawn(&self, req: &SpawnRequest) -> Result<SpawnResult, ExecError> {
        // argv[0] is the RESOLVED program (an absolute host path — no host-PATH lookup); argv[1..] its args.
        let (program, args) = match req.argv.split_first() {
            Some((p0, rest)) => (HostPath::new(p0.clone()), rest.to_vec()),
            None => {
                return Err(ExecError::SpawnFailed {
                    mnemonic: req.mnemonic.clone(),
                    detail: "empty argv: no program to run".into(),
                })
            }
        };
        // (1) allocate a per-execution exec root.
        let exec_root = self.sys.temp_dir().map_err(|e| ExecError::SpawnFailed {
            mnemonic: req.mnemonic.clone(),
            detail: format!("allocate exec root: {e:?}"),
        })?;
        // (2..5) stage → spawn → collect, then tear the exec root down on SUCCESS / leave it on failure.
        let result = self.run_in_root(&exec_root, &program, &args, req);
        match &result {
            // best-effort teardown — a cleanup failure must not mask a successful build.
            Ok(_) => {
                let _ = self.sys.remove_dir_all(&exec_root);
            }
            Err(_) if !self.policy.keep_on_failure => {
                let _ = self.sys.remove_dir_all(&exec_root);
            }
            Err(_) => { /* leave the exec root on disk for post-mortem diagnosis (ExecRootPolicy) */ }
        }
        result
    }
}

/// A host-level DISPATCHING `SpawnStrategy`: a build MIXES write-actions and spawn-actions, so
/// `build_execution_engine` keeps ONE injected strategy. Routes by mnemonic — the `WriteFile` convention
/// (`WRITE_FILE_MNEMONIC`) → the no-subprocess [`WriteStrategy`]; everything else → the real
/// [`LocalSpawnStrategy`]. Both sit behind the SAME exec-api fan-out seam, so the ACTION node never knows
/// which ran. (Explicitly-injected strategies in existing tests keep their own choice — this is only the
/// default the `BuildSession` local wiring uses.)
pub struct DispatchStrategy {
    write: WriteStrategy,
    local: LocalSpawnStrategy,
}
impl DispatchStrategy {
    pub fn new(sys: Arc<dyn System>) -> Self {
        Self { write: WriteStrategy, local: LocalSpawnStrategy::new(sys) }
    }
}
impl SpawnStrategy for DispatchStrategy {
    fn spawn(&self, req: &SpawnRequest) -> Result<SpawnResult, ExecError> {
        if req.mnemonic == WRITE_FILE_MNEMONIC {
            self.write.spawn(req)
        } else {
            self.local.spawn(req)
        }
    }
}
