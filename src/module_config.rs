//! `razel-host::module_config` — D6 (C6): razel reads the workspace MODULE.bazel (the reserved Bzlmod
//! evaluation) and builds its `ExternalRepos` + registered-toolchain set FROM it, replacing the hardcoded
//! `taut_shape_repos()` seed. This is the single declaration surface both razel and real Bazel read.
//!
//! Two derivations from the parsed [`ModuleFileValue`]:
//!   * [`module_external_repos`] — each `new_local_repository(path=, build_file=)` → an `ExternalRepo`
//!     (path resolved against the workspace root, build_file `//pkg:BUILD.bazel` → a main-root-relative path).
//!   * [`resolve_module_toolchains`] — each `register_toolchains(<label>)` is resolved THROUGH THE GRAPH (the
//!     honest path): demand `PACKAGE(pkg of the toolchain() target)`, read its `toolchain`/`toolchain_type`,
//!     analyze the impl `CONFIGURED_TARGET`, and extract its `platform_common.ToolchainInfo` — the SAME row
//!     the injection path (`rust_toolchain(rustc)`) builds, now sourced from MODULE.bazel.

use razel_analysis::{ConfiguredTarget, ConfiguredTargetKey};
use razel_bzl_api::{BzlValue, ModuleFileValue, ProviderId};
use razel_bzl_starlark::StarlarkEvaluator;
use razel_core::{Error, NodeKey};
use razel_engine::Engine;
use razel_engine_api::DemandEngine;
use razel_ids::RootRelativePath;
use razel_os_api::{HostPath, System};
use razel_package::{Package, PackageKey};
use razel_source::{ExternalRepo, ExternalRepos};
use razel_toolchain::{RegisteredToolchain, ToolchainType};

use crate::rust_toolchain::RUST_TOOLCHAIN_INFO;

/// The workspace marker filename (bzlmod) — the module file razel reads its declarations from.
pub const MODULE_FILE: &str = "MODULE.bazel";

/// Read + evaluate the workspace MODULE.bazel through the `System` seam. Fail-closed: an unreadable/absent
/// marker or a non-UTF-8 / invalid module file is a typed error (the daemon refuses to serve rootlessly).
pub fn read_module_file(sys: &dyn System, root: &HostPath) -> Result<ModuleFileValue, Error> {
    let path = HostPath::new(format!("{}/{MODULE_FILE}", root.as_str()));
    let bytes = sys
        .read(&path)
        .map_err(|e| Error::Invalid { what: "read MODULE.bazel".into(), detail: format!("{}: {e:?}", path.as_str()) })?;
    let source = String::from_utf8(bytes).map_err(|_| Error::Invalid { what: "MODULE.bazel".into(), detail: "non-utf8".into() })?;
    razel_bzl_api::BzlEvaluator::evaluate_module_file(&StarlarkEvaluator::new(), &source)
        .map_err(|e| Error::Invalid { what: "evaluate MODULE.bazel".into(), detail: format!("{e:?}") })
}

/// Resolve a workspace-root-relative repo `path` (which may contain `..`, escaping the workspace) to an
/// absolute host path — plain string arithmetic (not a syscall; the raw-OS wall is on filesystem access).
fn resolve_repo_root(root: &HostPath, rel_path: &str) -> HostPath {
    let mut segs: Vec<&str> = root.as_str().trim_end_matches('/').split('/').collect();
    for seg in rel_path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if segs.len() > 1 {
                    segs.pop();
                }
            }
            s => segs.push(s),
        }
    }
    HostPath::new(segs.join("/"))
}

/// A `//pkg:file` label → a main-root-relative path (`pkg/file`; the root package `//:file` → `file`).
fn label_to_root_rel(label: &str) -> Result<RootRelativePath, Error> {
    let body = label.strip_prefix("//").ok_or_else(|| Error::Invalid {
        what: "build_file label".into(),
        detail: format!("expected '//pkg:BUILD.bazel', got '{label}'"),
    })?;
    let (pkg, file) = body.split_once(':').ok_or_else(|| Error::Invalid {
        what: "build_file label".into(),
        detail: format!("expected '//pkg:file', got '{label}'"),
    })?;
    Ok(RootRelativePath(if pkg.is_empty() { file.to_string() } else { format!("{pkg}/{file}") }))
}

/// Read the workspace MODULE.bazel and build its `ExternalRepos` registry in one call (D6) — the daemon's
/// composition-root entry (replacing the hardcoded `taut_shape_repos()`), so it never names `ModuleFileValue`.
pub fn workspace_repos(sys: &dyn System, root: &HostPath) -> Result<ExternalRepos, Error> {
    let module = read_module_file(sys, root)?;
    module_external_repos(&module, root)
}

/// Build the `ExternalRepos` registry from the MODULE.bazel `new_local_repository` declarations (D6): each
/// `path` resolves against the workspace `root`. `build_file` is OPTIONAL (T20 R1): a `Some(label)` maps to
/// its main-root-relative overlay (BUILD-less repo, taut-shape); a `None` mounts the repo AS-IS with its own
/// BUILD/.bzl files (a real Bazel module, rules_rust).
pub fn module_external_repos(module: &ModuleFileValue, root: &HostPath) -> Result<ExternalRepos, Error> {
    let mut pairs = Vec::new();
    for repo in &module.repos {
        let build_file = match &repo.build_file {
            Some(label) => Some(label_to_root_rel(label)?),
            None => None,
        };
        pairs.push((repo.name.clone(), ExternalRepo { root: resolve_repo_root(root, &repo.path), build_file }));
    }
    Ok(ExternalRepos::from_pairs(pairs))
}

/// Split a `//pkg:name` label into `(package, name)`. Fail-closed on any other form.
fn split_label(label: &str) -> Result<(String, String), Error> {
    let body = label.strip_prefix("//").ok_or_else(|| Error::Invalid {
        what: "toolchain label".into(),
        detail: format!("expected '//pkg:name', got '{label}'"),
    })?;
    let (pkg, name) = body.split_once(':').ok_or_else(|| Error::Invalid {
        what: "toolchain label".into(),
        detail: format!("expected '//pkg:name', got '{label}'"),
    })?;
    Ok((pkg.to_string(), name.to_string()))
}

/// Resolve a same-package-or-absolute label (`:name` or `//pkg:name`) referenced from `pkg` to a full
/// `//pkg:name` label (the `toolchain()`/`toolchain_type` attrs use the `:name` form).
fn abs_label(pkg: &str, rel: &str) -> String {
    if let Some(name) = rel.strip_prefix(':') {
        format!("//{pkg}:{name}")
    } else {
        rel.to_string()
    }
}

/// Resolve the MODULE.bazel registered-toolchain labels into `RegisteredToolchain` rows THROUGH THE ENGINE
/// GRAPH (D6, the honest path): for each `register_toolchains(<label>)`, demand the `toolchain()` target's
/// package, read its `toolchain`/`toolchain_type`, analyze the implementation `CONFIGURED_TARGET`, and pull
/// its `platform_common.ToolchainInfo` — the same identity the injection path builds. `configuration` keys
/// the impl analysis (a rust build runs under `HOST_CONFIG`). Fail-closed at every missing edge.
pub fn resolve_module_toolchains(
    engine: &Engine,
    module: &ModuleFileValue,
    configuration: &str,
) -> Result<Vec<RegisteredToolchain>, Error> {
    let mut rows = Vec::new();
    for label in &module.registered_toolchains {
        let (pkg, name) = split_label(label)?;
        // (1) the toolchain() target's package + declaration.
        let pv = engine.request(&NodeKey::from_key(&PackageKey(RootRelativePath(pkg.clone()))))?;
        let package = pv.as_any().downcast_ref::<Package>().ok_or_else(|| Error::Invalid {
            what: "PACKAGE value".into(),
            detail: format!("package '{pkg}' did not analyze to a Package"),
        })?;
        let tgt = package.get(&name).ok_or_else(|| Error::NotFound {
            what: "toolchain target".into(),
            detail: format!("//{pkg}:{name} (from register_toolchains)"),
        })?;
        let attr = |a: &str| -> Result<String, Error> {
            match tgt.attrs.iter().find(|(n, _)| n == a).map(|(_, v)| v) {
                Some(BzlValue::Str(s)) => Ok(abs_label(&pkg, s)),
                _ => Err(Error::Invalid { what: "toolchain target".into(), detail: format!("//{pkg}:{name} missing '{a}'") }),
            }
        };
        let type_label = attr("toolchain_type")?;
        let impl_label = attr("toolchain")?;
        // (2) analyze the impl target's CONFIGURED_TARGET → extract its ToolchainInfo.
        let (impl_pkg, impl_name) = split_label(&impl_label)?;
        let ctk = ConfiguredTargetKey {
            package: impl_pkg,
            name: impl_name,
            configuration: Some(configuration.to_string()),
            exec_platform: None,
            rule_transition: None,
        };
        let ctv = engine.request(&NodeKey::from_key(&ctk))?;
        let ct = ctv.as_any().downcast_ref::<ConfiguredTarget>().ok_or_else(|| Error::Invalid {
            what: "CONFIGURED_TARGET value".into(),
            detail: format!("{impl_label} did not analyze to a ConfiguredTarget"),
        })?;
        let info = ct
            .provider(&ProviderId::from_name(RUST_TOOLCHAIN_INFO))
            .ok_or_else(|| Error::Invalid {
                what: "toolchain impl".into(),
                detail: format!("{impl_label} did not return platform_common.ToolchainInfo"),
            })?
            .clone();
        rows.push(RegisteredToolchain {
            toolchain_type: ToolchainType(type_label),
            target_compatible_with: Vec::new(),
            exec_compatible_with: Vec::new(),
            info,
        });
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_root_resolves_uplevel_path() {
        // `../taut-dev/...` against the workspace root climbs out and back down (the D3 relative form).
        let root = HostPath::new("/Users/u/limbo/razel-dev".to_string());
        assert_eq!(
            resolve_repo_root(&root, "../taut-dev/taut-shape-rs/crates/taut-shape").as_str(),
            "/Users/u/limbo/taut-dev/taut-shape-rs/crates/taut-shape"
        );
    }

    #[test]
    fn build_file_label_to_root_rel() {
        assert_eq!(label_to_root_rel("//overlays/taut-shape:BUILD.bazel").unwrap(), RootRelativePath("overlays/taut-shape/BUILD.bazel".into()));
        assert_eq!(label_to_root_rel("//:BUILD.bazel").unwrap(), RootRelativePath("BUILD.bazel".into()));
        assert!(label_to_root_rel("overlays:BUILD.bazel").is_err(), "a non-absolute build_file label fails closed");
    }
}
