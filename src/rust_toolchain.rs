//! `razel-host::rust_toolchain` — the "rust" toolchain's HOST-SIDE composition pieces (the rust-rules
//! wave): rustc DISCOVERY at the composition root (the only layer allowed to consult the ambient host —
//! `System::raw_env` / `System::stat` — per its `root` role) and the [`RegisteredToolchain`] row that puts
//! the discovered compiler into the ADR-0010 host-injected registry. The rules themselves are DATA
//! (`rules/rust/rust.bzl` in the workspace under build): a rule declares
//! `toolchains = ["//rules/rust:toolchain_type"]` (C6 — the label key that also drives real Bazel), analysis
//! resolves it through the TOOLCHAIN_CONTEXT node, and the impl reads
//! `ctx.toolchains["//rules/rust:toolchain_type"].rustc`.
//!
//! This INJECTION path is the "test composition" seam (C6): `rust_toolchain(rustc)` builds a
//! `RegisteredToolchain` under the toolchain-type LABEL carrying `platform_common.ToolchainInfo(rustc=…)` —
//! the identity the `.bzl` `rust_toolchain` rule produces, so the injected and the over-the-root
//! (MODULE.bazel-driven) resolution agree. The discovered rustc path matches the rules/rust/BUILD.bazel
//! pin (both `/Users/owebeeone/.cargo/bin/rustc` on this host) so razel and Bazel do not fork the action.
//!
//! Fail-closed: no discoverable rustc is a typed `Error::NotFound` — never a guessed path, never a bare
//! "rustc" left to a PATH lookup at spawn time (the local strategy takes an ABSOLUTE argv[0], the /bin/sh
//! precedent). An explicitly-set `$RUSTC` that does not stat is a typed `Error::Invalid` (the user pointed
//! at a missing compiler — misconfiguration must not silently fall through to probing).

use razel_bzl_api::{BzlValue, ProviderId, ProviderInstance};
use razel_core::Error;
use razel_os_api::{EnvName, HostPath, System};
use razel_toolchain::{RegisteredToolchain, ToolchainType};

/// The toolchain TYPE id a rust rule requires (`rule(toolchains = ["//rules/rust:toolchain_type"])`) — the
/// Appendix-A LABEL both razel and real Bazel key on (C6; was the v1 name-key `"rust"`).
pub const RUST_TOOLCHAIN_TYPE: &str = "//rules/rust:toolchain_type";
/// The provider the resolved rust toolchain carries (`ctx.toolchains[<type>]`) — `platform_common.ToolchainInfo`
/// (C6; was the ad-hoc `RustToolchainInfo`). One identity for the injected row and the `.bzl` rust_toolchain rule.
pub const RUST_TOOLCHAIN_INFO: &str = "ToolchainInfo";
/// Its one v1 field: the discovered rustc as an absolute host path string (argv[0] of every Rustc action).
pub const RUSTC_FIELD: &str = "rustc";
/// The v1 session configuration name a rust build runs under (toolchain resolution REQUIRES a
/// configuration — a config-less toolchain-requiring target fails closed by ratified decision). The
/// matching platform definition is `Platform { constraints: [] }` (the host, unconstrained in v1).
pub const HOST_CONFIG: &str = "host";

/// Discover the host rustc through the `System` seam, in order:
///   1. `$RUSTC` (explicit override) — MUST stat; a set-but-missing override is a typed `Invalid`.
///   2. `$HOME/.cargo/bin/rustc` (the rustup home), `/usr/local/bin/rustc`, `/usr/bin/rustc` — first that
///      stats wins.
/// None found → typed `Error::NotFound` (callers may skip-with-reason in tests on a machine with no rust).
pub fn discover_rustc(sys: &dyn System) -> Result<HostPath, Error> {
    if let Some(v) = sys.raw_env(&EnvName("RUSTC".to_string())) {
        let p = HostPath::new(v.0.clone());
        return match sys.stat(&p) {
            Ok(_) => Ok(p),
            Err(e) => Err(Error::Invalid {
                what: "RUSTC override".into(),
                detail: format!("$RUSTC='{}' does not stat: {e:?} (an explicit override never falls through to probing)", v.0),
            }),
        };
    }
    let mut candidates: Vec<HostPath> = Vec::new();
    if let Some(home) = sys.raw_env(&EnvName("HOME".to_string())) {
        candidates.push(HostPath::new(format!("{}/.cargo/bin/rustc", home.0)));
    }
    candidates.push(HostPath::new("/usr/local/bin/rustc".to_string()));
    candidates.push(HostPath::new("/usr/bin/rustc".to_string()));
    for c in &candidates {
        if sys.stat(c).is_ok() {
            return Ok(c.clone());
        }
    }
    Err(Error::NotFound {
        what: "rustc".into(),
        detail: format!(
            "no rustc found: $RUSTC unset and none of {:?} stat (install rust or set $RUSTC)",
            candidates.iter().map(|c| c.as_str().to_string()).collect::<Vec<_>>()
        ),
    })
}

/// The registry row for the discovered compiler: type `//rules/rust:toolchain_type` (C6), compatible with ANY
/// target/exec platform in v1 (empty constraint sets), carrying `ToolchainInfo { rustc: <abs path> }`. Seed it
/// under the session configuration: `registry.set_toolchains(&ConfigId(HOST_CONFIG.into()), vec![rust_toolchain(&rustc)])`.
pub fn rust_toolchain(rustc: &HostPath) -> RegisteredToolchain {
    RegisteredToolchain {
        toolchain_type: ToolchainType(RUST_TOOLCHAIN_TYPE.to_string()),
        target_compatible_with: Vec::new(),
        exec_compatible_with: Vec::new(),
        info: ProviderInstance {
            provider: ProviderId::from_name(RUST_TOOLCHAIN_INFO),
            fields: vec![(RUSTC_FIELD.to_string(), BzlValue::Str(rustc.as_str().to_string()))],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use razel_os_api::conformance::FakeSystem;

    #[test]
    fn discovery_probes_then_fails_closed() {
        // A FakeSystem with no files and no env → typed NotFound, never a guessed/default path.
        match discover_rustc(&FakeSystem::default()) {
            Err(Error::NotFound { what, .. }) => assert_eq!(what, "rustc"),
            other => panic!("no discoverable rustc must be a typed NotFound, got {other:?}"),
        }
        // With a probed well-known path present, discovery returns it.
        let sys = FakeSystem::default().with_file("/usr/local/bin/rustc", b"#!ELF");
        assert_eq!(discover_rustc(&sys).unwrap().as_str(), "/usr/local/bin/rustc");
        // $HOME probing: ~/.cargo/bin/rustc beats the system paths.
        let sys = FakeSystem::default()
            .with_env("HOME", "/Users/u")
            .with_file("/Users/u/.cargo/bin/rustc", b"#!ELF")
            .with_file("/usr/local/bin/rustc", b"#!ELF");
        assert_eq!(discover_rustc(&sys).unwrap().as_str(), "/Users/u/.cargo/bin/rustc");
    }

    #[test]
    fn explicit_rustc_override_wins_or_fails_closed() {
        // $RUSTC set and present → that exact path (no probing).
        let sys = FakeSystem::default()
            .with_env("RUSTC", "/opt/rust/bin/rustc")
            .with_file("/opt/rust/bin/rustc", b"#!ELF")
            .with_file("/usr/local/bin/rustc", b"#!ELF"); // would-be probe hit, must NOT win
        assert_eq!(discover_rustc(&sys).unwrap().as_str(), "/opt/rust/bin/rustc");
        // $RUSTC set but absent → typed Invalid (misconfiguration is loud, never falls through).
        let sys = FakeSystem::default()
            .with_env("RUSTC", "/nope/rustc")
            .with_file("/usr/local/bin/rustc", b"#!ELF");
        assert!(
            matches!(discover_rustc(&sys), Err(Error::Invalid { .. })),
            "a set-but-missing $RUSTC must fail closed, not silently probe"
        );
    }

    #[test]
    fn rust_toolchain_row_carries_the_rustc_path() {
        let row = rust_toolchain(&HostPath::new("/x/rustc"));
        assert_eq!(row.toolchain_type, ToolchainType(RUST_TOOLCHAIN_TYPE.into()));
        assert!(row.target_compatible_with.is_empty() && row.exec_compatible_with.is_empty());
        assert_eq!(row.info.provider, ProviderId::from_name(RUST_TOOLCHAIN_INFO));
        assert_eq!(row.info.get(RUSTC_FIELD), Some(&BzlValue::Str("/x/rustc".into())));
    }
}
