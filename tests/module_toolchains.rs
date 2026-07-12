//! THE D6 OVER-THE-ROOT PROOF (C6): a rust build whose toolchain is resolved ENTIRELY from the workspace
//! MODULE.bazel, THROUGH THE GRAPH — `register_toolchains("//rules/rust:host_rust")` → demand the
//! `toolchain()` target → analyze the `rust_toolchain` impl → extract its `platform_common.ToolchainInfo` →
//! that rustc compiles a `rust_binary`. This is the single-declaration-surface path (razel + Bazel from one
//! file), distinct from the injection path (rust_rules/self_host, which seed the registry directly).
//!
//! Row red-first mutant (tools/gate.sh, unfiltered, requires RED):
//!   mutant_toolchain_registration_ignores_module_bazel → the MODULE.bazel-sourced registration is silently
//!     skipped (the hardcoded-fallback shape) → no rust toolchain is registered under HOST_CONFIG → the
//!     rust build's toolchain resolution fails closed → this proof goes RED (terminating).
//!
//! HANG-PROOF: bounded deadline (real rustc). No rustc discoverable ⇒ SKIP-with-reason.

use razel_host::rust_toolchain::{discover_rustc, HOST_CONFIG};
use razel_host::BuildSession;
use razel_os_api::{HostPath, System};
use razel_os_darwin::DarwinSystem;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const HANG_DEADLINE: Duration = Duration::from_secs(120);

fn hang_proof<T: Send + 'static>(body: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(body());
    });
    match rx.recv_timeout(HANG_DEADLINE) {
        Ok(v) => v,
        Err(RecvTimeoutError::Disconnected) => panic!("test body panicked (see the failure output above)"),
        Err(RecvTimeoutError::Timeout) => panic!("hang-proof deadline exceeded: a real rustc subprocess never completed"),
    }
}

fn unique_root() -> String {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    format!("/tmp/razel-modtc-{nanos}-{n}")
}

fn repo_root() -> String {
    let manifest = env!("CARGO_MANIFEST_DIR"); // <repo>/razel-host
    manifest.rsplit_once('/').map(|(p, _)| p.to_string()).unwrap_or_else(|| manifest.to_string())
}

/// Stage a self-contained workspace whose MODULE.bazel drives toolchain registration + repo declarations.
/// rules/rust/rust.bzl is the REAL committed file (both tools read it); rules/rust/BUILD.bazel pins the
/// DISCOVERED rustc (portable) so `resolve_module_toolchains` extracts a valid compiler.
fn stage_workspace(sys: &dyn System, root: &str, rustc: &HostPath) {
    let repo = repo_root();
    let rust_bzl = sys.read(&HostPath::new(format!("{repo}/rules/rust/rust.bzl"))).expect("read committed rust.bzl");
    let w = |rel: &str, bytes: &[u8]| {
        sys.write_atomic(&HostPath::new(format!("{root}/{rel}")), bytes).unwrap_or_else(|e| panic!("write {rel}: {e:?}"));
    };
    // MODULE.bazel: register the toolchain (the one declaration the resolution reads). No repos needed here.
    w("MODULE.bazel", b"module(name = \"modtc\", version = \"0.0.1\")\nregister_toolchains(\"//rules/rust:host_rust\")\n");
    w("rules/rust/rust.bzl", &rust_bzl);
    // The toolchain targets — rustc pinned to the discovered compiler (portable across machines).
    let build = format!(
        "load(\":rust.bzl\", \"rust_toolchain\")\n\
toolchain_type(name = \"toolchain_type\")\n\
rust_toolchain(name = \"host_rust_impl\", rustc = \"{}\")\n\
toolchain(name = \"host_rust\", toolchain = \":host_rust_impl\", toolchain_type = \":toolchain_type\")\n",
        rustc.as_str()
    );
    w("rules/rust/BUILD.bazel", build.as_bytes());
    // A rust_binary to build (no deps — the toolchain resolution is the point).
    w("hi/BUILD.bazel", b"load(\"//rules/rust:rust.bzl\", \"rust_binary\")\nrust_binary(name = \"hi\", srcs = [\"hi.rs\"])\n");
    w("hi/hi.rs", b"fn main() {\n    println!(\"hi from a module-driven toolchain\");\n}\n");
}

fn rustc_or_skip(sys: &dyn System) -> Option<HostPath> {
    match discover_rustc(sys) {
        Ok(p) => Some(p),
        Err(e) => {
            eprintln!("SKIP module_toolchains: no rustc discoverable: {e:?}");
            None
        }
    }
}

#[test]
fn module_bazel_registered_toolchain_resolves_and_builds() {
    hang_proof(|| {
        let sys: Arc<dyn System> = Arc::new(DarwinSystem);
        let Some(rustc) = rustc_or_skip(sys.as_ref()) else { return };
        let root = unique_root();
        stage_workspace(sys.as_ref(), &root, &rustc);

        // The session sources BOTH the repos and the toolchains from MODULE.bazel (the honest graph path).
        // Under mutant_toolchain_registration_ignores_module_bazel the toolchain is never registered → build
        // fails closed (RED).
        let session = BuildSession::new_local_rust_from_module(sys.clone(), HostPath::new(root.clone()))
            .expect("a module-driven rust session builds (MODULE.bazel resolves + repos map)");
        let built = session
            .build("//hi:hi")
            .expect("razel build //hi:hi succeeds via the MODULE.bazel-registered toolchain (resolved through the graph)");
        assert_eq!(built.len(), 1, "the rust_binary has ONE default output");
        assert_eq!(built[0].exec_path, "hi/hi", "the built binary is the rust_binary's own output");

        // The emitted file is a real rustc-produced Mach-O binary (not fabricated): a non-trivial file exists.
        let on_disk = sys.read(&HostPath::new(built[0].host_path_str().to_string())).expect("read the emitted binary");
        assert!(on_disk.len() > 1024, "the emitted binary carries real compiled code — the MODULE.bazel toolchain really ran rustc");

        assert_eq!(HOST_CONFIG, "host", "the session runs under HOST_CONFIG (toolchain resolution requires it)");
        let _ = sys.remove_dir_all(&HostPath::new(root));
    });
}
