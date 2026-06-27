//! `razel-host` — a composition root. The ONLY layer permitted to depend on impls (`role: "root"` in the
//! dependency-deny wall): it picks a `System` impl and the incremental `Engine`, registers the source
//! node-kinds, and hands back a running graph. First assembly proving the seams compose end-to-end —
//! a generic engine + an OS capability + build-domain node-kinds, wired with no consumer rewrite.

use razel_engine::Engine;
use razel_os_api::{HostPath, System};
use std::sync::Arc;

/// Build an `Engine` with the source-graph node-kinds (`FILE_STATE` / `FILE`) registered over `sys`,
/// interpreting logical paths relative to `root`.
pub fn build_source_engine(sys: Arc<dyn System>, root: HostPath) -> Engine {
    let mut engine = Engine::new();
    razel_source::register_source_kinds(&mut engine, sys, root);
    engine
}
