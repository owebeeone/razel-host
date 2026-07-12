//! Integration gate for the composition root: the real incremental file story over the `Engine` + source
//! node-kinds + a controllable in-memory `System`. This is where `FILE_STATE` (stat) and `FILE` (content)
//! meet the engine's two prunings — proving the headline guarantee: **a touch (mtime change, same bytes)
//! re-stats and re-reads, but the content digest is unchanged, so the rebuild stops at `FILE`.**
//!
//! Carved into topic modules over a shared [`common`] scaffolding module; the test binary is still named
//! `integration` (`tests/integration/main.rs`), so every `--test integration` gate line stays valid.

mod common;

mod analysis;
mod bzl_load;
mod execution;
mod package;
mod rule_machinery;
mod source_glob;
mod toolchain;
