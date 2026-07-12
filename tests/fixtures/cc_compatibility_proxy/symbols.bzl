# FIXTURE STUB for the repo-phase-GENERATED @cc_compatibility_proxy repo (T20 R-load).
#
# In Bazel, @cc_compatibility_proxy is materialized at REPO-RESOLUTION time by rules_cc's
# `compatibility_proxy` module extension (cc/extensions.bzl `_compatibility_proxy_repo_impl`), whose
# generated `symbols.bzl` re-exports cc_common/CcInfo/... from `@rules_cc//cc/private:*` (the Starlark
# cc_common impl, which bottoms out in Bazel's `_builtins` bootstrap). razel runs NO repo rules and has
# NO `_builtins` (RazelRulesRustCompatPlan §0: repo-phase execution is out of scope; cc_common is the
# XL row-7 ANALYSIS lump, deferred to R-analyze/R-build).
#
# For R-load — which only requires the @rules_rust//rust:defs.bzl LOAD closure to EVALUATE — this stub
# supplies exactly the symbols the closure binds at load, and nothing more. Their real behavior is an
# ANALYSIS-time concern: `cc_common`/`merge_cc_infos` are `None`, so any analysis-time use is a typed
# error (fail-closed, never a silent no-op — the R-analyze burn-down surfaces it). `CcInfo` is a real
# provider because the closure references it at LOAD time in `providers=[CcInfo]` / `provides=[CcInfo]`
# lists, which must see a provider value. This is a fixture-local stand-in for a repo razel cannot
# generate, NOT a razel builtin — it lives only under the rules_rust_compat fixture.

CcInfo = provider(
    doc = "cc_compatibility_proxy R-load stub: a load-time provider value (real CcInfo data model = R-analyze row 7)",
    fields = ["_stub"],
)

# Analysis-time surfaces — None at load so any USE is a fail-closed typed error (row 7, deferred).
cc_common = None
merge_cc_infos = None
