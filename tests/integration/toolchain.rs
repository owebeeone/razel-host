//! #4: toolchain resolution — the G4 exam (select by constraint, no fixture) (carved out of the former monolithic `tests/integration.rs`).

use crate::common::*;
// ──────────────── #4: toolchain resolution — the G4 exam (select by constraint, no fixture) ────────────────

const TC_RULES: &[u8] = b"NumberInfo = provider(\"NumberInfo\", fields = [\"total\"])\n\
def _impl(ctx):\n\
\x20   tc = ctx.toolchains[\"//cc:toolchain_type\"]\n\
\x20   return [NumberInfo(total = tc.value)]\n\
my_rule = rule(implementation = _impl, toolchains = [\"//cc:toolchain_type\"])\n";

fn cc_toolchain(os: &str, value: i64) -> RegisteredToolchain {
    RegisteredToolchain {
        toolchain_type: ToolchainType("//cc:toolchain_type".into()),
        target_compatible_with: vec![Constraint(format!("os:{os}"))],
        exec_compatible_with: vec![],
        info: ProviderInstance {
            provider: ProviderId::from_name("CcInfo"),
            fields: vec![("value".to_string(), BzlValue::Int(value))],
        },
    }
}
fn two_platforms() -> HashMap<String, Platform> {
    let mut m = HashMap::new();
    m.insert("p_linux".to_string(), Platform { constraints: vec![Constraint("os:linux".into())] });
    m.insert("p_macos".to_string(), Platform { constraints: vec![Constraint("os:macos".into())] });
    m
}
fn host_ep() -> RegisteredExecPlatform {
    RegisteredExecPlatform { name: "host".to_string(), constraints: vec![] }
}
fn reg_tc_key(cfg: &str) -> NodeKey {
    NodeKey::from_key(&RegisteredToolchainsKey { configuration: ConfigId(cfg.into()) })
}
fn reg_ep_key(cfg: &str) -> NodeKey {
    NodeKey::from_key(&RegisteredExecutionPlatformsKey { configuration: ConfigId(cfg.into()) })
}
/// The SAME canonical key analysis builds for a rule's required type-set (all mandatory in v1).
fn tc_ctx_key(cfg: &str, types: &[&str]) -> NodeKey {
    NodeKey::from_key(&ToolchainContextKey::new(
        ConfigId(cfg.into()),
        types
            .iter()
            .map(|t| ToolchainTypeReq { toolchain_type: ToolchainType(t.to_string()), mandatory: true })
            .collect(),
        vec![],
        None,
        false,
    ))
}

#[test]
fn toolchain_resolves_by_platform_g4_exam() {
    // THE G4 exam over the engine: a rule requires a toolchain type; two toolchains are registered (linux/macos)
    // differing only by their target constraint; the resolved ctx.toolchains[type] — hence the rule's output —
    // FLIPS with the CONFIGURATION (from which the target platform is DERIVED). Data-driven, NO host fixture.
    let fs = Arc::new(MutFs::new());
    fs.set("/w/app/rules.bzl", TC_RULES, 1);
    fs.set("/w/app/BUILD.bazel", b"load(\":rules.bzl\", \"my_rule\")\nmy_rule(name = \"t\")\n", 1);
    let (engine, registry) = build_analysis_engine_with_toolchains(fs, HostPath::new("/w"), two_platforms(), host_ep());
    for cfg in ["p_linux", "p_macos"] {
        registry.set_toolchains(&ConfigId(cfg.into()), vec![cc_toolchain("linux", 1), cc_toolchain("macos", 2)]);
    }
    assert_eq!(ct_total(&engine.request(&ctkey_cfg("app", "t", "p_linux")).unwrap()), 1, "linux config → linux cc (value 1)");
    assert_eq!(
        ct_total(&engine.request(&ctkey_cfg("app", "t", "p_macos")).unwrap()),
        2,
        "flip the configuration → the derived platform + resolved toolchain flip (value 2) — data-driven, no fixture"
    );
}

#[test]
fn toolchain_requiring_target_without_configuration_is_fail_closed() {
    // A toolchain-requiring target whose configuration is None must FAIL CLOSED — even when a "" (empty-name)
    // configuration IS fully registered. The bug this guards: coercing a missing configuration to the empty
    // ConfigId so the target silently resolves against whatever "" registration exists (an Absorb — a missing
    // key dimension becoming a default value). Here the "" config has a platform AND a compatible cc toolchain
    // on purpose; correct behavior is still an error, because the target itself has no configuration.
    let fs = Arc::new(MutFs::new());
    fs.set("/w/app/rules.bzl", TC_RULES, 1);
    fs.set("/w/app/BUILD.bazel", b"load(\":rules.bzl\", \"my_rule\")\nmy_rule(name = \"t\")\n", 1);
    let mut platforms = HashMap::new();
    platforms.insert("".to_string(), Platform { constraints: vec![Constraint("os:linux".into())] });
    let (engine, registry) = build_analysis_engine_with_toolchains(fs, HostPath::new("/w"), platforms, host_ep());
    registry.set_toolchains(&ConfigId("".into()), vec![cc_toolchain("linux", 1)]);
    // `ctkey` (not `ctkey_cfg`) → configuration is None.
    assert!(
        engine.request(&ctkey("app", "t")).is_err(),
        "a toolchain-requiring target with no configuration must fail closed, not resolve against a default \"\" config"
    );
}

#[test]
fn rule_requiring_unavailable_toolchain_is_fail_closed() {
    // A rule requires a cc toolchain, but the target platform has no compatible one → fail closed (never a
    // default/fixture), and the failure propagates to the configured target.
    let fs = Arc::new(MutFs::new());
    fs.set("/w/app/rules.bzl", TC_RULES, 1);
    fs.set("/w/app/BUILD.bazel", b"load(\":rules.bzl\", \"my_rule\")\nmy_rule(name = \"t\")\n", 1);
    let mut platforms = HashMap::new();
    platforms.insert("p_windows".to_string(), Platform { constraints: vec![Constraint("os:windows".into())] });
    let (engine, registry) = build_analysis_engine_with_toolchains(fs, HostPath::new("/w"), platforms, host_ep());
    registry.set_toolchains(&ConfigId("p_windows".into()), vec![cc_toolchain("linux", 1)]);
    assert!(
        engine.request(&ctkey_cfg("app", "t", "p_windows")).is_err(),
        "no cc toolchain compatible with the platform → the configured target fails closed"
    );
}

#[test]
fn registered_toolchain_set_change_reresolves() {
    // THE HEADLINE lockdown gate (`toolchain_context_key_registered_toolchain_set_change`, decision A): the
    // registered set is a config-keyed DEPENDENCY node, so a `register_toolchains()` change — applied to the
    // SHARED registry under the RUNNING engine and dirtied via the engine Diff — re-resolves the context and
    // re-analyzes the configured target. `mutant_toolchain_registered_set_not_a_dep` (the spike's leaf shape)
    // bakes the set outside the edge: the change then invalidates NOTHING and this test goes RED on stale data.
    let fs = Arc::new(MutFs::new());
    fs.set("/w/app/rules.bzl", TC_RULES, 1);
    fs.set("/w/app/BUILD.bazel", b"load(\":rules.bzl\", \"my_rule\")\nmy_rule(name = \"t\")\n", 1);
    let (engine, registry) = build_analysis_engine_with_toolchains(fs, HostPath::new("/w"), two_platforms(), host_ep());
    let cfg = ConfigId("p_linux".into());
    registry.set_toolchains(&cfg, vec![cc_toolchain("linux", 1)]);
    let ct = ctkey_cfg("app", "t", "p_linux");
    assert_eq!(ct_total(&engine.request(&ct).unwrap()), 1, "warm: the registered cc resolves (value 1)");
    let before = engine.inspect(&ct).unwrap().version;

    // the registration CHANGES (same type, different toolchain_info) → dirty the registry node.
    registry.set_toolchains(&cfg, vec![cc_toolchain("linux", 7)]);
    engine.evaluate(&[ct.clone()], FailurePolicy::FailFast, Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(reg_tc_key("p_linux"))] });

    let after = engine.inspect(&ct).unwrap().version;
    assert!(after.last_changed > before.last_changed, "a registered-set change must re-resolve + re-analyze");
    assert_eq!(ct_total(&engine.request(&ct).unwrap()), 7, "the NEW registration is served, never the stale context");
}

#[test]
fn equal_registered_set_early_cuts() {
    // Decision A's other half: re-registering an EQUAL set recomputes only the registry node — the
    // comparable value early-cuts, so neither the toolchain context nor the configured target recomputes.
    let fs = Arc::new(MutFs::new());
    fs.set("/w/app/rules.bzl", TC_RULES, 1);
    fs.set("/w/app/BUILD.bazel", b"load(\":rules.bzl\", \"my_rule\")\nmy_rule(name = \"t\")\n", 1);
    let (engine, registry) = build_analysis_engine_with_toolchains(fs, HostPath::new("/w"), two_platforms(), host_ep());
    let cfg = ConfigId("p_linux".into());
    registry.set_toolchains(&cfg, vec![cc_toolchain("linux", 1)]);
    let ct = ctkey_cfg("app", "t", "p_linux");
    engine.request(&ct).unwrap(); // warm
    let tc = tc_ctx_key("p_linux", &["//cc:toolchain_type"]);
    let (tc_before, ct_before) = (engine.inspect(&tc).unwrap().version, engine.inspect(&ct).unwrap().version);

    registry.set_toolchains(&cfg, vec![cc_toolchain("linux", 1)]); // the SAME set again
    let rep = engine.evaluate(&[ct.clone()], FailurePolicy::FailFast, Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(reg_tc_key("p_linux"))] });

    assert_eq!(rep.recomputes, 1, "only REGISTERED_TOOLCHAINS recomputes; the equal set prunes everything above");
    assert_eq!(engine.inspect(&tc).unwrap().version.last_changed, tc_before.last_changed, "context cut off (equal set)");
    assert_eq!(engine.inspect(&ct).unwrap().version.last_changed, ct_before.last_changed, "configured target cut off");
}

#[test]
fn changed_set_with_equal_resolved_context_cuts_off() {
    // The lockdown §2 invalidation story, spelled out: the registered set CHANGES (an unrelated type is
    // added) → the edge dirties the context and it RE-RESOLVES — but the resolved context is value-equal,
    // so change-pruning stops there and the configured target is never re-analyzed.
    let fs = Arc::new(MutFs::new());
    fs.set("/w/app/rules.bzl", TC_RULES, 1);
    fs.set("/w/app/BUILD.bazel", b"load(\":rules.bzl\", \"my_rule\")\nmy_rule(name = \"t\")\n", 1);
    let (engine, registry) = build_analysis_engine_with_toolchains(fs, HostPath::new("/w"), two_platforms(), host_ep());
    let cfg = ConfigId("p_linux".into());
    registry.set_toolchains(&cfg, vec![cc_toolchain("linux", 1)]);
    let ct = ctkey_cfg("app", "t", "p_linux");
    engine.request(&ct).unwrap(); // warm
    let tc = tc_ctx_key("p_linux", &["//cc:toolchain_type"]);
    let (tc_before, ct_before) = (engine.inspect(&tc).unwrap().version, engine.inspect(&ct).unwrap().version);

    // ADD a toolchain of a type this rule never requested — the SET differs, the RESOLVED context doesn't.
    let unrelated = RegisteredToolchain {
        toolchain_type: ToolchainType("//zig:toolchain_type".into()),
        target_compatible_with: vec![],
        exec_compatible_with: vec![],
        info: ProviderInstance { provider: ProviderId::from_name("ZigInfo"), fields: vec![] },
    };
    registry.set_toolchains(&cfg, vec![cc_toolchain("linux", 1), unrelated]);
    let rep = engine.evaluate(&[ct.clone()], FailurePolicy::FailFast, Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(reg_tc_key("p_linux"))] });

    assert_eq!(rep.recomputes, 2, "the registry node AND the context re-resolve; the equal context prunes the CT");
    let tc_after = engine.inspect(&tc).unwrap().version;
    assert_eq!(tc_after.last_changed, tc_before.last_changed, "the re-resolved context is value-equal → cut off");
    assert!(tc_after.last_evaluated > tc_before.last_evaluated, "but the context WAS re-resolved this round");
    assert_eq!(engine.inspect(&ct).unwrap().version.last_changed, ct_before.last_changed, "the configured target never re-analyzed");
}

#[test]
fn exec_platform_registration_change_reresolves() {
    // REGISTERED_EXECUTION_PLATFORMS is its own config-keyed dependency node (Bazel-faithful): changing the
    // registered exec-platform set re-selects the context's execution platform through the SAME edge pattern.
    let fs = Arc::new(MutFs::new());
    fs.set("/w/app/rules.bzl", TC_RULES, 1);
    fs.set("/w/app/BUILD.bazel", b"load(\":rules.bzl\", \"my_rule\")\nmy_rule(name = \"t\")\n", 1);
    let (engine, registry) = build_analysis_engine_with_toolchains(fs, HostPath::new("/w"), two_platforms(), host_ep());
    let cfg = ConfigId("p_linux".into());
    registry.set_toolchains(&cfg, vec![cc_toolchain("linux", 1)]);
    registry.set_exec_platforms(&cfg, vec![RegisteredExecPlatform { name: "ep_a".into(), constraints: vec![] }]);
    let ct = ctkey_cfg("app", "t", "p_linux");
    assert_eq!(ct_total(&engine.request(&ct).unwrap()), 1);
    let tc = tc_ctx_key("p_linux", &["//cc:toolchain_type"]);
    let (tc_before, ct_before) = (engine.inspect(&tc).unwrap().version, engine.inspect(&ct).unwrap().version);

    // swap the registered exec platform → the selected platform changes → the context VALUE changes...
    registry.set_exec_platforms(&cfg, vec![RegisteredExecPlatform { name: "ep_b".into(), constraints: vec![] }]);
    engine.evaluate(&[ct.clone()], FailurePolicy::FailFast, Diff { changed: vec![ChangedLeaf::ChangedWithoutValue(reg_ep_key("p_linux"))] });

    assert!(engine.inspect(&tc).unwrap().version.last_changed > tc_before.last_changed, "the re-selected context propagates");
    // ...but the rule's OUTPUT (providers from the same toolchain_info) is unchanged → the CT cuts off.
    assert_eq!(engine.inspect(&ct).unwrap().version.last_changed, ct_before.last_changed, "same providers → CT early-cutoff");
    assert_eq!(ct_total(&engine.request(&ct).unwrap()), 1);
}

#[test]
fn exec_selection_supplies_all_mandatory_over_the_root() {
    // Decision F over the composition root: the FIRST registered exec platform cannot supply the mandatory
    // type (the cc toolchain is exec-compatible only with the capable one) → selection must skip it and the
    // rule still resolves. `mutant_toolchain_exec_selection_first_candidate` picks the first candidate
    // regardless → the mandatory type is unsupplied → this test goes RED (fail-closed error).
    let fs = Arc::new(MutFs::new());
    fs.set("/w/app/rules.bzl", TC_RULES, 1);
    fs.set("/w/app/BUILD.bazel", b"load(\":rules.bzl\", \"my_rule\")\nmy_rule(name = \"t\")\n", 1);
    let (engine, registry) = build_analysis_engine_with_toolchains(fs, HostPath::new("/w"), two_platforms(), host_ep());
    let cfg = ConfigId("p_linux".into());
    let mut tc = cc_toolchain("linux", 3);
    tc.exec_compatible_with = vec![Constraint("exec:cap".into())];
    registry.set_toolchains(&cfg, vec![tc]);
    registry.set_exec_platforms(
        &cfg,
        vec![
            RegisteredExecPlatform { name: "ep_plain".into(), constraints: vec![] },
            RegisteredExecPlatform { name: "ep_cap".into(), constraints: vec![Constraint("exec:cap".into())] },
        ],
    );
    assert_eq!(
        ct_total(&engine.request(&ctkey_cfg("app", "t", "p_linux")).unwrap()),
        3,
        "the exec platform supplying ALL mandatory types is selected (not the first candidate)"
    );
}

