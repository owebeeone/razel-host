# FIXTURE STUB for the Bazel-EMBEDDED @bazel_tools repo (T20 R-load).
#
# @bazel_tools is a repo Bazel MATERIALIZES from its own install (the embedded tools tree), never fetched or
# vendored — razel runs no repo rules and has no install tree, so the demanded files are vendored here as a
# MINIMAL fixture-local stub repo (the same posture as tests/fixtures/cc_compatibility_proxy/). This file is
# reached at LOAD time by rules_rust's `rust/private/rustc.bzl:19`
#   load("@bazel_tools//tools/build_defs/cc:action_names.bzl", "CPP_LINK_*_ACTION_NAME", …)
# for the link-action-name constants.
#
# PROVENANCE: copied VERBATIM (constants + the ACTION_NAMES struct) from the Bazel 9.x source tree at
#   /Users/owebeeone/limbo/bazel-dev/bazel/tools/build_defs/cc/action_names.bzl
# (Apache-2.0, © The Bazel Authors) — the SAME file Bazel embeds as @bazel_tools//tools/build_defs/cc:
# action_names.bzl. It is a CONSTANTS-ONLY .bzl (no rules, no cc_common surface), so the real symbols the
# closure binds are reproduced exactly; nothing is stubbed-to-None. Re-sync if the pinned oracle's Bazel bumps.

"""Constants for action names used for C++ rules."""

# Name for the C compilation action.
C_COMPILE_ACTION_NAME = "c-compile"

# Name of the C++ compilation action.
CPP_COMPILE_ACTION_NAME = "c++-compile"

# Name of the linkstamp-compile action.
LINKSTAMP_COMPILE_ACTION_NAME = "linkstamp-compile"

# Name of the action used to compute CC_FLAGS make variable.
CC_FLAGS_MAKE_VARIABLE_ACTION_NAME = "cc-flags-make-variable"

# Name of the C++ module codegen action.
CPP_MODULE_CODEGEN_ACTION_NAME = "c++-module-codegen"

# Name of the C++ header parsing action.
CPP_HEADER_PARSING_ACTION_NAME = "c++-header-parsing"

# Name of the C++ deps scanning action.
CPP_MODULE_DEPS_SCANNING_ACTION_NAME = "c++-module-deps-scanning"

# Name of the C++ module compile action.
CPP20_MODULE_COMPILE_ACTION_NAME = "c++20-module-compile"
CPP20_MODULE_CODEGEN_ACTION_NAME = "c++20-module-codegen"

# Name of the C++ module compile action.
CPP_MODULE_COMPILE_ACTION_NAME = "c++-module-compile"

# Name of the assembler action.
ASSEMBLE_ACTION_NAME = "assemble"

# Name of the assembly preprocessing action.
PREPROCESS_ASSEMBLE_ACTION_NAME = "preprocess-assemble"

LLVM_COV = "llvm-cov"

# Name of the action producing ThinLto index.
LTO_INDEXING_ACTION_NAME = "lto-indexing"

# Name of the action producing ThinLto index for executable.
LTO_INDEX_FOR_EXECUTABLE_ACTION_NAME = "lto-index-for-executable"

# Name of the action producing ThinLto index for dynamic library.
LTO_INDEX_FOR_DYNAMIC_LIBRARY_ACTION_NAME = "lto-index-for-dynamic-library"

# Name of the action producing ThinLto index for nodeps dynamic library.
LTO_INDEX_FOR_NODEPS_DYNAMIC_LIBRARY_ACTION_NAME = "lto-index-for-nodeps-dynamic-library"

# Name of the action compiling lto bitcodes into native objects.
LTO_BACKEND_ACTION_NAME = "lto-backend"

# Name of the link action producing executable binary.
CPP_LINK_EXECUTABLE_ACTION_NAME = "c++-link-executable"

# Name of the link action producing dynamic library.
CPP_LINK_DYNAMIC_LIBRARY_ACTION_NAME = "c++-link-dynamic-library"

# Name of the link action producing dynamic library that doesn't include it's
# transitive dependencies.
CPP_LINK_NODEPS_DYNAMIC_LIBRARY_ACTION_NAME = "c++-link-nodeps-dynamic-library"

# Name of the archiving action producing static library.
CPP_LINK_STATIC_LIBRARY_ACTION_NAME = "c++-link-static-library"

# Name of the action stripping the binary.
STRIP_ACTION_NAME = "strip"

# A string constant for the objc compilation action.
OBJC_COMPILE_ACTION_NAME = "objc-compile"

# A string constant for the objc++ compile action.
OBJCPP_COMPILE_ACTION_NAME = "objc++-compile"

# A string constant for the objc executable link action.
OBJC_EXECUTABLE_ACTION_NAME = "objc-executable"

# A string constant for the objc fully-link link action.
OBJC_FULLY_LINK_ACTION_NAME = "objc-fully-link"

# A string constant for the clif actions.
CLIF_MATCH_ACTION_NAME = "clif-match"

# A string constant for the obj copy actions.
OBJ_COPY_ACTION_NAME = "objcopy_embed_data"

# A string constant for the validation action for cc_static_library.
VALIDATE_STATIC_LIBRARY = "validate-static-library"

ACTION_NAMES = struct(
    c_compile = C_COMPILE_ACTION_NAME,
    cpp_compile = CPP_COMPILE_ACTION_NAME,
    linkstamp_compile = LINKSTAMP_COMPILE_ACTION_NAME,
    cc_flags_make_variable = CC_FLAGS_MAKE_VARIABLE_ACTION_NAME,
    cpp_module_codegen = CPP_MODULE_CODEGEN_ACTION_NAME,
    cpp_header_parsing = CPP_HEADER_PARSING_ACTION_NAME,
    cpp_module_deps_scanning = CPP_MODULE_DEPS_SCANNING_ACTION_NAME,
    cpp20_module_compile = CPP20_MODULE_COMPILE_ACTION_NAME,
    cpp20_module_codegen = CPP20_MODULE_CODEGEN_ACTION_NAME,
    cpp_module_compile = CPP_MODULE_COMPILE_ACTION_NAME,
    assemble = ASSEMBLE_ACTION_NAME,
    preprocess_assemble = PREPROCESS_ASSEMBLE_ACTION_NAME,
    llvm_cov = LLVM_COV,
    lto_indexing = LTO_INDEXING_ACTION_NAME,
    lto_backend = LTO_BACKEND_ACTION_NAME,
    lto_index_for_executable = LTO_INDEX_FOR_EXECUTABLE_ACTION_NAME,
    lto_index_for_dynamic_library = LTO_INDEX_FOR_DYNAMIC_LIBRARY_ACTION_NAME,
    lto_index_for_nodeps_dynamic_library = LTO_INDEX_FOR_NODEPS_DYNAMIC_LIBRARY_ACTION_NAME,
    cpp_link_executable = CPP_LINK_EXECUTABLE_ACTION_NAME,
    cpp_link_dynamic_library = CPP_LINK_DYNAMIC_LIBRARY_ACTION_NAME,
    cpp_link_nodeps_dynamic_library = CPP_LINK_NODEPS_DYNAMIC_LIBRARY_ACTION_NAME,
    cpp_link_static_library = CPP_LINK_STATIC_LIBRARY_ACTION_NAME,
    strip = STRIP_ACTION_NAME,
    objc_compile = OBJC_COMPILE_ACTION_NAME,
    objc_executable = OBJC_EXECUTABLE_ACTION_NAME,
    objc_fully_link = OBJC_FULLY_LINK_ACTION_NAME,
    objcpp_compile = OBJCPP_COMPILE_ACTION_NAME,
    clif_match = CLIF_MATCH_ACTION_NAME,
    objcopy_embed_data = OBJ_COPY_ACTION_NAME,
    validate_static_library = VALIDATE_STATIC_LIBRARY,
)
