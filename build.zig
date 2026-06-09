const std = @import("std");

/// Mirrors desktop's `Gui` enum (tag names must match). collab is itself
/// GUI-agnostic — it only consumes desktop's `compat`/`util_json` — but the
/// flavor MUST be forwarded to the desktop dependency so collab's `desktop`
/// instance dedupes with the consuming app's. Zig keys a dependency instance on
/// its full option set, so a gui mismatch forks `compat`/`util_json` into two
/// modules and fails with "file exists in modules 'compat' and 'compat0'".
const Gui = enum { react, vue, svelte, native, none };

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // GUI flavor passthrough — see the `Gui` doc comment. Defaults to react, so
    // collab's standalone build and existing react consumers are unchanged.
    const gui = b.option(
        Gui,
        "gui",
        "GUI flavor forwarded to the desktop dependency (default: react). collab " ++
            "is GUI-agnostic; this only keeps the shared desktop instance deduped " ++
            "with the consuming app.",
    ) orelse .react;

    const zora_dep = b.dependency("zora", .{
        .target = target,
        .optimize = optimize,
    });
    const zora_mod = zora_dep.module("zora");

    // collab is the TRANSITIVE path to `desktop` for any app that also depends
    // on desktop directly (e.g. studio pulls desktop both ways). Every keyed
    // option forwarded here MUST match the app's direct desktop dep, or Zig keys
    // the two instances apart and forks `compat`/`util_json`. Today only `.gui`
    // is forwarded; if a future option (e.g. `.llama_cpp`) is forwarded to
    // desktop, add it on BOTH paths. See the `Gui` doc comment above.
    const desktop_dep = b.dependency("desktop", .{
        .target = target,
        .optimize = optimize,
        .gui = gui,
    });
    const compat_mod = desktop_dep.module("compat");
    const util_json_mod = desktop_dep.module("util_json");

    const identity_mod = b.addModule("identity", .{
        .root_source_file = b.path("src/identity/mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    identity_mod.addImport("compat", compat_mod);

    const collab_mod = b.addModule("collab", .{
        .root_source_file = b.path("src/collab/lib.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    collab_mod.addImport("zora", zora_mod);
    collab_mod.addImport("compat", compat_mod);
    collab_mod.addImport("util_json", util_json_mod);
    collab_mod.addImport("identity", identity_mod);

    const collab_test_mod = b.createModule(.{
        .root_source_file = b.path("src/collab/lib.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    collab_test_mod.addImport("zora", zora_mod);
    collab_test_mod.addImport("compat", compat_mod);
    collab_test_mod.addImport("util_json", util_json_mod);
    collab_test_mod.addImport("identity", identity_mod);

    const collab_tests = b.addTest(.{
        .name = "collab-tests",
        .root_module = collab_test_mod,
    });

    const test_step = b.step("test", "Run collab tests");
    test_step.dependOn(&b.addRunArtifact(collab_tests).step);
}
