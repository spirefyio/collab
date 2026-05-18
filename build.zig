const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const zora_dep = b.dependency("zora", .{
        .target = target,
        .optimize = optimize,
    });
    const zora_mod = zora_dep.module("zora");

    const desktop_dep = b.dependency("desktop", .{
        .target = target,
        .optimize = optimize,
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
