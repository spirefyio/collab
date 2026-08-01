const std = @import("std");

/// Mirrors desktop's `Gui` enum (tag names must match). collab is itself
/// GUI-agnostic — it only consumes desktop's `compat`/`util_json` — but the
/// flavor MUST be forwarded to the desktop dependency so collab's `desktop`
/// instance dedupes with the consuming app's. Zig keys a dependency instance on
/// its full option set, so a gui mismatch forks `compat`/`util_json` into two
/// modules and fails with "file exists in modules 'compat' and 'compat0'".
const Gui = enum { react, vue, svelte, native, none };

pub fn build(b: *std.Build) void {

    // --- build stamp (Help -> About) -----------------------------------
    // CANONICAL COPY: desktop/build.zig (build.zig cannot import helpers
    // across packages) — edit there first, then mirror here. Every
    // `zig build` increments the gitignored per-machine counter; the app
    // aggregates each repo's `dep.module("stamp")` into the About dialog.
    const stamp_opts = b.addOptions();
    stamp_opts.addOption([]const u8, "module_name", stampName());
    stamp_opts.addOption([]const u8, "version", stampVersion());
    stamp_opts.addOption(u64, "build_number", stampBuildNumber(b));
    stamp_opts.addOption(i64, "built_epoch_s", stampEpoch(b));
    stamp_opts.addOption([]const u8, "built_on", stampHost(b));
    _ = b.addModule("stamp", .{ .root_source_file = stamp_opts.getOutput() });
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // GUI flavor passthrough — see the `Gui` doc comment. Defaults to native
    // since the M1.0 ecosystem flip (desktop dev@850640e, studio commit 4/4),
    // so a bare collab build matches what every consumer builds by default;
    // react consumers forward -Dgui=react explicitly (the frozen escape hatch).
    const gui = b.option(
        Gui,
        "gui",
        "GUI flavor forwarded to the desktop dependency (default: native). collab " ++
            "is GUI-agnostic; this only keeps the shared desktop instance deduped " ++
            "with the consuming app.",
    ) orelse .native;

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

// --- build-stamp helpers (canonical copy: desktop/build.zig) ----------------

/// The package name from `build.zig.zon` — besides being useful, it makes
/// each repo's generated stamp file UNIQUE: with identical versions, counter
/// values and build second, the content-addressed cache deduped two repos'
/// stamps into ONE file and the compiler refused it as belonging to two
/// modules.
fn stampName() []const u8 {
    const manifest = @embedFile("build.zig.zon");
    const key = ".name = .";
    const at = std.mem.indexOf(u8, manifest, key) orelse return "unknown";
    const rest = manifest[at + key.len ..];
    const end = std.mem.indexOfScalar(u8, rest, ',') orelse return "unknown";
    return rest[0..end];
}

fn stampVersion() []const u8 {
    const manifest = @embedFile("build.zig.zon");
    const key = ".version = \"";
    const at = std.mem.indexOf(u8, manifest, key) orelse return "0.0.0";
    const rest = manifest[at + key.len ..];
    const end = std.mem.indexOfScalar(u8, rest, '"') orelse return "0.0.0";
    return rest[0..end];
}

fn stampBuildNumber(b: *std.Build) u64 {
    // ABSOLUTE path: `b.run` inherits the TOP-LEVEL build's cwd, so a
    // dependency stamping "./.build-number" would increment the parent app's
    // counter instead of its own (observed: studio at 5, zora at none).
    const counter = b.pathFromRoot(".build-number");
    const cmd = b.fmt("n=$(cat '{s}' 2>/dev/null || echo 0); n=$((n+1)); printf %s \"$n\" > '{s}'; printf %s \"$n\"", .{ counter, counter });
    const out = b.run(&.{ "sh", "-c", cmd });
    return std.fmt.parseInt(u64, std.mem.trim(u8, out, " \t\r\n"), 10) catch 0;
}

fn stampEpoch(b: *std.Build) i64 {
    const out = b.run(&.{ "date", "+%s" });
    return std.fmt.parseInt(i64, std.mem.trim(u8, out, " \t\r\n"), 10) catch 0;
}

fn stampHost(b: *std.Build) []const u8 {
    const out = b.run(&.{ "hostname", "-s" });
    return std.mem.trim(u8, out, " \t\r\n");
}
