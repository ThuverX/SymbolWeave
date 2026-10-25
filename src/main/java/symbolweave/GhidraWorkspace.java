package symbolweave;

import ghidra.app.script.*;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.base.project.GhidraProject;
import ghidra.program.model.listing.Program;

import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public final class GhidraWorkspace implements AutoCloseable {
    private final GhidraProject project;
    private final Program program;

    public GhidraWorkspace(GhidraProject project, Program program) {
        this.project = project;
        this.program = program;
    }

    public static GhidraWorkspace open(String name, Path workspace, Path executable, boolean fresh)
            throws Exception {
        ProjectConfig.Input input = new ProjectConfig.Input();
        input.id = name;
        input.projectName = name;
        input.executable = executable.toAbsolutePath().toString();
        input.workspace = workspace.toAbsolutePath().toString();
        return open(null, input, fresh);
    }

    public static GhidraWorkspace open(
            ProjectConfig config, ProjectConfig.Input input, boolean fresh) throws Exception {
        ghidra.app.util.headless.HeadlessAnalyzer.getInstance();
        Path root =
                (config == null ? Path.of(input.workspace) : config.path(input.workspace))
                        .toAbsolutePath()
                        .normalize();
        Path executable =
                (config == null ? Path.of(input.executable) : config.path(input.executable))
                        .toAbsolutePath()
                        .normalize();
        if (!Files.isRegularFile(executable))
            throw new FileNotFoundException("Input " + input.id + ": " + executable);
        // Each analysis identity has its own project directory. Never delete an arbitrary
        // configured
        // directory.
        String settings = ProjectConfig.JSON.toJson(input);
        if (config != null) {
            settings += ProjectConfig.JSON.toJson(config.pluginJars);
            for (String jar : config.pluginJars) settings += fingerprint(config.path(jar), "");
            for (var script : input.scripts)
                if (Files.isRegularFile(config.path(script.name)))
                    settings += fingerprint(config.path(script.name), "");
        }
        String fingerprint = fingerprint(executable, settings);
        Path workspace = input.managedCache ? root.resolve(fingerprint.substring(0, 20)) : root;
        if (!input.managedCache && fresh)
            throw new IllegalArgumentException("--fresh is only allowed for managedCache inputs");
        boolean incomplete =
                input.managedCache
                        && Files.exists(workspace.resolve(".symbolweave-cache"))
                        && !Files.isRegularFile(workspace.resolve(".analysis-complete"));
        if ((fresh || incomplete) && Files.exists(workspace)) {
            if (!Files.isRegularFile(workspace.resolve(".symbolweave-cache")))
                throw new IOException("Refusing to reset unowned analysis directory: " + workspace);
            try (var files = Files.walk(workspace)) {
                for (Path file : files.sorted(Comparator.reverseOrder()).toList())
                    Files.delete(file);
            }
        }
        Files.createDirectories(workspace);
        if (input.managedCache)
            Files.writeString(workspace.resolve(".symbolweave-cache"), fingerprint);
        String name = input.projectName;
        if (name == null || !name.matches("[A-Za-z0-9_.-]+"))
            throw new IllegalArgumentException("Invalid Ghidra projectName: " + name);
        GhidraProject project =
                Files.exists(workspace.resolve(name + ".gpr"))
                        ? GhidraProject.openProject(workspace.toString(), name)
                        : GhidraProject.createProject(workspace.toString(), name, false);
        Program program = null;
        try {
            String programName =
                    input.programName == null
                            ? executable.getFileName().toString()
                            : input.programName;
            var folder = project.getProjectData().getFolder(input.programFolder);
            var existing = folder == null ? null : folder.getFile(programName);
            if (existing != null)
                program = project.openProgram(input.programFolder, programName, false);
            else {
                var loader =
                        ProgramLoader.builder()
                                .source(executable.toFile())
                                .project(project.getProject())
                                .projectFolderPath(input.programFolder)
                                .name(programName)
                                .monitor(Main.MONITOR);
                if (input.language != null) loader.language(input.language);
                if (input.compiler != null) loader.compiler(input.compiler);
                if (input.loader != null) loader.loaders(input.loader);
                input.loaderOptions.forEach(loader::addLoaderArg);
                try (var results = loader.load()) {
                    program = results.getPrimaryDomainObject(project);
                    var manager =
                            ghidra.app.plugin.core.analysis.AutoAnalysisManager.getAnalysisManager(
                                    program);
                    manager.registerOptions();
                    manager.initializeOptions();
                    var options = project.getAnalysisOptions(program);
                    int transaction = program.startTransaction("Configured SDK analysis");
                    boolean success = false;
                    try {
                        for (var setting : input.analyzers.entrySet()) {
                            if (!options.contains(setting.getKey()))
                                throw new IllegalArgumentException(
                                        "Unknown analyzer option for "
                                                + input.id
                                                + ": "
                                                + setting.getKey());
                            var value = setting.getValue().getAsJsonPrimitive();
                            if (value.isBoolean())
                                options.setBoolean(setting.getKey(), value.getAsBoolean());
                            else if (value.isNumber()) {
                                switch (options.getType(setting.getKey())) {
                                    case INT_TYPE ->
                                            options.setInt(setting.getKey(), value.getAsInt());
                                    case LONG_TYPE ->
                                            options.setLong(setting.getKey(), value.getAsLong());
                                    case DOUBLE_TYPE ->
                                            options.setDouble(
                                                    setting.getKey(), value.getAsDouble());
                                    default ->
                                            throw new IllegalArgumentException(
                                                    "Unsupported numeric analyzer option: "
                                                            + setting.getKey());
                                }
                            } else options.setString(setting.getKey(), value.getAsString());
                        }
                        GhidraScriptUtil.acquireBundleHostReference();
                        try {
                            project.analyze(program, false);

                        } finally {
                            GhidraScriptUtil.releaseBundleHostReference();
                        }
                        success = true;
                    } finally {
                        program.endTransaction(transaction, success);
                    }
                    results.save(Main.MONITOR);
                }
            }
            runScripts(config, input, project, program);
            project.save(program);
            if (input.managedCache)
                Files.writeString(workspace.resolve(".analysis-complete"), fingerprint);
            System.out.println("Loaded input " + input.id + " from " + workspace);
            return new GhidraWorkspace(project, program);
        } catch (Exception e) {
            if (program != null) project.close(program);
            project.close();
            throw e;
        }
    }

    private static void runScripts(
            ProjectConfig config, ProjectConfig.Input input, GhidraProject project, Program program)
            throws Exception {
        if (input.scripts.isEmpty()) return;
        int transaction = program.startTransaction("Configured SDK scripts");
        boolean success = false;
        GhidraScriptUtil.acquireBundleHostReference();
        try {
            for (ProjectConfig.Script spec : input.scripts) {
                var resource =
                        Files.isRegularFile(
                                        config == null
                                                ? Path.of(spec.name)
                                                : config.path(spec.name))
                                ? new generic.jar.ResourceFile(
                                        (config == null
                                                        ? Path.of(spec.name)
                                                        : config.path(spec.name))
                                                .toFile())
                                : GhidraScriptUtil.findScriptByName(spec.name);
                if (resource == null)
                    throw new FileNotFoundException("Ghidra script: " + spec.name);
                if (GhidraScriptUtil.findSourceDirectoryContaining(resource) == null)
                    GhidraScriptUtil.getBundleHost().add(resource.getParentFile(), true, false);

                var script =
                        GhidraScriptUtil.getProvider(resource)
                                .getScriptInstance(resource, new PrintWriter(System.out, true));
                script.setScriptArgs(spec.args.toArray(String[]::new));
                script.execute(
                        new GhidraState(null, project.getProject(), program, null, null, null),
                        Main.MONITOR,
                        new PrintWriter(System.out, true));
            }
            success = true;
        } finally {
            GhidraScriptUtil.releaseBundleHostReference();
            program.endTransaction(transaction, success);
        }
    }

    private static String fingerprint(Path file, String settings) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(settings.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        try (var stream = Files.newInputStream(file)) {
            byte[] buffer = new byte[1024 * 1024];
            int count;
            while ((count = stream.read(buffer)) != -1) digest.update(buffer, 0, count);
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    public Program getProgram() {
        return program;
    }

    public GhidraProject getProject() {
        return project;
    }

    public void close() {
        try {
            project.save(program);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to save Ghidra program", e);
        } finally {
            project.close(program);
            project.close();
        }
    }
}
