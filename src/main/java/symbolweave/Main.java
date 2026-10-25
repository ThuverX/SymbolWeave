package symbolweave;

import ghidra.util.task.TaskMonitor;

/** Application entry point. */
public final class Main {
    public static final TaskMonitor MONITOR = new ConsoleTaskMonitor();

    private Main() {}

    public static void main(String[] args) throws Exception {
        var options = CommandLine.parse(args);
        if (options.help) {
            System.out.println(CommandLine.USAGE);
            return;
        }
        var config = ProjectConfig.load(options.selectedConfig());
        options.apply(config);
        System.out.println("Configuration: " + config.file());
        try (var plugins = PluginRegistry.open(config)) {
            plugins.validate(config);
            if (options.printConfig) {
                printConfig(config);
                return;
            }
            new GenerationPipeline(config, plugins).run(options.fresh, options.vtableCheck);
        }
    }

    private static void printConfig(ProjectConfig config) {
        var effective = ProjectConfig.JSON.toJsonTree(config).getAsJsonObject();
        var paths = new com.google.gson.JsonObject();
        for (var input : config.inputs) {
            var values = new com.google.gson.JsonObject();
            values.addProperty("xml", config.path(input.xml).toString());
            values.addProperty("workspace", config.path(input.workspace).toString());
            if (input.executable != null)
                values.addProperty("executable", config.path(input.executable).toString());
            paths.add(input.id, values);
        }
        paths.addProperty("sdkXml", config.path(config.outputs.xml).toString());
        paths.addProperty("headers", config.path(config.outputs.headers).toString());
        effective.add("resolvedPaths", paths);
        System.out.println(ProjectConfig.JSON.toJson(effective));
    }
}
