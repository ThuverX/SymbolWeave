package symbolweave;

import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.ServiceLoader;

/** Owns plugin discovery and restores the caller's context class loader on close. */
final class PluginRegistry implements AutoCloseable {
    private final URLClassLoader loader;
    private final ClassLoader previousLoader;
    private final Map<String, SdkPlugin> plugins = new LinkedHashMap<>();

    private PluginRegistry(URLClassLoader loader) {
        this.loader = loader;
        previousLoader = Thread.currentThread().getContextClassLoader();
        Thread.currentThread().setContextClassLoader(loader);
    }

    static PluginRegistry open(ProjectConfig config) throws Exception {
        var jars = new ArrayList<URL>();
        for (String jar : config.pluginJars) {
            var path = config.path(jar);
            if (!Files.isRegularFile(path))
                throw new IllegalArgumentException("Missing plugin JAR: " + path);
            jars.add(path.toUri().toURL());
        }
        var registry =
                new PluginRegistry(
                        new URLClassLoader(
                                jars.toArray(URL[]::new), SdkPlugin.class.getClassLoader()));
        try {
            for (var plugin : BuiltinPlugins.all()) registry.register(plugin);
            for (var plugin : ServiceLoader.load(SdkPlugin.class, registry.loader))
                registry.register(plugin);
            return registry;
        } catch (Exception | Error failure) {
            try {
                registry.close();
            } catch (Exception closeFailure) {
                failure.addSuppressed(closeFailure);
            }
            throw failure;
        }
    }

    private void register(SdkPlugin plugin) {
        if (plugins.putIfAbsent(plugin.name(), plugin) != null)
            throw new IllegalArgumentException("Duplicate plugin: " + plugin.name());
    }

    SdkPlugin get(String name) {
        var plugin = plugins.get(name);
        if (plugin == null) throw new IllegalArgumentException("Unknown plugin: " + name);
        return plugin;
    }

    void validate(ProjectConfig config) {
        for (var input : config.inputs)
            for (var extractor : input.extractors)
                get(extractor.plugin).validate(extractor.options);
        for (var rule : config.matching) get(rule.plugin).validate(rule.options);
    }

    public void close() throws java.io.IOException {
        try {
            loader.close();
        } finally {
            Thread.currentThread().setContextClassLoader(previousLoader);
        }
    }
}
