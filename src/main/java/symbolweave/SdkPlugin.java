package symbolweave;

import com.google.gson.JsonObject;

import symbolweave.containers.FileContainer;

import java.util.Map;

/** Providers are registered in META-INF/services/symbolweave.SdkPlugin in plugin JARs. */
public interface SdkPlugin {
    String name();

    default void validate(JsonObject options) {}

    default FileContainer extract(
            ProjectConfig config,
            ProjectConfig.Input input,
            GhidraWorkspace workspace,
            JsonObject options)
            throws Exception {
        throw new UnsupportedOperationException(name() + " is not an extractor");
    }

    default void match(
            ProjectConfig config, ProjectConfig.Match rule, Map<String, FileContainer> containers)
            throws Exception {
        throw new UnsupportedOperationException(name() + " is not a matcher");
    }
}
