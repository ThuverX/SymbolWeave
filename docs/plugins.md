# Plugin interface

Put plugin JAR paths in `pluginJars`. Each JAR registers implementations in
`META-INF/services/symbolweave.SdkPlugin`, one fully-qualified class name per line.
Providers need a public no-argument constructor and a unique `name()`. Duplicate and
unknown plugin names are errors. Compile against the SDK classes and your Ghidra JAR.

```java
package example;

import com.google.gson.JsonObject;
import symbolweave.*;
import symbolweave.containers.FileContainer;

public final class CustomExtractor implements SdkPlugin {
  public String name() { return "custom-map"; }

  public void validate(JsonObject options) {
    Options.required(options, "file");
  }

  public FileContainer extract(ProjectConfig config, ProjectConfig.Input input,
      GhidraWorkspace workspace, JsonObject options) throws Exception {
    var path = config.path(Options.required(options, "file"));
    // Read this format and construct normalized SDK metadata.
    return new FileContainer(input.id);
  }
}
```

Extractors receive the configured Ghidra workspace and return a `FileContainer`.
Matchers implement `match(ProjectConfig, ProjectConfig.Match,
Map<String, FileContainer>)` and update the selected normalized containers.
Options are validated before any analysis starts. Plugin code and dependencies are loaded
through a separate URL class loader, also available as the thread context class loader.
Demangler classes selected by map settings can be supplied by the same plugin JARs.

A plugin is ordinary Java code running with the generator's permissions. Only configure
plugins you intend to execute. Built-in extractor names are `functions`, `map`, and
`rtti`; built-in matchers are `declarations` and `function-match`.
