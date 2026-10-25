# Development

## Code layout

- `SymbolWeave.java`: portable source launcher, compilation, resources, and developer commands.
- `Main`: application entry point and configuration diagnostics.
- `CommandLine`: argument parsing and explicit overrides.
- `ProjectConfig`: versioned model, validation, discovery, and path resolution.
- `PluginRegistry`: built-in and service-provider plugin lifecycle.
- `GenerationPipeline`: extraction, matching, merging, and export stages.
- `ConfigurableMerger`: identity and field-precedence policies.
- `InheritanceResolver`: primary/secondary vtable declaration reconciliation.
- `AbiClassLoader` / `SymbolMapLoader`: reusable ABI recovery and declarative map parsing.
- `SDKWriter`, signature/PDB generators, and Ghidra scripts: output integrations.

The generator has no dependency on a particular project's source tree or metadata.
`src/main/resources/include/SdkMetadata.h` is the generic C++ runtime support used by
generated headers. The launcher copies resources to the Java classpath; the writer
copies the runtime header into the selected header destination. A packaged distribution
must include both compiled classes and resources.

## Checks

Set `GHIDRA_JAR` to your local Ghidra JAR, then run:

```text
java SymbolWeave.java format --check
java SymbolWeave.java test
java SymbolWeave.java schema --check
```

The launcher finds its sources relative to `SymbolWeave.java`, uses `JavaCompiler`,
and invokes the current JDK through `ProcessBuilder`. Argument lists and classpaths
use Java's platform conventions. Compilation targets Java 21 and copies bundled resources.
Development command implementations live under `src/development/java`; ordinary runs
compile only application code and the launcher. The tests use both source sets.

The regression tests cover configuration discovery/validation, path resolution, XML
field presence, merge precedence, inheritance, matching ambiguity, custom map dialects,
external plugin discovery, generated members/functions/vtables, and signature decoding.
`SDKWriterCallingConventionTest` also accepts an output directory and writes `annotated/`
and `ignored/` C++ fixtures. Compile `src/test/cpp/SDKWriterCallingConventionTest.cpp`
with either directory on the include path. Run the annotated fixture with both x86
and x64 compilers; for the ignored fixture, use x64 and define
`SDK_TEST_IGNORE_CONVENTIONS`. The native test checks declaration/pointer types and
calls native functions and virtual entries for every supported convention. With MSVC,
`/Od /RTC1` also checks for stack corruption; `/Gz` exercises a non-cdecl default.

They create synthetic fixtures in temporary directories. No executable, symbol map,
analysis project, or generated SDK is checked in.

`java SymbolWeave.java schema` regenerates the JSON Schema from the configuration model.
Commit schema changes together with model changes. The formatter is pinned by version and
SHA-256 and caches its JAR in the system temporary directory.

Set `SYMBOLWEAVE_BUILD_DIR` to relocate compiled classes, or `SYMBOLWEAVE_TOOL_CACHE`
to relocate the formatter cache. Both are optional; normal builds use `out/` for classes.
The compiler and runtime must come from a JDK, not a standalone JRE.

For a project-level integration check, use your own inputs and config. Compare a known
baseline with the Java comparison command:

```text
java SymbolWeave.java compare expected.xml actual.xml --expected-headers expected/include --actual-headers actual/include
```

Add `--normalize-anonymous` only when comparing Ghidra-generated anonymous function-type
IDs across runs. The comparison preserves duplicate XML entries, ignores element ordering,
and normalizes header line endings. A difference returns a nonzero exit code.
Signature/PDB exports require suitable project inputs; optional MSVC checking is Windows-only.

The same source launcher accepts `-c config.json` for normal application commands. Build,
test, and schema commands can also use `-c` to select the configuration supplying the JAR.
When no consumer config is found, development commands fall back to the clone's `config.json`.

## Repository hygiene

Keep local binaries, metadata overrides, analysis caches, generated headers, and reports
in your own project or ignored build directories. Example configs should use generic
paths and explain any optional plugin requirements. Preserve configuration compatibility
and run the relevant regression checks when changing extraction or merge behavior.
