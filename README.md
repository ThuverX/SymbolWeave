# SymbolWeave

SymbolWeave keeps the editable description of a game's native interface outside Ghidra
and turns it into C++ headers for modding projects. Ghidra provides the recovered
addresses, functions, types, classes, and vtables. Your project's metadata holds the
corrections and declarations you want to maintain: names, signatures, class layouts,
inheritance, and the rules for combining information from different binaries.

The idea is to make those edits ordinary, version-controlled project files rather than
repeated manual changes to a Ghidra database. You can rerun analysis, apply the same
metadata and merge rules, and regenerate the interface your mod uses. Generated C++
declarations describe the target binary's layouts and calling conventions, so they can
be included directly in a modding project to access game objects and call native functions.
The metadata can also be imported back into Ghidra to keep the analysis aligned with
that external description.

Configuration selects the inputs, loaders, scripts, matching rules, merge precedence,
and exports. The generator can combine information from multiple releases or platforms
and produce headers, XML metadata, executable signatures, and debugger symbols. This
repository provides the reusable generator, runtime support, tests, and templates for
building that workflow around your own project.

## Origins and AI disclaimer

The idea for this project and its initial implementation are mine. I originally built
it to support my MySimsModLoader project. Later additions and rewrites were done by
Codex and verified by me.

## Get started

1. Clone the repository and install **JDK 21 or newer**.
2. Build a Ghidra JAR containing the processors, loaders, and scripts you need. The
   included `ghidra_scripts/BuildGhidraJarScript.java` can build one from your installation.
3. Set `ghidraJar` in `config.json` to your Ghidra JAR, or set the `GHIDRA_JAR`
   environment variable. Point the input paths at your own binaries.

Run the same commands on Windows, macOS, and Linux:

```text
java SymbolWeave.java --print-config
java SymbolWeave.java
```

The starter config reads `inputs/target.exe` and writes generated files under `build/`.
Supply your own input and adjust the paths before running analysis. Ghidra detects the
language and loader unless you specify them.

The launcher finds the nearest `config.json` by searching the caller's current
directory and then its parents. Select another config with `-c`:

```text
java SymbolWeave.java -c examples/windows-x64.json
java SymbolWeave.java --no-analyze
```

Paths inside a config are relative to that config's directory. CLI path overrides are
relative to the caller's directory. `${VARIABLE}` expands environment variables.

You can also keep the generator clone separate from your project: put a config in
your project directory and run `java /path/to/SymbolWeave.java` from there. The caller's
working directory determines configuration discovery; the source file locates the generator.

## Examples

| Configuration | Use |
| --- | --- |
| [config.json](config.json) | Minimal binary-analysis starter |
| [windows-x64.json](examples/windows-x64.json) | Explicit Windows x64 language/compiler settings |
| [metadata-only.json](examples/metadata-only.json) | Generate headers from your own XML metadata |
| [cross-binary.json](examples/cross-binary.json) | Transfer declarations from a symbol map to a separate target |

These are templates: input paths and map parsing rules must describe your project.
The cross-binary example uses an optional CodeWarrior demangler provided by the Ghidra
GameCube Loader module. Other formats can use a different demangler or an extraction plugin.

## Configuration

Configure named inputs, Ghidra projects, language/compiler/loader settings, analyzer
options, ordered scripts, extractors, matching rules, field-level merge policies, and
export destinations. Optional external metadata and support headers remain entirely
project-owned. The generic C++ runtime header is bundled with the generator.

The [JSON Schema](symbolweave.schema.json) provides editor completion. See the
[configuration reference](docs/configuration.md) for settings and precedence, and the
[plugin guide](docs/plugins.md) for custom extractors and matchers.

| Option | Action |
| --- | --- |
| `-c`, `--config <file>` | Select a config explicitly |
| `-a`, `--analyze` | Import/analyze configured inputs and extract metadata |
| `--no-analyze` | Reuse existing intermediate XML |
| `-f`, `--fresh` | Rebuild the selected managed analysis cache |
| `--exe <file>` | Override the input selected by `outputs.executable` |
| `-o`, `--output <directory>` | Override the generated-header directory |
| `-b`, `--bsim` | Run the configured BSim candidate matcher |
| `-s`, `--signatures` | Export version/hash-bound function signatures |
| `-pdb`, `--pdb` | Export a PDB using the executable's CodeView identity |
| `-vt`, `--vtable-check` | Check existing generated vtables with MSVC |
| `--print-config`, `--validate-config` | Validate settings and show resolved paths |

The signature instruction decoder targets x64 PE files. Binary extraction can use
other Ghidra languages. The optional MSVC vtable checker requires Windows and the Visual Studio C++ tools.
Analysis, metadata/header generation, signatures, and PDB writing use Java on the host
platform; Ghidra itself must include compatible host-native components.

## Ghidra integration

Run `ghidra_scripts/ImportSdkXml.java` in an open target program. It discovers your
config or accepts `-c <file>`; an XML path can also be supplied directly. The importer
applies class, function, inheritance, and vtable metadata. Manual data members are used
for C++ header layouts and are not imported as Ghidra class members.

The JAR builder includes installed modules by default. Supply module names as script
arguments to restrict the build to the languages/loaders you need.

## Development

```text
java SymbolWeave.java build
java SymbolWeave.java format
java SymbolWeave.java format --check
java SymbolWeave.java test
java SymbolWeave.java schema --check
```

The source launcher uses the JDK compiler and launches Java directly, with no shell,
Python, PowerShell, Maven, or Gradle dependency. `--help` and formatting do not require
Ghidra. The formatter downloads its pinned, checksum-verified JAR on first use.

Tests use synthetic metadata and temporary directories; they do not require project binaries. Build products
are ignored by Git. See [docs/development.md](docs/development.md) for the code layout,
resource packaging, and verification commands.
