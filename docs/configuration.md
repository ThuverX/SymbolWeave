# Configuration reference

The root object accepts `version` (currently `1`), `ghidraJar`, `pluginJars`, `analyze`,
`inputs`, `matching`, `merge`, `outputs`, `checker`, and `bsim`. `$schema` is optional.
All filesystem paths are relative to the selected configuration, and accept `${ENV}`.
Launch with `java SymbolWeave.java`; the JDK compiler handles the host platform.
The `GHIDRA_JAR` environment variable overrides the configured `ghidraJar` for launching.
The JSON Schema enumerates structural fields. `ProjectConfig.java` defines defaults.

## Inputs and Ghidra

Each input requires a unique `id` and an `xml` path. Extraction also requires
`executable`. An empty `extractors` list makes it XML-only.

| Setting | Meaning / default |
| --- | --- |
| `projectName` | Ghidra project name; defaults to input ID |
| `workspace` | Project/cache parent; defaults to `.cache/<id>` |
| `managedCache` | `true`: isolated hash directory; `false`: use workspace directly |
| `programFolder` | Ghidra folder, default `/` |
| `programName` | Existing/imported program name; default executable filename |
| `language`, `compiler`, `loader` | Explicit Ghidra identifiers; omitted means loader detection |
| `loaderOptions` | Map of Ghidra loader argument names to string values |
| `analyzers` | Map of registered option names to boolean, numeric, or string values |
| `scripts` | Ordered `{ "name": "script.java", "args": [] }` entries; file paths or installed script names |
| `extractors` | Ordered `{ "plugin": "name", "options": {} }` entries |

Analysis options apply at import. Scripts run on imported and reused programs. Managed
cache identity includes the executable bytes, input settings, plugin JAR bytes, and local
script bytes. Changed map/patch content is reread on extraction/merge; it does not require
reimporting the executable. `--fresh` rejects unmanaged project resets.

## Extraction plugins

`functions` has no options. It reads Ghidra functions, class namespaces, declarations,
calling conventions, parameters, types, variadic state, and implementation addresses.

`map` accepts these options:

| Setting | Meaning |
| --- | --- |
| `file` | Map file path, required |
| `lineFilter` | Whole-line regex selecting candidate lines; default `.*` |
| `lineRegex` | Whole-line regex with named capture groups, required |
| `fields` | Capture-group mappings for `address`, `size`, `storageSize`, `name`, `unit` |
| `radix`, `storageRadix` | Numeric bases, default 16 / 10 |
| `demanglerClass`, `demanglerMethod` | Class with a static String-to-DemangledObject method; default method `demangleSymbol` |
| `vtableRegex` | Regex identifying vtable symbols, required |
| `ignoreSymbolRegex` | Symbols that must not be demangled |
| `includeUnitRegex`, `excludeUnitRegex` | Include/exclude compilation units by regex |
| `pointerSize`, `headerSlots` | ABI pointer width and initial vtable metadata slots |
| `virtualCallingConvention` | Enum `CDECL`, `STDCALL`, `THISCALL`, or `FASTCALL` |
| `functionCallingConvention` | Convention for non-virtual map declarations |
| `defaultStorageSize` | Undefined return-type width when omitted, default 1 |
| `includeLooseFunctions`, `includeClassFunctions` | Include non-virtual declarations, default true |
| `malformed` | `error` (default) or `skip` for selected lines that fail the pattern |

Map extraction recovers virtual slots, parent namespaces, named class functions, and
loose functions. The map's address capture must describe addresses in the selected
Ghidra program. Use a custom extractor for map formats needing more complex relocation.

`rtti` implements MSVC-style RTTI extraction. Options are `vtableSymbolRegex`
(default `vftable`), `pureVirtualRegex` (`(?i)purecall`), `baseArraySymbolRegex`
(`RTTI_Base_Class_Array`), `rttiPointerSize` (4), `rttiRelative` (true), `baseArraySkip`
(1), `typeNameOffset` (16), and `typeNameStripRegex` (`^(class |struct )`). `followPureVirtualThunks` (true) follows thunks to matching pure-call imports, even
when the thunk has been renamed by metadata import. Physical
vtable pointers use the program's pointer size. Secondary vtables are retained.

## Matching

Rules execute in list order and reference input IDs through `source` and `target`.
Their plugin name is in `plugin`, with settings under `options`.

`declarations` matches class names and virtual slots. Options:

- `classRegex`: classes to consider, default `.*`.
- `namePattern`, `nameReplacement`: normalization applied to source/target class keys.
- `secondaryHeaderSlots`: remove unambiguous internal null header groups, default 0.
- `slotOffset`: offset applied to transferred virtual slots, default 0.
- `retainUnmatchedSlots`, `retainLooseFunctions`, `retainClassFunctions`: true by default.
- `returnType`, `callingConvention`: optional overrides for transferred declarations.
- `ambiguity`: `error` (default), `first`, or `skip` when normalized keys collide.
- `fields`, `classFields`: explicit function/class field assignments (see below).

By default declarations/parameters come from the source, and addresses, implementation
addresses, pure-virtual state, and physical owners come from the target. Configuration
can override each transferred field.

`function-match` matches loose, class, and virtual functions. Options are `sourceKey`
and `targetKey` (comma-separated getter properties, default `name`), `namePattern`,
`nameReplacement`, `sourceRegex`, `targetRegex`, `ambiguity`, and `fields`. It copies
names/parameters by default. Rules support joining target/source addresses as well as
normalized names by selecting the relevant identity properties.

Field assignments use `$source.<property>`, `$target.<property>`, or a literal JSON
value. `returnType` and `name` accept simple string literals; enum convention values
use enum names. The target values are those before the rule is applied.

```json
{
  "source": "symbols",
  "target": "pc",
  "plugin": "function-match",
  "options": {
    "sourceKey": "name",
    "targetKey": "name",
    "ambiguity": "error",
    "fields": {
      "name": "$source.name",
      "parameters": "$source.parameters",
      "address": "$target.address",
      "returnType": "bool"
    }
  }
}
```

## Merge precedence

`merge.sources` is an ordered list of input IDs. Later sources are applied over earlier
sources. If omitted, all input IDs are used in declaration order. Matching can update an
input without including that input separately in the merge.

`merge.patches` contains ordered patch selections: `directory` (default `metadata/overrides`), `glob` (`*.xml`),
`recursive` (false), `required` (false), `order` (`ascending`, `descending`, or `listed`),
`files` (explicit paths), and `headerFromFilename` (true). `listed` requires `files`.
Patch source groups execute in list order; later patches have higher precedence.

Identity settings are `classKey` (`name`), `functionKey` (`name,address`), and `memberKey`
(`name`). Comma-separated properties form composite keys. Virtual functions match by slot.
`duplicateFunctions` is `merge` (default), `append`, or `error`.

`sourcePolicies` maps input IDs to policy overrides, and each patch selection can have a
`policy` object. These objects accept `defaultPolicy`, `fields`, `duplicateFunctions`,
and `respectOmitted`; omitted settings inherit the global merge policy. This lets
analyzed inputs retain existing addresses while a manual patch is allowed to replace them.

`defaultPolicy` defaults to `nonempty`. `fields` overrides a policy per property:

```json
{
  "sources": ["target"],
  "fields": {
    "function.address": "keep",
    "function.name": "nonempty",
    "function.returnType": "replace",
    "class.parents": "append",
    "member.size": "error"
  }
}
```

| Policy | Behavior |
| --- | --- |
| `nonempty` | Incoming populated values win; zero/empty values preserve existing values |
| `replace` | Incoming value wins, including zero/empty values |
| `keep` | Existing value wins |
| `append` | Combine list/map values; lists retain unique entries |
| `error` | Reject differing populated values |

Available class properties include `name`, `vtableAddress`, `vtableCount`, `parents`,
`virtualFunctions`, `functions`, and `members`. Function properties include `name`,
`address`, `callingConvention`, `returnType`, `parameters`, `override`, `static`,
`varargs`, `pureVirtual`, `implementationAddress`, `vtableOwner`, and `headerFile`.
Member properties include `name`, `type`, `value`, `static`, `size`, `arraySize`,
`offset`, and `address`.

`respectOmitted` defaults to true: XML fields that are absent preserve existing values.
An explicit `false` boolean is distinct from omission. XML can explicitly clear values:
`<VirtualFunction index="0" name="C::Run" clear="parameters"/>`. Collection replacement
can also be selected through field policy. `respectOmitted: false` uses model defaults for omitted fields.

`backfillDeclarations`, `synchronizePrimary`, and `synchronizeSecondary` enable inherited
vtable reconciliation independently; each defaults to true. Patch-provided slots retain
priority during inherited declaration propagation.

## Outputs

`outputs.executable` selects the input used by executable exports and `--exe`.
`xml` defaults to `build/metadata/merged.xml`, `headers` to `build/include`, `supportHeaders` to `[]`,
`generatedFor` to `SDK`, and `importerCategory` to `/SymbolWeave`. The generic runtime header is bundled. Optional project support headers or trees
are copied in list order before generated headers are written.

`ignoreX86CallingConventions` defaults to `false`. Generated declarations and native
function-pointer types preserve `CDECL`, `STDCALL`, `THISCALL`, and `FASTCALL` through
portable `SDK_*` macros. These macros expand to the corresponding convention on x86
and to nothing on other architectures. Variadic functions use `CDECL`.
Set `"ignoreX86CallingConventions": true` under `outputs` to omit these annotations
entirely when generating headers exclusively for a 64-bit target. This leaves receiver
arguments and the calling-convention metadata in XML unchanged.

`pdbModule` optionally overrides the PDB module name (otherwise the executable stem).
`signatureLabel` optionally overrides the executable label in signature diagnostics
(otherwise the executable filename). Neither setting contains a built-in game name.

`signatures` and `pdb` default to false. `signatureDirectory` and `pdbDirectory` default
to `build`. Signature files retain executable version/hash binding, per-pattern match
counts, entity bindings, and diagnostics. PDBs use the executable's CodeView identity.

`dependencies` contains rules with `typeRegex`, `bodyRegex`, `header`, and `removeForward`
(default true). Matching types select an external header and optionally suppress generated
forward declarations. Matching body text can request an additional include. This covers
external C APIs, library templates, and support-header mappings without hardcoded names.

## BSim and vtable checking

`bsim.enabled` defaults to false. `source` and `target` identify Ghidra inputs.
`database`, `databaseName`, `template`, and `trackCallgraph` configure the database.
`maxMatches`, `similarity`, and `significance` control the nearest-function query.
`excludeExternal`, `excludeLibrary`, and `minReferences` filter target functions.
`mapInput` and `excludeUnitRegex` filter matches using source map compilation units.
`output` selects the XML report, ordered descending by numeric `sortBy`.
BSim produces a candidate report rather than modifying merged metadata. A custom matcher can consume candidate data when desired.

`checker.directory`, `workers`, `timeoutSeconds`, and optional `vcvars` control MSVC.
`typeReplacements` maps regexes to replacement strings in checker-only header copies.
`opaqueNamespaces` replaces qualified library types, including nested templates, with
stable opaque template types. `removeIncludeRegex` removes unavailable dependency includes
in the checker copy. Actual generated headers remain untouched.
