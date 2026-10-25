package symbolweave;

import com.google.gson.*;

import java.lang.reflect.*;
import java.nio.file.*;
import java.util.*;

/** Versioned configuration. All filesystem paths are relative to the selected file. */
public final class ProjectConfig {
    public int version = 1;
    public String ghidraJar = "${GHIDRA_JAR}";
    public List<String> pluginJars = new ArrayList<>();
    public List<Input> inputs = new ArrayList<>();
    public List<Match> matching = new ArrayList<>();
    public Merge merge = new Merge();
    public Outputs outputs = new Outputs();
    public Checker checker = new Checker();
    public Bsim bsim = new Bsim();
    public boolean analyze = true;
    private transient Path file;
    public static final Gson JSON =
            new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();

    public static final class Input {
        public String id;
        public String executable;
        public String xml;
        public String projectName;
        public String workspace;
        public boolean managedCache = true;
        public String programFolder = "/";
        public String programName;
        public String language;
        public String compiler;
        public String loader;
        public Map<String, String> loaderOptions = new LinkedHashMap<>();
        public Map<String, JsonElement> analyzers = new LinkedHashMap<>();
        public List<Script> scripts = new ArrayList<>();
        public List<Extractor> extractors = new ArrayList<>();
    }

    public static final class Script {
        public String name;
        public List<String> args = new ArrayList<>();
    }

    public static final class Extractor {
        public String plugin = "functions";
        public JsonObject options = new JsonObject();
    }

    public static final class Match {
        public String source;
        public String target;
        public String plugin = "declarations";
        public JsonObject options = new JsonObject();
    }

    public static final class Merge {
        public List<String> sources = new ArrayList<>();
        public List<Patch> patches = new ArrayList<>();
        public String classKey = "name";
        public String functionKey = "name,address";
        public String memberKey = "name";
        public String duplicateFunctions = "merge";
        public String defaultPolicy = "nonempty";
        public Map<String, String> fields = new LinkedHashMap<>();
        public Map<String, Policy> sourcePolicies = new LinkedHashMap<>();
        public boolean backfillDeclarations = true;
        public boolean synchronizePrimary = true;
        public boolean synchronizeSecondary = true;
        public boolean respectOmitted = true;
        public boolean stripAddresses = false;
    }

    public static final class Policy {
        public String defaultPolicy;
        public String duplicateFunctions;
        public Boolean respectOmitted;
        public Boolean stripAddresses;
        public Map<String, String> fields = new LinkedHashMap<>();
    }

    public static final class Patch {
        public String directory = "metadata/overrides";
        public String glob = "*.xml";
        public boolean recursive = false;
        public boolean required = false;
        public String order = "ascending";
        public List<String> files = new ArrayList<>();
        public boolean headerFromFilename = true;
        public Policy policy = new Policy();
    }

    public static final class Outputs {
        public String executable;
        public String xml = "build/metadata/merged.xml";
        public String headers = "build/include";
        public List<String> supportHeaders = new ArrayList<>();
        public boolean ignoreX86CallingConventions = false;
        public boolean signatures = false;
        public boolean pdb = false;
        public String signatureDirectory = "build";
        public String pdbDirectory = "build";
        public String pdbModule;
        public String signatureLabel;
        public String generatedFor = "SDK";
        public String importerCategory = "/SymbolWeave";
        public List<Dependency> dependencies = new ArrayList<>();
    }

    public static final class Dependency {
        public String typeRegex;
        public String bodyRegex;
        public String header;
        public boolean removeForward = true;
    }

    public static final class Checker {
        public String directory = ".cache/vtable-check";
        public int workers = 8;
        public int timeoutSeconds = 60;
        public String vcvars;
        public Map<String, String> typeReplacements = new LinkedHashMap<>();
        public List<String> opaqueNamespaces = new ArrayList<>();
        public List<String> removeIncludeRegex = new ArrayList<>();
    }

    public static final class Bsim {
        public boolean enabled = false;
        public String source;
        public String target;
        public String database = ".cache/bsim/database";
        public String databaseName = "sdk";
        public String template = "medium_nosize";
        public boolean trackCallgraph = true;
        public int maxMatches = 1;
        public double similarity = 0.7;
        public double significance = 0;
        public boolean excludeExternal = true;
        public boolean excludeLibrary = true;
        public int minReferences = 1;
        public String mapInput;
        public String excludeUnitRegex = "(?!)";
        public String output = "build/metadata/bsim.xml";
        public String sortBy = "significance";
    }

    public Path file() {
        return file;
    }

    public Path path(String value) {
        if (value == null || value.isBlank())
            throw new IllegalArgumentException("Missing path in " + file);
        var m = java.util.regex.Pattern.compile("\\$\\{([^}]+)}").matcher(value);
        var s = new StringBuilder();
        while (m.find()) {
            String env = System.getenv(m.group(1));
            if (env == null)
                throw new IllegalArgumentException(
                        "Environment variable is not set: " + m.group(1));
            m.appendReplacement(s, java.util.regex.Matcher.quoteReplacement(env));
        }
        m.appendTail(s);
        return file.getParent().resolve(s.toString()).toAbsolutePath().normalize();
    }

    public Input input(String id) {
        return inputs.stream()
                .filter(i -> Objects.equals(i.id, id))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unknown input: " + id));
    }

    public static Path discover(Path start) {
        for (Path dir = start.toAbsolutePath().normalize(); dir != null; dir = dir.getParent()) {
            Path candidate = dir.resolve("config.json");
            if (Files.isRegularFile(candidate)) return candidate;
        }
        throw new IllegalArgumentException(
                "No config.json found from " + start + "; use -c <file>");
    }

    public static ProjectConfig load(Path file) throws Exception {
        JsonObject root;
        try (var reader = Files.newBufferedReader(file)) {
            root = JsonParser.parseReader(reader).getAsJsonObject();
        }
        if (!root.has("version")) throw new IllegalArgumentException("$.version is required");
        checkObject(root, ProjectConfig.class, "$", Set.of("$schema"));
        ProjectConfig config = JSON.fromJson(root, ProjectConfig.class);
        config.file = file.toAbsolutePath().normalize();
        config.validate();
        return config;
    }

    private static void checkObject(
            JsonObject object, Class<?> type, String location, Set<String> ignored) {
        for (var entry : object.entrySet()) {
            if (ignored.contains(entry.getKey())) continue;
            try {
                Field field = type.getField(entry.getKey());
                if (Modifier.isStatic(field.getModifiers())) throw new NoSuchFieldException();
                checkValue(
                        entry.getValue(), field.getGenericType(), location + "." + entry.getKey());
            } catch (NoSuchFieldException e) {
                throw new IllegalArgumentException(
                        "Unknown config setting: " + location + "." + entry.getKey());
            }
        }
    }

    private static void checkValue(JsonElement value, Type type, String location) {
        if (value == null || value.isJsonNull())
            throw new IllegalArgumentException(location + " cannot be null");
        if (type instanceof ParameterizedType parameterized) {
            if (parameterized.getRawType() == List.class) {
                if (!value.isJsonArray())
                    throw new IllegalArgumentException(location + " must be an array");
                int index = 0;
                for (var child : value.getAsJsonArray())
                    checkValue(
                            child,
                            parameterized.getActualTypeArguments()[0],
                            location + "[" + (index++) + "]");
            } else {
                if (!value.isJsonObject())
                    throw new IllegalArgumentException(location + " must be an object");
                for (var child : value.getAsJsonObject().entrySet())
                    checkValue(
                            child.getValue(),
                            parameterized.getActualTypeArguments()[1],
                            location + "." + child.getKey());
            }
            return;
        }
        Class<?> expected = (Class<?>) type;
        if (expected == JsonElement.class) return;
        if (expected == JsonObject.class) {
            if (!value.isJsonObject())
                throw new IllegalArgumentException(location + " must be an object");
            return;
        }
        if (expected.getEnclosingClass() == ProjectConfig.class) {
            if (!value.isJsonObject())
                throw new IllegalArgumentException(location + " must be an object");
            checkObject(value.getAsJsonObject(), expected, location, Set.of());
            return;
        }
        if (expected == boolean.class || expected == Boolean.class) {
            if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isBoolean())
                throw new IllegalArgumentException(location + " must be boolean");
        } else if (expected == int.class || expected == double.class) {
            if (!value.isJsonPrimitive()
                    || !value.getAsJsonPrimitive().isNumber()
                    || !Double.isFinite(value.getAsDouble()))
                throw new IllegalArgumentException(location + " must be numeric");
            if (expected == int.class
                    && (value.getAsDouble() != Math.rint(value.getAsDouble())
                            || value.getAsDouble() < Integer.MIN_VALUE
                            || value.getAsDouble() > Integer.MAX_VALUE))
                throw new IllegalArgumentException(location + " must be an integer");
        } else if (expected == String.class
                && (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()))
            throw new IllegalArgumentException(location + " must be a string");
    }

    void validate() {
        if (version != 1) throw new IllegalArgumentException("$.version: supported version is 1");
        if (inputs.isEmpty())
            throw new IllegalArgumentException("$.inputs must contain at least one input");
        Set<String> ids = new HashSet<>();
        for (Input input : inputs) {
            if (input.id == null || input.id.isBlank() || !ids.add(input.id))
                throw new IllegalArgumentException(
                        "$.inputs: missing or duplicate id: " + input.id);
            if (input.xml == null)
                throw new IllegalArgumentException("$.inputs[" + input.id + "].xml is required");
            if (!input.extractors.isEmpty() && input.executable == null)
                throw new IllegalArgumentException(
                        "$.inputs[" + input.id + "].executable is required for extraction");
            if (input.workspace == null) input.workspace = ".cache/" + input.id;
            if (input.projectName == null) input.projectName = input.id;
            if (!input.projectName.matches("[A-Za-z0-9_][A-Za-z0-9_.-]*"))
                throw new IllegalArgumentException(
                        "Invalid Ghidra project name for " + input.id + ": " + input.projectName);
            for (var setting : input.analyzers.entrySet())
                if (!setting.getValue().isJsonPrimitive())
                    throw new IllegalArgumentException(
                            "Analyzer option must be a primitive value: " + setting.getKey());
        }
        if (merge.sources.isEmpty()) inputs.forEach(i -> merge.sources.add(i.id));
        merge.sources.forEach(this::input);
        merge.sourcePolicies.forEach(
                (id, policy) -> {
                    input(id);
                    ConfigurableMerger.validate(ConfigurableMerger.policy(merge, policy));
                });
        merge.patches.forEach(
                patch ->
                        ConfigurableMerger.validate(
                                ConfigurableMerger.policy(merge, patch.policy)));
        matching.forEach(
                m -> {
                    input(m.source);
                    input(m.target);
                });
        if (bsim.enabled) {
            input(bsim.source);
            input(bsim.target);
        }
        if (checker.workers < 1 || checker.timeoutSeconds < 1)
            throw new IllegalArgumentException(
                    "$.checker workers and timeoutSeconds must be positive");
        if (bsim.maxMatches < 1
                || bsim.similarity < 0
                || bsim.similarity > 1
                || bsim.significance < 0)
            throw new IllegalArgumentException("$.bsim: invalid query limits");
        if (outputs.executable != null) input(outputs.executable);
        if ((outputs.pdb || outputs.signatures) && outputs.executable == null)
            throw new IllegalArgumentException(
                    "$.outputs.executable is required for signatures/PDB");
        if (!Set.of("similarity", "significance", "size", "from", "to").contains(bsim.sortBy))
            throw new IllegalArgumentException("$.bsim.sortBy: unsupported field");
        if (bsim.mapInput != null) input(bsim.mapInput);
        for (Dependency dependency : outputs.dependencies) {
            if (dependency.typeRegex != null) java.util.regex.Pattern.compile(dependency.typeRegex);
            if (dependency.bodyRegex != null) java.util.regex.Pattern.compile(dependency.bodyRegex);
            if (dependency.typeRegex == null && dependency.bodyRegex == null)
                throw new IllegalArgumentException(
                        "$.outputs.dependencies requires typeRegex or bodyRegex");
        }
        java.util.regex.Pattern.compile(bsim.excludeUnitRegex);
        checker.typeReplacements.keySet().forEach(java.util.regex.Pattern::compile);
        checker.removeIncludeRegex.forEach(java.util.regex.Pattern::compile);
        ConfigurableMerger.validate(merge);
        for (Patch patch : merge.patches)
            if (!List.of("ascending", "descending", "listed").contains(patch.order))
                throw new IllegalArgumentException("$.merge.patches.order: " + patch.order);
    }
}
