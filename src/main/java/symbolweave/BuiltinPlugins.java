package symbolweave;

import com.google.gson.*;

import symbolweave.containers.*;

import java.util.*;
import java.util.regex.*;

/** Generic extractors and matching operations; game policy belongs in configuration. */
public final class BuiltinPlugins {
    public static List<SdkPlugin> all() {
        return List.of(
                new Functions(),
                new MapSymbols(),
                new Rtti(),
                new Declarations(),
                new FunctionMatching());
    }

    private static final class Functions implements SdkPlugin {
        public String name() {
            return "functions";
        }

        public void validate(JsonObject o) {
            Options.check(o, name(), Set.of());
        }

        public FileContainer extract(
                ProjectConfig c, ProjectConfig.Input i, GhidraWorkspace w, JsonObject o) {
            return new PcFunctionLoader().loadFromFunctions(w);
        }
    }

    private static final class MapSymbols implements SdkPlugin {
        public String name() {
            return "map";
        }

        public void validate(JsonObject o) {
            SymbolMapLoader.validate(o);
        }

        public FileContainer extract(
                ProjectConfig c, ProjectConfig.Input i, GhidraWorkspace w, JsonObject o)
                throws Exception {
            return new AbiClassLoader(o)
                    .loadFromMap(
                            new SymbolMapLoader(c.path(Options.required(o, "file")), o).entries(),
                            w);
        }
    }

    private static final class Rtti implements SdkPlugin {
        public String name() {
            return "rtti";
        }

        public void validate(JsonObject o) {
            Options.check(
                    o,
                    name(),
                    Set.of(
                            "pureVirtualRegex",
                            "followPureVirtualThunks",
                            "vtableSymbolRegex",
                            "baseArraySymbolRegex",
                            "rttiPointerSize",
                            "baseArraySkip",
                            "typeNameOffset",
                            "typeNameStripRegex",
                            "rttiRelative"));
        }

        public FileContainer extract(
                ProjectConfig c, ProjectConfig.Input i, GhidraWorkspace w, JsonObject o)
                throws Exception {
            return new AbiClassLoader(o).loadFromRTTI(w);
        }
    }

    private static final class Declarations implements SdkPlugin {
        public String name() {
            return "declarations";
        }

        public void validate(JsonObject o) {
            Options.check(
                    o,
                    name(),
                    Set.of(
                            "classRegex",
                            "namePattern",
                            "nameReplacement",
                            "secondaryHeaderSlots",
                            "retainUnmatchedSlots",
                            "retainLooseFunctions",
                            "retainClassFunctions",
                            "returnType",
                            "callingConvention",
                            "slotOffset",
                            "ambiguity",
                            "fields",
                            "classFields"));
            Pattern.compile(Options.string(o, "classRegex", ".*"));
            Pattern.compile(Options.string(o, "namePattern", "(?!)"));
            if (!Set.of("error", "first", "skip").contains(Options.string(o, "ambiguity", "error")))
                throw new IllegalArgumentException(
                        "declarations.ambiguity must be error, first, or skip");
        }

        public void match(
                ProjectConfig c, ProjectConfig.Match rule, Map<String, FileContainer> containers) {
            var source = containers.get(rule.source);
            var target = containers.get(rule.target);
            var o = rule.options;
            Pattern include = Pattern.compile(Options.string(o, "classRegex", ".*"));
            Pattern normalize = Pattern.compile(Options.string(o, "namePattern", "(?!)"));
            String replacement = Options.string(o, "nameReplacement", "");
            for (ClassContainer dest : target.getClasses()) {
                String key = normalize.matcher(dest.getName().toString()).replaceAll(replacement);
                if (!include.matcher(key).matches()) continue;
                var candidates =
                        source.getClasses().stream()
                                .filter(
                                        s ->
                                                normalize
                                                        .matcher(s.getName().toString())
                                                        .replaceAll(replacement)
                                                        .equals(key))
                                .toList();
                if (candidates.size() > 1) {
                    String ambiguity = Options.string(o, "ambiguity", "error");
                    if (ambiguity.equals("error"))
                        throw new IllegalArgumentException("Ambiguous class match: " + key);
                    if (ambiguity.equals("skip")) continue;
                }
                Map<Integer, FunctionContainer> output =
                        Options.bool(o, "retainUnmatchedSlots", true)
                                ? new HashMap<>(dest.getVirtualFunctions())
                                : new HashMap<>();
                if (!candidates.isEmpty()) {
                    Map<Integer, FunctionContainer> slots =
                            remap(
                                    candidates.getFirst().getVirtualFunctions(),
                                    dest.getVtableCount(),
                                    Options.integer(o, "secondaryHeaderSlots", 0));
                    int logical =
                            Math.max(
                                    dest.getVtableCount(),
                                    dest.getVirtualFunctions().keySet().stream()
                                            .mapToInt(i -> i + 1)
                                            .max()
                                            .orElse(0));
                    for (var slot : slots.entrySet()) {
                        int index = slot.getKey() + Options.integer(o, "slotOffset", 0);
                        if (logical > dest.getVtableCount() && index >= logical) continue;
                        FunctionContainer from = slot.getValue();
                        FunctionContainer to = dest.getVirtualFunctions().get(index);
                        if (from == null) {
                            if (to != null) output.put(index, to);
                            else output.put(index, null);
                            continue;
                        }
                        var merged = ConfigurableMerger.copyFunction(from);
                        merged.setAddress(to == null ? 0 : to.getAddress());
                        merged.setImplementationAddress(
                                to == null ? 0 : to.getImplementationAddress());
                        merged.clearPureVirtualValue();
                        if (to != null && to.hasPureVirtualValue())
                            merged.setPureVirtual(to.isPureVirtual());
                        merged.setVtableOwner(to == null ? null : to.getVtableOwner());
                        if (o.has("returnType"))
                            merged.setReturnType(
                                    new TypeContainer(
                                            Util.NamespacedString.parse(
                                                    o.get("returnType").getAsString())));
                        if (o.has("callingConvention"))
                            merged.setCallingConvention(
                                    FunctionContainer.CallingConvention.valueOf(
                                            o.get("callingConvention").getAsString()));
                        if (o.has("fields"))
                            transfer(merged, from, to, o.getAsJsonObject("fields"));
                        output.put(index, merged);
                    }
                }
                if (!candidates.isEmpty() && o.has("classFields"))
                    transfer(dest, candidates.getFirst(), dest, o.getAsJsonObject("classFields"));
                dest.setVirtualFunctions(output);
                if (!Options.bool(o, "retainClassFunctions", true)) dest.getFunctions().clear();
            }
            if (!Options.bool(o, "retainLooseFunctions", true)) target.getLooseFunctions().clear();
        }
    }

    private static final class FunctionMatching implements SdkPlugin {
        public String name() {
            return "function-match";
        }

        public void validate(JsonObject o) {
            Options.check(
                    o,
                    name(),
                    Set.of(
                            "sourceKey",
                            "targetKey",
                            "namePattern",
                            "nameReplacement",
                            "sourceRegex",
                            "targetRegex",
                            "ambiguity",
                            "fields"));
            Pattern.compile(Options.string(o, "sourceRegex", ".*"));
            Pattern.compile(Options.string(o, "targetRegex", ".*"));
            Pattern.compile(Options.string(o, "namePattern", "(?!)"));
            if (!Set.of("error", "first", "skip").contains(Options.string(o, "ambiguity", "error")))
                throw new IllegalArgumentException(
                        "function-match.ambiguity must be error, first, or skip");
        }

        public void match(
                ProjectConfig c, ProjectConfig.Match rule, Map<String, FileContainer> containers) {
            JsonObject o = rule.options;
            var source = functions(containers.get(rule.source));
            var target = functions(containers.get(rule.target));
            Pattern normalization = Pattern.compile(Options.string(o, "namePattern", "(?!)"));
            String replacement = Options.string(o, "nameReplacement", "");
            Map<String, List<FunctionContainer>> indexed = new LinkedHashMap<>();
            for (var f : source)
                if (f.getName().toString().matches(Options.string(o, "sourceRegex", ".*"))) {
                    String key =
                            normalization
                                    .matcher(
                                            ConfigurableMerger.identity(
                                                    f, Options.string(o, "sourceKey", "name")))
                                    .replaceAll(replacement);
                    indexed.computeIfAbsent(key, k -> new ArrayList<>()).add(f);
                }
            for (var f : target)
                if (f.getName().toString().matches(Options.string(o, "targetRegex", ".*"))) {
                    String key =
                            normalization
                                    .matcher(
                                            ConfigurableMerger.identity(
                                                    f, Options.string(o, "targetKey", "name")))
                                    .replaceAll(replacement);
                    var matches = indexed.getOrDefault(key, List.of());
                    if (matches.isEmpty()) continue;
                    if (matches.size() > 1) {
                        String policy = Options.string(o, "ambiguity", "error");
                        if (policy.equals("skip")) continue;
                        if (policy.equals("error"))
                            throw new IllegalArgumentException("Ambiguous function match: " + key);
                    }
                    JsonObject fields =
                            o.has("fields")
                                    ? o.getAsJsonObject("fields")
                                    : JsonParser.parseString(
                                                    "{\"name\":\"$source.name\",\"parameters\":\"$source.parameters\"}")
                                            .getAsJsonObject();
                    transfer(f, matches.getFirst(), ConfigurableMerger.copyFunction(f), fields);
                }
        }

        private List<FunctionContainer> functions(FileContainer file) {
            List<FunctionContainer> result = new ArrayList<>(file.getLooseFunctions());
            for (var cls : file.getClasses()) {
                result.addAll(cls.getFunctions());
                for (var fn : cls.getVirtualFunctions().values()) if (fn != null) result.add(fn);
            }
            return result;
        }
    }

    private static void transfer(
            Object destination, Object source, Object target, JsonObject fields) {
        for (var field : fields.entrySet())
            try {
                String name = field.getKey();
                String setter = "set" + Character.toUpperCase(name.charAt(0)) + name.substring(1);
                var method =
                        Arrays.stream(destination.getClass().getMethods())
                                .filter(
                                        m ->
                                                m.getName().equals(setter)
                                                        && m.getParameterCount() == 1)
                                .findFirst()
                                .orElseThrow(
                                        () ->
                                                new IllegalArgumentException(
                                                        "Unknown transfer field: " + name));
                JsonElement configured = field.getValue();
                Object value;
                String expression =
                        configured.isJsonPrimitive() && configured.getAsJsonPrimitive().isString()
                                ? configured.getAsString()
                                : "";
                if (expression.startsWith("$source.") || expression.startsWith("$target.")) {
                    Object owner = expression.startsWith("$source.") ? source : target;
                    String property = expression.substring(expression.indexOf('.') + 1);
                    String suffix =
                            Character.toUpperCase(property.charAt(0)) + property.substring(1);
                    java.lang.reflect.Method getter;
                    try {
                        getter = destination.getClass().getMethod("get" + suffix);
                    } catch (NoSuchMethodException e) {
                        getter = destination.getClass().getMethod("is" + suffix);
                    }
                    value = owner == null ? null : getter.invoke(owner);
                    if (value == null && method.getParameterTypes()[0].isPrimitive())
                        value =
                                method.getParameterTypes()[0] == boolean.class
                                        ? false
                                        : method.getParameterTypes()[0] == long.class ? 0L : 0;
                } else if (method.getParameterTypes()[0] == Util.NamespacedString.class)
                    value = Util.NamespacedString.parse(configured.getAsString());
                else if (method.getParameterTypes()[0] == TypeContainer.class
                        && configured.isJsonPrimitive())
                    value =
                            new TypeContainer(
                                    Util.NamespacedString.parse(configured.getAsString()));
                else
                    value =
                            ProjectConfig.JSON.fromJson(
                                    configured, method.getGenericParameterTypes()[0]);
                method.invoke(destination, value);
                XmlPresence.supplied(destination, name);
            } catch (ReflectiveOperationException e) {
                throw new IllegalArgumentException("Invalid transfer for " + field.getKey(), e);
            }
    }

    static Map<Integer, FunctionContainer> remap(
            Map<Integer, FunctionContainer> functions, int primary, int header) {
        Map<Integer, FunctionContainer> output = new HashMap<>();
        int removed = 0;
        int max = functions.keySet().stream().mapToInt(Integer::intValue).max().orElse(-1);
        for (int i = 0; i <= max; i++) {
            boolean isHeader =
                    header > 0
                            && i >= primary
                            && i > 0
                            && i + header <= max
                            && functions.get(i - 1) != null
                            && functions.get(i + header) != null;
            for (int n = 0; n < header && isHeader; n++)
                isHeader = functions.containsKey(i + n) && functions.get(i + n) == null;
            if (isHeader) {
                removed += header;
                i += header - 1;
                continue;
            }
            if (functions.containsKey(i)) output.put(i - removed, functions.get(i));
        }
        return output;
    }
}
