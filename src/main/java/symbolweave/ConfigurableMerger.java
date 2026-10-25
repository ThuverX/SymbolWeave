package symbolweave;

import symbolweave.containers.*;

import java.lang.reflect.*;
import java.util.*;

/** Field-level precedence shared by analyzed inputs and patches. */
public final class ConfigurableMerger {
    private static final Set<String> POLICIES =
            Set.of("nonempty", "replace", "keep", "append", "error");
    private static final Map<String, Class<?>> TYPES =
            Map.of(
                    "class",
                    ClassContainer.class,
                    "function",
                    FunctionContainer.class,
                    "member",
                    MemberContainer.class);

    public static void validate(ProjectConfig.Merge config) {
        if (!Set.of("merge", "append", "error").contains(config.duplicateFunctions))
            throw new IllegalArgumentException(
                    "$.merge.duplicateFunctions must be merge, append, or error");
        if (!POLICIES.contains(config.defaultPolicy))
            throw new IllegalArgumentException("$.merge.defaultPolicy: " + config.defaultPolicy);
        config.fields.forEach(
                (key, value) -> {
                    String[] parts = key.split("\\.");
                    if (parts.length != 2
                            || !TYPES.containsKey(parts[0])
                            || !properties(TYPES.get(parts[0])).containsKey(parts[1]))
                        throw new IllegalArgumentException("Unknown merge field: " + key);
                    if (!POLICIES.contains(value))
                        throw new IllegalArgumentException(
                                "Unknown merge policy for " + key + ": " + value);
                });
        validateKey(ClassContainer.class, config.classKey);
        validateKey(FunctionContainer.class, config.functionKey);
        validateKey(MemberContainer.class, config.memberKey);
    }

    private static void validateKey(Class<?> type, String key) {
        for (String part : key.split(","))
            if (!properties(type).containsKey(part.trim()))
                throw new IllegalArgumentException(
                        "Unknown identity field " + type.getSimpleName() + "." + part);
    }

    private static Map<String, Method> properties(Class<?> type) {
        Map<String, Method> methods = new TreeMap<>();
        for (Method method : type.getMethods()) {
            String name = method.getName();
            if (method.getParameterCount() != 0 || name.equals("getClass")) continue;
            String property =
                    name.startsWith("get")
                            ? name.substring(3)
                            : name.startsWith("is") ? name.substring(2) : "";
            if (!property.isEmpty()) {
                try {
                    type.getMethod("set" + property, method.getReturnType());
                } catch (NoSuchMethodException e) {
                    continue;
                }
                methods.put(
                        Character.toLowerCase(property.charAt(0)) + property.substring(1), method);
            }
        }
        return methods;
    }

    static String identity(Object object, String fields) {
        StringJoiner result = new StringJoiner("\u0000");
        try {
            for (String field : fields.split(",")) {
                Object value = properties(object.getClass()).get(field.trim()).invoke(object);
                result.add(
                        value == null
                                        || value instanceof String
                                        || value instanceof Number
                                        || value instanceof Boolean
                                        || value instanceof Enum<?>
                                        || value instanceof Util.NamespacedString
                                ? String.valueOf(value)
                                : ProjectConfig.JSON.toJson(value));
            }
        } catch (ReflectiveOperationException e) {
            throw new IllegalArgumentException("Cannot read identity " + fields, e);
        }
        return result.toString();
    }

    /** Merge an ordered set of metadata layers using the default policy. */
    public static FileContainer merge(List<FileContainer> containers) {
        List<Layer> layers = new ArrayList<>();
        for (int i = 0; i < containers.size(); i++) layers.add(new Layer(containers.get(i), i > 0));
        return merge(layers, new ProjectConfig.Merge());
    }

    public record Layer(FileContainer container, boolean patch, ProjectConfig.Policy policy) {
        public Layer(FileContainer container, boolean patch) {
            this(container, patch, null);
        }
    }

    static ProjectConfig.Merge policy(ProjectConfig.Merge base, ProjectConfig.Policy override) {
        if (override == null) return base;
        ProjectConfig.Merge result = new ProjectConfig.Merge();
        result.classKey = base.classKey;
        result.functionKey = base.functionKey;
        result.memberKey = base.memberKey;
        result.defaultPolicy =
                override.defaultPolicy == null ? base.defaultPolicy : override.defaultPolicy;
        result.duplicateFunctions =
                override.duplicateFunctions == null
                        ? base.duplicateFunctions
                        : override.duplicateFunctions;
        result.respectOmitted =
                override.respectOmitted == null ? base.respectOmitted : override.respectOmitted;
        result.fields.putAll(base.fields);
        result.fields.putAll(override.fields);
        return result;
    }

    public static FileContainer merge(List<Layer> layers, ProjectConfig.Merge settings) {
        FileContainer result = new FileContainer("Merged");
        Map<Util.NamespacedString, Set<Integer>> patched = new HashMap<>();
        for (Layer layer : layers) {
            ProjectConfig.Merge layerSettings = policy(settings, layer.policy());
            FileContainer source = layer.container();
            mergeFunctions(result.getLooseFunctions(), source.getLooseFunctions(), layerSettings);
            for (ClassContainer incoming : source.getClasses()) {
                if (layer.patch())
                    patched.computeIfAbsent(incoming.getName(), ignored -> new HashSet<>())
                            .addAll(incoming.getVirtualFunctions().keySet());
                ClassContainer existing =
                        result.getClasses().stream()
                                .filter(
                                        c ->
                                                identity(c, layerSettings.classKey)
                                                        .equals(
                                                                identity(
                                                                        incoming,
                                                                        layerSettings.classKey)))
                                .findFirst()
                                .orElse(null);
                if (existing == null) {
                    result.getClasses().add(copyClass(incoming));
                    continue;
                }
                mergeFields(
                        existing,
                        incoming,
                        "class",
                        Set.of("virtualFunctions", "functions", "members"),
                        layerSettings);
                if (collection(
                        existing,
                        incoming,
                        "functions",
                        existing.getFunctions(),
                        incoming.getFunctions(),
                        layerSettings))
                    mergeFunctions(existing.getFunctions(), incoming.getFunctions(), layerSettings);
                boolean mergeVirtuals =
                        collection(
                                existing,
                                incoming,
                                "virtualFunctions",
                                existing.getVirtualFunctions(),
                                incoming.getVirtualFunctions(),
                                layerSettings);
                for (var slot :
                        (mergeVirtuals
                                        ? incoming.getVirtualFunctions()
                                        : Map.<Integer, FunctionContainer>of())
                                .entrySet()) {
                    FunctionContainer current = existing.getVirtualFunctions().get(slot.getKey());
                    if (current == null || slot.getValue() == null) {
                        String policy =
                                layerSettings.fields.getOrDefault(
                                        "class.virtualFunctions", layerSettings.defaultPolicy);
                        if (!policy.equals("keep")
                                && (slot.getValue() != null || policy.equals("replace")))
                            existing.getVirtualFunctions()
                                    .put(
                                            slot.getKey(),
                                            slot.getValue() == null
                                                    ? null
                                                    : copyFunction(slot.getValue()));
                    } else
                        mergeFields(current, slot.getValue(), "function", Set.of(), layerSettings);
                }
                boolean mergeMembers =
                        collection(
                                existing,
                                incoming,
                                "members",
                                existing.getMembers(),
                                incoming.getMembers(),
                                layerSettings);
                for (MemberContainer member :
                        (mergeMembers ? incoming.getMembers() : List.<MemberContainer>of())) {
                    var old =
                            existing.getMembers().stream()
                                    .filter(
                                            m ->
                                                    identity(m, layerSettings.memberKey)
                                                            .equals(
                                                                    identity(
                                                                            member,
                                                                            layerSettings
                                                                                    .memberKey)))
                                    .findFirst()
                                    .orElse(null);
                    if (old == null) existing.getMembers().add(copyMember(member));
                    else mergeFields(old, member, "member", Set.of(), layerSettings);
                }
            }
        }
        InheritanceResolver.resolve(result, patched, settings);
        return result;
    }

    private static void mergeFunctions(
            List<FunctionContainer> output,
            List<FunctionContainer> input,
            ProjectConfig.Merge settings) {
        for (FunctionContainer function : input) {
            FunctionContainer existing =
                    output.stream()
                            .filter(
                                    f ->
                                            identity(f, settings.functionKey)
                                                    .equals(
                                                            identity(
                                                                    function,
                                                                    settings.functionKey)))
                            .findFirst()
                            .orElse(null);
            if (existing != null && settings.duplicateFunctions.equals("error"))
                throw new IllegalArgumentException("Duplicate function: " + function.getName());
            if (existing == null || settings.duplicateFunctions.equals("append"))
                output.add(copyFunction(function));
            else mergeFields(existing, function, "function", Set.of(), settings);
        }
    }

    private static boolean collection(
            Object target,
            Object source,
            String field,
            Object current,
            Object incoming,
            ProjectConfig.Merge settings) {
        if (settings.respectOmitted && XmlPresence.omitted(source, field)) return false;
        String policy = settings.fields.getOrDefault("class." + field, settings.defaultPolicy);
        if (policy.equals("keep")) return false;
        if (policy.equals("error")
                && !empty(current)
                && !empty(incoming)
                && !ProjectConfig.JSON.toJson(current).equals(ProjectConfig.JSON.toJson(incoming)))
            throw new IllegalArgumentException("Merge conflict: class." + field);
        if (policy.equals("replace") || XmlPresence.cleared(source, field)) {
            if (current instanceof Collection<?> c) c.clear();
            else if (current instanceof Map<?, ?> m) m.clear();
        }
        return !XmlPresence.cleared(source, field);
    }

    private static MemberContainer copyMember(MemberContainer source) {
        MemberContainer member =
                new MemberContainer(
                        source.getName(), source.getType(), source.getValue(), source.isStatic());
        member.setArraySize(source.getArraySize());
        member.setSize(source.getSize());
        member.setOffset(source.getOffset());
        member.setAddress(source.getAddress());
        XmlPresence.copy(source, member);
        return member;
    }

    static ClassContainer copyClass(ClassContainer c) {
        Map<Integer, FunctionContainer> virtuals = new HashMap<>();
        c.getVirtualFunctions()
                .forEach((i, f) -> virtuals.put(i, f == null ? null : copyFunction(f)));
        return new ClassContainer(
                c.getName(),
                c.getVtableAddress(),
                c.getVtableCount(),
                virtuals,
                new ArrayList<>(
                        c.getFunctions().stream().map(ConfigurableMerger::copyFunction).toList()),
                new ArrayList<>(c.getParents()),
                new ArrayList<>(
                        c.getMembers().stream().map(ConfigurableMerger::copyMember).toList()));
    }

    static FunctionContainer copyFunction(FunctionContainer f) {
        FunctionContainer copy =
                new FunctionContainer(
                        f.getAddress(),
                        f.getName(),
                        f.getCallingConvention(),
                        f.getReturnType(),
                        new HashMap<>(f.getParameters()),
                        f.isOverride(),
                        f.isStatic());
        copy.setVarargs(f.isVarargs());
        copy.setImplementationAddress(f.getImplementationAddress());
        copy.setVtableOwner(f.getVtableOwner());
        copy.setHeaderFile(f.getHeaderFile());
        if (f.hasPureVirtualValue()) copy.setPureVirtual(f.isPureVirtual());
        XmlPresence.copy(f, copy);
        return copy;
    }

    private static boolean empty(Object value) {
        return value == null
                || value instanceof Number n && n.doubleValue() == 0
                || value instanceof String s && s.isEmpty()
                || value instanceof Collection<?> c && c.isEmpty()
                || value instanceof Map<?, ?> m && m.isEmpty()
                || value instanceof Util.NamespacedString n
                        && (n.toString().isEmpty() || n.toString().equals("undefined"));
    }

    static void mergeFields(
            Object target,
            Object source,
            String kind,
            Set<String> skip,
            ProjectConfig.Merge settings) {
        for (var property : properties(source.getClass()).entrySet()) {
            String name = property.getKey();
            if (skip.contains(name)) continue;
            if (settings.respectOmitted && XmlPresence.omitted(source, name)) continue;
            if (name.equals("pureVirtual")
                    && source instanceof FunctionContainer f
                    && !f.hasPureVirtualValue()
                    && !XmlPresence.cleared(source, name)) continue;
            String policy = settings.fields.getOrDefault(kind + "." + name, settings.defaultPolicy);
            if (policy.equals("keep")) continue;
            try {
                Object incoming = property.getValue().invoke(source);
                Object current = property.getValue().invoke(target);
                if (XmlPresence.cleared(source, name)) {
                    if (incoming instanceof Map<?, ?>) incoming = new HashMap<>();
                    else if (incoming instanceof List<?>) incoming = new ArrayList<>();
                    else if (property.getValue().getReturnType() == boolean.class) incoming = false;
                    else if (property.getValue().getReturnType() == long.class) incoming = 0L;
                    else if (property.getValue().getReturnType() == int.class) incoming = 0;
                    else if (incoming instanceof String) incoming = "";
                    else if (incoming instanceof TypeContainer) incoming = TypeContainer.VOID;
                    else if (incoming instanceof Util.NamespacedString)
                        incoming = Util.NamespacedString.parse("");
                    else incoming = null;
                }
                if (policy.equals("nonempty")
                        && empty(incoming)
                        && !XmlPresence.cleared(source, name)) continue;
                if (policy.equals("error")
                        && !empty(current)
                        && !empty(incoming)
                        && !ProjectConfig.JSON
                                .toJson(current)
                                .equals(ProjectConfig.JSON.toJson(incoming)))
                    throw new IllegalArgumentException("Merge conflict: " + kind + "." + name);
                if (policy.equals("append")) {
                    if (incoming instanceof List<?> list && current instanceof List<?> old) {
                        List<Object> combined = new ArrayList<>(old);
                        for (Object item : list) if (!combined.contains(item)) combined.add(item);
                        incoming = combined;
                    } else if (incoming instanceof Map<?, ?> map
                            && current instanceof Map<?, ?> old) {
                        Map<Object, Object> combined = new HashMap<>(old);
                        combined.putAll(map);
                        incoming = combined;
                    } else
                        throw new IllegalArgumentException(
                                "append requires a collection: " + kind + "." + name);
                }
                String setter = "set" + Character.toUpperCase(name.charAt(0)) + name.substring(1);
                source.getClass()
                        .getMethod(setter, property.getValue().getReturnType())
                        .invoke(target, incoming);
            } catch (NoSuchMethodException e) {
                /* Read-only derived property. */
            } catch (ReflectiveOperationException e) {
                throw new IllegalStateException("Cannot merge " + kind + "." + name, e);
            }
        }
    }
}
