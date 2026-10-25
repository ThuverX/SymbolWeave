package symbolweave;

import com.google.gson.*;

import ghidra.app.util.demangler.*;

import java.nio.file.*;
import java.util.*;
import java.util.regex.*;

/** Declarative text map parser; symbol syntax is supplied by a demangler plugin class. */
public final class SymbolMapLoader {
    public static final class Entry {
        public long address;
        public long size;
        public int storageSize;
        public String name;
        public String unit;
        private DemangledObject demangled;

        public DemangledObject demangled() {
            return demangled;
        }

        public boolean function() {
            return demangled instanceof DemangledFunction;
        }
    }

    private final List<Entry> entries = new ArrayList<>();

    public List<Entry> entries() {
        return entries;
    }

    public SymbolMapLoader(Path file, JsonObject options) throws Exception {
        validate(options);
        Pattern filter = Pattern.compile(Options.string(options, "lineFilter", ".*"));
        Pattern pattern = Pattern.compile(Options.required(options, "lineRegex"));
        Pattern ignore = Pattern.compile(Options.string(options, "ignoreSymbolRegex", "(?!)"));
        JsonObject fields =
                options.has("fields") ? options.getAsJsonObject("fields") : new JsonObject();
        int radix = Options.integer(options, "radix", 16);
        Class<?> demangler =
                Class.forName(
                        Options.required(options, "demanglerClass"),
                        true,
                        Thread.currentThread().getContextClassLoader());
        var method =
                demangler.getMethod(
                        Options.string(options, "demanglerMethod", "demangleSymbol"), String.class);
        try (var lines = Files.lines(file)) {
            var iterator = lines.iterator();
            int number = 0;
            while (iterator.hasNext()) {
                String line = iterator.next();
                number++;
                if (!filter.matcher(line).matches()) continue;
                Matcher match = pattern.matcher(line);
                if (!match.matches()) {
                    if (Options.string(options, "malformed", "error").equals("error"))
                        throw new IllegalArgumentException(
                                file + ":" + number + ": map line does not match lineRegex");
                    continue;
                }
                try {
                    Entry entry = new Entry();
                    entry.address = parse(match, fields, "address", radix, 0);
                    entry.size = parse(match, fields, "size", radix, 0);
                    entry.storageSize =
                            (int)
                                    parse(
                                            match,
                                            fields,
                                            "storageSize",
                                            Options.integer(options, "storageRadix", 10),
                                            Options.integer(options, "defaultStorageSize", 1));
                    entry.name = group(match, fields, "name", "");
                    entry.unit = group(match, fields, "unit", "");
                    if (!entry.unit.matches(Options.string(options, "includeUnitRegex", ".*"))
                            || java.util.regex.Pattern.compile(
                                            Options.string(options, "excludeUnitRegex", "(?!)"))
                                    .matcher(entry.unit)
                                    .find()) continue;
                    if (!ignore.matcher(entry.name).find()) {
                        try {
                            entry.demangled = (DemangledObject) method.invoke(null, entry.name);
                        } catch (ReflectiveOperationException e) {
                            /* Not every map symbol has a demangled declaration. */
                        }
                    }
                    entries.add(entry);
                } catch (RuntimeException e) {
                    throw new IllegalArgumentException(
                            file + ":" + number + ": " + e.getMessage(), e);
                }
            }
        }
    }

    static void validate(JsonObject options) {
        Options.check(
                options,
                "map",
                Set.of(
                        "file",
                        "lineRegex",
                        "lineFilter",
                        "fields",
                        "radix",
                        "storageRadix",
                        "demanglerClass",
                        "demanglerMethod",
                        "vtableRegex",
                        "ignoreSymbolRegex",
                        "headerSlots",
                        "pointerSize",
                        "virtualCallingConvention",
                        "functionCallingConvention",
                        "defaultStorageSize",
                        "includeUnitRegex",
                        "excludeUnitRegex",
                        "includeLooseFunctions",
                        "includeClassFunctions",
                        "malformed"));
        Pattern line = Pattern.compile(Options.required(options, "lineRegex"));
        if (!options.has("fields")) throw new IllegalArgumentException("map.fields is required");
        JsonObject fields = options.getAsJsonObject("fields");
        for (String required : List.of("address", "size", "name"))
            if (!fields.has(required))
                throw new IllegalArgumentException("map.fields." + required + " is required");
        for (var field : fields.entrySet()) {
            if (!Set.of("address", "size", "storageSize", "name", "unit").contains(field.getKey()))
                throw new IllegalArgumentException("Unknown map field: " + field.getKey());
            if (!line.namedGroups().containsKey(field.getValue().getAsString()))
                throw new IllegalArgumentException(
                        "Unknown map capture group: " + field.getValue());
        }
        try {
            var clazz =
                    Class.forName(
                            Options.required(options, "demanglerClass"),
                            false,
                            Thread.currentThread().getContextClassLoader());
            var method =
                    clazz.getMethod(
                            Options.string(options, "demanglerMethod", "demangleSymbol"),
                            String.class);
            if (!java.lang.reflect.Modifier.isStatic(method.getModifiers())
                    || !DemangledObject.class.isAssignableFrom(method.getReturnType()))
                throw new IllegalArgumentException(
                        "Map demangler must be a static String-to-DemangledObject method");
        } catch (ReflectiveOperationException e) {
            throw new IllegalArgumentException("Invalid map demangler", e);
        }
        if (!Set.of("error", "skip").contains(Options.string(options, "malformed", "error")))
            throw new IllegalArgumentException("map.malformed must be error or skip");
        for (String name : List.of("virtualCallingConvention", "functionCallingConvention"))
            if (options.has(name))
                symbolweave.containers.FunctionContainer.CallingConvention.valueOf(
                        options.get(name).getAsString());

        Pattern.compile(Options.string(options, "lineFilter", ".*"));
        Pattern.compile(Options.required(options, "vtableRegex"));
        Options.required(options, "file");
        Options.required(options, "demanglerClass");
        int radix = Options.integer(options, "radix", 16);
        if (radix < 2 || radix > 36)
            throw new IllegalArgumentException("map.radix must be between 2 and 36");
        int width = Options.integer(options, "pointerSize", 4);
        if (width != 4 && width != 8)
            throw new IllegalArgumentException("map.pointerSize must be 4 or 8");
    }

    private static String group(Matcher matcher, JsonObject fields, String key, String fallback) {
        if (!fields.has(key)) return fallback;
        String value = matcher.group(fields.get(key).getAsString());
        return value == null ? fallback : value.trim();
    }

    private static long parse(
            Matcher matcher, JsonObject fields, String key, int radix, long fallback) {
        String value = group(matcher, fields, key, "");
        return value.isBlank()
                ? fallback
                : Long.parseUnsignedLong(value.replaceFirst("^0[xX]", ""), radix);
    }
}
