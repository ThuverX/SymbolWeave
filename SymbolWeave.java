import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.*;
import java.util.regex.Pattern;

import javax.tools.ToolProvider;

/** Portable source launcher: java SymbolWeave.java [command or application arguments]. */
public final class SymbolWeave {
    private static final String FORMAT_VERSION = "1.35.0";
    private static final String FORMAT_SHA256 =
            "bfb7f9ead6cd328389bc2da53860443bc0e805dfd08cc889bfdf43b26cb2a6e8";
    private static final Set<String> DEVELOPMENT_COMMANDS =
            Set.of("build", "test", "schema", "compare");
    private final Path home;
    private final Path build;

    private SymbolWeave(Path home) {
        this.home = home;
        build =
                Path.of(
                                System.getenv()
                                        .getOrDefault(
                                                "SYMBOLWEAVE_BUILD_DIR",
                                                home.resolve("out").toString()))
                        .toAbsolutePath()
                        .normalize();
    }

    public static void main(String[] args) {
        try {
            int status = new SymbolWeave(sourceDirectory()).execute(args);
            if (status != 0) System.exit(status);
        } catch (Exception failure) {
            System.err.println("SymbolWeave: " + failure.getMessage());
            System.exit(1);
        }
    }

    private static Path sourceDirectory() throws Exception {
        String source = System.getProperty("jdk.launcher.sourcefile");
        if (source != null) return Path.of(source).toAbsolutePath().normalize().getParent();
        Path location =
                Path.of(
                        SymbolWeave.class
                                .getProtectionDomain()
                                .getCodeSource()
                                .getLocation()
                                .toURI());
        if (Files.isRegularFile(location.resolve("SymbolWeave.java"))) return location;
        throw new IllegalStateException("Launch from source: java /path/to/SymbolWeave.java");
    }

    private int execute(String[] args) throws Exception {
        if (Arrays.asList(args).contains("--help") || Arrays.asList(args).contains("-h")) {
            System.out.println(
                    """
                    SymbolWeave
                    java SymbolWeave.java [application options]
                    java SymbolWeave.java build [-c config.json]
                    java SymbolWeave.java test [-c config.json]
                    java SymbolWeave.java format [--check]
                    java SymbolWeave.java schema [--check] [-c config.json]
                    java SymbolWeave.java compare expected.xml actual.xml [--expected-headers dir --actual-headers dir] [--normalize-anonymous]

                    Application options: -c/--config file, --analyze, --no-analyze, --fresh,
                    --exe file, -o/--output dir, --bsim, --signatures, --pdb, --vtable-check,
                    --print-config, --validate-config.
                    Requires JDK 21+. Set GHIDRA_JAR or configure ghidraJar in config.json.
                    """);
            return 0;
        }
        String command = args.length == 0 ? "run" : args[0];
        if (command.equals("format")) return format(Arrays.copyOfRange(args, 1, args.length));
        boolean development = DEVELOPMENT_COMMANDS.contains(command);
        String[] options = development ? Arrays.copyOfRange(args, 1, args.length) : args;
        Path config = selectedConfig(options, development);
        Path ghidra = ghidraJar(config);
        Path classes = compile(development, ghidra);
        String classpath = classes + File.pathSeparator + ghidra;
        return switch (command) {
            case "build" -> {
                checkBuildOptions(options, false);
                System.out.println("Compiled classes: " + classes);
                yield 0;
            }
            case "test" -> {
                checkBuildOptions(options, false);
                yield test(classes, classpath);
            }
            case "schema" -> {
                checkBuildOptions(options, true);
                List<String> arguments =
                        new ArrayList<>(
                                List.of(
                                        "-cp",
                                        classpath,
                                        "symbolweave.development.ConfigSchema",
                                        home.resolve("symbolweave.schema.json").toString()));
                if (Arrays.asList(options).contains("--check")) arguments.add("--check");
                yield java(arguments);
            }
            case "compare" ->
                    java(
                            withArguments(
                                    List.of(
                                            "-cp",
                                            classpath,
                                            "symbolweave.development.CompareArtifacts"),
                                    options));
            default -> java(withArguments(List.of("-cp", classpath, "symbolweave.Main"), args));
        };
    }

    private Path selectedConfig(String[] args, boolean development) {
        Path selected = null;
        for (int i = 0; i < args.length; i++)
            if (args[i].equals("-c") || args[i].equals("--config")) {
                if (++i == args.length)
                    throw new IllegalArgumentException("--config requires a file");
                selected = Path.of(args[i]).toAbsolutePath().normalize();
            }
        if (selected != null) return selected;
        Path found = discover(Path.of(""));
        if (found != null) return found;
        if (development) return home.resolve("config.json");
        throw new IllegalArgumentException("No config.json found; use -c <file>");
    }

    static Path discover(Path start) {
        for (Path directory = start.toAbsolutePath().normalize();
                directory != null;
                directory = directory.getParent()) {
            Path candidate = directory.resolve("config.json");
            if (Files.isRegularFile(candidate)) return candidate;
        }
        return null;
    }

    private Path ghidraJar(Path config) throws IOException {
        String value = System.getenv("GHIDRA_JAR");
        if (value == null || value.isBlank()) {
            Object configured = parseConfig(Files.readString(config)).get("ghidraJar");
            if (!(configured instanceof String))
                throw new IllegalArgumentException(
                        "Set GHIDRA_JAR or configure ghidraJar in " + config);
            value = (String) configured;
        }
        Path jar =
                config.toAbsolutePath()
                        .getParent()
                        .resolve(expandEnvironment(value, System.getenv()))
                        .normalize();
        if (!Files.isRegularFile(jar))
            throw new IllegalArgumentException("Ghidra JAR not found: " + jar);
        return jar;
    }

    static String expandEnvironment(String value, Map<String, String> environment) {
        var matcher = Pattern.compile("\\$\\{([^}]+)}").matcher(value);
        StringBuilder expanded = new StringBuilder();
        while (matcher.find()) {
            String replacement = environment.get(matcher.group(1));
            if (replacement == null)
                throw new IllegalArgumentException(
                        "Environment variable is not set: " + matcher.group(1));
            matcher.appendReplacement(
                    expanded, java.util.regex.Matcher.quoteReplacement(replacement));
        }
        matcher.appendTail(expanded);
        return expanded.toString();
    }

    private Path compile(boolean development, Path ghidra) throws IOException {
        List<Path> sources = new ArrayList<>(javaSources(home.resolve("src/main/java")));
        sources.add(home.resolve("SymbolWeave.java"));
        if (development) sources.addAll(javaSources(home.resolve("src/development/java")));
        Path classes = build.resolve("classes");
        compileSources(sources, classes, ghidra.toString());
        Path resources = home.resolve("src/main/resources");
        try (var paths = Files.walk(resources)) {
            for (Path source : paths.filter(Files::isRegularFile).toList()) {
                Path target = classes.resolve(resources.relativize(source));
                Files.createDirectories(target.getParent());
                Files.copy(source, target, StandardCopyOption.REPLACE_EXISTING);
            }
        }
        return classes;
    }

    private static void compileSources(List<Path> sources, Path destination, String classpath)
            throws IOException {
        var compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null)
            throw new IllegalStateException("A JDK is required; a JRE cannot compile SymbolWeave");
        Files.createDirectories(destination);
        try (var paths = Files.walk(destination)) {
            for (Path file : paths.filter(path -> path.toString().endsWith(".class")).toList())
                Files.delete(file);
        }
        try (var manager =
                compiler.getStandardFileManager(null, Locale.ROOT, StandardCharsets.UTF_8)) {
            var units = manager.getJavaFileObjectsFromPaths(sources);
            var options =
                    List.of(
                            "--release",
                            "21",
                            "-encoding",
                            "UTF-8",
                            "-cp",
                            classpath,
                            "-d",
                            destination.toString());
            if (!compiler.getTask(null, manager, null, options, null, units).call())
                throw new IllegalStateException("Java compilation failed");
        }
    }

    private int test(Path classes, String classpath) throws Exception {
        Path sourceRoot = home.resolve("src/test/java");
        List<Path> sources = javaSources(sourceRoot);
        Path tests = build.resolve("test-classes");
        compileSources(sources, tests, classpath);
        String testClasspath = tests + File.pathSeparator + classpath;
        int count = 0;
        for (Path source : sources)
            if (source.getFileName().toString().endsWith("Test.java")) {
                String relative = sourceRoot.relativize(source).toString();
                String name =
                        relative.substring(0, relative.length() - 5)
                                .replace(File.separatorChar, '.');
                System.out.println("Running " + name);
                int status = java(List.of("-cp", testClasspath, name));
                if (status != 0) return status;
                count++;
            }
        System.out.println("Passed " + count + " test programs");
        return 0;
    }

    private int format(String[] args) throws Exception {
        if (args.length > 1 || args.length == 1 && !args[0].equals("--check"))
            throw new IllegalArgumentException("Usage: java SymbolWeave.java format [--check]");
        Path cache =
                Path.of(
                        System.getenv()
                                .getOrDefault(
                                        "SYMBOLWEAVE_TOOL_CACHE",
                                        Path.of(System.getProperty("java.io.tmpdir"), "symbolweave")
                                                .toString()));
        Path jar = cache.resolve("google-java-format-" + FORMAT_VERSION + "-all-deps.jar");
        if (!Files.isRegularFile(jar)) {
            Files.createDirectories(cache);
            Path temporary = Files.createTempFile(cache, "formatter-", ".tmp");
            try {
                URI uri =
                        URI.create(
                                "https://repo.maven.apache.org/maven2/com/google/googlejavaformat/google-java-format/"
                                        + FORMAT_VERSION
                                        + "/"
                                        + jar.getFileName());
                var request = HttpRequest.newBuilder(uri).timeout(Duration.ofMinutes(2)).build();
                var client =
                        HttpClient.newBuilder()
                                .connectTimeout(Duration.ofSeconds(30))
                                .followRedirects(HttpClient.Redirect.NORMAL)
                                .build();
                var response = client.send(request, HttpResponse.BodyHandlers.ofFile(temporary));
                if (response.statusCode() != 200)
                    throw new IOException(
                            "Formatter download failed: HTTP " + response.statusCode());
                verifyFormatter(temporary);
                Files.move(temporary, jar, StandardCopyOption.REPLACE_EXISTING);
            } finally {
                Files.deleteIfExists(temporary);
            }
        }
        verifyFormatter(jar);
        List<String> command = new ArrayList<>(List.of("-jar", jar.toString()));
        command.add("--aosp");
        command.addAll(
                args.length == 1
                        ? List.of("--dry-run", "--set-exit-if-changed")
                        : List.of("--replace"));
        command.add(home.resolve("SymbolWeave.java").toString());
        for (Path source : javaSources(home.resolve("src"))) command.add(source.toString());
        for (Path source : javaSources(home.resolve("ghidra_scripts")))
            command.add(source.toString());
        return java(command);
    }

    private static void verifyFormatter(Path jar) throws Exception {
        String hash =
                HexFormat.of()
                        .formatHex(
                                MessageDigest.getInstance("SHA-256")
                                        .digest(Files.readAllBytes(jar)));
        if (!hash.equals(FORMAT_SHA256))
            throw new IOException("Formatter JAR checksum mismatch: " + jar);
    }

    private static List<Path> javaSources(Path directory) throws IOException {
        try (var paths = Files.walk(directory)) {
            return paths.filter(Files::isRegularFile)
                    .filter(path -> path.toString().endsWith(".java"))
                    .sorted()
                    .toList();
        }
    }

    private static void checkBuildOptions(String[] args, boolean checkAllowed) {
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("-c") || args[i].equals("--config")) {
                if (++i == args.length)
                    throw new IllegalArgumentException("--config requires a file");
            } else if (!checkAllowed || !args[i].equals("--check"))
                throw new IllegalArgumentException("Unknown development option: " + args[i]);
        }
    }

    private static List<String> withArguments(List<String> prefix, String[] args) {
        List<String> command = new ArrayList<>(prefix);
        command.addAll(Arrays.asList(args));
        return command;
    }

    private static int java(List<String> arguments) throws IOException, InterruptedException {
        String executable =
                System.getProperty("os.name").startsWith("Windows") ? "java.exe" : "java";
        List<String> command =
                new ArrayList<>(
                        List.of(
                                Path.of(System.getProperty("java.home"), "bin", executable)
                                        .toString(),
                                "--enable-native-access=ALL-UNNAMED"));
        command.addAll(arguments);
        return new ProcessBuilder(command).inheritIO().start().waitFor();
    }

    /** Reads bootstrap settings before the configured Ghidra/Gson dependency is available. */
    static Map<String, Object> parseConfig(String text) {
        JsonReader reader = new JsonReader(text);
        Object value = reader.value();
        reader.whitespace();
        if (!(value instanceof Map<?, ?>) || reader.position != text.length())
            throw new IllegalArgumentException("Expected a JSON configuration object");
        @SuppressWarnings("unchecked")
        Map<String, Object> object = (Map<String, Object>) value;
        return object;
    }

    private static final class JsonReader {
        private final String text;
        private int position;

        JsonReader(String text) {
            this.text = text;
        }

        void whitespace() {
            while (position < text.length() && Character.isWhitespace(text.charAt(position)))
                position++;
        }

        private char peek() {
            whitespace();
            if (position == text.length()) throw error();
            return text.charAt(position);
        }

        private IllegalArgumentException error() {
            return new IllegalArgumentException("Invalid JSON at character " + position);
        }

        private void expect(char expected) {
            if (peek() != expected) throw error();
            position++;
        }

        Object value() {
            char token = peek();
            if (token == '"') return string();
            if (token == '{') {
                position++;
                Map<String, Object> object = new LinkedHashMap<>();
                if (peek() == '}') {
                    position++;
                    return object;
                }
                while (true) {
                    if (peek() != '"') throw error();
                    String key = string();
                    expect(':');
                    if (object.containsKey(key))
                        throw new IllegalArgumentException("Duplicate JSON setting: " + key);
                    object.put(key, value());
                    char next = peek();
                    position++;
                    if (next == '}') return object;
                    if (next != ',') throw error();
                }
            }
            if (token == '[') {
                position++;
                List<Object> array = new ArrayList<>();
                if (peek() == ']') {
                    position++;
                    return array;
                }
                while (true) {
                    array.add(value());
                    char next = peek();
                    position++;
                    if (next == ']') return array;
                    if (next != ',') throw error();
                }
            }
            int start = position;
            while (position < text.length() && ",]} \t\r\n".indexOf(text.charAt(position)) < 0)
                position++;
            String literal = text.substring(start, position);
            if (literal.equals("true")) return true;
            if (literal.equals("false")) return false;
            if (literal.equals("null")) return null;
            if (!literal.matches("-?(0|[1-9][0-9]*)(\\.[0-9]+)?([eE][+-]?[0-9]+)?")) throw error();
            return new java.math.BigDecimal(literal);
        }

        private String string() {
            expect('"');
            StringBuilder value = new StringBuilder();
            while (position < text.length()) {
                char ch = text.charAt(position++);
                if (ch == '"') return value.toString();
                if (ch < 32) throw error();
                if (ch != '\\') {
                    value.append(ch);
                    continue;
                }
                if (position == text.length()) throw error();
                char escape = text.charAt(position++);
                switch (escape) {
                    case '"', '\\', '/' -> value.append(escape);
                    case 'b' -> value.append('\b');
                    case 'f' -> value.append('\f');
                    case 'n' -> value.append('\n');
                    case 'r' -> value.append('\r');
                    case 't' -> value.append('\t');
                    case 'u' -> {
                        if (position + 4 > text.length()) throw error();
                        try {
                            value.append(
                                    (char)
                                            Integer.parseInt(
                                                    text.substring(position, position + 4), 16));
                        } catch (NumberFormatException e) {
                            throw error();
                        }
                        position += 4;
                    }
                    default -> throw error();
                }
            }
            throw error();
        }
    }
}
