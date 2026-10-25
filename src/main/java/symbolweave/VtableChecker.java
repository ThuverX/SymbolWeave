package symbolweave;

import symbolweave.containers.ClassContainer;
import symbolweave.containers.FileContainer;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionService;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class VtableChecker {
    private static Path WORK_PATH = Path.of(".vtable-check");
    private static Path CHECK_SDK_PATH = WORK_PATH.resolve("sdk");
    private static Duration COMPILE_TIMEOUT = Duration.ofSeconds(60);
    private static final Pattern VFTABLE_HEADING =
            Pattern.compile("^\\s*(.+?)::\\$vftable(?:@.*)?@?:\\s*$");
    private static final Pattern SLOT = Pattern.compile("^\\s*(\\d+)\\s*\\|\\s*&(.+?)\\s*$");

    private static int workers = 8;
    private static Path configuredVcvars;
    private static Map<String, String> replacements = Map.of();
    private static List<String> opaqueNamespaces = List.of();
    private static List<String> removeIncludes = List.of();

    public static void configure(ProjectConfig config) {
        WORK_PATH = config.path(config.checker.directory);
        CHECK_SDK_PATH = WORK_PATH.resolve("sdk");
        COMPILE_TIMEOUT = Duration.ofSeconds(config.checker.timeoutSeconds);
        workers = config.checker.workers;
        configuredVcvars =
                config.checker.vcvars == null ? null : config.path(config.checker.vcvars);
        replacements = config.checker.typeReplacements;
        opaqueNamespaces = config.checker.opaqueNamespaces;
        removeIncludes = config.checker.removeIncludeRegex;
    }

    private VtableChecker() {}

    public static void run(Path sdkXmlPath, Path sdkPath) {
        if (!System.getProperty("os.name").startsWith("Windows")) {
            System.out.println(
                    "UNAVAILABLE MSVC vtable checking requires Windows and Visual Studio C++"
                            + " tools");
            return;
        }
        System.out.println("Checking SDK vtable indices with MSVC");

        try {
            Optional<Path> vcVars = findVcVars();
            if (vcVars.isEmpty()) {
                System.out.println("UNAVAILABLE MSVC build environment was not found");
                System.out.println("Summary: passed=0 failed=0 compile-failed=0 skipped=0");
                return;
            }
            if (!Files.isRegularFile(sdkXmlPath)) {
                System.out.println(
                        "UNAVAILABLE SDK metadata was not found: " + sdkXmlPath.toAbsolutePath());
                System.out.println("Summary: passed=0 failed=0 compile-failed=0 skipped=0");
                return;
            }

            Files.createDirectories(WORK_PATH);
            Path checkSdkPath = prepareCheckHeaders(sdkPath);
            FileContainer container = DataXMLSerializer.readContainerFromFile(sdkXmlPath);
            List<ClassContainer> classes =
                    container.getClasses().stream()
                            .sorted(Comparator.comparing(c -> c.getName().toString()))
                            .toList();

            int passed = 0;
            int failed = 0;
            int compileFailed = 0;
            int skipped = 0;

            int workerCount =
                    Math.max(1, Math.min(Runtime.getRuntime().availableProcessors(), workers));
            System.out.println("Using " + workerCount + " parallel MSVC workers");
            ExecutorService executor = Executors.newFixedThreadPool(workerCount);
            CompletionService<CheckResult> completion = new ExecutorCompletionService<>(executor);
            try {
                for (ClassContainer cls : classes) {
                    completion.submit(() -> checkClass(cls, checkSdkPath, vcVars.get()));
                }

                for (int i = 0; i < classes.size(); i++) {
                    CheckResult result;
                    try {
                        result = completion.take().get();
                    } catch (Exception e) {
                        result =
                                new CheckResult(
                                        Status.COMPILE_FAILED,
                                        "COMPILE FAILED unknown class - "
                                                + concise(e.getMessage()));
                    }
                    System.out.println(result.message());
                    switch (result.status()) {
                        case PASSED -> passed++;
                        case FAILED -> failed++;
                        case COMPILE_FAILED -> compileFailed++;
                        case SKIPPED -> skipped++;
                    }
                }
            } finally {
                executor.shutdownNow();
            }

            System.out.printf(
                    "Summary: passed=%d failed=%d compile-failed=%d skipped=%d%n",
                    passed, failed, compileFailed, skipped);
        } catch (Exception e) {
            // Checking is deliberately diagnostic and must not break normal automation.
            System.out.println("UNAVAILABLE " + concise(e.getMessage()));
            System.out.println("Summary: passed=0 failed=0 compile-failed=0 skipped=0");
        }
    }

    private static CheckResult checkClass(ClassContainer cls, Path sdkPath, Path vcVars) {
        String className = cls.getName().toString();
        if (className.contains("<") || className.contains(">")) {
            return new CheckResult(
                    Status.SKIPPED,
                    "SKIP " + className + " - template class has no generated header");
        }
        int expectedSlotCount = logicalSlotCount(cls);
        if (expectedSlotCount <= 0) {
            return new CheckResult(Status.SKIPPED, "SKIP " + className + " - no defined vtable");
        }

        Path header = sdkPath.resolve(headerPath(cls));
        if (!Files.isRegularFile(header)) {
            return new CheckResult(
                    Status.SKIPPED, "SKIP " + className + " - generated header not found");
        }

        try {
            Path source = writeUnit(cls, header);
            CompileResult compilation = compile(vcVars, sdkPath, source, cls.getName().getName());
            if (!compilation.completed()) {
                return new CheckResult(
                        Status.COMPILE_FAILED, "COMPILE FAILED " + className + " - timed out");
            }
            if (compilation.exitCode() != 0) {
                return new CheckResult(
                        Status.COMPILE_FAILED,
                        "COMPILE FAILED "
                                + className
                                + " - "
                                + firstDiagnostic(compilation.output()));
            }

            Map<Integer, String> actualSlots =
                    parseSlots(compilation.output(), className, cls.getName().getName());
            List<ExpectedFunction> expected = expectedFunctions(cls);
            List<String> deltas = new ArrayList<>();

            for (ExpectedFunction function : expected) {
                String actual = actualSlots.get(function.index());
                if (actual == null) {
                    deltas.add(
                            function.name() + " expected=" + function.index() + " actual=missing");
                } else if (!matchesFunction(actual, function.name())) {
                    deltas.add(
                            function.name()
                                    + " expected="
                                    + function.index()
                                    + " actual="
                                    + actual);
                }
            }

            if (actualSlots.isEmpty() && expected.isEmpty()) {
                return new CheckResult(
                        Status.SKIPPED,
                        "SKIP " + className + " - no checkable virtual declarations");
            }
            if (actualSlots.isEmpty()) {
                return new CheckResult(
                        Status.FAILED, "FAIL " + className + " - MSVC emitted no vftable slots");
            }
            if (actualSlots.size() != expectedSlotCount) {
                deltas.add(
                        "slot-count expected="
                                + expectedSlotCount
                                + " actual="
                                + actualSlots.size()
                                + " delta="
                                + signed(actualSlots.size() - expectedSlotCount));
            }
            if (deltas.isEmpty()) {
                return new CheckResult(
                        Status.PASSED,
                        "PASS " + className + " - " + actualSlots.size() + " slots match");
            }
            return new CheckResult(
                    Status.FAILED, "FAIL " + className + " - " + String.join("; ", deltas));
        } catch (Exception e) {
            return new CheckResult(
                    Status.COMPILE_FAILED,
                    "COMPILE FAILED " + className + " - " + concise(e.getMessage()));
        }
    }

    private static Path writeUnit(ClassContainer cls, Path header) throws IOException {
        String className = cls.getName().toString();
        String safeName = cls.getName().getName().replaceAll("[^A-Za-z0-9_.-]", "_");
        if (safeName.length() > 80) safeName = safeName.substring(0, 80);
        String unitId =
                UUID.nameUUIDFromBytes(className.getBytes(StandardCharsets.UTF_8)).toString();
        Path source = WORK_PATH.resolve(safeName + "-" + unitId + ".cpp");
        String include = header.toAbsolutePath().toString().replace("\\", "\\\\");
        String cpp =
                "// Generated by --vtable-check. Do not edit.\n#include <VtableCheckTypes.h>\n"
                        + "#include \""
                        + include
                        + "\"\n"
                        + "using SymbolWeaveVtableCheckTarget = "
                        + cls.getName()
                        + ";\n"
                        + "static_assert(sizeof(SymbolWeaveVtableCheckTarget) > 0);\n";
        Files.writeString(
                source, cpp, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        return source;
    }

    private static Path prepareCheckHeaders(Path sdkPath) throws IOException {
        Files.createDirectories(CHECK_SDK_PATH);
        try (var paths = Files.walk(sdkPath)) {
            for (Path source :
                    paths.filter(Files::isRegularFile).filter(VtableChecker::isHeader).toList()) {
                Path destination = CHECK_SDK_PATH.resolve(sdkPath.relativize(source));
                Files.createDirectories(destination.getParent());
                Files.writeString(
                        destination,
                        prepareHeader(Files.readString(source)),
                        StandardOpenOption.CREATE,
                        StandardOpenOption.TRUNCATE_EXISTING);
            }
        }

        Files.writeString(
                CHECK_SDK_PATH.resolve("VtableCheckTypes.h"),
                "#pragma once\n"
                    + "namespace sdk_vtable_check { template<unsigned long long Id> struct Opaque;"
                    + " }\n");
        return CHECK_SDK_PATH;
    }

    static String prepareHeader(String header) {
        for (String regex : removeIncludes) header = header.replaceAll(regex, "");
        for (var rule : replacements.entrySet())
            header = header.replaceAll(rule.getKey(), rule.getValue());
        for (String prefix : opaqueNamespaces) {
            StringBuilder output = new StringBuilder();
            int cursor = 0;
            while (cursor < header.length()) {
                int start =
                        header.toLowerCase(Locale.ROOT)
                                .indexOf(prefix.toLowerCase(Locale.ROOT), cursor);
                if (start < 0) {
                    output.append(header.substring(cursor));
                    break;
                }
                output.append(header, cursor, start);
                int end = start + prefix.length();
                while (end < header.length()
                        && (Character.isJavaIdentifierPart(header.charAt(end))
                                || header.charAt(end) == ':')) end++;
                int angle = end;
                while (angle < header.length() && Character.isWhitespace(header.charAt(angle)))
                    angle++;
                if (angle < header.length() && header.charAt(angle) == '<') {
                    int depth = 0;
                    for (int i = angle; i < header.length(); i++) {
                        if (header.charAt(i) == '<') depth++;
                        if (header.charAt(i) == '>' && --depth == 0) {
                            end = i + 1;
                            break;
                        }
                    }
                }
                String original = header.substring(start, end);
                long hash = 0xcbf29ce484222325L;
                for (byte b : original.getBytes(StandardCharsets.UTF_8)) {
                    hash ^= b & 255L;
                    hash *= 0x100000001b3L;
                }
                output.append("::sdk_vtable_check::Opaque<")
                        .append(Long.toUnsignedString(hash))
                        .append("ULL>");
                cursor = end;
            }
            header = output.toString();
        }
        return header;
    }

    private static boolean isHeader(Path path) {
        String name = path.getFileName().toString().toLowerCase(Locale.ROOT);
        return name.endsWith(".h")
                || name.endsWith(".hh")
                || name.endsWith(".hpp")
                || name.endsWith(".hxx");
    }

    private static CompileResult compile(
            Path vcVars, Path sdkPath, Path source, String simpleClassName)
            throws IOException, InterruptedException {
        String command =
                "call "
                        + quote(vcVars.toAbsolutePath().toString())
                        + " >nul && cl.exe /nologo /std:c++20 "
                        + "/permissive- /TP /Zs /I"
                        + quote(sdkPath.toAbsolutePath().toString())
                        + " "
                        + quote("/d1reportSingleClassLayout" + simpleClassName)
                        + " "
                        + quote(source.toAbsolutePath().toString());
        Process process =
                new ProcessBuilder("cmd.exe", "/d", "/s", "/c", command)
                        .redirectErrorStream(true)
                        .start();
        CompletableFuture<byte[]> outputFuture =
                CompletableFuture.supplyAsync(
                        () -> {
                            try {
                                return process.getInputStream().readAllBytes();
                            } catch (IOException e) {
                                return new byte[0];
                            }
                        });
        boolean completed = process.waitFor(COMPILE_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
        if (!completed) {
            process.destroyForcibly();
            process.waitFor();
        }
        String output = new String(outputFuture.join(), Charset.defaultCharset());
        return new CompileResult(completed, completed ? process.exitValue() : -1, output);
    }

    static Map<Integer, String> parseSlots(
            String output, String qualifiedClassName, String simpleClassName) {
        Map<Integer, String> result = new LinkedHashMap<>();
        boolean inTargetVftable = false;
        int tableOffset = 0;
        int tableMaximumIndex = -1;
        for (String line : output.split("\\R")) {
            Matcher heading = VFTABLE_HEADING.matcher(line);
            if (heading.matches()) {
                if (inTargetVftable) {
                    tableOffset += tableMaximumIndex + 1;
                }
                String owner = heading.group(1).trim();
                inTargetVftable =
                        owner.equals(qualifiedClassName)
                                || owner.equals(simpleClassName)
                                || owner.endsWith("::" + simpleClassName);
                tableMaximumIndex = -1;
                continue;
            }
            Matcher slot = SLOT.matcher(line);
            if (inTargetVftable && slot.matches()) {
                int localIndex = Integer.parseInt(slot.group(1));
                result.put(tableOffset + localIndex, slot.group(2).trim());
                tableMaximumIndex = Math.max(tableMaximumIndex, localIndex);
            } else if (inTargetVftable
                    && !line.isBlank()
                    && !line.startsWith(" ")
                    && !line.startsWith("\t")) {
                tableOffset += tableMaximumIndex + 1;
                tableMaximumIndex = -1;
                inTargetVftable = false;
            }
        }
        return result;
    }

    private static List<ExpectedFunction> expectedFunctions(ClassContainer cls) {
        return cls.getVirtualFunctions().entrySet().stream()
                .filter(
                        e ->
                                e.getValue() != null
                                        && e.getValue().getName() != null
                                        && !e.getValue().getName().toString().isBlank()
                                        && !e.getValue().getName().toString().equals("undefined"))
                .sorted(Map.Entry.comparingByKey())
                .map(e -> new ExpectedFunction(e.getKey(), e.getValue().getName().getName()))
                .toList();
    }

    private static int logicalSlotCount(ClassContainer cls) {
        return Math.max(
                cls.getVtableCount(),
                cls.getVirtualFunctions().keySet().stream()
                        .mapToInt(index -> index + 1)
                        .max()
                        .orElse(0));
    }

    private static boolean matchesFunction(String actual, String expectedName) {
        boolean destructor = expectedName.startsWith("~");
        if (destructor) {
            return actual.contains("{dtor}")
                    || actual.contains(expectedName)
                    || actual.toLowerCase(Locale.ROOT).contains("destructor");
        }
        return actual.matches(".*::" + Pattern.quote(expectedName) + "\\d*(?:\\s|\\(|$).*$");
    }

    private static Optional<Path> findVcVars() throws IOException {
        if (configuredVcvars != null)
            return Files.isRegularFile(configuredVcvars)
                    ? Optional.of(configuredVcvars)
                    : Optional.empty();
        String vsInstall = System.getenv("VSINSTALLDIR");
        if (vsInstall != null) {
            Path candidate = Path.of(vsInstall, "VC", "Auxiliary", "Build", "vcvars64.bat");
            if (Files.isRegularFile(candidate)) return Optional.of(candidate);
        }

        List<Path> roots = new ArrayList<>();
        addVisualStudioRoots(roots, System.getenv("ProgramFiles"));
        addVisualStudioRoots(roots, System.getenv("ProgramFiles(x86)"));
        return roots.stream()
                .filter(Files::isRegularFile)
                .max(Comparator.comparing(Path::toString));
    }

    private static void addVisualStudioRoots(List<Path> candidates, String programFiles)
            throws IOException {
        if (programFiles == null) return;
        Path visualStudio = Path.of(programFiles, "Microsoft Visual Studio");
        if (!Files.isDirectory(visualStudio)) return;
        try (var versions = Files.list(visualStudio)) {
            for (Path version : versions.filter(Files::isDirectory).toList()) {
                try (var editions = Files.list(version)) {
                    for (Path edition : editions.filter(Files::isDirectory).toList()) {
                        candidates.add(
                                edition.resolve(
                                        Path.of("VC", "Auxiliary", "Build", "vcvars64.bat")));
                    }
                }
            }
        }
    }

    private static String headerPath(ClassContainer cls) {
        return cls.getName().getParts().stream()
                        .map(VtableChecker::sanitizePathPart)
                        .reduce((left, right) -> left + "/" + right)
                        .orElse("")
                + ".h";
    }

    private static String sanitizePathPart(String value) {
        return value.replaceAll("[\\\\/:*?\"<>|]", "_");
    }

    private static String quote(String value) {
        return "\"" + value.replace("\"", "\"\"") + "\"";
    }

    private static String firstDiagnostic(String output) {
        for (String line : output.split("\\R")) {
            String trimmed = line.trim();
            if (trimmed.contains(": error ") || trimmed.contains("fatal error"))
                return concise(trimmed);
        }
        for (String line : output.split("\\R")) {
            if (!line.isBlank()) return concise(line);
        }
        return "MSVC exited without a diagnostic";
    }

    private static String concise(String message) {
        if (message == null || message.isBlank()) return "unknown error";
        String oneLine = message.replaceAll("\\s+", " ").trim();
        return oneLine.length() <= 240 ? oneLine : oneLine.substring(0, 237) + "...";
    }

    private static String signed(int value) {
        return value >= 0 ? "+" + value : Integer.toString(value);
    }

    private enum Status {
        PASSED,
        FAILED,
        COMPILE_FAILED,
        SKIPPED
    }

    private record CheckResult(Status status, String message) {}

    private record CompileResult(boolean completed, int exitCode, String output) {}

    private record ExpectedFunction(int index, String name) {}
}
