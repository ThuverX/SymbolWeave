package symbolweave;

import symbolweave.containers.ClassContainer;
import symbolweave.containers.FileContainer;
import symbolweave.containers.FunctionContainer;
import symbolweave.containers.TypeContainer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** Creates a version-bound, Ghidra-free signature database from the executable. */
public final class SignatureDatabaseGenerator {
    public static final int SCHEMA_VERSION = 1;
    public static final int MAX_SIGNATURE_BYTES = 128;
    private static final int TRAILING_INSTRUCTIONS = 2;

    public record Result(
            Path path,
            int patternCount,
            int verifiedPatternCount,
            int entityCount,
            int issueCount) {}

    private record Entity(
            String id,
            String kind,
            String name,
            String owner,
            Integer slot,
            long storedVa,
            long targetVa,
            long targetRva) {}

    private record Issue(String entityId, String reason) {}

    private record Signature(byte[] bytes, boolean[] wildcard, int matchCount) {}

    private record Pattern(String id, long targetVa, long targetRva, Signature signature) {}

    private SignatureDatabaseGenerator() {}

    public static Result generate(FileContainer sdk, Path executable, Path outputDirectory)
            throws IOException {
        return generate(sdk, executable, outputDirectory, null);
    }

    public static Result generate(
            FileContainer sdk, Path executable, Path outputDirectory, String diagnosticLabel)
            throws IOException {
        String label =
                diagnosticLabel == null ? executable.getFileName().toString() : diagnosticLabel;
        PortableExecutable pe = PortableExecutable.read(executable);
        boolean[] relocationMask = pe.relocationMask();
        List<Entity> entities = new ArrayList<>();
        List<Issue> issues = new ArrayList<>();
        Map<String, Integer> entityIdCounts = new HashMap<>();

        for (ClassContainer cls : sdk.getClasses()) {
            for (int index = 0; index < cls.getFunctions().size(); index++) {
                FunctionContainer function = cls.getFunctions().get(index);
                String id =
                        uniqueEntityId(
                                directId(
                                        "class-function",
                                        cls.getName().toString(),
                                        function,
                                        index),
                                entityIdCounts);
                addDirectEntity(
                        pe,
                        label,
                        entities,
                        issues,
                        id,
                        "class-function",
                        function.getName().toString(),
                        cls.getName().toString(),
                        function.getAddress());
            }
            cls.getVirtualFunctions().entrySet().stream()
                    .sorted(Map.Entry.comparingByKey())
                    .forEach(
                            entry -> {
                                FunctionContainer function = entry.getValue();
                                if (!hasUsefulName(function)) return;
                                String id =
                                        "virtual-function|"
                                                + cls.getName()
                                                + "|slot:"
                                                + entry.getKey();
                                long slotVa = function.getAddress();
                                try {
                                    if (pe.vaToOffset(slotVa) < 0) {
                                        issues.add(
                                                new Issue(
                                                        id,
                                                        "vtable slot is outside "
                                                                + label
                                                                + ": "
                                                                + hex(slotVa)));
                                        return;
                                    }
                                    long targetVa = pe.readLongAtVa(slotVa);
                                    if (!pe.isExecutableVa(targetVa)) {
                                        issues.add(
                                                new Issue(
                                                        id,
                                                        "vtable target is not executable: "
                                                                + hex(targetVa)));
                                        return;
                                    }
                                    entities.add(
                                            new Entity(
                                                    id,
                                                    "virtual-function",
                                                    function.getName().toString(),
                                                    cls.getName().toString(),
                                                    entry.getKey(),
                                                    slotVa,
                                                    targetVa,
                                                    pe.vaToRva(targetVa)));
                                } catch (IOException exception) {
                                    issues.add(new Issue(id, exception.getMessage()));
                                }
                            });
        }

        for (int index = 0; index < sdk.getLooseFunctions().size(); index++) {
            FunctionContainer function = sdk.getLooseFunctions().get(index);
            String id =
                    uniqueEntityId(directId("loose-function", "", function, index), entityIdCounts);
            addDirectEntity(
                    pe,
                    label,
                    entities,
                    issues,
                    id,
                    "loose-function",
                    function.getName().toString(),
                    "",
                    function.getAddress());
        }

        entities.sort(Comparator.comparing(Entity::id));
        Map<Long, Pattern> patternsByTarget = new TreeMap<>();
        int sequence = 1;
        int verifiedPatterns = 0;
        for (long targetVa : entities.stream().map(Entity::targetVa).distinct().sorted().toList()) {
            Signature signature = createSignature(pe, relocationMask, targetVa);
            String patternId = String.format("p%05d", sequence++);
            if (signature.matchCount() != 1) {
                for (Entity entity : entities) {
                    if (entity.targetVa() == targetVa) {
                        issues.add(
                                new Issue(
                                        entity.id(),
                                        "signature has "
                                                + signature.matchCount()
                                                + " matches after "
                                                + signature.bytes().length
                                                + " bytes"));
                    }
                }
            } else {
                verifiedPatterns++;
            }
            patternsByTarget.put(
                    targetVa, new Pattern(patternId, targetVa, pe.vaToRva(targetVa), signature));
        }

        Path signaturesDirectory = outputDirectory.resolve("signatures");
        Files.createDirectories(signaturesDirectory);
        PortableExecutable.Version version = pe.version();
        String displayVersion =
                version.productVersion().isBlank() ? "unknown" : version.productVersion();
        String fileName =
                executable
                                .getFileName()
                                .toString()
                                .replaceAll("(?i)\\.exe$", "")
                                .replaceAll("[^A-Za-z0-9._-]", "_")
                        + "-"
                        + displayVersion.replaceAll("[^A-Za-z0-9._-]", "_")
                        + "-"
                        + pe.sha256().substring(0, 12)
                        + ".json";
        Path output = signaturesDirectory.resolve(fileName);
        String json = toJson(executable, pe, version, patternsByTarget, entities, issues);
        Path temporary = Files.createTempFile(signaturesDirectory, fileName, ".tmp");
        try {
            Files.writeString(temporary, json, StandardCharsets.UTF_8);
            try {
                Files.move(
                        temporary,
                        output,
                        StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE);
            } catch (java.nio.file.AtomicMoveNotSupportedException ignored) {
                Files.move(temporary, output, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temporary);
        }

        return new Result(
                output, patternsByTarget.size(), verifiedPatterns, entities.size(), issues.size());
    }

    private static void addDirectEntity(
            PortableExecutable pe,
            String label,
            List<Entity> entities,
            List<Issue> issues,
            String id,
            String kind,
            String name,
            String owner,
            long address) {
        if (!hasUsefulName(name)) return;
        if (address == 0) {
            issues.add(new Issue(id, "function has no address"));
        } else if (!pe.isExecutableVa(address)) {
            issues.add(
                    new Issue(
                            id,
                            "function address is not executable in "
                                    + label
                                    + ": "
                                    + hex(address)));
        } else {
            entities.add(
                    new Entity(id, kind, name, owner, null, address, address, pe.vaToRva(address)));
        }
    }

    private static String directId(
            String kind, String owner, FunctionContainer function, int fallbackIndex) {
        StringBuilder id = new StringBuilder(kind).append('|');
        if (!owner.isBlank()) id.append(owner).append('|');
        id.append(function.getName())
                .append('|')
                .append(typeName(function.getReturnType()))
                .append('(');
        function.getParameters().entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .forEach(entry -> id.append(typeName(entry.getValue().getType())).append(','));
        id.append(')');
        if (!hasUsefulName(function)) id.append("|index:").append(fallbackIndex);
        return id.toString();
    }

    private static String uniqueEntityId(String base, Map<String, Integer> counts) {
        int occurrence = counts.merge(base, 1, Integer::sum);
        return occurrence == 1 ? base : base + "|occurrence:" + occurrence;
    }

    private static String typeName(TypeContainer type) {
        if (type == null) return "";
        return (type.isConst() ? "const " : "")
                + type.getPrefix()
                + type.getName()
                + type.getSuffix();
    }

    private static boolean hasUsefulName(FunctionContainer function) {
        return function != null && hasUsefulName(function.getName().toString());
    }

    private static boolean hasUsefulName(String name) {
        return name != null && !name.isBlank() && !name.equals("undefined");
    }

    private static Signature createSignature(
            PortableExecutable pe, boolean[] relocationMask, long targetVa) throws IOException {
        int start = pe.vaToOffset(targetVa);
        if (start < 0) throw new IOException("unmapped function address " + hex(targetVa));
        PortableExecutable.Section section =
                pe.executableSections().stream()
                        .filter(
                                candidate ->
                                        start >= candidate.rawOffset()
                                                && start
                                                        < candidate.rawOffset()
                                                                + candidate.rawSize())
                        .findFirst()
                        .orElseThrow(
                                () ->
                                        new IOException(
                                                "function is outside executable section: "
                                                        + hex(targetVa)));
        int limit = Math.min(start + MAX_SIGNATURE_BYTES, section.rawOffset() + section.rawSize());
        List<Integer> instructionEnds = new ArrayList<>();
        boolean[] wildcard = new boolean[Math.max(0, limit - start)];
        int cursor = start;
        while (cursor < limit) {
            X64InstructionDecoder.Instruction instruction =
                    X64InstructionDecoder.decode(pe.bytes(), cursor, limit);
            if (instruction.length() <= 0) break;
            for (X64InstructionDecoder.Field field : instruction.wildcardFields()) {
                for (int index = 0; index < field.length(); index++) {
                    int relative = cursor - start + field.offset() + index;
                    if (relative >= 0 && relative < wildcard.length) wildcard[relative] = true;
                }
            }
            cursor += instruction.length();
            instructionEnds.add(cursor - start);
        }
        for (int index = 0; index < wildcard.length; index++) {
            if (relocationMask[start + index]) wildcard[index] = true;
        }
        if (instructionEnds.isEmpty()) return new Signature(new byte[0], new boolean[0], 0);

        int low = 0;
        int high = instructionEnds.size() - 1;
        int uniqueIndex = -1;
        while (low <= high) {
            int middle = (low + high) >>> 1;
            int length = instructionEnds.get(middle);
            int matches = countMatches(pe, pe.bytes(), start, wildcard, length, 2);
            if (matches == 1) {
                uniqueIndex = middle;
                high = middle - 1;
            } else {
                low = middle + 1;
            }
        }
        int selectedIndex =
                uniqueIndex < 0
                        ? instructionEnds.size() - 1
                        : Math.min(instructionEnds.size() - 1, uniqueIndex + TRAILING_INSTRUCTIONS);
        int length = instructionEnds.get(selectedIndex);
        byte[] signatureBytes = Arrays.copyOfRange(pe.bytes(), start, start + length);
        boolean[] signatureMask = Arrays.copyOf(wildcard, length);
        int matches = countMatches(pe, signatureBytes, 0, signatureMask, length, Integer.MAX_VALUE);
        return new Signature(signatureBytes, signatureMask, matches);
    }

    private static int countMatches(
            PortableExecutable pe,
            byte[] source,
            int sourceStart,
            boolean[] wildcard,
            int length,
            int stopAfter) {
        int anchorStart = 0;
        int anchorLength = 0;
        for (int cursor = 0; cursor < length; ) {
            while (cursor < length && wildcard[cursor]) cursor++;
            int begin = cursor;
            while (cursor < length && !wildcard[cursor]) cursor++;
            if (cursor - begin > anchorLength) {
                anchorStart = begin;
                anchorLength = cursor - begin;
            }
        }
        int matches = 0;
        for (PortableExecutable.Section section : pe.executableSections()) {
            int first = section.rawOffset();
            int lastStart = section.rawOffset() + section.rawSize() - length;
            if (lastStart < first) continue;
            if (anchorLength == 0) {
                for (int candidate = first; candidate <= lastStart; candidate++) {
                    if (matches(source, sourceStart, pe.bytes(), candidate, wildcard, length)
                            && ++matches >= stopAfter) return matches;
                }
                continue;
            }
            int[] shift = new int[256];
            Arrays.fill(shift, anchorLength);
            for (int index = 0; index < anchorLength - 1; index++) {
                shift[Byte.toUnsignedInt(source[sourceStart + anchorStart + index])] =
                        anchorLength - 1 - index;
            }
            int anchor = first + anchorStart;
            int anchorEnd = lastStart + anchorStart;
            while (anchor <= anchorEnd) {
                int index = anchorLength - 1;
                while (index >= 0
                        && source[sourceStart + anchorStart + index] == pe.bytes()[anchor + index])
                    index--;
                if (index < 0) {
                    int candidate = anchor - anchorStart;
                    if (matches(source, sourceStart, pe.bytes(), candidate, wildcard, length)
                            && ++matches >= stopAfter) return matches;
                    anchor++;
                } else {
                    anchor += shift[Byte.toUnsignedInt(pe.bytes()[anchor + anchorLength - 1])];
                }
            }
        }
        return matches;
    }

    private static boolean matches(
            byte[] pattern,
            int patternStart,
            byte[] bytes,
            int offset,
            boolean[] wildcard,
            int length) {
        for (int index = 0; index < length; index++) {
            if (!wildcard[index] && pattern[patternStart + index] != bytes[offset + index])
                return false;
        }
        return true;
    }

    private static String toJson(
            Path executable,
            PortableExecutable pe,
            PortableExecutable.Version version,
            Map<Long, Pattern> patterns,
            List<Entity> entities,
            List<Issue> issues) {
        StringBuilder json = new StringBuilder(1024 * 1024);
        json.append("{\n  \"schemaVersion\": ").append(SCHEMA_VERSION).append(",\n");
        json.append("  \"executable\": {\n");
        property(json, "name", executable.getFileName().toString(), 4, true);
        property(json, "sha256", pe.sha256(), 4, true);
        property(json, "fileVersion", version.fileVersion(), 4, true);
        property(json, "productVersion", version.productVersion(), 4, true);
        property(json, "machine", "AMD64", 4, true);
        property(json, "imageBase", hex(pe.imageBase()), 4, true);
        property(json, "imageSize", hex(pe.sizeOfImage()), 4, true);
        property(json, "peTimestamp", hex(pe.timestamp()), 4, true);
        json.append("    \"fileSize\": ").append(pe.bytes().length).append("\n  },\n");
        json.append("  \"patterns\": [\n");
        int patternIndex = 0;
        for (Pattern pattern : patterns.values()) {
            json.append("    {\"id\": ")
                    .append(quote(pattern.id()))
                    .append(", \"targetRva\": ")
                    .append(quote(hex(pattern.targetRva())))
                    .append(", \"targetVa\": ")
                    .append(quote(hex(pattern.targetVa())))
                    .append(", \"length\": ")
                    .append(pattern.signature().bytes().length)
                    .append(", \"matches\": ")
                    .append(pattern.signature().matchCount())
                    .append(", \"bytes\": ")
                    .append(quote(format(pattern.signature())))
                    .append('}');
            if (++patternIndex < patterns.size()) json.append(',');
            json.append('\n');
        }
        json.append("  ],\n  \"entities\": [\n");
        int entityIndex = 0;
        List<Entity> resolved =
                entities.stream()
                        .filter(entity -> patterns.containsKey(entity.targetVa()))
                        .toList();
        for (Entity entity : resolved) {
            Pattern pattern = patterns.get(entity.targetVa());
            json.append("    {\"id\": ")
                    .append(quote(entity.id()))
                    .append(", \"kind\": ")
                    .append(quote(entity.kind()))
                    .append(", \"name\": ")
                    .append(quote(entity.name()));
            if (!entity.owner().isBlank())
                json.append(", \"owner\": ").append(quote(entity.owner()));
            if (entity.slot() != null) json.append(", \"slot\": ").append(entity.slot());
            json.append(", \"storedVa\": ")
                    .append(quote(hex(entity.storedVa())))
                    .append(", \"targetRva\": ")
                    .append(quote(hex(entity.targetRva())))
                    .append(", \"patternId\": ")
                    .append(quote(pattern.id()))
                    .append('}');
            if (++entityIndex < resolved.size()) json.append(',');
            json.append('\n');
        }
        json.append("  ],\n  \"issues\": [\n");
        issues.sort(Comparator.comparing(Issue::entityId).thenComparing(Issue::reason));
        for (int index = 0; index < issues.size(); index++) {
            Issue issue = issues.get(index);
            json.append("    {\"entityId\": ")
                    .append(quote(issue.entityId()))
                    .append(", \"reason\": ")
                    .append(quote(issue.reason()))
                    .append('}');
            if (index + 1 < issues.size()) json.append(',');
            json.append('\n');
        }
        json.append("  ]\n}\n");
        return json.toString();
    }

    private static void property(
            StringBuilder json, String name, String value, int indent, boolean comma) {
        json.append(" ".repeat(indent)).append(quote(name)).append(": ").append(quote(value));
        if (comma) json.append(',');
        json.append('\n');
    }

    private static String format(Signature signature) {
        StringBuilder text = new StringBuilder(signature.bytes().length * 3);
        for (int index = 0; index < signature.bytes().length; index++) {
            if (index > 0) text.append(' ');
            if (signature.wildcard()[index]) text.append("??");
            else text.append(String.format("%02X", Byte.toUnsignedInt(signature.bytes()[index])));
        }
        return text.toString();
    }

    private static String quote(String value) {
        StringBuilder escaped = new StringBuilder(value.length() + 2).append('"');
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '"' -> escaped.append("\\\"");
                case '\\' -> escaped.append("\\\\");
                case '\b' -> escaped.append("\\b");
                case '\f' -> escaped.append("\\f");
                case '\n' -> escaped.append("\\n");
                case '\r' -> escaped.append("\\r");
                case '\t' -> escaped.append("\\t");
                default -> {
                    if (character < 0x20) escaped.append(String.format("\\u%04X", (int) character));
                    else escaped.append(character);
                }
            }
        }
        return escaped.append('"').toString();
    }

    private static String hex(long value) {
        return String.format("0x%X", value);
    }
}
