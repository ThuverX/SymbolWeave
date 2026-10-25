package symbolweave;

import symbolweave.containers.ClassContainer;
import symbolweave.containers.FileContainer;
import symbolweave.containers.FunctionContainer;
import symbolweave.containers.MemberContainer;
import symbolweave.containers.ParameterContainer;
import symbolweave.containers.TypeContainer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

public class SDKWriter {

    private static List<ProjectConfig.Dependency> dependencyRules = List.of();

    public static void configure(ProjectConfig config) {
        dependencyRules = List.copyOf(config.outputs.dependencies);
    }

    private static void bodyDependencies(String body, Set<String> imports) {
        for (var rule : dependencyRules)
            if (rule.bodyRegex != null
                    && java.util.regex.Pattern.compile(rule.bodyRegex).matcher(body).find()
                    && rule.header != null) imports.add(rule.header);
    }

    public static void validateMembers(FileContainer fc) {
        for (ClassContainer classContainer : fc.getClasses()) {
            validatedInstanceMembers(classContainer, fc.getClasses());
        }
    }

    // collapses classes up into their parents, i.e. only changed virtual methods survive
    public static FileContainer collapseContainer(FileContainer fc) {
        FileContainer collapsedContainer = new FileContainer("Collapsed");
        collapsedContainer.getLooseFunctions().addAll(fc.getLooseFunctions());

        for (ClassContainer classContainer : fc.getClasses()) {
            collapsedContainer.getClasses().add(collapseClass(classContainer, fc.getClasses()));
        }

        return collapsedContainer;
    }

    private static ClassContainer collapseClass(
            ClassContainer classContainer, List<ClassContainer> sourceClasses) {
        List<ClassContainer> listedParents =
                classContainer.getParents().stream()
                        .map(parent -> findClass(sourceClasses, parent))
                        .filter(Objects::nonNull)
                        .toList();

        List<ClassContainer> directParents =
                listedParents.stream()
                        .filter(
                                candidate ->
                                        listedParents.stream()
                                                .filter(other -> other != candidate)
                                                .noneMatch(
                                                        other ->
                                                                inheritsFrom(
                                                                        other,
                                                                        candidate,
                                                                        sourceClasses,
                                                                        new HashSet<>())))
                        .toList();

        List<Util.NamespacedString> collapsedParents =
                directParents.stream().map(ClassContainer::getName).toList();

        if (directParents.isEmpty()) {
            HashMap<Integer, FunctionContainer> vtableFunctions = new HashMap<>();

            for (int slot = 0; slot < classContainer.getVtableCount(); slot++) {
                FunctionContainer function = classContainer.getVirtualFunctions().get(slot);

                if (isEmpty(function)) {
                    continue;
                }

                vtableFunctions.put(slot, copyFunction(function, classContainer.getName(), false));
            }

            return new ClassContainer(
                    classContainer.getName(),
                    classContainer.getVtableAddress(),
                    classContainer.getVtableCount(),
                    vtableFunctions,
                    classContainer.getFunctions(),
                    new ArrayList<>(collapsedParents),
                    new ArrayList<>(classContainer.getMembers()));
        }

        HashMap<Integer, FunctionContainer> collapsedFunctions = new HashMap<>();
        Set<String> emittedOverrides = new HashSet<>();
        int logicalSlotCount = logicalSlotCount(classContainer);
        for (int slot = 0; slot < logicalSlotCount; slot++) {
            FunctionContainer function = classContainer.getVirtualFunctions().get(slot);
            if (isEmpty(function)) continue;

            InheritedSlot inherited = findInheritedSlot(classContainer, directParents, slot);
            if (inherited == null) {
                collapsedFunctions.put(
                        slot, copyFunction(function, classContainer.getName(), false));
                continue;
            }

            if (isEmpty(inherited.function())) {
                if (!function.isOverride()) continue;
                FunctionContainer override = copyFunction(function, inherited.owner(), true);
                if (slot < classContainer.getVtableCount()
                        || emittedOverrides.add(declarationKey(override))) {
                    collapsedFunctions.put(slot, override);
                }
                continue;
            }

            if (!hasDifferentImplementation(function, inherited.function())) continue;

            FunctionContainer override =
                    copyFunctionWithSignature(
                            function, inherited.function(), inherited.owner(), true);
            if (slot >= classContainer.getVtableCount()
                    && !emittedOverrides.add(declarationKey(override))) continue;
            collapsedFunctions.put(slot, override);
        }

        return new ClassContainer(
                classContainer.getName(),
                classContainer.getVtableAddress(),
                classContainer.getVtableCount(),
                collapsedFunctions,
                classContainer.getFunctions(),
                new ArrayList<>(collapsedParents),
                new ArrayList<>(classContainer.getMembers()));
    }

    private static ClassContainer findClass(
            List<ClassContainer> classes, Util.NamespacedString name) {
        for (ClassContainer c : classes) {
            if (c.getName().equals(name)) {
                return c;
            }
        }
        return null;
    }

    private static boolean inheritsFrom(
            ClassContainer child,
            ClassContainer ancestor,
            List<ClassContainer> classes,
            Set<Util.NamespacedString> visited) {
        if (!visited.add(child.getName())) {
            return false;
        }

        for (Util.NamespacedString parentName : child.getParents()) {
            if (parentName.equals(ancestor.getName())) {
                return true;
            }

            ClassContainer parent = findClass(classes, parentName);
            if (parent != null && inheritsFrom(parent, ancestor, classes, visited)) {
                return true;
            }
        }

        return false;
    }

    private static InheritedSlot findInheritedSlot(
            ClassContainer child, List<ClassContainer> directParents, int childSlot) {
        ClassContainer primaryParent = directParents.getFirst();
        if (childSlot < child.getVtableCount()) {
            return childSlot < primaryParent.getVtableCount()
                    ? new InheritedSlot(
                            primaryParent.getName(),
                            primaryParent.getVirtualFunctions().get(childSlot))
                    : null;
        }

        int segmentStart = child.getVtableCount();
        int primaryTail =
                Math.max(0, logicalSlotCount(primaryParent) - primaryParent.getVtableCount());
        if (childSlot < segmentStart + primaryTail) {
            int parentSlot = primaryParent.getVtableCount() + childSlot - segmentStart;
            return new InheritedSlot(
                    primaryParent.getName(), primaryParent.getVirtualFunctions().get(parentSlot));
        }
        segmentStart += primaryTail;

        for (int parentIndex = 1; parentIndex < directParents.size(); parentIndex++) {
            ClassContainer parent = directParents.get(parentIndex);
            int segmentEnd = segmentStart + logicalSlotCount(parent);
            if (childSlot < segmentEnd) {
                return new InheritedSlot(
                        parent.getName(),
                        parent.getVirtualFunctions().get(childSlot - segmentStart));
            }
            segmentStart = segmentEnd;
        }
        return null;
    }

    private static int logicalSlotCount(ClassContainer cls) {
        return Math.max(
                cls.getVtableCount(),
                cls.getVirtualFunctions().keySet().stream()
                        .mapToInt(index -> index + 1)
                        .max()
                        .orElse(0));
    }

    private static boolean hasDifferentImplementation(
            FunctionContainer child, FunctionContainer parent) {
        if (child.getImplementationAddress() != 0 && parent.getImplementationAddress() != 0) {
            return child.getImplementationAddress() != parent.getImplementationAddress();
        }
        if (child.isOverride()) return true;
        return !child.getName().equals(parent.getName());
    }

    private static FunctionContainer copyFunction(
            FunctionContainer function, Util.NamespacedString vtableOwner, boolean isOverride) {
        FunctionContainer copy =
                new FunctionContainer(
                        function.getAddress(),
                        function.getName(),
                        function.getCallingConvention(),
                        function.getReturnType(),
                        function.getParameters(),
                        isOverride,
                        function.isStatic());
        copy.setVarargs(function.isVarargs());
        copy.setVtableOwner(vtableOwner);
        copyAnalysis(function, copy);
        return copy;
    }

    private static FunctionContainer copyFunctionWithSignature(
            FunctionContainer implementation,
            FunctionContainer signature,
            Util.NamespacedString vtableOwner,
            boolean isOverride) {
        FunctionContainer copy =
                new FunctionContainer(
                        implementation.getAddress(),
                        signature.getName(),
                        signature.getCallingConvention(),
                        signature.getReturnType(),
                        signature.getParameters(),
                        isOverride,
                        signature.isStatic());
        copy.setVarargs(signature.isVarargs());
        copy.setVtableOwner(vtableOwner);
        copyAnalysis(implementation, copy);
        return copy;
    }

    private static void copyAnalysis(FunctionContainer source, FunctionContainer target) {
        target.setImplementationAddress(source.getImplementationAddress());
        if (source.hasPureVirtualValue()) target.setPureVirtual(source.isPureVirtual());
    }

    private record InheritedSlot(Util.NamespacedString owner, FunctionContainer function) {}

    private static String declarationKey(FunctionContainer function) {
        StringBuilder key = new StringBuilder(function.getName().getName()).append('(');
        for (ParameterContainer parameter : explicitParameters(function)) {
            key.append(formatTypeContainer(parameter.getType())).append(';');
        }
        return key.append(')').toString();
    }

    private static boolean isEmpty(FunctionContainer function) {
        return function == null;
    }

    public static void writeToDirectory(FileContainer fc, Path outPath) {
        writeToDirectory(fc, outPath, List.of());
    }

    public static void writeToDirectory(FileContainer fc, Path outPath, List<Path> supportHeaders) {
        copyRuntimeHeader(outPath);
        for (Path support : supportHeaders) copyHeaderFiles(support, outPath);

        for (ClassContainer classContainer : fc.getClasses()) {
            Path path =
                    classContainer.getName().getParts().stream()
                            .map(SDKWriter::removeIllegalPathCharacters)
                            .reduce(outPath, Path::resolve, Path::resolve)
                            .getParent();

            // Template declarations require concrete instantiations before emitting a class header.
            if (classContainer.getName().toString().contains("<")
                    || classContainer.getName().toString().contains(">")) continue;

            writeClassToFile(classContainer, path, fc.getClasses());
        }

        writeLooseFunctions(fc.getLooseFunctions(), outPath);
    }

    private static void copyRuntimeHeader(Path outPath) {
        try (var resource = SDKWriter.class.getResourceAsStream("/include/SdkMetadata.h")) {
            if (resource == null)
                throw new IllegalStateException(
                        "Missing bundled C++ runtime header; rebuild the generator with its"
                                + " resources");
            Files.createDirectories(outPath);
            Files.copy(
                    resource,
                    outPath.resolve("SdkMetadata.h"),
                    StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new java.io.UncheckedIOException("Cannot write C++ runtime header", e);
        }
    }

    private static void copyHeaderFiles(Path sourceRoot, Path outPath) {
        try {
            Files.createDirectories(outPath);
            if (Files.isRegularFile(sourceRoot)) {
                Files.copy(
                        sourceRoot,
                        outPath.resolve(sourceRoot.getFileName()),
                        StandardCopyOption.REPLACE_EXISTING);
                return;
            }

            try (var paths = Files.walk(sourceRoot)) {
                for (Path source :
                        paths.filter(Files::isRegularFile)
                                .filter(SDKWriter::isHeaderFile)
                                .toList()) {
                    Path destination = outPath.resolve(sourceRoot.relativize(source));
                    Files.createDirectories(destination.getParent());
                    Files.copy(source, destination, StandardCopyOption.REPLACE_EXISTING);
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static boolean isHeaderFile(Path path) {
        String fileName = path.getFileName().toString().toLowerCase(Locale.ROOT);
        return fileName.endsWith(".h")
                || fileName.endsWith(".hh")
                || fileName.endsWith(".hpp")
                || fileName.endsWith(".hxx");
    }

    private static void writeClassToFile(
            ClassContainer cc, Path outPath, List<ClassContainer> classes) {
        try {
            outPath.toFile().mkdirs();
            Files.writeString(
                    outPath.resolve(removeIllegalPathCharacters(cc.getName().getName()) + ".h"),
                    classContainerToCPP(cc, classes));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static void writeLooseFunctions(List<FunctionContainer> functions, Path outPath) {
        Map<String, List<FunctionContainer>> functionsByNamespace = new TreeMap<>();
        Map<String, List<FunctionContainer>> functionsByHeader = new TreeMap<>();

        for (FunctionContainer function : functions) {
            if (!hasDeclaration(function)) continue;

            List<String> parts = function.getName().getParts();
            if (parts.size() == 1 && !function.getHeaderFile().isEmpty()) {
                functionsByHeader
                        .computeIfAbsent(function.getHeaderFile(), ignored -> new ArrayList<>())
                        .add(function);
            } else {
                String namespace =
                        parts.size() > 1
                                ? String.join("::", parts.subList(0, parts.size() - 1))
                                : "";
                functionsByNamespace
                        .computeIfAbsent(namespace, ignored -> new ArrayList<>())
                        .add(function);
            }
        }

        for (Map.Entry<String, List<FunctionContainer>> entry : functionsByNamespace.entrySet()) {
            Path path = looseFunctionHeaderPath(outPath, entry.getKey());
            try {
                Files.createDirectories(path.getParent());
                Files.writeString(path, looseFunctionsToCPP(entry.getKey(), entry.getValue()));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        for (Map.Entry<String, List<FunctionContainer>> entry : functionsByHeader.entrySet()) {
            Path path = outPath.resolve(removeIllegalPathCharacters(entry.getKey()) + ".h");
            try {
                Files.createDirectories(path.getParent());
                Files.writeString(path, looseFunctionsToCPP("", entry.getValue()));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private static Path looseFunctionHeaderPath(Path outPath, String namespace) {
        if (namespace.isEmpty()) return outPath.resolve("Global.h");

        List<String> parts = Util.NamespacedString.parse(namespace).getParts();
        Path directory = outPath;
        for (int i = 0; i < parts.size() - 1; i++) {
            directory = directory.resolve(removeIllegalPathCharacters(parts.get(i)));
        }
        return directory.resolve(removeIllegalPathCharacters(parts.getLast()) + ".h");
    }

    private static String looseFunctionsToCPP(String namespace, List<FunctionContainer> functions) {
        Set<String> imports = new TreeSet<>();
        Set<Util.NamespacedString> forwardDeclarations = new HashSet<>();
        for (FunctionContainer function : functions) {
            collectDependencies(function, imports, forwardDeclarations);
        }

        StringBuilder body = new StringBuilder();

        if (!namespace.isEmpty()) body.append("namespace ").append(namespace).append("\n{\n\n");

        body.append("\n");

        Map<String, Integer> metadataNameCounts = new HashMap<>();
        for (FunctionContainer function : functions) {
            String functionName = numberedFunctionName(function, metadataNameCounts);
            body.append(
                            functionContainerToCPPMetadata(
                                    function,
                                    "void",
                                    metadataName(functionName),
                                    functionName,
                                    false))
                    .append("\n\n");
        }

        body.append("\n");

        Map<String, Integer> declarationNameCounts = new HashMap<>();
        for (FunctionContainer function : functions) {
            String functionName = numberedFunctionName(function, declarationNameCounts);
            StringBuilder args = new StringBuilder();
            List<ParameterContainer> parameters = explicitParameters(function);
            for (int i = 0; i < parameters.size(); i++) {
                ParameterContainer pc = parameters.get(i);
                args.append(pc.getName());
                if (i < parameters.size() - 1) args.append(", ");
            }
            if (function.isVarargs()) body.append("template <typename... TArgs>\n");
            body.append("inline ")
                    .append(functionContainerToCPP(function, "", functionName, false))
                    .append("{ SDK_STATIC_IMPLEMENTATION(")
                    .append(metadataName(functionName));
            appendImplementationArguments(body, function, args);
            body.append("); };").append("\n");
        }

        if (!namespace.isEmpty()) body.append("}\n");

        cleanForwardDeclarations(forwardDeclarations, imports);

        bodyDependencies(body.toString(), imports);

        StringBuilder header =
                new StringBuilder("// Generated file. Do not edit.\n#pragma once\n\n")
                        .append(
                                "#include <cstddef>\n"
                                        + "#include <cstdint>\n"
                                        + "#include \"SdkMetadata.h\"\n");
        for (String importPath : imports) {
            header.append("#include \"").append(importPath).append("\"\n");
        }
        header.append("\n");

        forwardDeclarations.stream()
                .sorted(Comparator.comparing(Util.NamespacedString::toString))
                .forEach(
                        type ->
                                header.append("namespace ")
                                        .append(type.parent())
                                        .append(" { class ")
                                        .append(type.getName())
                                        .append("; }\n"));
        if (!forwardDeclarations.isEmpty()) header.append("\n");

        return header.append(body).toString().replace("\t", "");
    }

    private static void cleanForwardDeclarations(
            Set<Util.NamespacedString> forwardDeclarations, Set<String> imports) {
        for (var rule : dependencyRules)
            if (rule.typeRegex != null) {
                var pattern = java.util.regex.Pattern.compile(rule.typeRegex);
                if (rule.header != null
                        && forwardDeclarations.stream()
                                .anyMatch(t -> pattern.matcher(t.toString()).find()))
                    imports.add(rule.header);
                if (rule.removeForward)
                    forwardDeclarations.removeIf(t -> pattern.matcher(t.toString()).find());
            }
    }

    private static String classContainerToCPP(ClassContainer cc, List<ClassContainer> classes) {
        StringBuilder body = new StringBuilder();

        boolean isNamespace =
                cc.getVtableCount() == 0
                        && cc.getVirtualFunctions().size() == 0
                        && cc.getFunctions().size() > 0
                        && cc.getFunctions().stream().allMatch(FunctionContainer::isStatic);

        boolean hasNamespace = !cc.getName().isTopLevel();
        Set<String> imports = new TreeSet<>();
        Set<Util.NamespacedString> forwardDeclarations = new HashSet<>();

        for (Util.NamespacedString parent : cc.getParents()) {
            imports.add(headerPath(parent));
        }

        List<Map.Entry<Integer, FunctionContainer>> virtualFunctions =
                cc.getVirtualFunctions().entrySet().stream()
                        .filter(entry -> hasDeclaration(entry.getValue()))
                        .sorted(Map.Entry.comparingByKey())
                        .toList();
        List<FunctionContainer> functions =
                cc.getFunctions().stream().filter(SDKWriter::hasDeclaration).toList();

        for (Map.Entry<Integer, FunctionContainer> entry : virtualFunctions) {
            collectDependencies(entry.getValue(), imports, forwardDeclarations);
        }
        for (FunctionContainer function : functions) {
            collectDependencies(function, imports, forwardDeclarations);
        }
        for (MemberContainer member : cc.getMembers()) {
            collectMemberDependency(member, imports, forwardDeclarations);
        }

        List<MemberContainer> instanceMembers = validatedInstanceMembers(cc, classes);

        if (hasNamespace) body.append("namespace ").append(cc.getName().parent()).append("\n{\n\n");

        if (!instanceMembers.isEmpty() && !isNamespace) body.append("#pragma pack(push, 1)\n");

        if (!isNamespace) {
            body.append("class ");
        } else {
            body.append("namespace ");
        }

        body.append(cc.getName().getName());

        if (!isNamespace) {
            if (!cc.getParents().isEmpty()) body.append(" : ");
            for (int i = 0; i < cc.getParents().size(); i++) {
                if (i > 0) body.append(", ");
                body.append("public ").append(cc.getParents().get(i));
            }
        }

        if ((!virtualFunctions.isEmpty() || !functions.isEmpty() || !cc.getMembers().isEmpty())
                && !isNamespace) {
            body.append("\n{\npublic:\n");
        } else {
            body.append("\n{\n");
        }

        boolean inheritsVtable =
                cc.getParents().stream()
                        .map(parent -> findClass(classes, parent))
                        .filter(Objects::nonNull)
                        .anyMatch(parent -> isPolymorphic(parent, classes, new HashSet<>()));
        if (!isNamespace
                && cc.getVtableCount() > 0
                && virtualFunctions.isEmpty()
                && !inheritsVtable) {
            // Preserve the native vptr even when no virtual signatures were recovered.
            // Otherwise C++ treats this as an empty base while layout calculations count a vptr.
            body.append("private:\n\tvirtual void _sdkUnknownVirtualSlot0() {}\npublic:\n\n");
        }

        Map<String, Integer> metadataNameCounts = new HashMap<>();
        Map<String, Integer> metadataDeclarationNameCounts = new HashMap<>();
        for (Map.Entry<Integer, FunctionContainer> entry : virtualFunctions) {
            String functionName =
                    declarationFunctionName(entry.getValue(), metadataDeclarationNameCounts);
            if (functionName.startsWith("~")) functionName = "~" + cc.getName().getName();

            String metadataStem = numberedFunctionName(entry.getValue(), metadataNameCounts);
            if (metadataStem.startsWith("~")) metadataStem = "~" + cc.getName().getName();
            String metadataName = virtualMetadataName(entry.getValue(), metadataStem);
            String metadataFunctionName =
                    entry.getValue().isOverride() ? functionName + "_Override" : functionName;
            String metadata =
                    functionContainerToCPPMetaData(
                            entry.getValue(),
                            cc.getName(),
                            entry.getKey(),
                            metadataName,
                            metadataFunctionName);
            if (metadata != null) body.append(metadata).append("\n\n");
        }

        for (FunctionContainer functionContainer : functions) {
            String functionName = numberedFunctionName(functionContainer, metadataNameCounts);
            if (functionName.startsWith("~")) functionName = "~" + cc.getName().getName();

            String metadataName = metadataName(functionName);
            String metadata =
                    functionContainerToCPPMetadata(
                            functionContainer,
                            isNamespace ? Util.NamespacedString.parse("void") : cc.getName(),
                            metadataName,
                            functionName,
                            functionContainer.getCallingConvention()
                                    == FunctionContainer.CallingConvention.THISCALL);
            if (metadata != null) body.append(metadata).append("\n\n");
        }

        Map<String, Integer> declarationNameCounts = new HashMap<>();
        Map<String, Integer> declarationMetadataNameCounts = new HashMap<>();
        for (Map.Entry<Integer, FunctionContainer> entry : virtualFunctions) {
            String functionName = declarationFunctionName(entry.getValue(), declarationNameCounts);
            String metadataStem =
                    numberedFunctionName(entry.getValue(), declarationMetadataNameCounts);
            if (metadataStem.startsWith("~")) metadataStem = "~" + cc.getName().getName();
            String metadataName = virtualMetadataName(entry.getValue(), metadataStem);
            String function =
                    functionContainerToCPP(entry.getValue(), cc.getName().getName(), functionName);
            if (function != null) {
                body.append(function);
                if (entry.getValue().isPureVirtual()) {
                    body.append(";\n");
                } else if (entry.getValue().getName().getName().startsWith("~")) {
                    body.append(" = default;\n");
                } else {
                    body.append(" { SDK_VIRTUAL_IMPLEMENTATION(")
                            .append(metadataName)
                            .append(", this");
                    for (ParameterContainer parameter : explicitParameters(entry.getValue())) {
                        body.append(", ").append(parameter.getName());
                    }
                    body.append("); }\n");
                }
            }
        }

        if (!virtualFunctions.isEmpty() && !functions.isEmpty()) body.append("\n");
        Map<String, Integer> inlineStaticMetadataNameCounts = new HashMap<>();
        for (Map.Entry<Integer, FunctionContainer> entry : virtualFunctions) {
            numberedFunctionName(entry.getValue(), inlineStaticMetadataNameCounts);
        }
        for (FunctionContainer functionContainer : functions) {
            String functionName = numberedFunctionName(functionContainer, declarationNameCounts);
            String metadataFunctionName =
                    numberedFunctionName(functionContainer, inlineStaticMetadataNameCounts);
            String function =
                    functionContainerToCPP(
                            functionContainer, cc.getName().getName(), functionName, false);
            if (function != null) {
                if (functionContainer.isVarargs()) body.append("template <typename... TArgs>\n");
                body.append(function);
                boolean isConstructor =
                        functionContainer.getName().getName().equals(cc.getName().getName())
                                && !isStaticConstructor(functionContainer);
                boolean isDestructor = functionContainer.getName().getName().startsWith("~");
                boolean takesReceiver =
                        !functionContainer.isStatic()
                                && functionContainer.getCallingConvention()
                                        == FunctionContainer.CallingConvention.THISCALL;
                // Explicit-memory constructors are static wrappers; only thiscall entries
                // receive the implicit this argument.
                if (!isDestructor || takesReceiver) {
                    body.append(" { ");
                    // The implementation macro returns the native result. Constructors and
                    // destructors cannot return expressions, so discard that result in a lambda.
                    if (isConstructor || isDestructor) body.append("[&]() { ");
                    body.append("SDK_STATIC_IMPLEMENTATION(")
                            .append(metadataName(metadataFunctionName));
                    if (takesReceiver) body.append(", this");
                    appendImplementationArguments(body, functionContainer, null);
                    body.append("); ");
                    if (isConstructor || isDestructor) body.append("}(); ");
                    body.append("}\n");
                } else {
                    body.append(";\n");
                }
            }
        }

        if (!cc.getMembers().isEmpty()) body.append("\n");
        long layoutCursor = instanceDataStart(cc, classes, new HashSet<>());
        for (MemberContainer member : instanceMembers) {
            long gap = member.getOffset() - layoutCursor;
            if (gap > 0) {
                body.append("\tstd::byte _pad_")
                        .append(String.format("%04X", layoutCursor))
                        .append("[0x")
                        .append(Long.toHexString(gap).toUpperCase(Locale.ROOT))
                        .append("];\n");
            }
            body.append("\t").append(formatMemberDeclaration(member)).append(";\n");
            layoutCursor = member.getOffset() + member.getSize();
        }
        for (MemberContainer member : cc.getMembers()) {
            if (instanceMembers.contains(member)) continue;
            body.append("\t");
            if (member.isAddressed()) {
                body.append(formatAddressedMember(member)).append("\n");
            } else {
                if (member.isStatic()) body.append("static ");
                body.append(formatMemberDeclaration(member));
                if (!member.getValue().isEmpty()) body.append(" = ").append(member.getValue());
                body.append(";\n");
            }
        }

        body.append("};\n\n");

        if (!instanceMembers.isEmpty() && !isNamespace) body.append("#pragma pack(pop)\n\n");

        if (!isNamespace) {
            for (MemberContainer member : instanceMembers) {
                body.append("static_assert(offsetof(")
                        .append(cc.getName().getName())
                        .append(", ")
                        .append(member.getName())
                        .append(") == ")
                        .append(String.format("0x%X", member.getOffset()))
                        .append(");\n");
                body.append("static_assert(sizeof(decltype(")
                        .append(cc.getName().getName())
                        .append("::")
                        .append(member.getName())
                        .append(")) == ")
                        .append(String.format("0x%X", member.getSize()))
                        .append(");\n");
            }
            if (!instanceMembers.isEmpty()) body.append("\n");
        }

        if (hasNamespace) body.append("}\n");

        cleanForwardDeclarations(forwardDeclarations, imports);

        bodyDependencies(body.toString(), imports);

        StringBuilder header =
                new StringBuilder("// Generated file. Do not edit.\n#pragma once\n\n")
                        .append(
                                "#include <cstddef>\n"
                                        + "#include <cstdint>\n"
                                        + "#include \"SdkMetadata.h\"\n");
        for (String importPath : imports) {
            header.append("#include \"").append(importPath).append("\"\n");
        }
        header.append("\n");
        forwardDeclarations.stream()
                .sorted((a, b) -> a.toString().compareTo(b.toString()))
                .forEach(
                        type ->
                                header.append("namespace ")
                                        .append(type.parent())
                                        .append(" { class ")
                                        .append(type.getName())
                                        .append("; }\n"));
        if (!forwardDeclarations.isEmpty()) header.append("\n");

        return header.append(body).toString();
    }

    private static String formatTypeContainer(TypeContainer tc) {
        StringBuilder sb = new StringBuilder();

        if (tc.isConst()) sb.append("const ");
        sb.append(tc.getPrefix());
        sb.append(tc.getName());
        sb.append(tc.getSuffix());

        return sb.toString();
    }

    private static String formatMemberDeclaration(MemberContainer member) {
        TypeContainer type = member.getType();
        String suffix = type.getSuffix();
        StringBuilder declaration = new StringBuilder();
        if (type.isConst()) declaration.append("const ");
        declaration.append(type.getPrefix()).append(type.getName());
        if (suffix.startsWith("[")) {
            declaration.append(" ").append(member.getName()).append(suffix);
        } else {
            declaration.append(suffix).append(" ").append(member.getName());
        }
        if (member.getArraySize() > 0) {
            declaration.append("[").append(member.getArraySize()).append("]");
        }
        return declaration.toString();
    }

    private static String formatAddressedMember(MemberContainer member) {
        TypeContainer type = member.getType();
        if (!type.getSuffix().startsWith("[") && member.getArraySize() == 0) {
            return "SDK_ADDRESS_MEMBER(("
                    + formatTypeContainer(type)
                    + "), "
                    + member.getName()
                    + ", "
                    + String.format("0x%X", member.getAddress())
                    + ");";
        }

        String baseType =
                type.getSuffix().startsWith("[")
                        ? (type.isConst() ? "const " : "") + type.getPrefix() + type.getName()
                        : formatTypeContainer(type);
        String arraySuffix =
                (type.getSuffix().startsWith("[") ? type.getSuffix() : "")
                        + (member.getArraySize() > 0 ? "[" + member.getArraySize() + "]" : "");
        return "static auto "
                + member.getName()
                + "() -> "
                + baseType
                + " (&)"
                + arraySuffix
                + " { return *reinterpret_cast<"
                + baseType
                + " (*)"
                + arraySuffix
                + ">("
                + "SDK_REBASE_ADDRESS("
                + String.format("0x%X", member.getAddress())
                + ")); }";
    }

    private static List<MemberContainer> validatedInstanceMembers(
            ClassContainer cc, List<ClassContainer> classes) {
        Set<String> names = new HashSet<>();
        List<MemberContainer> instanceMembers = new ArrayList<>();

        for (MemberContainer member : cc.getMembers()) {
            String description = cc.getName() + "::" + member.getName();
            if (member.getName() == null || member.getName().isBlank()) {
                throw new IllegalArgumentException("Member in " + cc.getName() + " has no name");
            }
            if (!names.add(member.getName())) {
                throw new IllegalArgumentException("Duplicate member " + description);
            }

            boolean legacyValue =
                    member.getSize() == 0
                            && member.getOffset() == null
                            && member.getAddress() == null
                            && !member.getValue().isEmpty();
            if (legacyValue) continue;

            if (member.getSize() <= 0) {
                throw new IllegalArgumentException(description + " must have a positive size");
            }

            boolean requiresAddress = member.isStatic() || member.getType().isConst();
            if (requiresAddress) {
                if (member.getAddress() == null || member.getAddress() <= 0) {
                    throw new IllegalArgumentException(
                            description + " is static and/or const and requires an address");
                }
                if (member.getOffset() != null) {
                    throw new IllegalArgumentException(
                            description + " cannot have both an address and an offset");
                }
            } else {
                if (member.getAddress() != null) {
                    throw new IllegalArgumentException(
                            description + " has an address but is neither static nor const");
                }
                if (member.getOffset() == null || member.getOffset() < 0) {
                    throw new IllegalArgumentException(
                            description + " requires a non-negative offset");
                }
                instanceMembers.add(member);
            }
        }

        instanceMembers.sort(Comparator.comparingLong(MemberContainer::getOffset));
        if (!instanceMembers.isEmpty()) {
            for (Util.NamespacedString parentName : cc.getParents()) {
                if (findClass(classes, parentName) == null) {
                    throw new IllegalArgumentException(
                            cc.getName()
                                    + " has instance members but parent "
                                    + parentName
                                    + " has no generated layout");
                }
            }
        }
        long cursor = instanceDataStart(cc, classes, new HashSet<>());
        for (MemberContainer member : instanceMembers) {
            if (member.getOffset() < cursor) {
                throw new IllegalArgumentException(
                        cc.getName()
                                + "::"
                                + member.getName()
                                + " at "
                                + String.format("0x%X", member.getOffset())
                                + " overlaps layout ending at "
                                + String.format("0x%X", cursor));
            }
            cursor = member.getOffset() + member.getSize();
        }
        return instanceMembers;
    }

    private static long instanceDataStart(
            ClassContainer cc, List<ClassContainer> classes, Set<Util.NamespacedString> visiting) {
        if (!visiting.add(cc.getName())) {
            throw new IllegalArgumentException("Inheritance cycle involving " + cc.getName());
        }

        long size = 0;
        boolean inheritsVtable = false;
        for (Util.NamespacedString parentName : cc.getParents()) {
            ClassContainer parent = findClass(classes, parentName);
            if (parent == null) continue;
            size += classLayoutSize(parent, classes, visiting);
            inheritsVtable |= isPolymorphic(parent, classes, new HashSet<>());
        }
        if (cc.getVtableCount() > 0 && !inheritsVtable) size += Long.BYTES;

        visiting.remove(cc.getName());
        return size;
    }

    private static long classLayoutSize(
            ClassContainer cc, List<ClassContainer> classes, Set<Util.NamespacedString> visiting) {
        long size = instanceDataStart(cc, classes, visiting);
        for (MemberContainer member : cc.getMembers()) {
            if (member.getOffset() != null && !member.isStatic() && !member.getType().isConst()) {
                size = Math.max(size, member.getOffset() + member.getSize());
            }
        }
        long alignment = classLayoutAlignment(cc, classes, new HashSet<>());
        return alignment <= 1 ? size : (size + alignment - 1) / alignment * alignment;
    }

    private static long classLayoutAlignment(
            ClassContainer cc, List<ClassContainer> classes, Set<Util.NamespacedString> visiting) {
        // Classes with instance members are emitted under #pragma pack(push, 1).
        if (cc.getMembers().stream()
                .anyMatch(
                        member ->
                                member.getOffset() != null
                                        && !member.isStatic()
                                        && !member.getType().isConst())) return 1;
        if (!visiting.add(cc.getName())) return 1;
        long alignment = isPolymorphic(cc, classes, new HashSet<>()) ? Long.BYTES : 1;
        for (Util.NamespacedString parentName : cc.getParents()) {
            ClassContainer parent = findClass(classes, parentName);
            if (parent != null)
                alignment = Math.max(alignment, classLayoutAlignment(parent, classes, visiting));
        }
        for (MemberContainer member : cc.getMembers()) {
            if (member.getOffset() != null)
                alignment = Math.max(alignment, memberAlignment(member));
        }
        visiting.remove(cc.getName());
        return alignment;
    }

    private static long memberAlignment(MemberContainer member) {
        String suffix = member.getType().getSuffix();
        if (suffix.contains("*") || suffix.contains("&")) return Long.BYTES;
        return switch (member.getType().getName().toString()) {
            case "bool",
                    "char",
                    "signed char",
                    "unsigned char",
                    "std::int8_t",
                    "std::uint8_t",
                    "int8_t",
                    "uint8_t",
                    "byte",
                    "undefined",
                    "undefined1" ->
                    1;
            case "short",
                    "short int",
                    "unsigned short",
                    "unsigned short int",
                    "std::int16_t",
                    "std::uint16_t",
                    "int16_t",
                    "uint16_t",
                    "wchar_t",
                    "undefined2" ->
                    2;
            case "int",
                    "signed int",
                    "unsigned",
                    "unsigned int",
                    "long",
                    "signed long",
                    "unsigned long",
                    "std::int32_t",
                    "std::uint32_t",
                    "int32_t",
                    "uint32_t",
                    "float",
                    "undefined4" ->
                    4;
            case "long long",
                    "signed long long",
                    "unsigned long long",
                    "std::int64_t",
                    "std::uint64_t",
                    "int64_t",
                    "uint64_t",
                    "double",
                    "std::size_t",
                    "undefined8" ->
                    8;
            default -> Math.min(Long.lowestOneBit(member.getSize()), Long.BYTES);
        };
    }

    private static boolean isPolymorphic(
            ClassContainer cc, List<ClassContainer> classes, Set<Util.NamespacedString> visiting) {
        if (!visiting.add(cc.getName())) return false;
        if (cc.getVtableCount() > 0) return true;
        for (Util.NamespacedString parentName : cc.getParents()) {
            ClassContainer parent = findClass(classes, parentName);
            if (parent != null && isPolymorphic(parent, classes, visiting)) return true;
        }
        return false;
    }

    private static String functionContainerToCPPMetaData(
            FunctionContainer fc,
            Util.NamespacedString owner,
            int vtableIndex,
            String metadataName,
            String functionName) {
        StringBuilder s = new StringBuilder();

        if (fc.getName().toString().isEmpty()) {
            return null;
        }

        String ownerName = owner.getName();
        String receiverName =
                fc.getVtableOwner() == null || fc.getVtableOwner().equals(owner)
                        ? ownerName
                        : fc.getVtableOwner().toString();
        s.append("\tSDK_VIRTUAL_FUNCTION(");
        s.append(metadataName);
        s.append(", ");
        s.append(ownerName);
        s.append(", ");
        s.append(functionName);
        s.append(", ");
        s.append(String.format("0x%X", fc.getImplementationAddress()));
        s.append(", ");
        s.append(vtableIndex);
        s.append(", (");

        s.append(" " + formatTypeContainer(fc.getReturnType()));

        s.append(" (*)(");

        s.append(receiverName);
        s.append("*");

        // Explicit parameters
        for (ParameterContainer pc : explicitParameters(fc)) {
            s.append(", ");
            s.append(formatTypeContainer(pc.getType()));
        }

        s.append(")));");

        return s.toString();
    }

    private static String functionContainerToCPP(
            FunctionContainer fc, String className, String functionName) {
        return functionContainerToCPP(fc, className, functionName, true);
    }

    private static String functionContainerToCPP(
            FunctionContainer fc, String className, String functionName, boolean isVirtual) {
        StringBuilder s = new StringBuilder();

        if (fc.getName().toString().isEmpty()) {
            return null;
        }

        boolean isStaticConstructor = isStaticConstructor(fc);
        boolean isConstructor = fc.getName().getName().equals(className) && !isStaticConstructor;

        s.append("\t");
        if (isVirtual && !fc.isOverride()) {
            s.append("virtual ");
        } else if (fc.isStatic() || isStaticConstructor) {
            s.append("static ");
        }
        if (isConstructor) {
            s.append("explicit ");
            functionName = className;
        }
        if (fc.getName().getName().startsWith("~")) functionName = "~" + className;
        if (!fc.getName().getName().startsWith("~") && !isConstructor)
            s.append(formatTypeContainer(fc.getReturnType())).append(" ");
        s.append(functionName);
        s.append("(");
        List<ParameterContainer> parameters = explicitParameters(fc);
        for (int i = 0; i < parameters.size(); i++) {
            ParameterContainer pc = parameters.get(i);
            s.append(parameterContainerToCPP(pc));
            if (i < parameters.size() - 1) s.append(", ");
        }
        if (fc.isVarargs()) {
            if (!parameters.isEmpty()) s.append(", ");
            if (isVirtual) s.append("...");
            else s.append("TArgs&&... args");
        }
        s.append(")");
        if (isVirtual && fc.isOverride()) s.append(" override");
        if (isVirtual && fc.isPureVirtual()) s.append(" = 0");

        return s.toString();
    }

    private static String functionContainerToCPPMetadata(
            FunctionContainer function,
            Util.NamespacedString owner,
            String metadataName,
            String functionName,
            boolean includeOwnerParameter) {
        return functionContainerToCPPMetadata(
                function, owner.getName(), metadataName, functionName, includeOwnerParameter);
    }

    private static String functionContainerToCPPMetadata(
            FunctionContainer function,
            String ownerName,
            String metadataName,
            String functionName,
            boolean includeOwnerParameter) {
        StringBuilder s = new StringBuilder();

        s.append("\tSDK_DIRECT_FUNCTION(")
                .append(metadataName)
                .append(", ")
                .append(ownerName)
                .append(", ")
                .append(functionName)
                .append(", ")
                .append(String.format("0x%X", function.getAddress()))
                .append(", (");
        appendFunctionPointerSignature(s, function, ownerName, includeOwnerParameter);
        s.append("));");
        return s.toString();
    }

    private static void appendFunctionPointerSignature(
            StringBuilder s,
            FunctionContainer function,
            String ownerName,
            boolean includeOwnerParameter) {
        s.append(formatTypeContainer(function.getReturnType())).append(" (*)(");
        int parameterCount = 0;
        if (includeOwnerParameter) {
            s.append(ownerName).append("*");
            parameterCount++;
        }
        for (ParameterContainer parameter : explicitParameters(function)) {
            if (parameterCount++ > 0) s.append(", ");
            s.append(formatTypeContainer(parameter.getType()));
        }
        if (function.isVarargs()) {
            if (parameterCount++ > 0) s.append(", ");
            s.append("...");
        }
        s.append(")");
    }

    private static String metadataName(String functionName) {
        return functionName.startsWith("~")
                ? functionName.substring(1) + "DeconstructorMetadata"
                : functionName + "Metadata";
    }

    private static String virtualMetadataName(FunctionContainer function, String functionName) {
        String baseName =
                functionName.startsWith("~")
                        ? functionName.substring(1) + "Deconstructor"
                        : functionName;
        return baseName + (function.isOverride() ? "_Override" : "") + "Metadata";
    }

    private static String numberedFunctionName(
            FunctionContainer function, Map<String, Integer> nameCounts) {
        String functionName =
                isStaticConstructor(function) ? "Constructor" : function.getName().getName();
        if (functionName.startsWith("~")) return functionName;

        int occurrence = nameCounts.merge(functionName, 1, Integer::sum);
        return functionName + (occurrence == 1 ? "" : occurrence);
    }

    private static boolean isStaticConstructor(FunctionContainer function) {
        return !function.getName().isTopLevel()
                && function.getName().getName().equals(function.getName().parent().getName())
                && function.getCallingConvention() != FunctionContainer.CallingConvention.THISCALL;
    }

    private static String declarationFunctionName(
            FunctionContainer function, Map<String, Integer> signatureCounts) {
        String functionName = function.getName().getName();
        if (functionName.startsWith("~")) return functionName;

        int occurrence = signatureCounts.merge(declarationKey(function), 1, Integer::sum);
        return functionName + (occurrence == 1 ? "" : occurrence);
    }

    private static String parameterContainerToCPP(ParameterContainer pc) {
        StringBuilder sb = new StringBuilder();

        sb.append(formatTypeContainer(pc.getType()));
        sb.append(" ");
        sb.append(pc.getName().toString());

        return sb.toString();
    }

    private static void appendImplementationArguments(
            StringBuilder body, FunctionContainer function, StringBuilder preformattedArguments) {
        if (preformattedArguments != null && !preformattedArguments.isEmpty()) {
            body.append(",").append(preformattedArguments);
        } else {
            for (ParameterContainer parameter : explicitParameters(function)) {
                body.append(", ").append(parameter.getName());
            }
        }
        if (function.isVarargs()) {
            body.append(", static_cast<TArgs&&>(args)...");
        }
    }

    private static List<ParameterContainer> explicitParameters(FunctionContainer function) {
        return function.getParameters().entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .map(Map.Entry::getValue)
                .filter(parameter -> !isVoidPlaceholder(parameter))
                .toList();
    }

    private static boolean isVoidPlaceholder(ParameterContainer parameter) {
        return parameter.getType().getName().toString().equals("void")
                && parameter.getType().getPrefix().isEmpty()
                && parameter.getType().getSuffix().isEmpty();
    }

    private static boolean hasDeclaration(FunctionContainer function) {
        return function != null
                && !function.getName().toString().isEmpty()
                && !function.getName().toString().equals("undefined");
    }

    private static void collectDependencies(
            FunctionContainer function,
            Set<String> imports,
            Set<Util.NamespacedString> forwardDeclarations) {
        collectTypeDependency(function.getReturnType(), imports, forwardDeclarations);
        for (ParameterContainer parameter : function.getParameters().values()) {
            collectTypeDependency(parameter.getType(), imports, forwardDeclarations);
        }
    }

    private static void collectMemberDependency(
            MemberContainer member,
            Set<String> imports,
            Set<Util.NamespacedString> forwardDeclarations) {
        String typeName = member.getType().getName().toString();
        if (typeName.startsWith("std::") || isBuiltinType(typeName)) return;
        if (member.getType().getSuffix().contains("*")
                || member.getType().getSuffix().contains("&")
                || member.isAddressed()) {
            collectTypeDependency(member.getType(), imports, forwardDeclarations);
            return;
        }
        imports.add(headerPath(member.getType().getName()));
    }

    private static boolean isBuiltinType(String name) {
        return switch (name) {
            case "void",
                    "bool",
                    "boolean",
                    "char",
                    "signed char",
                    "unsigned char",
                    "byte",
                    "short",
                    "short int",
                    "unsigned short",
                    "unsigned short int",
                    "int",
                    "signed int",
                    "unsigned",
                    "unsigned int",
                    "long",
                    "signed long",
                    "unsigned long",
                    "long long",
                    "signed long long",
                    "unsigned long long",
                    "float",
                    "double",
                    "wchar_t",
                    "undefined",
                    "undefined1",
                    "undefined2",
                    "undefined3",
                    "undefined4",
                    "undefined8" ->
                    true;
            default -> false;
        };
    }

    private static void collectTypeDependency(
            TypeContainer typeContainer,
            Set<String> imports,
            Set<Util.NamespacedString> forwardDeclarations) {
        Util.NamespacedString type = typeContainer.getName();
        for (var rule : dependencyRules)
            if (rule.typeRegex != null
                    && java.util.regex.Pattern.compile(rule.typeRegex)
                            .matcher(type.toString())
                            .find()) {
                if (rule.header != null) imports.add(rule.header);
                if (rule.removeForward) return;
            }
        if (type.isTopLevel()) {
            return;
        }
        if (type.toString().startsWith("std::")) return;

        if (typeContainer.getSuffix().contains("*") || typeContainer.getSuffix().contains("&")) {
            forwardDeclarations.add(type);
        } else {
            imports.add(headerPath(type));
        }
    }

    private static String headerPath(Util.NamespacedString type) {
        return type.getParts().stream()
                        .map(SDKWriter::removeIllegalPathCharacters)
                        .reduce("", (path, part) -> path + "/" + part)
                        .substring(1)
                + ".h";
    }

    private static String removeIllegalPathCharacters(String path) {
        return path.replaceAll("[\\\\/:*?\"<>|]", "_");
    }
}
